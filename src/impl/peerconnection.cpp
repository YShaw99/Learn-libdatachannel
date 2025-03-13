/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 * Copyright (c) 2020 Filip Klembara (in2core)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "peerconnection.hpp"
#include "certificate.hpp"
#include "dtlstransport.hpp"
#include "icetransport.hpp"
#include "internals.hpp"
#include "logcounter.hpp"
#include "peerconnection.hpp"
#include "processor.hpp"
#include "rtp.hpp"
#include "sctptransport.hpp"
#include "utils.hpp"

#if RTC_ENABLE_MEDIA
#include "dtlssrtptransport.hpp"
#endif

#include <algorithm>
#include <array>
#include <iomanip>
#include <set>
#include <sstream>
#include <thread>

using namespace std::placeholders;

namespace rtc::impl {

// 全局日志计数器定义，用于统计各类传输相关的错误及异常事件
static LogCounter COUNTER_MEDIA_TRUNCATED(plog::warning,
                                          "Number of truncated RTP packets over past second");
static LogCounter COUNTER_SRTP_DECRYPT_ERROR(plog::warning,
                                             "Number of SRTP decryption errors over past second");
static LogCounter COUNTER_SRTP_ENCRYPT_ERROR(plog::warning,
                                             "Number of SRTP encryption errors over past second");
static LogCounter
    COUNTER_UNKNOWN_PACKET_TYPE(plog::warning,
                                "Number of unknown RTCP packet types over past second");

const string PemBeginCertificateTag = "-----BEGIN CERTIFICATE-----";

// 函数 PeerConnection 构造函数
// 1. 初始化连接所需的证书、端口范围和 MTU 等配置参数
PeerConnection::PeerConnection(Configuration config_) : config(std::move(config_)) {
	// 1.1 日志输出：创建 PeerConnection
	PLOG_VERBOSE << "Creating PeerConnection";

	// 1.2 如果同时提供证书和密钥文件，则从文件中加载证书
	if (config.certificatePemFile && config.keyPemFile) {
		// 1.2.1 创建 promise 用于异步传递证书对象
		std::promise<certificate_ptr> cert;
		cert.set_value(std::make_shared<Certificate>(
		    config.certificatePemFile->find(PemBeginCertificateTag) != string::npos
		        ? Certificate::FromString(*config.certificatePemFile, *config.keyPemFile) // 1.2.1 判断是否包含证书标记，采用字符串加载
		        : Certificate::FromFile(*config.certificatePemFile, *config.keyPemFile,
		                                config.keyPemPass.value_or(""))));           // 1.2.2 从文件加载证书
		mCertificate = cert.get_future();
	} else if (!config.certificatePemFile && !config.keyPemFile) {
		// 1.3 未提供证书和密钥文件，则根据证书类型生成默认证书
		mCertificate = make_certificate(config.certificateType);
	} else {
		// 1.4 配置错误：必须同时提供证书和密钥文件，否则抛出异常
		throw std::invalid_argument(
		    "Either none or both certificate and key PEM files must be specified");
	}

	// 2. 校验端口范围，若起始端口大于结束端口则抛出异常
	if (config.portRangeEnd && config.portRangeBegin > config.portRangeEnd)
		throw std::invalid_argument("Invalid port range");

	// 3. 如果配置了 MTU，则检查 MTU 值的合法性
	if (config.mtu) {
		// 3.1 检查 MTU 是否低于 IPv4 最小值 576
		if (*config.mtu < 576) // Min MTU for IPv4
			throw std::invalid_argument("Invalid MTU value");

		// 3.2 根据 MTU 值范围输出不同级别的日志信息
		if (*config.mtu > 1500) { // Standard Ethernet
			PLOG_WARNING << "MTU set to " << *config.mtu;
		} else {
			PLOG_VERBOSE << "MTU set to " << *config.mtu;
		}
	}
}

// 函数 ~PeerConnection 析构函数
// 1. 输出日志并等待处理线程结束，确保资源正确释放
PeerConnection::~PeerConnection() {
	// 1.1 日志输出：销毁 PeerConnection
	PLOG_VERBOSE << "Destroying PeerConnection";
	mProcessor.join();
}

// 函数 close：关闭 PeerConnection
// 1. 防止重复关闭，并根据当前传输状态执行相应关闭操作
void PeerConnection::close() {
	// 1. 标记正在关闭，防止重复调用
	if (!closing.exchange(true)) {
		PLOG_VERBOSE << "Closing PeerConnection";
		// 2. 如果 SCTP 传输存在，则停止 SCTP，否则执行远程关闭操作
		if (auto transport = std::atomic_load(&mSctpTransport))
			transport->stop();
		else
			remoteClose();
	}
}

// 函数 remoteClose：远程关闭 PeerConnection
// 1. 通过调用 close() 及异步关闭数据通道和轨道实现远程关闭
void PeerConnection::remoteClose() {
	// 1. 调用 close() 进行基础关闭操作
	close();
	// 2. 若状态未完全关闭，则异步关闭数据通道和轨道，并关闭所有传输
	if (state.load() != State::Closed) {
		// 2.1 异步关闭数据通道
		mProcessor.enqueue(&PeerConnection::closeDataChannels, shared_from_this());
		// 2.2 异步关闭媒体轨道
		mProcessor.enqueue(&PeerConnection::closeTracks, shared_from_this());

		closeTransports();
	}
}

// 函数 localDescription：获取本地描述信息（线程安全）
// 1. 返回当前存储的本地 SDP 描述
optional<Description> PeerConnection::localDescription() const {
	// 1.1 通过互斥锁保护本地描述的访问
	std::lock_guard lock(mLocalDescriptionMutex);
	return mLocalDescription;
}

// 函数 remoteDescription：获取远程描述信息（线程安全）
// 1. 返回当前存储的远程 SDP 描述
optional<Description> PeerConnection::remoteDescription() const {
	// 1.1 通过互斥锁保护远程描述的访问
	std::lock_guard lock(mRemoteDescriptionMutex);
	return mRemoteDescription;
}

// 函数 remoteMaxMessageSize：计算远程最大消息大小
// 1. 根据本地配置和远程描述中设置的最大消息大小计算最终可用的消息大小
size_t PeerConnection::remoteMaxMessageSize() const {
	// 1. 获取本地最大消息大小，若未设置则采用默认值
	const size_t localMax = config.maxMessageSize.value_or(DEFAULT_LOCAL_MAX_MESSAGE_SIZE);

	size_t remoteMax = DEFAULT_REMOTE_MAX_MESSAGE_SIZE;
	{
		// 2. 加锁访问远程描述
		std::lock_guard lock(mRemoteDescriptionMutex);
		if (mRemoteDescription)
			if (auto *application = mRemoteDescription->application())
				if (auto max = application->maxMessageSize()) {
					// 2.1 如果 SDP 属性中设置为零，则表示无限制（受内存等因素影响）
					remoteMax = *max > 0 ? *max : std::numeric_limits<size_t>::max();
				}
	}

	// 3. 返回本地和远程最大消息大小中的最小值
	return std::min(remoteMax, localMax);
}

// 模板函数 emplaceTransport：用于初始化并启动传输层，同时处理异常
// 1. 将传输对象存储至成员变量并尝试启动
template <typename T>
shared_ptr<T> emplaceTransport(PeerConnection *pc, shared_ptr<T> *member, shared_ptr<T> transport) {
	// 1. 存储传输对象到成员变量中
	std::atomic_store(member, transport);
	try {
		// 2. 启动传输
		transport->start();
	} catch (...) {
		// 2.1 若启动异常，重置传输成员并重新抛出异常
		std::atomic_store(member, decltype(transport)(nullptr));
		throw;
	}

	// 3. 检查连接状态：若连接正在关闭或已关闭，则停止传输并返回空指针
	if (pc->closing.load() || pc->state.load() == PeerConnection::State::Closed) {
		std::atomic_store(member, decltype(transport)(nullptr));
		transport->stop();
		return nullptr;
	}

	// 4. 成功启动传输，返回该传输对象
	return transport;
}

// 函数 initIceTransport：初始化 ICE 传输
// 1. 创建新的 ICE 传输对象，并设置状态和候选收集回调函数
shared_ptr<IceTransport> PeerConnection::initIceTransport() {
	try {
		// 1. 检查是否已有 ICE 传输对象，若存在则直接返回
		if (auto transport = std::atomic_load(&mIceTransport))
			return transport;

		// 2. 日志输出：开始 ICE 传输
		PLOG_VERBOSE << "Starting ICE transport";

		// 2.1 构造新的 ICE 传输对象，并注册状态变化和候选收集回调
		auto transport = std::make_shared<IceTransport>(
		    config, weak_bind(&PeerConnection::processLocalCandidate, this, _1),
		    [this, weak_this = weak_from_this()](IceTransport::State transportState) {
			    auto shared_this = weak_this.lock();
			    if (!shared_this)
				    return;
			    switch (transportState) {
			    	std::cout << "IceTransport::State:: change to " << (int)transportState << std::endl;
			    case IceTransport::State::Connecting:
				    // 2.1.1 更新 ICE 状态为 Checking，同时将整体状态设为 Connecting
				    changeIceState(IceState::Checking);
				    changeState(State::Connecting);
				    break;
			    case IceTransport::State::Connected:
				    // 2.1.2 更新 ICE 状态为 Connected，并初始化 DTLS 传输
				    changeIceState(IceState::Connected);
				    initDtlsTransport();
				    break;
			    case IceTransport::State::Completed:
				    // 2.1.3 更新 ICE 状态为 Completed
				    changeIceState(IceState::Completed);
				    break;
			    case IceTransport::State::Failed:
				    // 2.1.4 状态为 Failed，更新状态并异步关闭连接
				    changeIceState(IceState::Failed);
				    changeState(State::Failed);
				    mProcessor.enqueue(&PeerConnection::remoteClose, shared_from_this());
				    break;
			    case IceTransport::State::Disconnected:
				    // 2.1.5 状态为 Disconnected，更新状态并异步关闭连接
				    changeIceState(IceState::Disconnected);
				    changeState(State::Disconnected);
				    mProcessor.enqueue(&PeerConnection::remoteClose, shared_from_this());
				    break;
			    default:
				    // 2.1.6 其他状态暂不处理
				    break;
			    }
		    },
		    [this, weak_this = weak_from_this()](IceTransport::GatheringState gatheringState) {
			    auto shared_this = weak_this.lock();
			    if (!shared_this)
				    return;
			    switch (gatheringState) {
			    case IceTransport::GatheringState::InProgress:
				    // 3.1 ICE 候选收集中
				    changeGatheringState(GatheringState::InProgress);
				    break;
			    case IceTransport::GatheringState::Complete:
				    // 3.2 ICE 候选收集完成，结束本地候选并更新状态
				    endLocalCandidates();
				    changeGatheringState(GatheringState::Complete);
				    break;
			    default:
				    // 3.3 其他状态不处理
				    break;
			    }
		    });

		// 4. 使用 emplaceTransport 辅助函数存储并启动 ICE 传输，返回传输对象
		return emplaceTransport(this, &mIceTransport, std::move(transport));

	} catch (const std::exception &e) {
		// 5. 捕获异常：记录错误日志，更新状态为 Failed，并抛出运行时异常
		PLOG_ERROR << e.what();
		changeState(State::Failed);
		throw std::runtime_error("ICE transport initialization failed");
	}
}

// 函数 initDtlsTransport：初始化 DTLS 传输
// 1. 创建 DTLS 传输对象，并设置指纹验证和状态变化回调
shared_ptr<DtlsTransport> PeerConnection::initDtlsTransport() {
	try {
		// 1. 检查是否已有 DTLS 传输对象，若存在则直接返回
		if (auto transport = std::atomic_load(&mDtlsTransport))
			return transport;

		// 2. 日志输出：开始 DTLS 传输
		PLOG_VERBOSE << "Starting DTLS transport";

		CertificateFingerprint::Algorithm fingerprintAlgorithm;
		{
			// 3. 从远程描述中获取指纹算法（需要线程安全访问）
			std::lock_guard lock(mRemoteDescriptionMutex);
			if (mRemoteDescription && mRemoteDescription->fingerprint()) {
				mRemoteFingerprintAlgorithm = mRemoteDescription->fingerprint()->algorithm;
			}
			fingerprintAlgorithm = mRemoteFingerprintAlgorithm;
		}

		// 4. 获取底层 ICE 传输对象，若不存在则抛出逻辑错误
		auto lower = std::atomic_load(&mIceTransport);
		if (!lower)
			throw std::logic_error("No underlying ICE transport for DTLS transport");

		// 5. 获取本地证书并设置指纹验证回调
		auto certificate = mCertificate.get();
		auto verifierCallback = weak_bind(&PeerConnection::checkFingerprint, this, _1);
		// 6. 定义 DTLS 状态变化回调函数
		auto dtlsStateChangeCallback =
		    [this, weak_this = weak_from_this()](DtlsTransport::State transportState) {
			    auto shared_this = weak_this.lock();
			    if (!shared_this)
				    return;

			    switch (transportState) {
			    case DtlsTransport::State::Connected:
				    // 6.1 状态为 Connected：若远程描述包含应用，则初始化 SCTP 传输；否则更新状态
				    if (auto remote = remoteDescription(); remote && remote->hasApplication())
					    initSctpTransport();
				    else
					    changeState(State::Connected);

				    // 6.1.1 异步打开媒体轨道
				    mProcessor.enqueue(&PeerConnection::openTracks, shared_from_this());
				    break;
			    case DtlsTransport::State::Failed:
				    // 6.2 状态为 Failed：更新状态为 Failed，并异步关闭连接
				    changeState(State::Failed);
				    mProcessor.enqueue(&PeerConnection::remoteClose, shared_from_this());
				    break;
			    case DtlsTransport::State::Disconnected:
				    // 6.3 状态为 Disconnected：更新状态为 Disconnected，并异步关闭连接
				    changeState(State::Disconnected);
				    mProcessor.enqueue(&PeerConnection::remoteClose, shared_from_this());
				    break;
			    default:
				    // 6.4 其他状态不做处理
				    break;
			    }
		    };

		shared_ptr<DtlsTransport> transport;
		auto local = localDescription();
		// 7. 判断是否需要媒体支持（或强制媒体传输）
		if (config.forceMediaTransport || (local && local->hasAudioOrVideo())) {
#if RTC_ENABLE_MEDIA
			PLOG_INFO << "This connection requires media support";

			// 7.1 使用 DTLS-SRTP 传输支持媒体数据
			transport = std::make_shared<DtlsSrtpTransport>(
			    lower, certificate, config.mtu, fingerprintAlgorithm, verifierCallback,
			    weak_bind(&PeerConnection::forwardMedia, this, _1), dtlsStateChangeCallback);
			printf("xy: pc: %p, create transport: %p\n", this, transport.get());
#else
			PLOG_WARNING << "Ignoring media support (not compiled with media support)";
#endif
		}

		if (!transport) {
			// 8. 若未使用媒体传输，则创建纯 DTLS 传输
			transport = std::make_shared<DtlsTransport>(lower, certificate, config.mtu,
			                                            fingerprintAlgorithm, verifierCallback,
			                                            dtlsStateChangeCallback);
		}

		// 9. 使用 emplaceTransport 存储并启动 DTLS 传输，返回传输对象
		return emplaceTransport(this, &mDtlsTransport, std::move(transport));

	} catch (const std::exception &e) {
		// 10. 捕获异常：记录错误日志，更新状态为 Failed，并抛出运行时异常
		PLOG_ERROR << e.what();
		changeState(State::Failed);
		throw std::runtime_error("DTLS transport initialization failed");
	}
}

// 函数 initSctpTransport：初始化 SCTP 传输
// 1. 创建 SCTP 传输对象，并设置传输端口和状态回调
shared_ptr<SctpTransport> PeerConnection::initSctpTransport() {
	try {
		// 1. 检查是否已有 SCTP 传输对象，若存在则直接返回
		if (auto transport = std::atomic_load(&mSctpTransport))
			return transport;

		// 2. 日志输出：开始 SCTP 传输
		PLOG_VERBOSE << "Starting SCTP transport";

		// 3. 获取底层 DTLS 传输对象，若不存在则抛出异常
		auto lower = std::atomic_load(&mDtlsTransport);
		if (!lower)
			throw std::logic_error("No underlying DTLS transport for SCTP transport");

		// 4. 获取本地描述，必须包含应用描述，否则抛出异常
		auto local = localDescription();
		if (!local || !local->application())
			throw std::logic_error("Starting SCTP transport without local application description");

		// 5. 获取远程描述，必须包含应用描述，否则抛出异常
		auto remote = remoteDescription();
		if (!remote || !remote->application())
			throw std::logic_error(
			    "Starting SCTP transport without remote application description");

		// 6. 设置 SCTP 传输的本地和远程端口
		SctpTransport::Ports ports = {};
		ports.local = local->application()->sctpPort().value_or(DEFAULT_SCTP_PORT);
		ports.remote = remote->application()->sctpPort().value_or(DEFAULT_SCTP_PORT);

		// 6.1 创建 SCTP 传输对象，并注册消息转发及状态变化回调
		auto transport = std::make_shared<SctpTransport>(
		    lower, config, std::move(ports), weak_bind(&PeerConnection::forwardMessage, this, _1),
		    weak_bind(&PeerConnection::forwardBufferedAmount, this, _1, _2),
		    [this, weak_this = weak_from_this()](SctpTransport::State transportState) {
			    auto shared_this = weak_this.lock();
			    if (!shared_this)
				    return;

			    switch (transportState) {
			    case SctpTransport::State::Connected:
				    // 6.2 状态为 Connected：更新状态、分配数据通道并异步打开数据通道
				    changeState(State::Connected);
				    assignDataChannels();
				    mProcessor.enqueue(&PeerConnection::openDataChannels, shared_from_this());
				    break;
			    case SctpTransport::State::Failed:
				    // 6.3 状态为 Failed：更新状态，并异步关闭连接
				    changeState(State::Failed);
				    mProcessor.enqueue(&PeerConnection::remoteClose, shared_from_this());
				    break;
			    case SctpTransport::State::Disconnected:
				    // 6.4 状态为 Disconnected：更新状态，并异步关闭连接
				    changeState(State::Disconnected);
				    mProcessor.enqueue(&PeerConnection::remoteClose, shared_from_this());
				    break;
			    default:
				    // 6.5 其他状态不处理
				    break;
			    }
		    });

		// 7. 使用 emplaceTransport 存储并启动 SCTP 传输，返回传输对象
		return emplaceTransport(this, &mSctpTransport, std::move(transport));

	} catch (const std::exception &e) {
		// 8. 捕获异常：记录错误日志，更新状态为 Failed，并抛出运行时异常
		PLOG_ERROR << e.what();
		changeState(State::Failed);
		throw std::runtime_error("SCTP transport initialization failed");
	}
}

// 函数 getIceTransport：获取当前 ICE 传输对象
shared_ptr<IceTransport> PeerConnection::getIceTransport() const {
	return std::atomic_load(&mIceTransport);
}

// 函数 getDtlsTransport：获取当前 DTLS 传输对象
shared_ptr<DtlsTransport> PeerConnection::getDtlsTransport() const {
	return std::atomic_load(&mDtlsTransport);
}

// 函数 getSctpTransport：获取当前 SCTP 传输对象
shared_ptr<SctpTransport> PeerConnection::getSctpTransport() const {
	return std::atomic_load(&mSctpTransport);
}

// 函数 closeTransports：关闭所有传输并清理相关资源
// 1. 更新状态、取消回调，并通过异步任务关闭各传输对象
void PeerConnection::closeTransports() {
	// 1. 日志输出：标识开始关闭传输
	PLOG_VERBOSE << "Closing transports";

	// 2. 将 ICE 状态设置为 Closed
	changeIceState(IceState::Closed);

	// 3. 更新整体状态为 Closed；若已关闭则直接返回
	if (!changeState(State::Closed))
		return; // already closed

	// 4. 重置媒体处理器和所有回调
	setMediaHandler(nullptr);
	resetCallbacks();

	// 5. 通过原子交换获取并清空 SCTP、DTLS 和 ICE 传输对象
	auto sctp = std::atomic_exchange(&mSctpTransport, decltype(mSctpTransport)(nullptr));
	auto dtls = std::atomic_exchange(&mDtlsTransport, decltype(mDtlsTransport)(nullptr));
	auto ice = std::atomic_exchange(&mIceTransport, decltype(mIceTransport)(nullptr));

	// 6. 若 SCTP 传输存在，则取消其接收和缓冲回调
	if (sctp) {
		sctp->onRecv(nullptr);
		sctp->onBufferedAmount(nullptr);
	}

	// 7. 为所有传输对象取消状态变化回调
	using array = std::array<shared_ptr<Transport>, 3>;
	array transports{std::move(sctp), std::move(dtls), std::move(ice)};

	for (const auto &t : transports)
		if (t)
			t->onStateChange(nullptr);

	// 8. 异步终止传输，并释放传输对象资源
	TearDownProcessor::Instance().enqueue(
	    [transports = std::move(transports), token = Init::Instance().token()]() mutable {
		    for (const auto &t : transports) {
			    if (t) {
				    t->stop();
				    break;
			    }
		    }

		    for (auto &t : transports)
			    t.reset();
	    });
}

// 函数 endLocalCandidates：结束本地 ICE 候选收集
// 1. 加锁后调用本地描述的 endCandidates 方法
void PeerConnection::endLocalCandidates() {
	std::lock_guard lock(mLocalDescriptionMutex);
	if (mLocalDescription)
		mLocalDescription->endCandidates();
}

// 函数 rollbackLocalDescription：回滚本地描述至上一个有效状态
// 1. 保存当前候选信息并恢复上一次的本地描述
void PeerConnection::rollbackLocalDescription() {
	// 1. 日志输出：标识正在回滚本地描述
	PLOG_DEBUG << "Rolling back pending local description";

	std::unique_lock lock(mLocalDescriptionMutex);
	if (mCurrentLocalDescription) {
		std::vector<Candidate> existingCandidates;
		if (mLocalDescription)
			existingCandidates = mLocalDescription->extractCandidates();

		// 2. 回滚操作：用当前待定描述替换本地描述，并恢复候选信息
		mLocalDescription.emplace(std::move(*mCurrentLocalDescription));
		mLocalDescription->addCandidates(std::move(existingCandidates));
		mCurrentLocalDescription.reset();
	}
}

// 函数 checkFingerprint：验证远程指纹是否匹配
// 1. 将接收到的指纹与远程描述中的预期指纹进行比较，返回验证结果
bool PeerConnection::checkFingerprint(const std::string &fingerprint) {
	// 1. 保存接收到的远程指纹
	std::lock_guard lock(mRemoteDescriptionMutex);
	mRemoteFingerprint = fingerprint;

	// 2. 检查远程描述及指纹算法是否匹配
	if (!mRemoteDescription || !mRemoteDescription->fingerprint()
			|| mRemoteFingerprintAlgorithm != mRemoteDescription->fingerprint()->algorithm)
		return false;

	// 3. 若配置中禁用了指纹验证，则跳过验证
	if (config.disableFingerprintVerification) {
		PLOG_VERBOSE << "Skipping fingerprint validation";
		return true;
	}

	// 4. 比较接收到的指纹与预期指纹，返回验证结果
	auto expectedFingerprint = mRemoteDescription->fingerprint()->value;
	if (expectedFingerprint == fingerprint) {
		PLOG_VERBOSE << "Valid fingerprint \"" << fingerprint << "\"";
		return true;
	}

	PLOG_ERROR << "Invalid fingerprint \"" << fingerprint << "\", expected \""
	           << expectedFingerprint << "\"";
	return false;
}

// 函数 forwardMessage：处理并转发 SCTP 消息到对应数据通道
// 1. 根据消息类型查找或创建数据通道，并转发消息；若消息无效则进行相应处理
void PeerConnection::forwardMessage(message_ptr message) {
	// 1. 若消息为空，则关闭远程数据通道并返回
	if (!message) {
		remoteCloseDataChannels();
		return;
	}

	// 2. 检查 ICE 和 SCTP 传输是否有效
	auto iceTransport = std::atomic_load(&mIceTransport);
	auto sctpTransport = std::atomic_load(&mSctpTransport);
	if (!iceTransport || !sctpTransport)
		return;

	// 3. 获取消息对应的流标识，并查找对应的数据通道
	const uint16_t stream = uint16_t(message->stream);
	auto [channel, found] = findDataChannel(stream);

	// 4. 处理打开数据通道的消息
	if (DataChannel::IsOpenMessage(message)) {
		if (found) {
			// 4.1 数据通道已存在，收到重复打开消息，关闭该数据通道
			PLOG_WARNING << "Got open message on already used stream " << stream;
			if (channel && !channel->isClosed())
				channel->close();
			else
				sctpTransport->closeStream(message->stream);

			return;
		}

		// 4.2 检查奇偶规则是否符合（根据 ICE 角色确定）
		const uint16_t remoteParity = (iceTransport->role() == Description::Role::Active) ? 1 : 0;
		if (stream % 2 != remoteParity) {
			// 4.2.1 奇偶规则违规，关闭该数据流
			PLOG_WARNING << "Got open message violating the odd/even rule on stream " << stream;
			sctpTransport->closeStream(message->stream);
			return;
		}

		// 4.3 为新数据通道分配流标识，并设置打开回调
		channel = std::make_shared<IncomingDataChannel>(weak_from_this(), sctpTransport);
		channel->assignStream(stream);
		channel->openCallback =
		    weak_bind(&PeerConnection::triggerDataChannel, this, weak_ptr<DataChannel>{channel});

		// 4.4 将新数据通道添加到管理容器中（加锁保护）
		std::unique_lock lock(mDataChannelsMutex); // we are going to emplace
		mDataChannels.emplace(stream, channel);
	} else if (!found) {
		// 5. 对于非打开消息但未找到数据通道的情况：
		if (message->type == Message::Reset)
			return; // 忽略 Reset 消息

		// 5.1 非法消息，关闭该数据流
		PLOG_WARNING << "Got unexpected message on stream " << stream;
		sctpTransport->closeStream(message->stream);
		return;
	}

	// 6. 如果消息为 Reset 类型，则移除对应数据通道
	if (message->type == Message::Reset) {
		removeDataChannel(stream);
	}

	// 7. 将消息转发到数据通道
	if (channel) {
		channel->incoming(message);
	} else {
		// 8. 数据通道已销毁，忽略该消息
		PLOG_DEBUG << "Ignored message on stream " << stream << ", DataChannel is destroyed";
	}
}

// 函数 forwardMedia：处理媒体数据消息的转发（仅在支持媒体时有效）
// 1. 通过媒体处理器对消息进行链式处理后，再分发消息
void PeerConnection::forwardMedia([[maybe_unused]] message_ptr message) {
#if RTC_ENABLE_MEDIA
	// 1. 若消息为空，则直接返回
	if (!message)
		return;

	// 2. 如果存在媒体处理器，则使用其处理链处理媒体消息
	if (auto handler = getMediaHandler()) {
		message_vector messages{std::move(message)};

		try {
			// 2.1 调用媒体处理器进行链式处理，并通过回调转发处理后的消息
			handler->incomingChain(messages, [this](message_ptr message) {
				auto transport = std::atomic_load(&mDtlsTransport);
				if (auto srtpTransport = std::dynamic_pointer_cast<DtlsSrtpTransport>(transport))
					srtpTransport->send(std::move(message));
			});
		} catch(const std::exception &e) {
			// 2.2 若处理过程中发生异常，则记录警告并退出
			PLOG_WARNING << "Exception in global incoming media handler: " << e.what();
			return;
		}

		// 2.3 分发处理后的每条媒体消息
		for (auto &m : messages)
			dispatchMedia(std::move(m));

	} else {
		// 3. 如果没有媒体处理器，则直接分发媒体消息
		dispatchMedia(std::move(message));
	}
#endif
}

// 函数 dispatchMedia：将媒体消息分发到对应的轨道（Track）
// 1. 根据消息类型解析 SSRC 并分发给对应媒体轨道
void PeerConnection::dispatchMedia([[maybe_unused]] message_ptr message) {
#if RTC_ENABLE_MEDIA
	// 1. 获取轨道列表，若只有一个轨道则直接转发消息
	std::shared_lock lock(mTracksMutex); // read-only
	if (mTrackLines.size() == 1) {
		if (auto track = mTrackLines.front().lock())
			track->incoming(message);
		return;
	}
	// 2. 处理 RTCP 复合包：解析随机 SSRC 以分发报告块
	// 2.1 解析 RTCP 报文，根据不同 payloadType 分析并收集 SSRC
	if (message->type == Message::Control) {
		std::set<uint32_t> ssrcs;
		size_t offset = 0;
		while ((sizeof(RtcpHeader) + offset) <= message->size()) {
			auto header = reinterpret_cast<RtcpHeader *>(message->data() + offset);
			if (header->lengthInBytes() > message->size() - offset) {
				COUNTER_MEDIA_TRUNCATED++;
				break;
			}
			offset += header->lengthInBytes();
			if (header->payloadType() == 205 || header->payloadType() == 206) {
				auto rtcpfb = reinterpret_cast<RtcpFbHeader *>(header);
				ssrcs.insert(rtcpfb->packetSenderSSRC());
				ssrcs.insert(rtcpfb->mediaSourceSSRC());

			} else if (header->payloadType() == 200) {
				auto rtcpsr = reinterpret_cast<RtcpSr *>(header);
				ssrcs.insert(rtcpsr->senderSSRC());
				for (int i = 0; i < rtcpsr->header.reportCount(); ++i)
					ssrcs.insert(rtcpsr->getReportBlock(i)->getSSRC());
			} else if (header->payloadType() == 201) {
				auto rtcprr = reinterpret_cast<RtcpRr *>(header);
				ssrcs.insert(rtcprr->senderSSRC());
				for (int i = 0; i < rtcprr->header.reportCount(); ++i)
					ssrcs.insert(rtcprr->getReportBlock(i)->getSSRC());
			} else if (header->payloadType() == 202) {
				auto sdes = reinterpret_cast<RtcpSdes *>(header);
				if (!sdes->isValid()) {
					PLOG_WARNING << "RTCP SDES packet is invalid";
					continue;
				}
				for (unsigned int i = 0; i < sdes->chunksCount(); i++) {
					auto chunk = sdes->getChunk(i);
					ssrcs.insert(chunk->ssrc());
				}
			} else {
				// 2.2 对于非关键 RTCP 类型，统计未知的包类型
				// PT=203 == Goodbye
				// PT=204 == Application Specific
				// PT=207 == Extended Report
				if (header->payloadType() != 203 && header->payloadType() != 204 &&
				    header->payloadType() != 207) {
					COUNTER_UNKNOWN_PACKET_TYPE++;
				}
			}
		}

		// 2.3 如果成功解析到 SSRC，则依次查找并转发给对应轨道
		if (!ssrcs.empty()) {
			for (uint32_t ssrc : ssrcs) {
				if (auto it = mTracksBySsrc.find(ssrc); it != mTracksBySsrc.end()) {
					if (auto track = it->second.lock())
						track->incoming(message);
				}
			}
			return;
		}
	}

	// 3. 根据消息流标识作为 SSRC，尝试找到对应轨道
	uint32_t ssrc = uint32_t(message->stream);

	if (auto it = mTracksBySsrc.find(ssrc); it != mTracksBySsrc.end()) {
		if (auto track = it->second.lock())
			track->incoming(message);
	} else {
		/*
		 * TODO: So the problem is that when stop sending streams, we stop getting report blocks for
		 * those streams Therefore when we get compound RTCP packets, they are empty, and we can't
		 * forward them. Therefore, it is expected that we don't know where to forward packets. Is
		 * this ideal? No! Do I know how to fix it? No!
		 */
		// 4. 未找到对应轨道，忽略该消息（原有警告被注释掉）
		// PLOG_WARNING << "Track not found for SSRC " << ssrc << ", dropping";
		return;
	}
#endif
}

// 函数 forwardBufferedAmount：转发缓冲区数据量更新到对应数据通道
// 1. 根据流标识找到数据通道，并触发其缓冲量更新回调
void PeerConnection::forwardBufferedAmount(uint16_t stream, size_t amount) {
	[[maybe_unused]] auto [channel, found] = findDataChannel(stream);
	if (channel)
		channel->triggerBufferedAmount(amount);
}

// 函数 emplaceDataChannel：创建并注册新的数据通道
// 1. 根据传入的 label 与初始化参数创建数据通道，若指定了流 id 则直接分配，否则稍后分配
shared_ptr<DataChannel> PeerConnection::emplaceDataChannel(string label, DataChannelInit init) {
	std::unique_lock lock(mDataChannelsMutex); // we are going to emplace

	// 1. 根据是否用户协商，选择创建 OutgoingDataChannel 或标准 DataChannel
	auto channel =
	    init.negotiated
	        ? std::make_shared<DataChannel>(weak_from_this(), std::move(label),
	                                        std::move(init.protocol), std::move(init.reliability))
	        : std::make_shared<OutgoingDataChannel>(weak_from_this(), std::move(label),
	                                                std::move(init.protocol),
	                                                std::move(init.reliability));

	// 2. 如果用户指定了流 id，则直接分配和注册数据通道；否则加入未分配列表
	if (init.id) {
		uint16_t stream = *init.id;
		if (stream > maxDataChannelStream())
			throw std::invalid_argument("DataChannel stream id is too high");

		channel->assignStream(stream);
		mDataChannels.emplace(std::make_pair(stream, channel));

	} else {
		mUnassignedDataChannels.push_back(channel);
	}

	// 3. 解锁后调用 assignDataChannels() 进行未分配通道的流 id 分配
	lock.unlock(); // we are going to call assignDataChannels()

	// 4. 如果 SCTP 已连接，则为数据通道分配流 id 并打开数据通道
	auto sctpTransport = std::atomic_load(&mSctpTransport);
	if (sctpTransport && sctpTransport->state() == SctpTransport::State::Connected) {
		assignDataChannels();
		channel->open(sctpTransport);
	}

	return channel;
}

// 函数 findDataChannel：根据流标识查找已注册的数据通道
// 1. 返回查找到的数据通道及是否存在的标志
std::pair<shared_ptr<DataChannel>, bool> PeerConnection::findDataChannel(uint16_t stream) {
	std::shared_lock lock(mDataChannelsMutex); // read-only
	if (auto it = mDataChannels.find(stream); it != mDataChannels.end())
		return std::make_pair(it->second.lock(), true);
	else
		return std::make_pair(nullptr, false);
}

// 函数 removeDataChannel：从管理容器中移除指定流标识的数据通道
// 1. 返回移除操作是否成功
bool PeerConnection::removeDataChannel(uint16_t stream) {
	std::unique_lock lock(mDataChannelsMutex); // we are going to erase
	return mDataChannels.erase(stream) != 0;
}

// 函数 maxDataChannelStream：获取最大可用的数据通道流标识
// 1. 若 SCTP 传输存在，则返回其最大流 id，否则返回默认最大值
uint16_t PeerConnection::maxDataChannelStream() const {
	auto sctpTransport = std::atomic_load(&mSctpTransport);
	return sctpTransport ? sctpTransport->maxStream() : (MAX_SCTP_STREAMS_COUNT - 1);
}

// 函数 assignDataChannels：为所有未分配数据通道分配可用的流标识
// 1. 根据 ICE 角色和可用流 id，遍历未分配列表进行分配
void PeerConnection::assignDataChannels() {
	std::unique_lock lock(mDataChannelsMutex); // we are going to emplace

	// 1. 检查 ICE 传输是否存在，否则抛出异常
	auto iceTransport = std::atomic_load(&mIceTransport);
	if (!iceTransport)
		throw std::logic_error("Attempted to assign DataChannels without ICE transport");

	// 2. 获取最大可用流 id，并遍历未分配数据通道列表
	const uint16_t maxStream = maxDataChannelStream();
	for (auto it = mUnassignedDataChannels.begin(); it != mUnassignedDataChannels.end(); ++it) {
		auto channel = it->lock();
		if (!channel)
			continue;

		// 2.1 根据 ICE 角色确定初始流 id（奇偶规则）
		uint16_t stream = (iceTransport->role() == Description::Role::Active) ? 0 : 1;
		while (true) {
			// 2.2 检查流 id 是否超出最大值，若超出则抛出异常
			if (stream > maxStream)
				throw std::runtime_error("Too many DataChannels");

			// 2.3 查找当前流 id 是否已被占用
			if (mDataChannels.find(stream) == mDataChannels.end())
				break;

			stream += 2;
		}

		// 2.4 分配流 id，并将数据通道注册到管理容器中
		PLOG_DEBUG << "Assigning stream " << stream << " to DataChannel";

		channel->assignStream(stream);
		mDataChannels.emplace(std::make_pair(stream, channel));
	}

	// 3. 清空未分配数据通道列表
	mUnassignedDataChannels.clear();
}

// 函数 iterateDataChannels：遍历所有活跃的数据通道，并对每个通道执行指定操作
// 1. 复制所有未关闭的数据通道到局部容器，然后调用传入的回调函数
void PeerConnection::iterateDataChannels(
    std::function<void(shared_ptr<DataChannel> channel)> func) {
	std::vector<shared_ptr<DataChannel>> locked;
	{
		std::shared_lock lock(mDataChannelsMutex); // read-only
		locked.reserve(mDataChannels.size());
		for (auto it = mDataChannels.begin(); it != mDataChannels.end(); ++it) {
			auto channel = it->second.lock();
			if (channel && !channel->isClosed())
				locked.push_back(std::move(channel));
		}
	}

	// 2. 遍历所有复制的通道，并执行回调（捕获异常以防中断）
	for (auto &channel : locked) {
		try {
			func(std::move(channel));
		} catch (const std::exception &e) {
			PLOG_WARNING << e.what();
		}
	}
}

// 函数 openDataChannels：打开所有未打开的数据通道
// 1. 检查 SCTP 传输是否连接，并遍历所有数据通道调用 open 操作
void PeerConnection::openDataChannels() {
	if (auto transport = std::atomic_load(&mSctpTransport))
		iterateDataChannels([&](shared_ptr<DataChannel> channel) {
			if (!channel->isOpen())
				channel->open(transport);
		});
}

// 函数 closeDataChannels：关闭所有数据通道
// 1. 遍历所有数据通道并调用其 close 方法
void PeerConnection::closeDataChannels() {
	iterateDataChannels([&](shared_ptr<DataChannel> channel) { channel->close(); });
}

// 函数 remoteCloseDataChannels：远程关闭所有数据通道
// 1. 遍历所有数据通道并调用其 remoteClose 方法
void PeerConnection::remoteCloseDataChannels() {
	iterateDataChannels([&](shared_ptr<DataChannel> channel) { channel->remoteClose(); });
}

// 函数 emplaceTrack：创建或更新媒体轨道，并注册到 PeerConnection 中
// 1. 根据传入的媒体描述查找或创建新的轨道对象，支持更新与新建操作
shared_ptr<Track> PeerConnection::emplaceTrack(Description::Media description) {
	std::unique_lock lock(mTracksMutex); // we are going to emplace

#if !RTC_ENABLE_MEDIA
	// 1. 若不支持媒体，则标记轨道为已移除
	PLOG_WARNING << "Tracks are disabled (not compiled with media support)";
	description.markRemoved();
#endif

	// 2. 尝试查找已有轨道，若存在且未关闭则进行更新
	shared_ptr<Track> track;
	if (auto it = mTracks.find(description.mid()); it != mTracks.end())
		if (auto t = it->second.lock(); t && !t->isClosed())
			track = std::move(t);

	// 3. 如果找到已有轨道，则更新描述；否则创建新轨道并注册
	if (track) {
		track->setDescription(std::move(description));
	} else {
		track = std::make_shared<Track>(weak_from_this(), std::move(description));
		mTracks.emplace(std::make_pair(track->mid(), track));
		mTrackLines.emplace_back(track);
	}

	// 4. 如果存在媒体处理器，则传递轨道描述
	auto handler = getMediaHandler();
	if (handler)
		handler->media(track->description());

	// 5. 若轨道被标记为移除，则关闭该轨道
	if (track->description().isRemoved())
		track->close();

	return track;
}

// 函数 iterateTracks：遍历所有活跃的媒体轨道，并对每个轨道执行指定操作
// 1. 复制所有未关闭的轨道到局部容器，然后调用传入的回调函数
void PeerConnection::iterateTracks(std::function<void(shared_ptr<Track> track)> func) {
	std::vector<shared_ptr<Track>> locked;
	{
		std::shared_lock lock(mTracksMutex); // read-only
		locked.reserve(mTrackLines.size());
		for (auto it = mTrackLines.begin(); it != mTrackLines.end(); ++it) {
			auto track = it->lock();
			if (track && !track->isClosed())
				locked.push_back(std::move(track));
		}
	}

	for (auto &track : locked) {
		try {
			func(std::move(track));
		} catch (const std::exception &e) {
			PLOG_WARNING << e.what();
		}
	}
}
// 1. PeerConnection::iterateRemoteTracks：遍历远程描述中的所有轨道，并对每个有效轨道调用回调函数
void PeerConnection::iterateRemoteTracks(std::function<void(shared_ptr<Track> track)> func) {
	// 1.1 获取远程描述，若不存在则直接返回
	auto remote = remoteDescription();
	if(!remote)
		return;

	// 1.2 定义局部容器用于存储查找到的轨道
	std::vector<shared_ptr<Track>> locked;
	{
		// 1.2.1 使用共享锁保护轨道容器访问
		std::shared_lock lock(mTracksMutex); // read-only
		// 1.2.2 根据远程描述的媒体条目预分配空间
		locked.reserve(remote->mediaCount());
		// 1.2.3 遍历每个媒体条目
		for(int i = 0; i < remote->mediaCount(); ++i) {
			// 1.2.3.1 判断当前媒体条目是否为 Media 类型
			if (std::holds_alternative<Description::Media *>(remote->media(i))) {
				// 1.2.3.2 获取媒体条目指针
				auto remoteMedia = std::get<Description::Media *>(remote->media(i));
				// 1.2.3.3 如果该媒体未被标记为移除，则查找对应的 Track 对象
				if (!remoteMedia->isRemoved())
					if (auto it = mTracks.find(remoteMedia->mid()); it != mTracks.end())
						if (auto track = it->second.lock())
							locked.push_back(std::move(track));
			}
		}
	}

	// 1.3 遍历收集到的轨道并调用回调函数
	for (auto &track : locked) {
		try {
			func(std::move(track));
		} catch (const std::exception &e) {
			PLOG_WARNING << e.what();
		}
	}
}

// 2. PeerConnection::openTracks：打开所有远程轨道（仅在媒体支持时生效）
void PeerConnection::openTracks() {
#if RTC_ENABLE_MEDIA
	// 2.1 获取当前 DTLS 传输对象，若不存在则返回
	auto transport = std::atomic_load(&mDtlsTransport);
	if (!transport)
		return;

	// 2.2 尝试将 DTLS 传输转换为支持 SRTP 的传输类型
	auto srtpTransport = std::dynamic_pointer_cast<DtlsSrtpTransport>(transport);
	// 2.3 遍历所有远程轨道并对每个轨道进行打开操作
	iterateRemoteTracks([&](shared_ptr<Track> track) {
		// 2.3.1 如果轨道未打开则执行打开操作
		if(!track->isOpen()) {
			if (srtpTransport) {
				// 2.3.1.1 通过 SRTP 传输打开轨道
				track->open(srtpTransport);
			} else {
				// 2.3.1.2 如果没有媒体传输，则触发错误回调，提示用户需要 forceMediaTransport
				auto errorMsg = "The connection has no media transport";
				PLOG_ERROR << errorMsg;
				track->triggerError(errorMsg);
			}
		}
	});
#endif
}

// 3. PeerConnection::closeTracks：关闭所有轨道
void PeerConnection::closeTracks() {
	// 3.1 使用共享锁保护轨道容器访问，并调用 iterateTracks 遍历所有轨道关闭它们
	std::shared_lock lock(mTracksMutex); // read-only
	iterateTracks([&](shared_ptr<Track> track) { track->close(); });
}

// 4. PeerConnection::validateRemoteDescription：验证远程描述是否合法
void PeerConnection::validateRemoteDescription(const Description &description) {
	// 4.1 检查 ICE 用户片段是否存在
	if (!description.iceUfrag())
		throw std::invalid_argument("Remote description has no ICE user fragment");

	// 4.2 检查 ICE 密码是否存在
	if (!description.icePwd())
		throw std::invalid_argument("Remote description has no ICE password");

	// 4.3 检查指纹是否存在
	if (!description.fingerprint())
		throw std::invalid_argument("Remote description has no valid fingerprint");

	// 4.4 检查媒体条目数量是否为零
	if (description.mediaCount() == 0)
		throw std::invalid_argument("Remote description has no media line");

	// 4.5 统计有效媒体条目的数量
	int activeMediaCount = 0;
	for (int i = 0; i < description.mediaCount(); ++i)
		std::visit(rtc::overloaded{
			// 4.5.1 对于 Application 类型，若未被移除则计数
			[&](const Description::Application *application) {
				if (!application->isRemoved())
					++activeMediaCount;
			},
			// 4.5.2 对于 Media 类型，若未被移除或方向非 Inactive，则计数
			[&](const Description::Media *media) {
				if (!media->isRemoved() ||
				    media->direction() != Description::Direction::Inactive)
					++activeMediaCount;
			}},
			description.media(i));

	// 4.6 如果没有有效媒体，则认为远程描述无效
	if (activeMediaCount == 0)
		throw std::invalid_argument("Remote description has no active media");

	// 4.7 输出日志说明远程描述验证通过
	PLOG_VERBOSE << "Remote description looks valid";
}

// 5. PeerConnection::processLocalDescription：处理并生成本地描述
void PeerConnection::processLocalDescription(Description description) {
	// 5.1 定义本地 SCTP 端口和最大消息大小
	const uint16_t localSctpPort = DEFAULT_SCTP_PORT;
	const size_t localMaxMessageSize =
	    config.maxMessageSize.value_or(DEFAULT_LOCAL_MAX_MESSAGE_SIZE);

	// 5.2 清理描述中可能由 ICE 传输添加的应用条目
	// Clean up the application entry the ICE transport might have added already (libnice)
	description.clearMedia();

	// 5.3 如果存在远程描述，则对每个远程媒体进行“互惠”处理
	if (auto remote = remoteDescription()) {
		// 5.3.1 遍历远程描述中的每个媒体条目
		for (int i = 0; i < remote->mediaCount(); ++i)
			std::visit( // reciprocate each media
			    rtc::overloaded{
			        // 5.3.1.1 对于 Application 类型，优先使用本地描述，否则生成互惠描述
			        [&](Description::Application *remoteApp) {
				        std::shared_lock lock(mDataChannelsMutex);
				        if (!mDataChannels.empty() || !mUnassignedDataChannels.empty()) {
					        // Prefer local description
					        Description::Application app(remoteApp->mid());
					        app.setSctpPort(localSctpPort);
					        app.setMaxMessageSize(localMaxMessageSize);

					        PLOG_DEBUG << "Adding application to local description, mid=\""
					                   << app.mid() << "\"";

					        description.addMedia(std::move(app));
					        return;
				        }

				        // 5.3.1.2 生成互惠的应用描述，并设置端口和消息大小
				        auto reciprocated = remoteApp->reciprocate();
				        reciprocated.hintSctpPort(localSctpPort);
				        reciprocated.setMaxMessageSize(localMaxMessageSize);

				        PLOG_DEBUG << "Reciprocating application in local description, mid=\""
				                   << reciprocated.mid() << "\"";

				        description.addMedia(std::move(reciprocated));
			        },
			        // 5.3.1.3 对于 Media 类型，先检查本地是否已有对应轨道
			        [&](Description::Media *remoteMedia) {
				        std::unique_lock lock(mTracksMutex); // we may emplace a track
				        if (auto it = mTracks.find(remoteMedia->mid()); it != mTracks.end()) {
					        // Prefer local description
					        if (auto track = it->second.lock()) {
						        auto media = track->description();

						        PLOG_DEBUG << "Adding media to local description, mid=\""
						                   << media.mid() << "\", removed=" << std::boolalpha
						                   << media.isRemoved();

						        description.addMedia(std::move(media));

					        } else {
						        auto reciprocated = remoteMedia->reciprocate();
						        reciprocated.markRemoved();

						        PLOG_DEBUG << "Adding media to local description, mid=\""
						                   << reciprocated.mid()
						                   << "\", removed=true (track is destroyed)";

						        description.addMedia(std::move(reciprocated));
					        }
					        return;
				        }

				        // 5.3.1.4 如果本地没有该轨道，则生成互惠描述并（可能）创建新轨道
				        auto reciprocated = remoteMedia->reciprocate();
#if !RTC_ENABLE_MEDIA
				        if (!reciprocated.isRemoved()) {
					        // No media support, mark as removed
					        PLOG_WARNING << "Rejecting track (not compiled with media support)";
					        reciprocated.markRemoved();
				        }
#endif

				        PLOG_DEBUG << "Reciprocating media in local description, mid=\""
				                   << reciprocated.mid() << "\", removed=" << std::boolalpha
				                   << reciprocated.isRemoved();

				        // 5.3.1.5 创建新的 Track 对象，并将其注册到内部容器中
				        auto track =
				            std::make_shared<Track>(weak_from_this(), std::move(reciprocated));
				        mTracks.emplace(std::make_pair(track->mid(), track));
				        mTrackLines.emplace_back(track);
				        triggerTrack(track); // The user may modify the track description

				        // 5.3.1.6 调用媒体处理器传递轨道描述
				        auto handler = getMediaHandler();
				        if (handler)
					        handler->media(track->description());

				        // 5.3.1.7 如果轨道被标记为移除，则关闭该轨道
				        if (track->description().isRemoved())
					        track->close();

				        description.addMedia(track->description());
			        },
			    },
			    remote->media(i));

		// 5.4 更新新创建的入站轨道的 SSRC 缓存
		updateTrackSsrcCache(*remote);
	}

	// 5.5 针对 Offer 类型的描述，添加本地创建的数据通道和轨道
	if (description.type() == Description::Type::Offer) {
		// 5.5.1 添加本地轨道媒体
		std::shared_lock lock(mTracksMutex);
		for (auto it = mTrackLines.begin(); it != mTrackLines.end(); ++it) {
			if (auto track = it->lock()) {
				if (description.hasMid(track->mid()))
					continue;

				auto media = track->description();

				PLOG_DEBUG << "Adding media to local description, mid=\"" << media.mid()
				           << "\", removed=" << std::boolalpha << media.isRemoved();

				description.addMedia(std::move(media));
			}
		}

		// 5.5.2 添加应用描述以支持数据通道
		if (!description.hasApplication()) {
			std::shared_lock lock(mDataChannelsMutex);
			if (!mDataChannels.empty() || !mUnassignedDataChannels.empty()) {
				// Prevents mid collision with remote or local tracks
				unsigned int m = 0;
				while (description.hasMid(std::to_string(m)))
					++m;

				Description::Application app(std::to_string(m));
				app.setSctpPort(localSctpPort);
				app.setMaxMessageSize(localMaxMessageSize);

				PLOG_DEBUG << "Adding application to local description, mid=\"" << app.mid()
				           << "\"";

				description.addMedia(std::move(app));
			}
		}

		// 5.5.3 如果此时描述中没有媒体条目，则报错
		if (description.mediaCount() == 0)
			throw std::runtime_error("No DataChannel or Track to negotiate");
	}

	// 5.6 设置本地指纹（等待证书加载）
	description.setFingerprint(mCertificate.get()->fingerprint());

	PLOG_VERBOSE << "Issuing local description: " << description;

	// 5.7 如果描述中没有媒体条目，则抛出逻辑异常
	if (description.mediaCount() == 0)
		throw std::logic_error("Local description has no media line");

	// 5.8 更新轨道的 SSRC 缓存
	updateTrackSsrcCache(description);

	{
		// 5.9 将新生成的本地描述设置到内部存储中，同时保留原有候选信息
		std::lock_guard lock(mLocalDescriptionMutex);

		std::vector<Candidate> existingCandidates;
		if (mLocalDescription) {
			existingCandidates = mLocalDescription->extractCandidates();
			mCurrentLocalDescription.emplace(std::move(*mLocalDescription));
		}

		mLocalDescription.emplace(description);
		mLocalDescription->addCandidates(std::move(existingCandidates));
	}

	// 5.10 异步触发本地描述回调
	mProcessor.enqueue(&PeerConnection::trigger<Description>, shared_from_this(),
	                   &localDescriptionCallback, std::move(description));

	// 5.11 若 DTLS 传输已连接，则异步尝试打开轨道
	if (auto dtlsTransport = std::atomic_load(&mDtlsTransport);
	    dtlsTransport && dtlsTransport->state() == Transport::State::Connected)
		mProcessor.enqueue(&PeerConnection::openTracks, shared_from_this());
}

// 6. PeerConnection::processLocalCandidate：处理本地 ICE 候选信息
void PeerConnection::processLocalCandidate(Candidate candidate) {
	// 6.1 使用互斥锁保证对本地描述的安全访问
	std::lock_guard lock(mLocalDescriptionMutex);
	if (!mLocalDescription)
		throw std::logic_error("Got a local candidate without local description");

	// 6.2 根据 ICE 传输策略判断是否发出候选（仅中继候选符合策略时发出）
	if (config.iceTransportPolicy == TransportPolicy::Relay &&
	    candidate.type() != Candidate::Type::Relayed) {
		PLOG_VERBOSE << "Not issuing local candidate because of transport policy: " << candidate;
		return;
	}

	// 6.3 输出候选日志，并对候选进行简单解析
	PLOG_VERBOSE << "Issuing local candidate: " << candidate;

	candidate.resolve(Candidate::ResolveMode::Simple);
	mLocalDescription->addCandidate(candidate);

	// 6.4 异步触发本地候选回调
	mProcessor.enqueue(&PeerConnection::trigger<Candidate>, shared_from_this(),
	                   &localCandidateCallback, std::move(candidate));
}

// 7. PeerConnection::processRemoteDescription：处理远程描述，更新缓存并初始化传输
void PeerConnection::processRemoteDescription(Description description) {
	// 7.1 更新现有轨道的 SSRC 缓存
	updateTrackSsrcCache(description);

	{
		// 7.2 将新的远程描述设置到内部存储中，同时保留原有候选信息
		std::lock_guard lock(mRemoteDescriptionMutex);

		std::vector<Candidate> existingCandidates;
		if (mRemoteDescription)
			existingCandidates = mRemoteDescription->extractCandidates();

		mRemoteDescription.emplace(description);
		mRemoteDescription->addCandidates(std::move(existingCandidates));
	}

	// 7.3 如果远程描述包含应用描述，则根据 DTLS 状态决定是否初始化 SCTP 传输
	auto dtlsTransport = std::atomic_load(&mDtlsTransport);
	if (description.hasApplication()) {
		auto sctpTransport = std::atomic_load(&mSctpTransport);
		if (!sctpTransport && dtlsTransport &&
		    dtlsTransport->state() == Transport::State::Connected)
			initSctpTransport();
	} else {
		// 7.4 若没有应用描述，则异步关闭数据通道
		mProcessor.enqueue(&PeerConnection::remoteCloseDataChannels, shared_from_this());
	}

	// 7.5 如果 DTLS 传输处于连接状态，则异步尝试打开轨道
	if (dtlsTransport && dtlsTransport->state() == Transport::State::Connected)
		mProcessor.enqueue(&PeerConnection::openTracks, shared_from_this());

}

// 8. PeerConnection::processRemoteCandidate：处理远程 ICE 候选信息
void PeerConnection::processRemoteCandidate(Candidate candidate) {
	// 8.1 获取当前 ICE 传输对象
	auto iceTransport = std::atomic_load(&mIceTransport);
	{
		// 8.2 使用锁保护对远程描述的访问，并确保候选合法
		std::lock_guard lock(mRemoteDescriptionMutex);
		if (!mRemoteDescription)
			throw std::logic_error("Got a remote candidate without remote description");

		if (!iceTransport)
			throw std::logic_error("Got a remote candidate without ICE transport");

		// 8.3 对候选设置 bundle mid 提示
		candidate.hintMid(mRemoteDescription->bundleMid());

		// 8.4 如果候选已存在则忽略
		if (mRemoteDescription->hasCandidate(candidate))
			return; // already in description, ignore

		// 8.5 解析候选并添加到远程描述中
		candidate.resolve(Candidate::ResolveMode::Simple);
		mRemoteDescription->addCandidate(candidate);
	}

	// 8.6 如果候选已解析，则直接添加到 ICE 传输；否则异步进行查找解析
	if (candidate.isResolved()) {
		iceTransport->addRemoteCandidate(std::move(candidate));
	} else {
		// 8.7 异步查找候选解析（不使用线程池，因超时不可控）
		if ((iceTransport = std::atomic_load(&mIceTransport))) {
			weak_ptr<IceTransport> weakIceTransport{iceTransport};
			std::thread t([weakIceTransport, candidate = std::move(candidate)]() mutable {
				utils::this_thread::set_name("RTC resolver");
				if (candidate.resolve(Candidate::ResolveMode::Lookup))
					if (auto iceTransport = weakIceTransport.lock())
						iceTransport->addRemoteCandidate(std::move(candidate));
			});
			t.detach();
		}
	}
}

// 9. PeerConnection::localBundleMid：返回本地描述的 bundle mid，如无则返回 "0"
string PeerConnection::localBundleMid() const {
	// 9.1 使用锁保护本地描述访问
	std::lock_guard lock(mLocalDescriptionMutex);
	return mLocalDescription ? mLocalDescription->bundleMid() : "0";
}

// 10. PeerConnection::negotiationNeeded：判断是否需要重新协商
bool PeerConnection::negotiationNeeded() const {
	// 10.1 获取当前本地描述
	auto description = localDescription();

	{
		// 10.2 检查是否有数据通道未在描述中注册
		std::shared_lock lock(mDataChannelsMutex);
		if (!mDataChannels.empty() || !mUnassignedDataChannels.empty())
			if(!description || !description->hasApplication()) {
				PLOG_DEBUG << "Negotiation needed for data channels";
				return true;
			}
	}

	{
		// 10.3 检查是否有轨道未在描述中注册或已关闭
		std::shared_lock lock(mTracksMutex);
		for(const auto &[mid, weakTrack] : mTracks)
			if (auto track = weakTrack.lock())
				if (!description || !description->hasMid(track->mid())) {
					PLOG_DEBUG << "Negotiation needed to add track, mid=" << track->mid();
					return true;
				}

		if(description) {
			// 10.4 遍历描述中的媒体条目，检测是否存在需要移除的轨道
			for(int i = 0; i < description->mediaCount(); ++i) {
				if (std::holds_alternative<Description::Media *>(description->media(i))) {
					auto media = std::get<Description::Media *>(description->media(i));
					if (!media->isRemoved())
						if (auto it = mTracks.find(media->mid()); it != mTracks.end())
							if (auto track = it->second.lock(); !track || track->isClosed()) {
								PLOG_DEBUG << "Negotiation needed to remove track, mid=" << media->mid();
								return true;
							}
				}
			}
		}
	}

	// 10.5 如果以上检查均未触发协商需求，则返回 false
	return false;
}

// 11. PeerConnection::setMediaHandler：设置媒体处理器
void PeerConnection::setMediaHandler(shared_ptr<MediaHandler> handler) {
	// 11.1 使用独占锁设置媒体处理器
	std::unique_lock lock(mMediaHandlerMutex);
	mMediaHandler = handler;
}

// 12. PeerConnection::getMediaHandler：获取当前媒体处理器
shared_ptr<MediaHandler> PeerConnection::getMediaHandler() {
	// 12.1 使用共享锁读取媒体处理器
	std::shared_lock lock(mMediaHandlerMutex);
	return mMediaHandler;
}

// 13. PeerConnection::triggerDataChannel：触发数据通道打开事件
void PeerConnection::triggerDataChannel(weak_ptr<DataChannel> weakDataChannel) {
	// 13.1 获取数据通道实例并重置内部 open 回调
	auto dataChannel = weakDataChannel.lock();
	if (dataChannel) {
		dataChannel->resetOpenCallback(); // might be set internally
		// 13.2 将数据通道加入待处理队列
		mPendingDataChannels.push(std::move(dataChannel));
	}
	// 13.3 触发处理待处理数据通道的回调
	triggerPendingDataChannels();
}

// 14. PeerConnection::triggerTrack：触发轨道事件
void PeerConnection::triggerTrack(weak_ptr<Track> weakTrack) {
	// 14.1 获取轨道实例并重置内部 open 回调
	auto track = weakTrack.lock();
	if (track) {
		track->resetOpenCallback(); // might be set internally
		// 14.2 将轨道加入待处理队列
		mPendingTracks.push(std::move(track));
	}
	// 14.3 触发处理待处理轨道的回调
	triggerPendingTracks();
}

// 15. PeerConnection::triggerPendingDataChannels：处理并触发所有待处理数据通道
void PeerConnection::triggerPendingDataChannels() {
	// 15.1 当存在数据通道回调时，循环处理队列中的每个数据通道
	while (dataChannelCallback) {
		auto next = mPendingDataChannels.pop();
		if (!next)
			break;

		auto impl = std::move(*next);

		try {
			// 15.2 调用用户注册的数据通道回调，并包装成 rtc::DataChannel 对象
			dataChannelCallback(std::make_shared<rtc::DataChannel>(impl));
		} catch (const std::exception &e) {
			PLOG_WARNING << "Uncaught exception in callback: " << e.what();
		}

		// 15.3 触发数据通道的内部 open 逻辑
		impl->triggerOpen();
	}
}

// 16. PeerConnection::triggerPendingTracks：处理并触发所有待处理轨道
void PeerConnection::triggerPendingTracks() {
	// 16.1 当存在轨道回调时，循环处理队列中的每个轨道
	while (trackCallback) {
		auto next = mPendingTracks.pop();
		if (!next)
			break;

		auto impl = std::move(*next);

		try {
			// 16.2 调用用户注册的轨道回调，并包装成 rtc::Track 对象
			trackCallback(std::make_shared<rtc::Track>(impl));
		} catch (const std::exception &e) {
			PLOG_WARNING << "Uncaught exception in callback: " << e.what();
		}

		// 16.3 注意：轨道的 open 事件稍后再触发，不在此处调用
	}
}

// 17. PeerConnection::flushPendingDataChannels：异步刷新待处理数据通道队列
void PeerConnection::flushPendingDataChannels() {
	mProcessor.enqueue(&PeerConnection::triggerPendingDataChannels, shared_from_this());
}

// 18. PeerConnection::flushPendingTracks：异步刷新待处理轨道队列
void PeerConnection::flushPendingTracks() {
	mProcessor.enqueue(&PeerConnection::triggerPendingTracks, shared_from_this());
}

// 19. PeerConnection::changeState：改变 PeerConnection 的整体状态
bool PeerConnection::changeState(State newState) {
	State current;
	// 19.1 循环尝试更新状态，若当前状态为 Closed 或与目标状态相同，则返回 false
	do {
		current = state.load();
		if (current == State::Closed)
			return false;
		if (current == newState)
			return false;

	} while (!state.compare_exchange_weak(current, newState));

	// 19.2 输出新的状态日志
	std::ostringstream s;
	s << newState;
	PLOG_INFO << "Changed state to " << s.str();

	// 19.3 根据新状态同步或异步触发状态变化回调
	if (newState == State::Closed) {
		auto callback = std::move(stateChangeCallback); // steal the callback
		callback(State::Closed);                        // call it synchronously
	} else {
		mProcessor.enqueue(&PeerConnection::trigger<State>, shared_from_this(),
		                   &stateChangeCallback, newState);
	}
	return true;
}

// 20. PeerConnection::changeIceState：改变 ICE 状态
bool PeerConnection::changeIceState(IceState newState) {
	// 20.1 如果当前 ICE 状态与目标状态相同，则直接返回 false
	if (iceState.exchange(newState) == newState)
		return false;

	// 20.2 输出新的 ICE 状态日志
	std::ostringstream s;
	s << newState;
	PLOG_INFO << "Changed ICE state to " << s.str();

	// 20.3 根据新状态同步或异步触发 ICE 状态变化回调
	if (newState == IceState::Closed) {
		auto callback = std::move(iceStateChangeCallback); // steal the callback
		callback(IceState::Closed);                        // call it synchronously
	} else {
		mProcessor.enqueue(&PeerConnection::trigger<IceState>, shared_from_this(),
		                   &iceStateChangeCallback, newState);
	}
	return true;
}

// 21. PeerConnection::changeGatheringState：改变 ICE 候选收集状态
bool PeerConnection::changeGatheringState(GatheringState newState) {
	// 21.1 如果当前状态与目标状态相同，则返回 false
	if (gatheringState.exchange(newState) == newState)
		return false;

	// 21.2 输出新的候选收集状态日志
	std::ostringstream s;
	s << newState;
	PLOG_INFO << "Changed gathering state to " << s.str();
	// 21.3 异步触发候选收集状态变化回调
	mProcessor.enqueue(&PeerConnection::trigger<GatheringState>, shared_from_this(),
	                   &gatheringStateChangeCallback, newState);

	return true;
}

// 22. PeerConnection::changeSignalingState：改变信令状态
bool PeerConnection::changeSignalingState(SignalingState newState) {
	// 22.1 如果当前信令状态与目标状态相同，则返回 false
	if (signalingState.exchange(newState) == newState)
		return false;

	// 22.2 输出新的信令状态日志
	std::ostringstream s;
	s << newState;
	PLOG_INFO << "Changed signaling state to " << s.str();
	// 22.3 异步触发信令状态变化回调
	mProcessor.enqueue(&PeerConnection::trigger<SignalingState>, shared_from_this(),
	                   &signalingStateChangeCallback, newState);

	return true;
}

// 23. PeerConnection::resetCallbacks：重置所有注册的回调函数
void PeerConnection::resetCallbacks() {
	// 23.1 将所有回调置空，取消注册
	// Unregister all callbacks
	dataChannelCallback = nullptr;
	localDescriptionCallback = nullptr;
	localCandidateCallback = nullptr;
	stateChangeCallback = nullptr;
	iceStateChangeCallback = nullptr;
	gatheringStateChangeCallback = nullptr;
	signalingStateChangeCallback = nullptr;
	trackCallback = nullptr;
}

// 24. PeerConnection::remoteFingerprint：获取远程证书指纹
CertificateFingerprint PeerConnection::remoteFingerprint() {
	// 24.1 使用锁保护远程描述的访问
	std::lock_guard lock(mRemoteDescriptionMutex);
	if (mRemoteFingerprint)
		return {CertificateFingerprint{mRemoteFingerprintAlgorithm, *mRemoteFingerprint}};
	else
		return {};
}

// 25. PeerConnection::updateTrackSsrcCache：更新轨道与 SSRC 的映射缓存
void PeerConnection::updateTrackSsrcCache(const Description &description) {
	// 25.1 使用独占锁以安全写入 mTracksBySsrc
	std::unique_lock lock(mTracksMutex); // for safely writing to mTracksBySsrc

	// 25.2 遍历描述中的每个媒体条目，建立 SSRC -> Track 的映射
	for (int i = 0; i < description.mediaCount(); ++i)
		std::visit( // ssrc -> track mapping
		    rtc::overloaded{
		        // 25.2.1 对于 Application 类型不做处理
		        [&](Description::Application const *) { return; },
		        // 25.2.2 对于 Media 类型，提取 SSRC 并与对应轨道关联
		        [&](Description::Media const *media) {
			        const auto ssrcs = media->getSSRCs();

			        // 25.2.2.1 如果没有 SSRC 则跳过
			        if (ssrcs.size() <= 0) {
				        return;
			        }

			        // 25.2.2.2 查找当前媒体对应的 Track 对象
			        std::shared_ptr<Track> track{nullptr};
			        if (auto it = mTracks.find(media->mid()); it != mTracks.end())
				        if (auto track_for_mid = it->second.lock())
					        track = track_for_mid;

			        // 25.2.2.3 如果找不到 Track，则跳过映射更新
			        if (!track) {
				        // Unable to find track for MID
				        return;
			        }

			        // 25.2.2.4 将所有 SSRC 与该 Track 关联
			        for (auto ssrc : ssrcs) {
				        mTracksBySsrc.insert_or_assign(ssrc, track);
			        }
		        },
		    },
		    description.media(i));
}

} // namespace rtc::impl
