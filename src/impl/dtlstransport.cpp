/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "dtlstransport.hpp"
#include "dtlssrtptransport.hpp"
#include "icetransport.hpp"
#include "internals.hpp"
#include "threadpool.hpp"

#include <algorithm>
#include <iostream>
#include <chrono>
#include <cstring>
#include <exception>

#if !USE_GNUTLS
#ifdef _WIN32
#include <winsock2.h> // Windows 下用于 timeval 结构
#else
#include <sys/time.h> // Unix/Linux 下用于 timeval 结构
#endif
#endif

using namespace std::chrono;

namespace rtc::impl {

// 将接收任务加入线程池中，避免重复提交（mPendingRecvCount > 0时说明已经有任务在队列中）
void DtlsTransport::enqueueRecv() {
	if (mPendingRecvCount > 0)
		return;  // 如果已有接收任务待处理，则直接返回

	// 获取当前对象的 shared_ptr（通过 weak_ptr 转换）
	if (auto shared_this = weak_from_this().lock()) {
		++mPendingRecvCount;  // 增加挂起接收任务的计数
		// 将 doRecv 函数提交到线程池中执行
		ThreadPool::Instance().enqueue(&DtlsTransport::doRecv, std::move(shared_this));
	}
}

#if USE_GNUTLS

// GnuTLS 模式下的初始化函数，初始化全局 GnuTLS 环境
void DtlsTransport::Init() {
	gnutls_global_init(); // 初始化 GnuTLS（可选）
}

// GnuTLS 模式下的清理函数
void DtlsTransport::Cleanup() { 
	gnutls_global_deinit(); 
}

// 构造函数，使用 GnuTLS 实现 DTLS 传输
DtlsTransport::DtlsTransport(shared_ptr<IceTransport> lower, certificate_ptr certificate,
							 optional<size_t> mtu,
							 CertificateFingerprint::Algorithm fingerprintAlgorithm,
							 verifier_callback verifierCallback, state_callback stateChangeCallback)
	: Transport(lower, std::move(stateChangeCallback)), mMtu(mtu), mCertificate(certificate),
	  mFingerprintAlgorithm(fingerprintAlgorithm), mVerifierCallback(std::move(verifierCallback)),
	  mIsClient(lower->role() == Description::Role::Active),
	  mIncomingQueue(RECV_QUEUE_LIMIT, message_size_func) {

	PLOG_DEBUG << "Initializing DTLS transport (GnuTLS)";

	if (!mCertificate)
		throw std::invalid_argument("DTLS certificate is null");

	// 从证书中获取 GnuTLS 凭据
	gnutls_certificate_credentials_t creds = mCertificate->credentials();
	// 设置证书验证回调函数
	gnutls_certificate_set_verify_function(creds, CertificateCallback);

	// 根据角色设置标志：客户端或服务器，以及设置非阻塞、数据报模式
	unsigned int flags =
		GNUTLS_DATAGRAM | GNUTLS_NONBLOCK | (mIsClient ? GNUTLS_CLIENT : GNUTLS_SERVER);
	gnutls::check(gnutls_init(&mSession, flags));

	try {
		// 设置优先级和密码套件
		// RFC 8261要求DTLS层不使用压缩算法
		const char *priorities = "SECURE128:-VERS-SSL3.0:-ARCFOUR-128:-COMP-ALL:+COMP-NULL";
		const char *err_pos = NULL;
		gnutls::check(gnutls_priority_set_direct(mSession, priorities, &err_pos),
					  "Failed to set TLS priorities");

		// 设置 SRTP 的保护配置，要求支持 SRTP_AES128_CM_HMAC_SHA1_80
		gnutls::check(gnutls_srtp_set_profile(mSession, GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80),
					  "Failed to set SRTP profile");

		// 将证书凭据设置到会话中
		gnutls::check(gnutls_credentials_set(mSession, GNUTLS_CRD_CERTIFICATE, creds));

		// 设置 DTLS 重传超时：第一次1秒，最大30秒超时
		gnutls_dtls_set_timeouts(mSession,
								 1000,   // 1秒重传超时（RFC 6347推荐）
								 30000); // 30秒总超时
		gnutls_handshake_set_timeout(mSession, 30000);

		// 将当前对象指针与会话关联，方便在回调中获取
		gnutls_session_set_ptr(mSession, this);
		gnutls_transport_set_ptr(mSession, this);
		// 设置数据发送和接收回调函数
		gnutls_transport_set_push_function(mSession, WriteCallback);
		gnutls_transport_set_pull_function(mSession, ReadCallback);
		gnutls_transport_set_pull_timeout_function(mSession, TimeoutCallback);

	} catch (...) {
		// 如果出现异常则释放会话资源后抛出异常
		gnutls_deinit(mSession);
		throw;
	}

	// 设置默认 DSCP 值，用于握手阶段的 QoS（参考 RFC 8837）
	mCurrentDscp = 10; // AF11: 第一类保证转发，低丢包概率
}

// 析构函数，停止传输并释放 GnuTLS 会话资源
DtlsTransport::~DtlsTransport() {
	stop();

	PLOG_DEBUG << "Destroying DTLS transport";
	gnutls_deinit(mSession);
}

// 启动 DTLS 传输：注册接收数据、改变状态、设置 MTU 并开始握手
void DtlsTransport::start() {
	PLOG_DEBUG << "Starting DTLS transport";
	registerIncoming();  // 注册接收数据
	changeState(State::Connecting);

	// 根据设置的 MTU 计算 DTLS 层的最大传输单元，减去 UDP/IPv6 头部开销
	size_t mtu = mMtu.value_or(DEFAULT_MTU) - 8 - 40; // UDP/IPv6
	gnutls_dtls_set_mtu(mSession, static_cast<unsigned int>(mtu));
	PLOG_VERBOSE << "DTLS MTU set to " << mtu;

	// 提交接收任务以启动握手
	enqueueRecv();
}

// 停止 DTLS 传输：取消注册接收数据并停止接收队列
void DtlsTransport::stop() {
	PLOG_DEBUG << "Stopping DTLS transport";
	unregisterIncoming();
	mIncomingQueue.stop();
	enqueueRecv();
}

// 发送消息：调用 gnutls_record_send() 发送数据
bool DtlsTransport::send(message_ptr message) {
	if (!message || state() != State::Connected)
		return false;

	PLOG_VERBOSE << "Send size=" << message->size();

	ssize_t ret;
	do {
		// 使用互斥锁保证线程安全
		std::lock_guard lock(mSendMutex);
		mCurrentDscp = message->dscp;
		ret = gnutls_record_send(mSession, message->data(), message->size());
	} while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

	if (ret == GNUTLS_E_LARGE_PACKET)
		return false;

	if (!gnutls::check(ret))
		return false;

	return mOutgoingResult;
}

// 处理接收到的消息，将消息加入内部队列，并重新提交接收任务
void DtlsTransport::incoming(message_ptr message) {
	if (!message) {
		mIncomingQueue.stop();
		return;
	}

	PLOG_VERBOSE << "Incoming size=" << message->size();
	mIncomingQueue.push(message);
	enqueueRecv();
}

// 处理发送前的消息封装，更新 DSCP 值后调用上层发送接口
bool DtlsTransport::outgoing(message_ptr message) {
	message->dscp = mCurrentDscp;

	bool result = Transport::outgoing(std::move(message));
	mOutgoingResult = result;
	return result;
}

// demuxMessage 为虚函数，这里作为占位符返回 false
bool DtlsTransport::demuxMessage(message_ptr) {
	// Dummy
	return false;
}

// postHandshake 为虚函数占位符，握手完成后可扩展处理
void DtlsTransport::postHandshake() {
	// Dummy
}

// doRecv 处理接收数据：进行 DTLS 握手、读取数据、处理错误和超时
void DtlsTransport::doRecv() {
	// 锁定接收互斥锁，确保同一时刻只有一个接收线程在运行
	std::lock_guard lock(mRecvMutex);
	--mPendingRecvCount;

	// 如果当前状态不是连接中或已连接，则不处理接收数据
	if (state() != State::Connecting && state() != State::Connected)
		return;

	try {
		const size_t bufferSize = 4096;
		char buffer[bufferSize];

		// 如果还处于握手阶段，则处理握手
		if (state() == State::Connecting) {
			int ret;
			do {
				ret = gnutls_handshake(mSession);

				if (ret == GNUTLS_E_AGAIN) {
					// 如果需要等待，则根据超时设置调度下一次握手调用
					auto timeout = milliseconds(gnutls_dtls_get_timeout(mSession));
					ThreadPool::Instance().schedule(timeout, [weak_this = weak_from_this()]() {
						if (auto locked = weak_this.lock())
							locked->doRecv();
					});
					return;
				}

				if (ret == GNUTLS_E_LARGE_PACKET) {
					throw std::runtime_error("MTU is too low");
				}

			} while (!gnutls::check(ret, "Handshake failed")); // 重试非致命错误

			// 根据 RFC 8261，DTLS必须支持发送大于当前路径MTU的消息
			gnutls_dtls_set_mtu(mSession, bufferSize + 1);

			PLOG_INFO << "DTLS handshake finished";
			changeState(State::Connected);
			postHandshake();
		}

		// 如果处于连接状态，则循环读取数据
		if (state() == State::Connected) {
			while (true) {
				ssize_t ret = gnutls_record_recv(mSession, buffer, bufferSize);

				if (ret == GNUTLS_E_AGAIN) {
					return;
				}

				// 如果对端要求重握手，则发送 no_renegotiation 警告
				if (ret == GNUTLS_E_REHANDSHAKE) {
					do {
						std::lock_guard lock(mSendMutex);
						ret = gnutls_alert_send(mSession, GNUTLS_AL_WARNING,
												GNUTLS_A_NO_RENEGOTIATION);
					} while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
					continue;
				}

				// 认为对方提前关闭即为正常关闭
				if (ret == GNUTLS_E_PREMATURE_TERMINATION) {
					PLOG_DEBUG << "DTLS connection terminated";
					break;
				}

				if (gnutls::check(ret)) {
					if (ret == 0) {
						// 对方关闭连接
						PLOG_DEBUG << "DTLS connection cleanly closed";
						break;
					}
					auto *b = reinterpret_cast<byte *>(buffer);
					// 将接收到的数据封装成消息后传递给上层
					recv(make_message(b, b + ret));
				}
			}
		}
	} catch (const std::exception &e) {
		PLOG_ERROR << "DTLS recv: " << e.what();
	}

	// 发送关闭通知
	gnutls_bye(mSession, GNUTLS_SHUT_WR);

	if (state() == State::Connected) {
		PLOG_INFO << "DTLS closed";
		changeState(State::Disconnected);
		recv(nullptr);
	} else {
		PLOG_ERROR << "DTLS handshake failed";
		changeState(State::Failed);
	}
}

// 证书验证回调函数，通过提取证书指纹并调用用户的验证回调返回验证结果
int DtlsTransport::CertificateCallback(gnutls_session_t session) {
	DtlsTransport *t = static_cast<DtlsTransport *>(gnutls_session_get_ptr(session));
	try {
		if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
			return GNUTLS_E_CERTIFICATE_ERROR;
		}

		unsigned int count = 0;
		const gnutls_datum_t *array = gnutls_certificate_get_peers(session, &count);
		if (!array || count == 0) {
			return GNUTLS_E_CERTIFICATE_ERROR;
		}

		gnutls_x509_crt_t crt;
		gnutls::check(gnutls_x509_crt_init(&crt));
		int ret = gnutls_x509_crt_import(crt, &array[0], GNUTLS_X509_FMT_DER);
		if (ret != GNUTLS_E_SUCCESS) {
			gnutls_x509_crt_deinit(crt);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}

		// 生成证书指纹
		string fingerprint = make_fingerprint(crt, t->mFingerprintAlgorithm);
		gnutls_x509_crt_deinit(crt);

		// 调用用户回调函数进行验证
		bool success = t->mVerifierCallback(fingerprint);
		return success ? GNUTLS_E_SUCCESS : GNUTLS_E_CERTIFICATE_ERROR;

	} catch (const std::exception &e) {
		PLOG_WARNING << e.what();
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
}

// 写回调函数：将 DTLS 层发送的数据通过 outgoing() 传递给下层传输
ssize_t DtlsTransport::WriteCallback(gnutls_transport_ptr_t ptr, const void *data, size_t len) {
	DtlsTransport *t = static_cast<DtlsTransport *>(ptr);
	try {
		if (len > 0) {
			auto b = reinterpret_cast<const byte *>(data);
			t->outgoing(make_message(b, b + len));
		}
		gnutls_transport_set_errno(t->mSession, 0);
		return ssize_t(len);

	} catch (const std::exception &e) {
		PLOG_WARNING << e.what();
		gnutls_transport_set_errno(t->mSession, ECONNRESET);
		return -1;
	}
}

// 读回调函数：从内部接收队列中提取消息数据传递给 DTLS 层
ssize_t DtlsTransport::ReadCallback(gnutls_transport_ptr_t ptr, void *data, size_t maxlen) {
	DtlsTransport *t = static_cast<DtlsTransport *>(ptr);
	try {
		while (t->mIncomingQueue.running()) {
			auto next = t->mIncomingQueue.pop();
			if (!next) {
				gnutls_transport_set_errno(t->mSession, EAGAIN);
				return -1;
			}

			message_ptr message = std::move(*next);
			if (t->demuxMessage(message))
				continue;

			ssize_t len = std::min(maxlen, message->size());
			std::memcpy(data, message->data(), len);
			gnutls_transport_set_errno(t->mSession, 0);
			return len;
		}

		// 如果队列为空，则认为连接关闭
		gnutls_transport_set_errno(t->mSession, 0);
		return 0;

	} catch (const std::exception &e) {
		PLOG_WARNING << e.what();
		gnutls_transport_set_errno(t->mSession, ECONNRESET);
		return -1;
	}
}

// 超时回调函数，根据内部队列是否为空返回不同的超时状态
int DtlsTransport::TimeoutCallback(gnutls_transport_ptr_t ptr, unsigned int /* ms */) {
	DtlsTransport *t = static_cast<DtlsTransport *>(ptr);
	try {
		return !t->mIncomingQueue.empty() ? 1 : 0;

	} catch (const std::exception &e) {
		PLOG_WARNING << e.what();
		return 1;
	}
}

#elif USE_MBEDTLS

// mbedTLS 支持的 SRTP 保护配置数组
const mbedtls_ssl_srtp_profile srtpSupportedProtectionProfiles[] = {
	MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
	MBEDTLS_TLS_SRTP_UNSET,
};

// 构造函数：使用 mbedTLS 实现 DTLS 传输
DtlsTransport::DtlsTransport(shared_ptr<IceTransport> lower, certificate_ptr certificate,
							 optional<size_t> mtu,
							 CertificateFingerprint::Algorithm fingerprintAlgorithm,
							 verifier_callback verifierCallback, state_callback stateChangeCallback)
	: Transport(lower, std::move(stateChangeCallback)), mMtu(mtu), mCertificate(certificate),
	  mFingerprintAlgorithm(fingerprintAlgorithm), mVerifierCallback(std::move(verifierCallback)),
	  mIsClient(lower->role() == Description::Role::Active),
	  mIncomingQueue(RECV_QUEUE_LIMIT, message_size_func) {

	PLOG_DEBUG << "Initializing DTLS transport (MbedTLS)";

	if (!mCertificate)
		throw std::invalid_argument("DTLS certificate is null");

	// 初始化 mbedTLS 相关模块
	mbedtls_entropy_init(&mEntropy);
	mbedtls_ctr_drbg_init(&mDrbg);
	mbedtls_ssl_init(&mSsl);
	mbedtls_ssl_config_init(&mConf);
	mbedtls_ctr_drbg_set_prediction_resistance(&mDrbg, MBEDTLS_CTR_DRBG_PR_ON);

	try {
		mbedtls::check(mbedtls_ctr_drbg_seed(&mDrbg, mbedtls_entropy_func, &mEntropy, NULL, 0));

		mbedtls::check(mbedtls_ssl_config_defaults(
						   &mConf, mIsClient ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
						   MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT));

		// 强制使用 TLS 1.2（最小版本 TLS 1.2）
		mbedtls_ssl_conf_max_version(&mConf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
		mbedtls_ssl_conf_authmode(&mConf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		mbedtls_ssl_conf_verify(&mConf, DtlsTransport::CertificateCallback, this);
		mbedtls_ssl_conf_rng(&mConf, mbedtls_ctr_drbg_random, &mDrbg);

		// 从证书中获取凭据，并设置到配置中
		auto [crt, pk] = mCertificate->credentials();
		mbedtls::check(mbedtls_ssl_conf_own_cert(&mConf, crt.get(), pk.get()));

		mbedtls_ssl_conf_dtls_cookies(&mConf, NULL, NULL, NULL);
		mbedtls_ssl_conf_dtls_srtp_protection_profiles(&mConf, srtpSupportedProtectionProfiles);

		mbedtls::check(mbedtls_ssl_setup(&mSsl, &mConf));

		// 设置导出密钥回调，用于 DTLS-SRTP 密钥导出
		mbedtls_ssl_set_export_keys_cb(&mSsl, DtlsTransport::ExportKeysCallback, this);
		mbedtls_ssl_set_bio(&mSsl, this, WriteCallback, ReadCallback, NULL);
		mbedtls_ssl_set_timer_cb(&mSsl, this, SetTimerCallback, GetTimerCallback);

	} catch (...) {
		// 如果出错则释放所有 mbedTLS 分配的资源
		mbedtls_entropy_free(&mEntropy);
		mbedtls_ctr_drbg_free(&mDrbg);
		mbedtls_ssl_free(&mSsl);
		mbedtls_ssl_config_free(&mConf);
		throw;
	}

	mCurrentDscp = 10; // 设置默认 DSCP 值
}

DtlsTransport::~DtlsTransport() {
	stop();

	PLOG_DEBUG << "Destroying DTLS transport";
	mbedtls_entropy_free(&mEntropy);
	mbedtls_ctr_drbg_free(&mDrbg);
	mbedtls_ssl_free(&mSsl);
	mbedtls_ssl_config_free(&mConf);
}

void DtlsTransport::Init() {
	// 对于 mbedTLS 不需要额外初始化
}

void DtlsTransport::Cleanup() {
	// 对于 mbedTLS 不需要额外清理
}

void DtlsTransport::start() {
	PLOG_DEBUG << "Starting DTLS transport";
	registerIncoming();
	changeState(State::Connecting);

	{
		// 设置 MTU，计算方式同样为减去 UDP/IPv6 头部开销
		std::lock_guard lock(mSslMutex);
		size_t mtu = mMtu.value_or(DEFAULT_MTU) - 8 - 40; // UDP/IPv6
		mbedtls_ssl_set_mtu(&mSsl, static_cast<unsigned int>(mtu));
		PLOG_VERBOSE << "DTLS MTU set to " << mtu;
	}

	enqueueRecv(); // 提交接收任务以开始握手
}

void DtlsTransport::stop() {
	PLOG_DEBUG << "Stopping DTLS transport";
	unregisterIncoming();
	mIncomingQueue.stop();
	enqueueRecv();
}

// 发送数据，调用 mbedtls_ssl_write 写数据到 SSL 层
bool DtlsTransport::send(message_ptr message) {
	if (!message || state() != State::Connected)
		return false;

	PLOG_VERBOSE << "Send size=" << message->size();

	int ret;
	do {
		std::lock_guard lock(mSslMutex);
		if (message->size() > size_t(mbedtls_ssl_get_max_out_record_payload(&mSsl)))
			return false;

		mCurrentDscp = message->dscp;
		ret = mbedtls_ssl_write(&mSsl, reinterpret_cast<const unsigned char *>(message->data()),
								message->size());
	} while (!mbedtls::check(ret));

	return mOutgoingResult;
}

// 处理接收到的数据：将消息放入内部队列，然后继续安排接收任务
void DtlsTransport::incoming(message_ptr message) {
	if (!message) {
		mIncomingQueue.stop();
		enqueueRecv();
		return;
	}

	PLOG_VERBOSE << "Incoming size=" << message->size();
	mIncomingQueue.push(message);
	enqueueRecv();
}

bool DtlsTransport::outgoing(message_ptr message) {
	message->dscp = mCurrentDscp;

	bool result = Transport::outgoing(std::move(message));
	mOutgoingResult = result;
	return result;
}

bool DtlsTransport::demuxMessage(message_ptr) {
	// Dummy 占位函数，返回 false 表示不进行分流处理
	return false;
}

void DtlsTransport::postHandshake() {
	// Dummy 占位函数，握手完成后可扩展后续处理
}

void DtlsTransport::doRecv() {
	std::lock_guard lock(mRecvMutex);
	--mPendingRecvCount;

	if (state() != State::Connecting && state() != State::Connected)
		return;

	try {
		const size_t bufferSize = 4096;
		byte buffer[bufferSize];

		// 如果处于握手阶段，则循环尝试完成握手
		if (state() == State::Connecting) {
			while (true) {
				int ret;
				{
					std::lock_guard lock(mSslMutex);
					ret = mbedtls_ssl_handshake(&mSsl);
				}

				if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
					// 安排超时后继续握手
					ThreadPool::Instance().schedule(mTimerSetAt + milliseconds(mFinMs),
						[weak_this = weak_from_this()]() {
							if (auto locked = weak_this.lock())
								locked->doRecv();
						});
					return;
				}

				if (mbedtls::check(ret, "Handshake failed")) {
					// 握手成功后，设置 MTU 为 bufferSize+1
					{
						std::lock_guard lock(mSslMutex);
						mbedtls_ssl_set_mtu(&mSsl, static_cast<unsigned int>(bufferSize + 1));
					}

					PLOG_INFO << "DTLS handshake finished";
					postHandshake();
					changeState(State::Connected);
					break;
				}
			}
		}

		if (state() == State::Connected) {
			while (true) {
				int ret;
				{
					std::lock_guard lock(mSslMutex);
					ret = mbedtls_ssl_read(&mSsl, reinterpret_cast<unsigned char *>(buffer),
					                       bufferSize);
				}

				if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
					return;
				}

				if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
					PLOG_DEBUG << "DTLS connection cleanly closed";
					break;
				}

				if (mbedtls::check(ret)) {
					if (ret == 0) {
						PLOG_DEBUG << "DTLS connection terminated";
						break;
					}
					auto *b = reinterpret_cast<byte *>(buffer);
					recv(make_message(b, b + ret));
				}
			}
		}
	} catch (const std::exception &e) {
		PLOG_ERROR << "DTLS recv: " << e.what();
	}

	if (state() == State::Connected) {
		PLOG_INFO << "DTLS closed";
		changeState(State::Disconnected);
		recv(nullptr);
	} else {
		PLOG_ERROR << "DTLS handshake failed";
		changeState(State::Failed);
	}
}

// 定时器回调：记录中间和最终超时值，并更新定时器设置时间
void DtlsTransport::SetTimerCallback(void *ctx, uint32_t int_ms, uint32_t fin_ms) {
	auto dtlsTransport = static_cast<DtlsTransport *>(ctx);
	dtlsTransport->mIntMs = int_ms;
	dtlsTransport->mFinMs = fin_ms;

	if (fin_ms != 0) {
		dtlsTransport->mTimerSetAt = std::chrono::steady_clock::now();
	}
}

// 获取定时器状态：根据当前时间返回超时级别
int DtlsTransport::GetTimerCallback(void *ctx) {
	auto dtlsTransport = static_cast<DtlsTransport *>(ctx);
	auto now = std::chrono::steady_clock::now();

	if (dtlsTransport->mFinMs == 0) {
		return -1;
	} else if (now >= dtlsTransport->mTimerSetAt + milliseconds(dtlsTransport->mFinMs)) {
		return 2;
	} else if (now >= dtlsTransport->mTimerSetAt + milliseconds(dtlsTransport->mIntMs)) {
		return 1;
	} else {
		return 0;
	}
}

#else // OPENSSL

// OpenSSL 模式下的全局 BIO 方法和扩展索引
BIO_METHOD *DtlsTransport::BioMethods = NULL;
int DtlsTransport::TransportExIndex = -1;
std::mutex DtlsTransport::GlobalMutex;

// OpenSSL 模式下初始化函数：初始化 OpenSSL 库和创建自定义 BIO 方法
void DtlsTransport::Init() {
	std::lock_guard lock(GlobalMutex);

	openssl::init();

	if (!BioMethods) {
		BioMethods = BIO_meth_new(BIO_TYPE_BIO, "DTLS writer");
		if (!BioMethods)
			throw std::runtime_error("Failed to create BIO methods for DTLS writer");
		BIO_meth_set_create(BioMethods, BioMethodNew);
		BIO_meth_set_destroy(BioMethods, BioMethodFree);
		BIO_meth_set_write(BioMethods, BioMethodWrite);
		BIO_meth_set_ctrl(BioMethods, BioMethodCtrl);
	}
	if (TransportExIndex < 0) {
		TransportExIndex = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	}
}

// OpenSSL 模式下清理函数
void DtlsTransport::Cleanup() {
	// Nothing to do
}
using namespace std;
// 构造函数：使用 OpenSSL 实现 DTLS 传输
DtlsTransport::DtlsTransport(shared_ptr<IceTransport> lower, certificate_ptr certificate,
                             optional<size_t> mtu,
                             CertificateFingerprint::Algorithm fingerprintAlgorithm,
                             verifier_callback verifierCallback, state_callback stateChangeCallback)
    : Transport(lower, std::move(stateChangeCallback)), mMtu(mtu), mCertificate(certificate),
      mFingerprintAlgorithm(fingerprintAlgorithm), mVerifierCallback(std::move(verifierCallback)),
      mIsClient(lower->role() == Description::Role::Active),
      mIncomingQueue(RECV_QUEUE_LIMIT, message_size_func) {

	cout << "[DltsTrasport] Initializing DTLS transport (OpenSSL)" << endl;

	if (!mCertificate)
		throw std::invalid_argument("DTLS certificate is null");

	try {
		// 创建 DTLS 上下文，采用 DTLS_method() 方法
		mCtx = SSL_CTX_new(DTLS_method());
		if (!mCtx)
			throw std::runtime_error("Failed to create SSL context");

		// 禁用 SSLv3、压缩、MTU查询和重新协商（符合 RFC 8261 和 RFC 8827）
		SSL_CTX_set_options(mCtx, SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_QUERY_MTU |
		                              SSL_OP_NO_RENEGOTIATION);

		// 设置最小协议版本为 DTLS1
		SSL_CTX_set_min_proto_version(mCtx, DTLS1_VERSION);
		SSL_CTX_set_read_ahead(mCtx, 1);
		SSL_CTX_set_quiet_shutdown(mCtx, 0); // 发送 close_notify 警告
		SSL_CTX_set_info_callback(mCtx, InfoCallback);

		// 配置证书验证模式和验证深度
		SSL_CTX_set_verify(mCtx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		                   CertificateCallback);
		SSL_CTX_set_verify_depth(mCtx, 1);

		// 设置密码套件，排除低强度和不安全的算法
		openssl::check(SSL_CTX_set_cipher_list(mCtx, "ALL:!LOW:!EXP:!RC4:!MD5:@STRENGTH"),
		               "Failed to set SSL priorities");

#if OPENSSL_VERSION_NUMBER >= 0x30000000
		// OpenSSL 3.x 版本，设置椭圆曲线组
		openssl::check(SSL_CTX_set1_groups_list(mCtx, "P-256"), "Failed to set SSL groups");
#else
		// 旧版本通过 EC_KEY 设置临时 ECDH 参数
		auto ecdh = unique_ptr<EC_KEY, decltype(&EC_KEY_free)>(
		    EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
		SSL_CTX_set_tmp_ecdh(mCtx, ecdh.get());
#endif

		// 从证书中获取 X509 和私钥，设置到 SSL 上下文中
		auto [x509, pkey] = mCertificate->credentials();
		SSL_CTX_use_certificate(mCtx, x509);
		SSL_CTX_use_PrivateKey(mCtx, pkey);
		openssl::check(SSL_CTX_check_private_key(mCtx), "SSL local private key check failed");

		// 创建 SSL 实例并设置扩展数据索引
		mSsl = SSL_new(mCtx);
		if (!mSsl)
			throw std::runtime_error("Failed to create SSL instance");

		SSL_set_ex_data(mSsl, TransportExIndex, this);

		// 根据角色设置连接状态
		if (mIsClient)
			SSL_set_connect_state(mSsl);
		else
			SSL_set_accept_state(mSsl);

		// 创建内存 BIO 用于数据输入和自定义 BIO 用于数据输出
		mInBio = BIO_new(BIO_s_mem());
		mOutBio = BIO_new(BioMethods);
		if (!mInBio || !mOutBio)
			throw std::runtime_error("Failed to create BIO");

		BIO_set_mem_eof_return(mInBio, BIO_EOF);
		BIO_set_data(mOutBio, this);
		// 将 BIO 与 SSL 实例关联
		SSL_set_bio(mSsl, mInBio, mOutBio);

		// 设置 SRTP 配置，要求支持 SRTP_AES128_CM_SHA1_80 或者 AES-GCM（如果支持）
#if RTC_ENABLE_MEDIA
		// 尝试使用 GCM 加密套件
		if (!DtlsSrtpTransport::IsGcmSupported() ||
		    SSL_set_tlsext_use_srtp(
		        mSsl, "SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80")) {
			cout << "[DltsTrasport] AES-GCM for SRTP is not supported, falling back to default profile" << endl;
			if (SSL_set_tlsext_use_srtp(mSsl, "SRTP_AES128_CM_SHA1_80"))
				throw std::runtime_error("Failed to set SRTP profile: " +
										 openssl::error_string(ERR_get_error()));
		}
#else
		if (SSL_set_tlsext_use_srtp(mSsl, "SRTP_AES128_CM_SHA1_80"))
			throw std::runtime_error("Failed to set SRTP profile: " +
									 openssl::error_string(ERR_get_error()));
#endif
	} catch (...) {
		if (mSsl)
			SSL_free(mSsl);
		if (mCtx)
			SSL_CTX_free(mCtx);
		throw;
	}

	mCurrentDscp = 10; // 设置默认 DSCP 值
}

DtlsTransport::~DtlsTransport() {
	stop();

	cout << "[DltsTrasport] Destroying DTLS transport" << endl;
	SSL_free(mSsl);
	SSL_CTX_free(mCtx);
}

void DtlsTransport::start() {
	cout << "[DltsTrasport] Starting DTLS transport" << endl;
	registerIncoming();
	changeState(State::Connecting);

	int ret, err;
	{
		std::lock_guard lock(mSslMutex);

		// 根据设置的 MTU 计算 UDP/IPv6 下的 MTU
		size_t mtu = mMtu.value_or(DEFAULT_MTU) - 8 - 40; // UDP/IPv6
		SSL_set_mtu(mSsl, static_cast<unsigned int>(mtu));
		cout << "[DltsTrasport] DTLS MTU set to " << mtu << endl;

		// 发起 DTLS 握手
		ret = SSL_do_handshake(mSsl);
		err = SSL_get_error(mSsl, ret);
	}

	openssl::check_error(err, "Handshake failed");

	handleTimeout();
}

void DtlsTransport::stop() {
	cout << "[DltsTrasport] Stopping DTLS transport" << endl;
	unregisterIncoming();
	mIncomingQueue.stop();
	enqueueRecv();
}

// 发送数据，调用 SSL_write 将数据写入 DTLS 通道
bool DtlsTransport::send(message_ptr message) {
	if (!message || state() != State::Connected)
		return false;

	cout << "[DltsTrasport] Send size=" << message->size() << ", type=" << message->type << endl;

	int ret, err;
	{
		std::lock_guard lock(mSslMutex);
		mCurrentDscp = message->dscp;
		ret = SSL_write(mSsl, message->data(), int(message->size()));
		err = SSL_get_error(mSsl, ret);
	}

	if (!openssl::check_error(err))
		return false;

	return mOutgoingResult;
}

void DtlsTransport::incoming(message_ptr message) {
	if (!message) {
		mIncomingQueue.stop();
		enqueueRecv();
		return;
	}

	cout << "[DltsTrasport] Incoming size=" << message->size() << endl;
	mIncomingQueue.push(message);
	enqueueRecv();
}

bool DtlsTransport::outgoing(message_ptr message) {
	message->dscp = mCurrentDscp;

	bool result = Transport::outgoing(std::move(message));
	mOutgoingResult = result;
	return result;
}

bool DtlsTransport::demuxMessage(message_ptr) {
	// Dummy
	return false;
}

void DtlsTransport::postHandshake() {
	// Dummy 占位函数，握手完成后可扩展其他处理
}

void DtlsTransport::doRecv() {
	std::lock_guard lock(mRecvMutex);
	--mPendingRecvCount;

	if (state() != State::Connecting && state() != State::Connected)
		return;

	try {
		const size_t bufferSize = 4096;
		byte buffer[bufferSize];

		// 处理挂起的数据：如果还有消息在队列中，写入内存 BIO
		while (mIncomingQueue.running()) {
			auto next = mIncomingQueue.pop();
			if (!next) {
				// 如果没有更多数据且处于握手阶段，则处理超时
				if (state() == State::Connecting)
					handleTimeout();

				return;
			}

			message_ptr message = std::move(*next);
			if (demuxMessage(message))
				continue;

			BIO_write(mInBio, message->data(), int(message->size()));

			if (state() == State::Connecting) {
				// 继续完成握手过程
				int ret, err;
				{
					std::lock_guard lock(mSslMutex);
					ret = SSL_do_handshake(mSsl);
					err = SSL_get_error(mSsl, ret);
				}

				if (openssl::check_error(err, "Handshake failed")) {
					// 握手成功后，根据 RFC 8261 设置 MTU
					{
						std::lock_guard lock(mSslMutex);
						SSL_set_mtu(mSsl, bufferSize + 1);
					}

					cout << "[DltsTrasport] DTLS handshake finished" << endl;
					postHandshake();
					changeState(State::Connected);
				}
			}

			if (state() == State::Connected) {
				int ret, err;
				{
					std::lock_guard lock(mSslMutex);
					ret = SSL_read(mSsl, buffer, bufferSize);
					err = SSL_get_error(mSsl, ret);
				}

				if (err == SSL_ERROR_ZERO_RETURN) {
					cout << "[DltsTrasport] TLS connection cleanly closed" << endl;
					break;
				}
				// int test = (message->size() == 3016);
				if (/*test ||*/ openssl::check_error(err))
					recv(make_message(buffer, buffer + ret));	//这个是close的回调...
			}
		}

		std::lock_guard lock(mSslMutex);
		SSL_shutdown(mSsl);

	} catch (const std::exception &e) {
		cout << "[DltsTrasport] DTLS recv: " << e.what() << endl;
	}

	if (state() == State::Connected) {
		cout << "[DltsTrasport] DTLS closed" << endl;
		changeState(State::Disconnected);
		recv(nullptr);
	} else {
		cout << "[DltsTrasport] DTLS handshake failed" << endl;
		changeState(State::Failed);
	}
}

// 处理握手超时，调用 DTLSv1_handle_timeout 并根据返回值进行重传调度
void DtlsTransport::handleTimeout() {
	std::lock_guard lock(mSslMutex);

	// 注意：该函数返回值不遵循常规约定
	int ret = DTLSv1_handle_timeout(mSsl);
	if (ret < 0) {
		throw std::runtime_error("Handshake timeout"); // 写 BIO 不能失败
	} else if (ret > 0) {
		cout << "[DltsTrasport] DTLS retransmit done" << endl;
	}

	struct timeval tv = {};
	if (DTLSv1_get_timeout(mSsl, &tv)) {
		auto timeout = milliseconds(tv.tv_sec * 1000 + tv.tv_usec / 1000);
		// 手动处理握手超时，因为 OpenSSL 会指数退避
		if (timeout > 30s)
			throw std::runtime_error("Handshake timeout");

		LOG_VERBOSE << "DTLS retransmit timeout is " << timeout.count() << "ms";
		ThreadPool::Instance().schedule(timeout, [weak_this = weak_from_this()]() {
			if (auto locked = weak_this.lock())
				locked->doRecv();
		});
	}
}

// 证书验证回调（OpenSSL版）：通过证书生成指纹，并调用用户回调验证
int DtlsTransport::CertificateCallback(int /*preverify_ok*/, X509_STORE_CTX *ctx) {
	SSL *ssl =
		static_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
	DtlsTransport *t =
		static_cast<DtlsTransport *>(SSL_get_ex_data(ssl, DtlsTransport::TransportExIndex));

	X509 *crt = X509_STORE_CTX_get_current_cert(ctx);
	string fingerprint = make_fingerprint(crt, t->mFingerprintAlgorithm);

	return t->mVerifierCallback(fingerprint) ? 1 : 0;
}

// OpenSSL 的信息回调，用于输出 DTLS 警告或错误信息，同时在收到 Alert 后关闭连接
void DtlsTransport::InfoCallback(const SSL *ssl, int where, int ret) {
	DtlsTransport *t =
		static_cast<DtlsTransport *>(SSL_get_ex_data(ssl, DtlsTransport::TransportExIndex));

	if (where & SSL_CB_ALERT) {
		if (ret != 256) { // 256 表示 Close Notify
			cout << "[DltsTrasport] DTLS alert: " << SSL_alert_desc_string_long(ret) << endl;
		}
		t->mIncomingQueue.stop(); // 收到警告则关闭连接
	}
}

// 自定义 BIO 方法：新建 BIO 时初始化
int DtlsTransport::BioMethodNew(BIO *bio) {
	BIO_set_init(bio, 1);
	BIO_set_data(bio, NULL);
	BIO_set_shutdown(bio, 0);
	return 1;
}

// 自定义 BIO 方法：释放 BIO 时清理数据
int DtlsTransport::BioMethodFree(BIO *bio) {
	if (!bio)
		return 0;
	BIO_set_data(bio, NULL);
	return 1;
}

// 自定义 BIO 写回调：将数据传给 outgoing() 发送
int DtlsTransport::BioMethodWrite(BIO *bio, const char *in, int inl) {
	if (inl <= 0)
		return inl;
	auto transport = reinterpret_cast<DtlsTransport *>(BIO_get_data(bio));
	if (!transport)
		return -1;
	auto b = reinterpret_cast<const byte *>(in);
	transport->outgoing(make_message(b, b + inl));
	return inl; // 写操作假定不会失败
}

// 自定义 BIO 控制回调：处理诸如刷新、查询 MTU、待写数据等操作
long DtlsTransport::BioMethodCtrl(BIO * /*bio*/, int cmd, long /*num*/, void * /*ptr*/) {
	switch (cmd) {
	case BIO_CTRL_FLUSH:
		return 1;
	case BIO_CTRL_DGRAM_QUERY_MTU:
		return 0; // 当设置了 SSL_OP_NO_QUERY_MTU 时返回 0
	case BIO_CTRL_WPENDING:
	case BIO_CTRL_PENDING:
		return 0;
	default:
		break;
	}
	return 0;
}

#endif // END OPENSSL

} // namespace rtc::impl
