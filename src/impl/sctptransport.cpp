/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "sctptransport.hpp"
#include "dtlstransport.hpp"
#include "internals.hpp"
#include "logcounter.hpp"
#include "utils.hpp"

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <exception>
#include <iostream>
#include <limits>
#include <shared_mutex>
#include <thread>
#include <unordered_set>
#include <vector>

// RFC 8831: SCTP MUST support performing Path MTU discovery without relying on ICMP or ICMPv6 as
// specified in [RFC4821] by using probing messages specified in [RFC4820].
// See https://www.rfc-editor.org/rfc/rfc8831.html#section-5
//
// However, usrsctp does not implement Path MTU discovery, so we need to disable it for now.
// See https://github.com/sctplab/usrsctp/issues/205
#define USE_PMTUD 0

// TODO: When Path MTU discovery is supported, it needs to be enabled with libjuice as ICE backend
// on all platforms except Mac OS where the Don't Fragment (DF) flag can't be set:
/*
#if !USE_NICE
#ifndef __APPLE__
// libjuice enables Linux path MTU discovery or sets the DF flag
#define USE_PMTUD 1
#else
// Setting the DF flag is not available on Mac OS
#define USE_PMTUD 0
#endif
#else // USE_NICE == 1
#define USE_PMTUD 0
#endif
*/

using namespace std::chrono_literals;
using namespace std::chrono;

namespace rtc::impl {

using utils::to_uint16;
using utils::to_uint32;

static LogCounter COUNTER_UNKNOWN_PPID(plog::warning,
                                       "Number of SCTP packets received with an unknown PPID");

class SctpTransport::InstancesSet {
public:
	void insert(SctpTransport *instance) {
		std::unique_lock lock(mMutex);
		mSet.insert(instance);
	}

	void erase(SctpTransport *instance) {
		std::unique_lock lock(mMutex);
		mSet.erase(instance);
	}

	using shared_lock = std::shared_lock<std::shared_mutex>;
	optional<shared_lock> lock(SctpTransport *instance) noexcept {
		shared_lock lock(mMutex);
		return mSet.find(instance) != mSet.end() ? std::make_optional(std::move(lock)) : nullopt;
	}

private:
	std::unordered_set<SctpTransport *> mSet;
	std::shared_mutex mMutex;
};

std::unique_ptr<SctpTransport::InstancesSet> SctpTransport::Instances = std::make_unique<InstancesSet>();

void SctpTransport::Init() {
    // 初始化 SCTP 库
    // 第一个参数 0 表示不使用特定端口，第二个和第三个参数分别为写回调和调试回调函数
	usrsctp_init(0, SctpTransport::WriteCallback, SctpTransport::DebugCallback);
	// 开启部分可靠性扩展（Partial Reliability Extension, RFC 3758），允许部分重传
	usrsctp_sysctl_set_sctp_pr_enable(1);  // Enable Partial Reliability Extension (RFC 3758)
	// 禁用 ECN (Explicit Congestion Notification)
	usrsctp_sysctl_set_sctp_ecn_enable(0); // Disable Explicit Congestion Notification
#ifndef SCTP_ACCEPT_ZERO_CHECKSUM
	// 如果不支持 SCTP_ACCEPT_ZERO_CHECKSUM，则启用 CRC32c offload，仅对外发包计算 CRC32 校验和
	usrsctp_enable_crc32c_offload(); // We'll compute CRC32 only for outgoing packets
#endif
#ifdef SCTP_DEBUG
	// 如果启用了 SCTP_DEBUG 宏，则开启 SCTP 全部调试信息
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
}

void SctpTransport::SetSettings(const SctpSettings &s) {
	// 修改 SCTP 发送和接收窗口大小，默认增加到 1MiB，以适应较长的 RTT
	// 参见 https://bugzilla.mozilla.org/show_bug.cgi?id=1051685
	usrsctp_sysctl_set_sctp_recvspace(to_uint32(s.recvBufferSize.value_or(1024 * 1024)));
	usrsctp_sysctl_set_sctp_sendspace(to_uint32(s.sendBufferSize.value_or(1024 * 1024)));

	// 将队列中最大 chunk 数量增加到 10K
	usrsctp_sysctl_set_sctp_max_chunks_on_queue(to_uint32(s.maxChunksOnQueue.value_or(10 * 1024)));

	// 增加初始拥塞窗口大小到 10 个 MTU（参照 RFC 6928），提升初始发送性能
	usrsctp_sysctl_set_sctp_initial_cwnd(to_uint32(s.initialCongestionWindow.value_or(10)));

	// 设置最大突发发送数为 10 个 MTU（默认 0 表示禁用）
	usrsctp_sysctl_set_sctp_max_burst_default(to_uint32(s.maxBurst.value_or(10)));

	// 选择标准的 SCTP 拥塞控制算法（RFC 4960）
	// 参见 https://github.com/paullouisageneau/libdatachannel/issues/354
	usrsctp_sysctl_set_sctp_default_cc_module(to_uint32(s.congestionControlModule.value_or(0)));

	// 将 SACK 延迟时间缩短到 20ms（RFC 4960 推荐值为 200ms）
	usrsctp_sysctl_set_sctp_delayed_sack_time_default(
	    to_uint32(s.delayedSackTime.value_or(20ms).count()));

	// RTO（重传超时）设置：最小值设为 200ms，比 RFC 2988 推荐的 1s 小，但 Linux 默认为 200ms
	usrsctp_sysctl_set_sctp_rto_min_default(
	    to_uint32(s.minRetransmitTimeout.value_or(200ms).count()));
	// 将最大 RTO 设置为 10s（而非 60s），缩短连接超时时间
	usrsctp_sysctl_set_sctp_rto_max_default(
	    to_uint32(s.maxRetransmitTimeout.value_or(10000ms).count()));
	usrsctp_sysctl_set_sctp_init_rto_max_default(
	    to_uint32(s.maxRetransmitTimeout.value_or(10000ms).count()));
	// 初始 RTO 仍设为 1s
	usrsctp_sysctl_set_sctp_rto_initial_default(
	    to_uint32(s.initialRetransmitTimeout.value_or(1000ms).count()));

	// RTX 设置：最大重传次数设为 5 次（比默认 8 次少，以缩短超时）
	auto maxRtx = to_uint32(s.maxRetransmitAttempts.value_or(5));
	usrsctp_sysctl_set_sctp_init_rtx_max_default(maxRtx);
	usrsctp_sysctl_set_sctp_assoc_rtx_max_default(maxRtx);
	usrsctp_sysctl_set_sctp_path_rtx_max_default(maxRtx); // 针对单路径

	// 设置心跳间隔，默认 10 秒
	usrsctp_sysctl_set_sctp_heartbeat_interval_default(
	    to_uint32(s.heartbeatInterval.value_or(100000ms).count()));
}

void SctpTransport::Cleanup() {
	// 清理 SCTP 库资源，循环调用 usrsctp_finish 直到返回 0，然后休眠 100ms
	while (usrsctp_finish())
		std::this_thread::sleep_for(100ms);
}

SctpTransport::SctpTransport(shared_ptr<Transport> lower, const Configuration &config, Ports ports,
                             message_callback recvCallback, amount_callback bufferedAmountCallback,
                             state_callback stateChangeCallback)
    : Transport(lower, std::move(stateChangeCallback)),
      mMaxMessageSize(config.maxMessageSize.value_or(DEFAULT_LOCAL_MAX_MESSAGE_SIZE)),
      mPorts(std::move(ports)), mSendQueue(0, message_size_func),
      mBufferedAmountCallback(std::move(bufferedAmountCallback)) {
	// 设置接收回调
	onRecv(std::move(recvCallback));

	PLOG_DEBUG << "Initializing SCTP transport";

	// 创建 SCTP socket
	mSock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, nullptr, nullptr, 0, nullptr);
	if (!mSock)
		throw std::runtime_error("Could not create SCTP socket, errno=" + std::to_string(errno));

	// 设置 socket 的 upcall 回调，用于异步事件通知
	usrsctp_set_upcall(mSock, &SctpTransport::UpcallCallback, this);

	// 将 socket 设置为非阻塞模式
	if (usrsctp_set_non_blocking(mSock, 1))
		throw std::runtime_error("Unable to set non-blocking mode, errno=" + std::to_string(errno));

	// 设置 SO_LINGER 为 0，确保底层关闭时不阻塞发送数据
	struct linger sol = {};
	sol.l_onoff = 1;
	sol.l_linger = 0;
	if (usrsctp_setsockopt(mSock, SOL_SOCKET, SO_LINGER, &sol, sizeof(sol)))
		throw std::runtime_error("Could not set socket option SO_LINGER, errno=" +
		                         std::to_string(errno));

	// 启用 SCTP 流重置功能，允许在 SCTP 连接中重置流
	struct sctp_assoc_value av = {};
	av.assoc_id = SCTP_ALL_ASSOC;
	av.assoc_value = 1;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av)))
		throw std::runtime_error("Could not set socket option SCTP_ENABLE_STREAM_RESET, errno=" +
		                         std::to_string(errno));
	int on = 1;
	// 允许接收 SCTP 传输信息（如 stream id、ppid 等）
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on)))
		throw std::runtime_error("Could set socket option SCTP_RECVRCVINFO, errno=" +
		                         std::to_string(errno));

	// 订阅 SCTP 事件，如 association change、sender dry、stream reset
	struct sctp_event se = {};
	se.se_assoc_id = SCTP_ALL_ASSOC;
	se.se_on = 1;
	se.se_type = SCTP_ASSOC_CHANGE;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_EVENT, &se, sizeof(se)))
		throw std::runtime_error("Could not subscribe to event SCTP_ASSOC_CHANGE, errno=" +
		                         std::to_string(errno));
	se.se_type = SCTP_SENDER_DRY_EVENT;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_EVENT, &se, sizeof(se)))
		throw std::runtime_error("Could not subscribe to event SCTP_SENDER_DRY_EVENT, errno=" +
		                         std::to_string(errno));
	se.se_type = SCTP_STREAM_RESET_EVENT;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_EVENT, &se, sizeof(se)))
		throw std::runtime_error("Could not subscribe to event SCTP_STREAM_RESET_EVENT, errno=" +
		                         std::to_string(errno));

	// RFC 8831 6.6 建议禁用 Nagle 算法以降低延迟
	int nodelay = 1;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay)))
		throw std::runtime_error("Could not set socket option SCTP_NODELAY, errno=" +
		                         std::to_string(errno));

	// 配置 SCTP 对等地址参数（paddr params），开启心跳检测
	struct sctp_paddrparams spp = {};
	spp.spp_flags = SPP_HB_ENABLE;

	// RFC 8261 关于 DTLS 的考虑：如果 SCTP 执行 PMTUD 并使用 IPv4，建议使用 DF 位，若不支持则设置安全 MTU
#if USE_PMTUD
	if (!config.mtu.has_value()) {
#else
	if (false) {
#endif
		// 启用 SCTP 路径 MTU 发现
		spp.spp_flags |= SPP_PMTUD_ENABLE;
		PLOG_VERBOSE << "Path MTU discovery enabled";

	} else {
		// 禁用 SCTP PMTUD，使用安全的 MTU 值
		spp.spp_flags |= SPP_PMTUD_DISABLE;
		// 计算安全 MTU：从给定 MTU 中扣除 SCTP/DTLS/UDP/IPv6 头部的开销
		size_t pmtu = config.mtu.value_or(DEFAULT_MTU) - 12 - 48 - 8 - 40; // SCTP/DTLS/UDP/IPv6
		spp.spp_pathmtu = to_uint32(pmtu);
		PLOG_VERBOSE << "Path MTU discovery disabled, SCTP MTU set to " << pmtu;
	}

	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &spp, sizeof(spp)))
		throw std::runtime_error("Could not set socket option SCTP_PEER_ADDR_PARAMS, errno=" +
		                         std::to_string(errno));

	// SCTP 关联管理
	// RFC 8831 建议 SCTP 协议协商时支持最多 65535 个流，但为了节省内存，使用较低的数量
	struct sctp_initmsg sinit = {};
	sinit.sinit_num_ostreams = MAX_SCTP_STREAMS_COUNT;
	sinit.sinit_max_instreams = MAX_SCTP_STREAMS_COUNT;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_INITMSG, &sinit, sizeof(sinit)))
		throw std::runtime_error("Could not set socket option SCTP_INITMSG, errno=" +
		                         std::to_string(errno));

	// 禁用 SCTP fragmented interleave（避免消息片段交叉），见 RFC 6458
	int level = 0;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &level, sizeof(level)))
		throw std::runtime_error("Could not disable SCTP fragmented interleave, errno=" +
		                         std::to_string(errno));

#ifdef SCTP_ACCEPT_ZERO_CHECKSUM // not available in usrsctp v0.9.5.0
	// 如果 SCTP 在 DTLS 下运行，数据完整性由 DTLS 保证，不需要额外检查 CRC32c
	int edmid = SCTP_EDMID_LOWER_LAYER_DTLS;
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_ACCEPT_ZERO_CHECKSUM, &edmid, sizeof(edmid)))
		throw std::runtime_error("Could set socket option SCTP_ACCEPT_ZERO_CHECKSUM, errno=" +
		                         std::to_string(errno));
#endif

	// 获取并设置 SCTP 收发缓冲区大小，确保能够容纳最大消息
	int rcvBuf = 0;
	socklen_t rcvBufLen = sizeof(rcvBuf);
	if (usrsctp_getsockopt(mSock, SOL_SOCKET, SO_RCVBUF, &rcvBuf, &rcvBufLen))
		throw std::runtime_error("Could not get SCTP recv buffer size, errno=" +
		                         std::to_string(errno));
	int sndBuf = 0;
	socklen_t sndBufLen = sizeof(sndBuf);
	if (usrsctp_getsockopt(mSock, SOL_SOCKET, SO_SNDBUF, &sndBuf, &sndBufLen))
		throw std::runtime_error("Could not get SCTP send buffer size, errno=" +
		                         std::to_string(errno));

	// 确保缓冲区大小至少能容纳最大消息
	const int minBuf = int(std::min(mMaxMessageSize, size_t(std::numeric_limits<int>::max())));
	rcvBuf = std::max(rcvBuf, minBuf);
	sndBuf = std::max(sndBuf, minBuf);

	if (usrsctp_setsockopt(mSock, SOL_SOCKET, SO_RCVBUF, &rcvBuf, sizeof(rcvBuf)))
		throw std::runtime_error("Could not set SCTP recv buffer size, errno=" +
		                         std::to_string(errno));

	if (usrsctp_setsockopt(mSock, SOL_SOCKET, SO_SNDBUF, &sndBuf, sizeof(sndBuf)))
		throw std::runtime_error("Could not set SCTP send buffer size, errno=" +
		                         std::to_string(errno));

	// 注册地址以便 usrsctp 内部管理，加入实例集合
	usrsctp_register_address(this);
	Instances->insert(this);
}

SctpTransport::~SctpTransport() {
	PLOG_DEBUG << "Destroying SCTP transport";

	// 等待处理线程结束
	mProcessor.join(); // if we are here, the processor must be empty

	// 在注销 incoming 回调之前，确保下层线程不会被 mWrittenOnce 阻塞
	mWrittenOnce = true;
	mWrittenCondition.notify_all();

	unregisterIncoming();

	// 关闭 SCTP socket
	usrsctp_close(mSock);

	// 注销地址，移除实例集合中的本对象
	usrsctp_deregister_address(this);
	Instances->erase(this);
}

void SctpTransport::onBufferedAmount(amount_callback callback) {
	// 设置缓冲量回调函数
	mBufferedAmountCallback = std::move(callback);
}

void SctpTransport::start() {
	// 启动 SCTP 传输：注册 incoming 回调后发起连接
	registerIncoming();
	connect();
}

void SctpTransport::stop() { close(); }

struct sockaddr_conn SctpTransport::getSockAddrConn(uint16_t port) {
	// 构造一个 sockaddr_conn 结构体，用于 SCTP 连接，port 为网络字节序
	struct sockaddr_conn sconn = {};
	sconn.sconn_family = AF_CONN;
	sconn.sconn_port = htons(port);
	sconn.sconn_addr = this;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(sconn);
#endif
	return sconn;
}

void SctpTransport::connect() {
	// 开始 SCTP 连接过程，打印本地和远端端口
	PLOG_DEBUG << "SCTP connecting (local port=" << mPorts.local
	           << ", remote port=" << mPorts.remote << ")";
	changeState(State::Connecting);

	// 绑定本地 SCTP 地址
	auto local = getSockAddrConn(mPorts.local);
	if (usrsctp_bind(mSock, reinterpret_cast<struct sockaddr *>(&local), sizeof(local)))
		throw std::runtime_error("Could not bind usrsctp socket, errno=" + std::to_string(errno));

	// 同时发起 SCTP 连接（simultaneous open），双方均需调用 connect()
	auto remote = getSockAddrConn(mPorts.remote);
	int ret = usrsctp_connect(mSock, reinterpret_cast<struct sockaddr *>(&remote), sizeof(remote));
	// EINPROGRESS 表示非阻塞连接正在进行中
	if (ret && errno != EINPROGRESS)
		throw std::runtime_error("Connection attempt failed, errno=" + std::to_string(errno));
}

bool SctpTransport::send(message_ptr message) {
	// 加锁保护发送队列
	std::lock_guard lock(mSendMutex);
	if (state() != State::Connected)
		return false;

	// 如果 message 为空，则尝试发送队列中的消息
	if (!message)
		return trySendQueue();

	PLOG_VERBOSE << "Send size=" << message->size();

	// 检查消息大小是否超过最大限制
	if (message->size() > mMaxMessageSize)
		throw std::invalid_argument("Message is too large");

	// 尝试先发送队列中的消息，如果队列为空，则直接发送当前 message
	if (trySendQueue() && trySendMessage(message))
		return true;

	// 否则将消息加入发送队列，并更新缓冲量
	mSendQueue.push(message);
	updateBufferedAmount(to_uint16(message->stream), ptrdiff_t(message_size_func(message)));
	return false;
}

bool SctpTransport::flush() {
	try {
		std::lock_guard lock(mSendMutex);
		if (state() != State::Connected)
			return false;

		trySendQueue();
		return true;

	} catch (const std::exception &e) {
		PLOG_WARNING << "SCTP flush: " << e.what();
		return false;
	}
}

void SctpTransport::closeStream(unsigned int stream) {
	std::lock_guard lock(mSendMutex);

	// 根据 RFC 8831 6.7 关闭 Data Channel，发送 Reset 消息
	mSendQueue.push(make_message(0, Message::Reset, to_uint16(stream)));

	// 异步刷新发送队列，确保 Reset 消息能及时发送
	mProcessor.enqueue(&SctpTransport::flush, shared_from_this());
}

void SctpTransport::close() {
	// 停止发送队列
	mSendQueue.stop();
	if (state() == State::Connected) {
		// 如果处于连接状态，则异步刷新队列
		mProcessor.enqueue(&SctpTransport::flush, shared_from_this());
	} else if (state() == State::Connecting) {
		PLOG_DEBUG << "SCTP early shutdown";
		// 如果正在连接，则立即关闭 SCTP socket
		if (usrsctp_shutdown(mSock, SHUT_RDWR)) {
			if (errno == ENOTCONN) {
				PLOG_VERBOSE << "SCTP already shut down";
			} else {
				PLOG_WARNING << "SCTP shutdown failed, errno=" << errno;
			}
		}
		changeState(State::Failed);
		mWrittenCondition.notify_all();
	}
}

unsigned int SctpTransport::maxStream() const {
	// 返回协商后最大可用的 stream 数量（减去 1）
	unsigned int streamsCount = mNegotiatedStreamsCount.value_or(MAX_SCTP_STREAMS_COUNT);
	return streamsCount > 0 ? streamsCount - 1 : 0;
}

void SctpTransport::incoming(message_ptr message) {
	// 处理接收到的消息。为了避免远端 INIT 在本地 INIT 之前到达，等待本地数据发送（mWrittenOnce）后再处理
	if (!mWrittenOnce) { // 首先测试原子布尔值，防止锁竞争
		std::unique_lock lock(mWriteMutex);
		mWrittenCondition.wait(lock, [&]() { return mWrittenOnce || state() == State::Failed; });
	}

	if (state() == State::Failed)
		return;

	if (!message) {
		PLOG_INFO << "SCTP disconnected";
		changeState(State::Disconnected);
		recv(nullptr);
		return;
	}

	PLOG_VERBOSE << "Incoming size=" << message->size();

	// 将接收到的数据传递给 usrsctp 的输入接口进行处理
	usrsctp_conninput(this, message->data(), message->size(), 0);
}

bool SctpTransport::outgoing(message_ptr message) {
	// 设置推荐的中等优先级 DSCP 值（AF11）以降低丢包率，参见 RFC 8837
	message->dscp = 10; // AF11: Assured Forwarding class 1, low drop probability
	// 调用基类 Transport 的 outgoing 方法发送消息
	return Transport::outgoing(std::move(message));
}

void SctpTransport::doRecv() {
	std::lock_guard lock(mRecvMutex);
	--mPendingRecvCount;
	try {
		// 循环接收数据，直到状态变为 Disconnected 或 Failed
		while (state() != State::Disconnected && state() != State::Failed) {
			const size_t bufferSize = 65536;
			byte buffer[bufferSize];
			socklen_t fromlen = 0;
			struct sctp_rcvinfo info = {};
			socklen_t infolen = sizeof(info);
			unsigned int infotype = 0;
			int flags = 0;
			// 使用 usrsctp_recvv 接收数据及相关 SCTP 接收信息
			ssize_t len = usrsctp_recvv(mSock, buffer, bufferSize, nullptr, &fromlen, &info,
			                            &infolen, &infotype, &flags);
			if (len < 0) {
				// 如果遇到 EWOULDBLOCK/EAGAIN/ECONNRESET 则跳出循环
				if (errno == EWOULDBLOCK || errno == EAGAIN || errno == ECONNRESET)
					break;
				else
					throw std::runtime_error("SCTP recv failed, errno=" + std::to_string(errno));
			} else if (len == 0) {
				break;
			}

			PLOG_VERBOSE << "SCTP recv, len=" << len;

			// 对于大于 64KB 的消息，SCTP_FRAGMENT_INTERLEAVE 可能无法正常工作，因此需要分别处理通知和消息
			if (flags & MSG_NOTIFICATION) {
				// SCTP 事件通知处理
				mPartialNotification.insert(mPartialNotification.end(), buffer, buffer + len);

				if (flags & MSG_EOR) {
					// 如果接收完毕，将部分通知数据交换到 notification 中并调用 processNotification 处理
					binary notification;
					mPartialNotification.swap(notification);
					auto n = reinterpret_cast<union sctp_notification *>(notification.data());
					processNotification(n, notification.size());
				}

			} else {
				// SCTP 普通消息处理
				mPartialMessage.insert(mPartialMessage.end(), buffer, buffer + len);
				if (mPartialMessage.size() > mMaxMessageSize) {
					PLOG_WARNING << "SCTP message is too large, truncating it";
					mPartialMessage.resize(mMaxMessageSize);
				}

				if (flags & MSG_EOR) {
					// 消息接收完毕，交换数据并调用 processData 进行处理
					binary message;
					mPartialMessage.swap(message);
					if (infotype != SCTP_RECVV_RCVINFO)
						throw std::runtime_error("Missing SCTP recv info");

					processData(std::move(message), info.rcv_sid, PayloadId(ntohl(info.rcv_ppid)));
				}
			}
		}
	} catch (const std::exception &e) {
		PLOG_WARNING << e.what();
	}
}

void SctpTransport::doFlush() {
	std::lock_guard lock(mSendMutex);
	--mPendingFlushCount;
	try {
		trySendQueue();
	} catch (const std::exception &e) {
		PLOG_WARNING << e.what();
	}
}

void SctpTransport::enqueueRecv() {
	// 如果接收任务已经在排队，则直接返回
	if (mPendingRecvCount > 0)
		return;

	if (auto shared_this = weak_from_this().lock()) {
		// 由 upcall 回调调用，确保 shared_ptr 不被释放
		++mPendingRecvCount;
		mProcessor.enqueue(&SctpTransport::doRecv, std::move(shared_this));
	}
}

void SctpTransport::enqueueFlush() {
	// 如果刷新任务已经在排队，则直接返回
	if (mPendingFlushCount > 0)
		return;

	if (auto shared_this = weak_from_this().lock()) {
		++mPendingFlushCount;
		mProcessor.enqueue(&SctpTransport::doFlush, std::move(shared_this));
	}
}

bool SctpTransport::trySendQueue() {
	// 要求 mSendMutex 已加锁
	// 利用 peek() 得到队列头部的消息（但不移除）
	while (auto next = mSendQueue.peek()) {
		message_ptr message = std::move(*next);
		if (!trySendMessage(message))
			return false;

		// 移除已成功发送的消息并更新缓冲量
		mSendQueue.pop();
		updateBufferedAmount(to_uint16(message->stream), -ptrdiff_t(message_size_func(message)));
	}

	// 如果发送队列不再运行且尚未触发关闭标志，则触发 SCTP shutdown
	if (!mSendQueue.running() && !std::exchange(mSendShutdown, true)) {
		PLOG_DEBUG << "SCTP shutdown";
		if (usrsctp_shutdown(mSock, SHUT_WR)) {
			if (errno == ENOTCONN) {
				PLOG_VERBOSE << "SCTP already shut down";
			} else {
				PLOG_WARNING << "SCTP shutdown failed, errno=" << errno;
				changeState(State::Disconnected);
				recv(nullptr);
			}
		}
	}

	return true;
}

bool SctpTransport::trySendMessage(message_ptr message) {
	// 要求 mSendMutex 已加锁
	if (state() != State::Connected)
		return false;

	uint32_t ppid;
	// 根据消息类型设置 PPID，用于 SCTP 分段传输和消息标识
	switch (message->type) {
	case Message::String:
		ppid = !message->empty() ? PPID_STRING : PPID_STRING_EMPTY;
		break;
	case Message::Binary:
		ppid = !message->empty() ? PPID_BINARY : PPID_BINARY_EMPTY;
		break;
	case Message::Control:
		ppid = PPID_CONTROL;
		break;
	case Message::Reset:
		sendReset(uint16_t(message->stream));
		return true;
	default:
		// 其他类型消息忽略
		return true;
	}

	PLOG_VERBOSE << "SCTP try send size=" << message->size();

	// TODO: Implement SCTP ndata specification draft when supported everywhere
	// See https://datatracker.ietf.org/doc/html/draft-ietf-tsvwg-sctp-ndata-08

	// 获取消息的可靠性信息，如果未设置则使用默认构造的 Reliability 对象
	const Reliability reliability = message->reliability ? *message->reliability : Reliability();

	struct sctp_sendv_spa spa = {};

	// 设置发送信息（sndinfo）
	spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
	spa.sendv_sndinfo.snd_sid = uint16_t(message->stream);
	spa.sendv_sndinfo.snd_ppid = htonl(ppid);
	spa.sendv_sndinfo.snd_flags |= SCTP_EOR; // 表示消息结束

	// 设置传输策略信息（prinfo）
	spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
	if (reliability.unordered)
		spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;

	if (reliability.maxPacketLifeTime) {
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
		spa.sendv_prinfo.pr_value = to_uint32(reliability.maxPacketLifeTime->count());
	} else if (reliability.maxRetransmits) {
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
		spa.sendv_prinfo.pr_value = to_uint32(*reliability.maxRetransmits);
	}
	// 如果未设置，则根据 Deprecated 类型处理（目前已弃用）
	else switch (reliability.typeDeprecated) {
	case Reliability::Type::Rexmit:
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
		spa.sendv_prinfo.pr_value = to_uint32(std::get<int>(reliability.rexmit));
		break;
	case Reliability::Type::Timed:
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
		spa.sendv_prinfo.pr_value = to_uint32(std::get<milliseconds>(reliability.rexmit).count());
		break;
	default:
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_NONE;
		break;
	}

	ssize_t ret;
	// 如果消息不为空，则发送消息数据，否则发送一个空字节
	if (!message->empty()) {
		ret = usrsctp_sendv(mSock, message->data(), message->size(), nullptr, 0, &spa, sizeof(spa),
		                    SCTP_SENDV_SPA, 0);
	} else {
		const char zero = 0;
		ret = usrsctp_sendv(mSock, &zero, 1, nullptr, 0, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
	}

	if (ret < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			PLOG_VERBOSE << "SCTP sending not possible";
			return false;
		}

		PLOG_ERROR << "SCTP sending failed, errno=" << errno;
		throw std::runtime_error("Sending failed, errno=" + std::to_string(errno));
	}

	PLOG_VERBOSE << "SCTP sent size=" << message->size();
	// 累加发送的字节数（针对 Binary 或 String 消息）
	if (message->type == Message::Binary || message->type == Message::String)
		mBytesSent += message->size();
	return true;
}

void SctpTransport::updateBufferedAmount(uint16_t streamId, ptrdiff_t delta) {
	// 要求 mSendMutex 已加锁
	if (delta == 0)
		return;

	auto it = mBufferedAmount.insert(std::make_pair(streamId, 0)).first;
	size_t amount = size_t(std::max(ptrdiff_t(it->second) + delta, ptrdiff_t(0)));
	if (amount == 0)
		mBufferedAmount.erase(it);
	else
		it->second = amount;

	// 同步调用回调函数通知上层更新当前流的缓冲量
	triggerBufferedAmount(streamId, amount);
}

void SctpTransport::triggerBufferedAmount(uint16_t streamId, size_t amount) {
	try {
		mBufferedAmountCallback(streamId, amount);
	} catch (const std::exception &e) {
		PLOG_WARNING << "SCTP buffered amount callback: " << e.what();
	}
}

void SctpTransport::sendReset(uint16_t streamId) {
	// 要求 mSendMutex 已加锁；仅在连接状态下发送 Reset
	if (state() != State::Connected)
		return;

	PLOG_DEBUG << "SCTP resetting stream " << streamId;

	using srs_t = struct sctp_reset_streams;
	// 构造 Reset 消息，包含一个流 ID
	const size_t len = sizeof(srs_t) + sizeof(uint16_t);
	byte buffer[len] = {};
	srs_t &srs = *reinterpret_cast<srs_t *>(buffer);
	srs.srs_flags = SCTP_STREAM_RESET_OUTGOING;
	srs.srs_number_streams = 1;
	srs.srs_stream_list[0] = streamId;

	mWritten = false;
	// 发送 Reset 请求，等待确认 Reset 完成
	if (usrsctp_setsockopt(mSock, IPPROTO_SCTP, SCTP_RESET_STREAMS, &srs, len) == 0) {
		std::unique_lock lock(mWriteMutex); // 注意：在 setsockopt 前加锁可能会导致 usrsctp 死锁
		mWrittenCondition.wait_for(lock, 1000ms,
		                           [&]() { return mWritten || state() != State::Connected; });
	} else if (errno == EINVAL) {
		PLOG_DEBUG << "SCTP stream " << streamId << " already reset";
	} else {
		PLOG_WARNING << "SCTP reset stream " << streamId << " failed, errno=" << errno;
	}
}

void SctpTransport::handleUpcall() noexcept {
	try {
		PLOG_VERBOSE << "Handle upcall";

		// 获取当前 SCTP socket 上的事件标志
		int events = usrsctp_get_events(mSock);

		if (events & SCTP_EVENT_READ)
			enqueueRecv();

		if (events & SCTP_EVENT_WRITE)
			enqueueFlush();

	} catch (const std::exception &e) {
		PLOG_ERROR << "SCTP upcall: " << e.what();
	}
}

int SctpTransport::handleWrite(byte *data, size_t len, uint8_t /*tos*/,
                               uint8_t /*set_df*/) noexcept {
	try {
		std::unique_lock lock(mWriteMutex);
		PLOG_VERBOSE << "Handle write, len=" << len;

		// 尝试将数据构造成消息后发送
		if (!outgoing(make_message(data, data + len)))
			return -1;

		// 标记写操作成功，并通知等待线程
		mWritten = true;
		mWrittenOnce = true;
		mWrittenCondition.notify_all();

	} catch (const std::exception &e) {
		PLOG_ERROR << "SCTP write: " << e.what();
		return -1;
	}
	return 0; // 成功
}

void SctpTransport::processData(binary &&data, uint16_t sid, PayloadId ppid) {
	PLOG_VERBOSE << "Process data, size=" << data.size();

	// 针对接收到的数据，根据 PPID 进行不同类型数据处理
	// 注意：部分 PPID（如 PPID_STRING_PARTIAL/PPID_BINARY_PARTIAL）已弃用，仅为兼容性处理
	switch (ppid) {
	case PPID_CONTROL:
		recv(make_message(std::move(data), Message::Control, sid));
		break;

	case PPID_STRING_PARTIAL: // deprecated
		mPartialStringData.insert(mPartialStringData.end(), data.begin(), data.end());
		mPartialStringData.resize(mMaxMessageSize);
		break;

	case PPID_STRING:
		if (mPartialStringData.empty()) {
			mBytesReceived += data.size();
			recv(make_message(std::move(data), Message::String, sid));
		} else {
			mPartialStringData.insert(mPartialStringData.end(), data.begin(), data.end());
			mPartialStringData.resize(mMaxMessageSize);
			mBytesReceived += mPartialStringData.size();
			auto message = make_message(std::move(mPartialStringData), Message::String, sid);
			mPartialStringData.clear();
			recv(std::move(message));
		}
		break;

	case PPID_STRING_EMPTY:
		recv(make_message(std::move(mPartialStringData), Message::String, sid));
		mPartialStringData.clear();
		break;

	case PPID_BINARY_PARTIAL: // deprecated
		mPartialBinaryData.insert(mPartialBinaryData.end(), data.begin(), data.end());
		mPartialBinaryData.resize(mMaxMessageSize);
		break;

	case PPID_BINARY:
		if (mPartialBinaryData.empty()) {
			mBytesReceived += data.size();
			recv(make_message(std::move(data), Message::Binary, sid));
		} else {
			mPartialBinaryData.insert(mPartialBinaryData.end(), data.begin(), data.end());
			mPartialBinaryData.resize(mMaxMessageSize);
			mBytesReceived += mPartialBinaryData.size();
			auto message = make_message(std::move(mPartialBinaryData), Message::Binary, sid);
			mPartialBinaryData.clear();
			recv(std::move(message));
		}
		break;

	case PPID_BINARY_EMPTY:
		recv(make_message(std::move(mPartialBinaryData), Message::Binary, sid));
		mPartialBinaryData.clear();
		break;

	default:
		// 如果收到未知的 PPID，则增加计数器并记录调试信息
		COUNTER_UNKNOWN_PPID++;
		PLOG_VERBOSE << "Unknown PPID: " << uint32_t(ppid);
		return;
	}
}

void SctpTransport::processNotification(const union sctp_notification *notify, size_t len) {
	// 检查通知长度是否与 header 中指定的长度匹配
	if (len != size_t(notify->sn_header.sn_length)) {
		PLOG_WARNING << "Unexpected notification length, expected=" << notify->sn_header.sn_length
		             << ", actual=" << len;
		return;
	}

	auto type = notify->sn_header.sn_type;
	PLOG_VERBOSE << "Processing notification, type=" << type;

	switch (type) {
	case SCTP_ASSOC_CHANGE: {
		PLOG_VERBOSE << "SCTP association change event";
		const struct sctp_assoc_change &sac = notify->sn_assoc_change;
		if (sac.sac_state == SCTP_COMM_UP) {
			// 当 SCTP 连接建立成功时，记录协商的流数（入站和出站）
			PLOG_DEBUG << "SCTP negotiated streams: incoming=" << sac.sac_inbound_streams
			           << ", outgoing=" << sac.sac_outbound_streams;
			// 保存实际协商的流数（取较小值）
			mNegotiatedStreamsCount.emplace(
			    std::min(sac.sac_inbound_streams, sac.sac_outbound_streams));

			PLOG_INFO << "SCTP connected";
			changeState(State::Connected);
		} else {
			// 如果连接断开，则更新状态为 Disconnected 或 Failed
			if (state() == State::Connected) {
				PLOG_INFO << "SCTP disconnected";
				changeState(State::Disconnected);
				recv(nullptr);
			} else {
				PLOG_ERROR << "SCTP connection failed";
				changeState(State::Failed);
			}
			mWrittenCondition.notify_all();
		}
		break;
	}

	case SCTP_SENDER_DRY_EVENT: {
		PLOG_VERBOSE << "SCTP sender dry event";
		// 当发送队列空闲时，尝试立即刷新发送
		flush();
		break;
	}

	case SCTP_STREAM_RESET_EVENT: {
		// 处理 SCTP stream reset 事件（数据通道关闭）
		const struct sctp_stream_reset_event &reset_event = notify->sn_strreset_event;
		const int count = (reset_event.strreset_length - sizeof(reset_event)) / sizeof(uint16_t);
		const uint16_t flags = reset_event.strreset_flags;

		IF_PLOG(plog::verbose) {
			std::ostringstream desc;
			desc << "flags=";
			if (flags & SCTP_STREAM_RESET_OUTGOING_SSN && flags & SCTP_STREAM_RESET_INCOMING_SSN)
				desc << "outgoing|incoming";
			else if (flags & SCTP_STREAM_RESET_OUTGOING_SSN)
				desc << "outgoing";
			else if (flags & SCTP_STREAM_RESET_INCOMING_SSN)
				desc << "incoming";
			else
				desc << "0";

			desc << ", streams=[";
			for (int i = 0; i < count; ++i) {
				uint16_t streamId = reset_event.strreset_stream_list[i];
				desc << (i != 0 ? "," : "") << streamId;
			}
			desc << "]";

			PLOG_VERBOSE << "SCTP reset event, " << desc.str();
		}

		// 根据 RFC 8831 6.7：当接收到流重置事件时，将通知应用数据通道关闭
		if (flags & SCTP_STREAM_RESET_INCOMING_SSN) {
			for (int i = 0; i < count; ++i) {
				uint16_t streamId = reset_event.strreset_stream_list[i];
				recv(make_message(0, Message::Reset, streamId));
			}
		}
		break;
	}

	default:
		// 对于其他类型的通知，不处理
		break;
	}
}

void SctpTransport::clearStats() {
	mBytesReceived = 0;
	mBytesSent = 0;
}

size_t SctpTransport::bytesSent() { return mBytesSent; }

size_t SctpTransport::bytesReceived() { return mBytesReceived; }

optional<milliseconds> SctpTransport::rtt() {
	if (state() != State::Connected)
		return nullopt;

	struct sctp_status status = {};
	socklen_t len = sizeof(status);
	if (usrsctp_getsockopt(mSock, IPPROTO_SCTP, SCTP_STATUS, &status, &len))
		return nullopt;

	return milliseconds(status.sstat_primary.spinfo_srtt);
}

void SctpTransport::UpcallCallback(struct socket *, void *arg, int /* flags */) {
	auto *transport = static_cast<SctpTransport *>(arg);

	if (auto locked = Instances->lock(transport))
		transport->handleUpcall();
}

int SctpTransport::WriteCallback(void *ptr, void *data, size_t len, uint8_t tos, uint8_t set_df) {
	auto *transport = static_cast<SctpTransport *>(ptr);

#ifndef SCTP_ACCEPT_ZERO_CHECKSUM
	// Set the CRC32 ourselves as we have enabled CRC32 offloading
	if (len >= 12) {
		uint32_t *checksum = reinterpret_cast<uint32_t *>(data) + 2;
		*checksum = 0;
		*checksum = usrsctp_crc32c(data, len);
	}
#endif

	// Workaround for sctplab/usrsctp#405: Send callback is invoked on already closed socket
	// https://github.com/sctplab/usrsctp/issues/405
	if (auto locked = Instances->lock(transport))
		return transport->handleWrite(static_cast<byte *>(data), len, tos, set_df);
	else
		return -1;
}

void SctpTransport::DebugCallback(const char *format, ...) {
	const size_t bufferSize = 1024;
	char buffer[bufferSize];
	va_list va;
	va_start(va, format);
	int len = std::vsnprintf(buffer, bufferSize, format, va);
	va_end(va);
	if (len <= 0)
		return;

	len = std::min(len, int(bufferSize - 1));
	buffer[len - 1] = '\0'; // remove newline

	PLOG_VERBOSE << "usrsctp: " << buffer; // usrsctp debug as verbose
}

} // namespace rtc::impl
