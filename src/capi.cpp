/**
 * Copyright (c) 2019-2021 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "rtc.h"
#include "rtc.hpp"

#include "impl/internals.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <mutex>
#include <type_traits>
#include <unordered_map>
#include <utility>

using namespace rtc;
using namespace std::chrono_literals;
using std::chrono::milliseconds;

namespace {
// 全局数据结构，用于存储各种对象，使用 int 作为唯一标识符。
// peerConnectionMap 存储 PeerConnection 对象
std::unordered_map<int, shared_ptr<PeerConnection>> peerConnectionMap;
// dataChannelMap 存储 DataChannel 对象
std::unordered_map<int, shared_ptr<DataChannel>> dataChannelMap;
// trackMap 存储 Track 对象
std::unordered_map<int, shared_ptr<Track>> trackMap;
#if RTC_ENABLE_MEDIA
// rtcpSrReporterMap 存储 RTCP SR Reporter 对象，用于统计和上报
std::unordered_map<int, shared_ptr<RtcpSrReporter>> rtcpSrReporterMap;
// rtpConfigMap 存储 RTP Packetization 配置对象
std::unordered_map<int, shared_ptr<RtpPacketizationConfig>> rtpConfigMap;
#endif
#if RTC_ENABLE_WEBSOCKET
// webSocketMap 存储 WebSocket 对象
std::unordered_map<int, shared_ptr<WebSocket>> webSocketMap;
// webSocketServerMap 存储 WebSocketServer 对象
std::unordered_map<int, shared_ptr<WebSocketServer>> webSocketServerMap;
#endif
// userPointerMap 用于存储与各个 ID 关联的用户自定义指针
std::unordered_map<int, void *> userPointerMap;
// 保护以上数据结构的互斥锁
std::mutex mutex;
// 用于生成唯一 ID 的计数器
int lastId = 0;

// 根据 id 查找并返回与之关联的用户指针，返回 optional
optional<void *> getUserPointer(int id) {
	std::lock_guard lock(mutex);
	auto it = userPointerMap.find(id);
	return it != userPointerMap.end() ? std::make_optional(it->second) : nullopt;
}

// 设置指定 id 的用户指针
void setUserPointer(int i, void *ptr) {
	std::lock_guard lock(mutex);
	userPointerMap[i] = ptr;
}

// 根据 id 获取 PeerConnection 对象，若不存在则抛出异常
shared_ptr<PeerConnection> getPeerConnection(int id) {
	std::lock_guard lock(mutex);
	if (auto it = peerConnectionMap.find(id); it != peerConnectionMap.end())
		return it->second;
	else
		throw std::invalid_argument("PeerConnection ID does not exist");
}

// 根据 id 获取 DataChannel 对象，若不存在则抛出异常
shared_ptr<DataChannel> getDataChannel(int id) {
	std::lock_guard lock(mutex);
	if (auto it = dataChannelMap.find(id); it != dataChannelMap.end())
		return it->second;
	else
		throw std::invalid_argument("DataChannel ID does not exist");
}

// 根据 id 获取 Track 对象，若不存在则抛出异常
shared_ptr<Track> getTrack(int id) {
	std::lock_guard lock(mutex);
	if (auto it = trackMap.find(id); it != trackMap.end())
		return it->second;
	else
		throw std::invalid_argument("Track ID does not exist");
}

// 添加一个 PeerConnection 对象到全局 peerConnectionMap 中，生成新的 ID 并在 userPointerMap 中建立对应的空指针，返回生成的 ID
int emplacePeerConnection(shared_ptr<PeerConnection> ptr) {
	std::lock_guard lock(mutex);
	int pc = ++lastId;
	peerConnectionMap.emplace(std::make_pair(pc, ptr));
	userPointerMap.emplace(std::make_pair(pc, nullptr));
	return pc;
}

// 添加一个 DataChannel 对象到 dataChannelMap 中，生成新的 ID，并在 userPointerMap 中建立对应的空指针，返回生成的 ID
int emplaceDataChannel(shared_ptr<DataChannel> ptr) {
	std::lock_guard lock(mutex);
	int dc = ++lastId;
	dataChannelMap.emplace(std::make_pair(dc, ptr));
	userPointerMap.emplace(std::make_pair(dc, nullptr));
	return dc;
}

// 添加一个 Track 对象到 trackMap 中，生成新的 ID，并在 userPointerMap 中建立对应的空指针，返回生成的 ID
int emplaceTrack(shared_ptr<Track> ptr) {
	std::lock_guard lock(mutex);
	int tr = ++lastId;
	trackMap.emplace(std::make_pair(tr, ptr));
	userPointerMap.emplace(std::make_pair(tr, nullptr));
	return tr;
}

// 根据 id 删除 PeerConnection 对象，如果不存在则抛出异常，同时在 userPointerMap 中删除对应项
void erasePeerConnection(int pc) {
	std::lock_guard lock(mutex);
	if (peerConnectionMap.erase(pc) == 0)
		throw std::invalid_argument("Peer Connection ID does not exist");
	userPointerMap.erase(pc);
}

// 根据 id 删除 DataChannel 对象，如果不存在则抛出异常，同时在 userPointerMap 中删除对应项
void eraseDataChannel(int dc) {
	std::lock_guard lock(mutex);
	if (dataChannelMap.erase(dc) == 0)
		throw std::invalid_argument("Data Channel ID does not exist");
	userPointerMap.erase(dc);
}

// 根据 id 删除 Track 对象，如果不存在则抛出异常，同时删除与该 id 相关的 userPointerMap 项
// 如果开启媒体支持，还会删除 rtcpSrReporterMap 和 rtpConfigMap 中的对应项
void eraseTrack(int tr) {
	std::lock_guard lock(mutex);
	if (trackMap.erase(tr) == 0)
		throw std::invalid_argument("Track ID does not exist");
#if RTC_ENABLE_MEDIA
	rtcpSrReporterMap.erase(tr);
	rtpConfigMap.erase(tr);
#endif
	userPointerMap.erase(tr);
}

// 删除所有对象，清空所有全局 map，返回删除的总数
size_t eraseAll() {
	std::lock_guard lock(mutex);
	size_t count = dataChannelMap.size() + trackMap.size() + peerConnectionMap.size();
	dataChannelMap.clear();
	trackMap.clear();
	peerConnectionMap.clear();
#if RTC_ENABLE_MEDIA
	count += rtcpSrReporterMap.size() + rtpConfigMap.size();
	rtcpSrReporterMap.clear();
	rtpConfigMap.clear();
#endif
#if RTC_ENABLE_WEBSOCKET
	count += webSocketMap.size() + webSocketServerMap.size();
	webSocketMap.clear();
	webSocketServerMap.clear();
#endif
	userPointerMap.clear();
	return count;
}

// 根据 id 获取一个 Channel 对象。
// 这里 Channel 包括 DataChannel、Track，若启用 WebSocket 则也包括 WebSocket。
// 若 id 未找到，则抛出异常。
shared_ptr<Channel> getChannel(int id) {
	std::lock_guard lock(mutex);
	if (auto it = dataChannelMap.find(id); it != dataChannelMap.end())
		return it->second;
	if (auto it = trackMap.find(id); it != trackMap.end())
		return it->second;
#if RTC_ENABLE_WEBSOCKET
	if (auto it = webSocketMap.find(id); it != webSocketMap.end())
		return it->second;
#endif
	throw std::invalid_argument("DataChannel, Track, or WebSocket ID does not exist");
}

// 删除指定 id 的 Channel 对象。
// 先尝试从 dataChannelMap 中删除，如果未删除则再尝试从 trackMap 中删除，如果开启 WebSocket 支持还会尝试从 webSocketMap 中删除。
// 如果都未找到，则抛出异常。
void eraseChannel(int id) {
	std::lock_guard lock(mutex);
	if (dataChannelMap.erase(id) != 0) {
		userPointerMap.erase(id);
		return;
	}
	if (trackMap.erase(id) != 0) {
		userPointerMap.erase(id);
#if RTC_ENABLE_MEDIA
		rtcpSrReporterMap.erase(id);
		rtpConfigMap.erase(id);
#endif
		return;
	}
#if RTC_ENABLE_WEBSOCKET
	if (webSocketMap.erase(id) != 0) {
		userPointerMap.erase(id);
		return;
	}
#endif
	throw std::invalid_argument("DataChannel, Track, or WebSocket ID does not exist");
}

// 将 string 拷贝到 buffer 中，如果 buffer 为 nullptr，则返回所需空间大小（包括终止符）。
// 如果 buffer 不足，则返回 RTC_ERR_TOO_SMALL，否则返回拷贝的字节数。
int copyAndReturn(string s, char *buffer, int size) {
	if (!buffer)
		return int(s.size() + 1);

	if (size < int(s.size() + 1))
		return RTC_ERR_TOO_SMALL;

	std::copy(s.begin(), s.end(), buffer);
	buffer[s.size()] = '\0';
	return int(s.size() + 1);
}

// 将 binary 数据拷贝到 buffer 中，逻辑与上面的 string 版本类似
int copyAndReturn(binary b, char *buffer, int size) {
	if (!buffer)
		return int(b.size());

	if (size < int(b.size()))
		return RTC_ERR_TOO_SMALL;

	auto data = reinterpret_cast<const char *>(b.data());
	std::copy(data, data + b.size(), buffer);
	return int(b.size());
}

// 模板函数，将 vector 中的元素拷贝到 buffer 中，返回拷贝的元素个数
template <typename T> int copyAndReturn(std::vector<T> b, T *buffer, int size) {
	if (!buffer)
		return int(b.size());

	if (size < int(b.size()))
		return RTC_ERR_TOO_SMALL;
	std::copy(b.begin(), b.end(), buffer);
	return int(b.size());
}

// wrap 函数包装器，用于捕获异常，并返回对应的错误码。
// 如果 func() 抛出 std::invalid_argument 则返回 RTC_ERR_INVALID；抛出其他异常返回 RTC_ERR_FAILURE。
template <typename F> int wrap(F func) {
	try {
		return int(func());

	} catch (const std::invalid_argument &e) {
		std::cout << "xy: wrap error!" << e.what() << std::endl;
		PLOG_ERROR << e.what();
		return RTC_ERR_INVALID;
	} catch (const std::exception &e) {
		PLOG_ERROR << e.what();
		std::cout << "xy: wrap error!" << e.what() << std::endl;
		return RTC_ERR_FAILURE;
	}
}

#if RTC_ENABLE_MEDIA

// lowercased: 将字符串全部转换为小写
string lowercased(string str) {
	std::transform(str.begin(), str.end(), str.begin(),
	               [](unsigned char c) { return std::tolower(c); });
	return str;
}

// 获取指定 id 的 RTCP SR Reporter 对象，如果不存在则抛出异常
shared_ptr<RtcpSrReporter> getRtcpSrReporter(int id) {
	std::lock_guard lock(mutex);
	if (auto it = rtcpSrReporterMap.find(id); it != rtcpSrReporterMap.end()) {
		return it->second;
	} else {
		throw std::invalid_argument("RTCP SR reporter ID does not exist");
	}
}

// 将 RTCP SR Reporter 对象插入到 rtcpSrReporterMap 中，key 为 tr（Track ID）
void emplaceRtcpSrReporter(shared_ptr<RtcpSrReporter> ptr, int tr) {
	std::lock_guard lock(mutex);
	rtcpSrReporterMap.emplace(std::make_pair(tr, ptr));
}

// 获取指定 id 的 RTP Packetization 配置对象，如果不存在则抛出异常
shared_ptr<RtpPacketizationConfig> getRtpConfig(int id) {
	std::lock_guard lock(mutex);
	if (auto it = rtpConfigMap.find(id); it != rtpConfigMap.end()) {
		return it->second;
	} else {
		throw std::invalid_argument("RTP configuration ID does not exist");
	}
}

// 将 RTP Packetization 配置对象插入到 rtpConfigMap 中，key 为 tr（Track ID）
void emplaceRtpConfig(shared_ptr<RtpPacketizationConfig> ptr, int tr) {
	std::lock_guard lock(mutex);
	rtpConfigMap.emplace(std::make_pair(tr, ptr));
}

// createRtpPacketizationConfig: 根据 rtcPacketizationHandlerInit 创建 RTP Packetization 配置对象
shared_ptr<RtpPacketizationConfig>
createRtpPacketizationConfig(const rtcPacketizationHandlerInit *init) {
	if (!init)
		throw std::invalid_argument("Unexpected null pointer for packetization handler init");

	if (!init->cname)
		throw std::invalid_argument("Unexpected null pointer for cname");

	auto config = std::make_shared<RtpPacketizationConfig>(init->ssrc, init->cname,
	                                                       init->payloadType, init->clockRate);
	config->sequenceNumber = init->sequenceNumber;
	config->timestamp = init->timestamp;
	config->playoutDelayId = init->playoutDelayId;
	config->playoutDelayMin = init->playoutDelayMin;
	config->playoutDelayMax = init->playoutDelayMax;
	return config;
}

// MediaInterceptor 类是 MediaHandler 的最终实现，用于拦截并处理来自远端的媒体数据。
// 它通过传入的回调 incomingCallback 处理每个收到的消息，允许用户自定义媒体处理逻辑。
class MediaInterceptor final : public MediaHandler {
public:
	using MessageCallback = std::function<void *(void *data, int size)>;

	MediaInterceptor(MessageCallback cb) : incomingCallback(cb) {}

	// 当远端有媒体数据到达时调用此方法
	void incoming(message_vector &messages,
	              [[maybe_unused]] const message_callback &send) override {
		// 如果没有设置回调，则直接不做处理
		if (!incomingCallback)
			return;

		message_vector result;
		for (auto &msg : messages) {
			// 调用用户回调处理数据，返回处理后的数据指针
			auto res = incomingCallback(reinterpret_cast<void *>(msg->data()), int(msg->size()));

			// 如果回调返回空，则丢弃该消息
			if (!res)
				continue;

			if (res == msg->data()) {
				// 如果回调返回原始数据，则直接转发该消息
				result.push_back(std::move(msg));
			} else {
				// 否则根据返回的 opaque 指针构造新的消息对象
				result.push_back(
				    make_message_from_opaque_ptr(std::move(reinterpret_cast<rtcMessage *>(res))));
			}
		}
	}

private:
	MessageCallback incomingCallback;
};

#endif // RTC_ENABLE_MEDIA

#if RTC_ENABLE_WEBSOCKET

// getWebSocket: 根据 id 获取 WebSocket 对象，若不存在则抛出异常
shared_ptr<WebSocket> getWebSocket(int id) {
	std::lock_guard lock(mutex);
	if (auto it = webSocketMap.find(id); it != webSocketMap.end())
		return it->second;
	else
		throw std::invalid_argument("WebSocket ID does not exist");
}

// emplaceWebSocket: 插入 WebSocket 对象到全局 map，并生成唯一 id，同时在 userPointerMap 中建立对应项
int emplaceWebSocket(shared_ptr<WebSocket> ptr) {
	std::lock_guard lock(mutex);
	int ws = ++lastId;
	webSocketMap.emplace(std::make_pair(ws, ptr));
	userPointerMap.emplace(std::make_pair(ws, nullptr));
	return ws;
}

// eraseWebSocket: 根据 id 删除 WebSocket 对象，不存在则抛出异常，同时删除 userPointerMap 中对应项
void eraseWebSocket(int ws) {
	std::lock_guard lock(mutex);
	if (webSocketMap.erase(ws) == 0)
		throw std::invalid_argument("WebSocket ID does not exist");
	userPointerMap.erase(ws);
}

// getWebSocketServer: 根据 id 获取 WebSocketServer 对象，若不存在则抛出异常
shared_ptr<WebSocketServer> getWebSocketServer(int id) {
	std::lock_guard lock(mutex);
	if (auto it = webSocketServerMap.find(id); it != webSocketServerMap.end())
		return it->second;
	else
		throw std::invalid_argument("WebSocketServer ID does not exist");
}

// emplaceWebSocketServer: 插入 WebSocketServer 对象到全局 map，并生成唯一 id，同时在 userPointerMap 中建立对应项
int emplaceWebSocketServer(shared_ptr<WebSocketServer> ptr) {
	std::lock_guard lock(mutex);
	int wsserver = ++lastId;
	webSocketServerMap.emplace(std::make_pair(wsserver, ptr));
	userPointerMap.emplace(std::make_pair(wsserver, nullptr));
	return wsserver;
}

// eraseWebSocketServer: 根据 id 删除 WebSocketServer 对象，不存在则抛出异常，同时删除 userPointerMap 中对应项
void eraseWebSocketServer(int wsserver) {
	std::lock_guard lock(mutex);
	if (webSocketServerMap.erase(wsserver) == 0)
		throw std::invalid_argument("WebSocketServer ID does not exist");
	userPointerMap.erase(wsserver);
}

#endif

} // namespace

// rtcInitLogger: 初始化日志系统，设置日志级别及回调函数（转换为内部 LogCallback 格式）
void rtcInitLogger(rtcLogLevel level, rtcLogCallbackFunc cb) {
	LogCallback callback = nullptr;
	if (cb)
		callback = [cb](LogLevel level, string message) {
			cb(static_cast<rtcLogLevel>(level), message.c_str());
		};

	InitLogger(static_cast<LogLevel>(level), callback);
}

// rtcSetUserPointer: 设置指定 id 的用户指针（封装 setUserPointer 函数）
void rtcSetUserPointer(int i, void *ptr) { setUserPointer(i, ptr); }

// rtcGetUserPointer: 获取指定 id 的用户指针，返回 nullptr 表示不存在
void *rtcGetUserPointer(int i) { return getUserPointer(i).value_or(nullptr); }

// rtcCreatePeerConnection: 根据 rtcConfiguration 创建一个 PeerConnection 对象，并返回生成的唯一 ID。
// 内部将 rtcConfiguration 转换为 Configuration 类型后创建 PeerConnection 对象，并调用 emplacePeerConnection 存储。
int rtcCreatePeerConnection(const rtcConfiguration *config) {
	return wrap([config] {
		Configuration c;
		for (int i = 0; i < config->iceServersCount; ++i)
			c.iceServers.emplace_back(string(config->iceServers[i]));

		if (config->proxyServer)
			c.proxyServer.emplace(config->proxyServer);

		if (config->bindAddress)
			c.bindAddress = string(config->bindAddress);

		if (config->portRangeBegin > 0 || config->portRangeEnd > 0) {
			c.portRangeBegin = config->portRangeBegin;
			c.portRangeEnd = config->portRangeEnd;
		}

		c.certificateType = static_cast<CertificateType>(config->certificateType);
		c.iceTransportPolicy = static_cast<TransportPolicy>(config->iceTransportPolicy);
		c.enableIceTcp = config->enableIceTcp;
		c.enableIceUdpMux = config->enableIceUdpMux;
		c.disableAutoNegotiation = config->disableAutoNegotiation;
		c.forceMediaTransport = config->forceMediaTransport;

		if (config->mtu > 0)
			c.mtu = size_t(config->mtu);

		if (config->maxMessageSize)
			c.maxMessageSize = size_t(config->maxMessageSize);

		return emplacePeerConnection(std::make_shared<PeerConnection>(std::move(c)));
	});
}

// rtcClosePeerConnection: 关闭指定 ID 的 PeerConnection 对象
int rtcClosePeerConnection(int pc) {
	return wrap([pc] {
		auto peerConnection = getPeerConnection(pc);
		peerConnection->close();
		return RTC_ERR_SUCCESS;
	});
}

// rtcDeletePeerConnection: 删除指定 ID 的 PeerConnection 对象（先关闭再删除）
int rtcDeletePeerConnection(int pc) {
	return wrap([pc] {
		auto peerConnection = getPeerConnection(pc);
		peerConnection->close();
		erasePeerConnection(pc);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetLocalDescriptionCallback: 设置本地描述回调函数
int rtcSetLocalDescriptionCallback(int pc, rtcDescriptionCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onLocalDescription([pc, cb](Description desc) {
				if (auto ptr = getUserPointer(pc))
					cb(pc, string(desc).c_str(), desc.typeString().c_str(), *ptr);
			});
		else
			peerConnection->onLocalDescription(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetLocalCandidateCallback: 设置本地候选回调函数
int rtcSetLocalCandidateCallback(int pc, rtcCandidateCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onLocalCandidate([pc, cb](Candidate cand) {
				if (auto ptr = getUserPointer(pc))
					cb(pc, cand.candidate().c_str(), cand.mid().c_str(), *ptr);
			});
		else
			peerConnection->onLocalCandidate(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetStateChangeCallback: 设置 PeerConnection 状态变化回调函数
int rtcSetStateChangeCallback(int pc, rtcStateChangeCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onStateChange([pc, cb](PeerConnection::State state) {
				if (auto ptr = getUserPointer(pc))
					cb(pc, static_cast<rtcState>(state), *ptr);
			});
		else
			peerConnection->onStateChange(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetIceStateChangeCallback: 设置 ICE 状态变化回调函数
int rtcSetIceStateChangeCallback(int pc, rtcIceStateChangeCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onIceStateChange([pc, cb](PeerConnection::IceState state) {
				if (auto ptr = getUserPointer(pc))
					cb(pc, static_cast<rtcIceState>(state), *ptr);
			});
		else
			peerConnection->onIceStateChange(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetGatheringStateChangeCallback: 设置候选收集状态变化回调函数
int rtcSetGatheringStateChangeCallback(int pc, rtcGatheringStateCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onGatheringStateChange([pc, cb](PeerConnection::GatheringState state) {
				if (auto ptr = getUserPointer(pc))
					cb(pc, static_cast<rtcGatheringState>(state), *ptr);
			});
		else
			peerConnection->onGatheringStateChange(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetSignalingStateChangeCallback: 设置信令状态变化回调函数
int rtcSetSignalingStateChangeCallback(int pc, rtcSignalingStateCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onSignalingStateChange([pc, cb](PeerConnection::SignalingState state) {
				if (auto ptr = getUserPointer(pc))
					cb(pc, static_cast<rtcSignalingState>(state), *ptr);
			});
		else
			peerConnection->onSignalingStateChange(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetDataChannelCallback: 设置数据通道创建回调函数，当新的 DataChannel 被创建时触发
int rtcSetDataChannelCallback(int pc, rtcDataChannelCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onDataChannel([pc, cb](shared_ptr<DataChannel> dataChannel) {
				int dc = emplaceDataChannel(dataChannel);
				if (auto ptr = getUserPointer(pc)) {
					rtcSetUserPointer(dc, *ptr);
					cb(pc, dc, *ptr);
				}
			});
		else
			peerConnection->onDataChannel(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetTrackCallback: 设置媒体轨道（Track）创建回调函数，当新的 Track 被创建时触发
int rtcSetTrackCallback(int pc, rtcTrackCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		if (cb)
			peerConnection->onTrack([pc, cb](shared_ptr<Track> track) {
				int tr = emplaceTrack(track);
				if (auto ptr = getUserPointer(pc)) {
					rtcSetUserPointer(tr, *ptr);
					cb(pc, tr, *ptr);
				}
			});
		else
			peerConnection->onTrack(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetLocalDescription: 设置本地描述，参数 type 用于指定描述类型
int rtcSetLocalDescription(int pc, const char *type) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		peerConnection->setLocalDescription(type ? Description::stringToType(type)
		                                         : Description::Type::Unspec);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetRemoteDescription: 设置远端描述，参数 sdp 为 SDP 字符串，type 为描述类型字符串（可选）
int rtcSetRemoteDescription(int pc, const char *sdp, const char *type) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (!sdp)
			throw std::invalid_argument("Unexpected null pointer for remote description");

		peerConnection->setRemoteDescription({string(sdp), type ? string(type) : ""});
		return RTC_ERR_SUCCESS;
	});
}

// rtcAddRemoteCandidate: 添加远端候选，参数 cand 为候选 SDP 字符串，mid 为媒体标识（可选）
int rtcAddRemoteCandidate(int pc, const char *cand, const char *mid) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (!cand)
			throw std::invalid_argument("Unexpected null pointer for remote candidate");

		peerConnection->addRemoteCandidate({string(cand), mid ? string(mid) : ""});
		return RTC_ERR_SUCCESS;
	});
}

// rtcGetLocalDescription: 获取本地描述，拷贝到 buffer 中，返回拷贝的字节数或错误码
int rtcGetLocalDescription(int pc, char *buffer, int size) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (auto desc = peerConnection->localDescription())
			return copyAndReturn(string(*desc), buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcGetRemoteDescription: 获取远端描述，拷贝到 buffer 中，返回拷贝的字节数或错误码
int rtcGetRemoteDescription(int pc, char *buffer, int size) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (auto desc = peerConnection->remoteDescription())
			return copyAndReturn(string(*desc), buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcGetLocalDescriptionType: 获取本地描述的类型字符串
int rtcGetLocalDescriptionType(int pc, char *buffer, int size) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (auto desc = peerConnection->localDescription())
			return copyAndReturn(desc->typeString(), buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcGetRemoteDescriptionType: 获取远端描述的类型字符串
int rtcGetRemoteDescriptionType(int pc, char *buffer, int size) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (auto desc = peerConnection->remoteDescription())
			return copyAndReturn(desc->typeString(), buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcGetLocalAddress: 获取本地地址描述
int rtcGetLocalAddress(int pc, char *buffer, int size) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (auto addr = peerConnection->localAddress())
			return copyAndReturn(std::move(*addr), buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcGetRemoteAddress: 获取远端地址描述
int rtcGetRemoteAddress(int pc, char *buffer, int size) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (auto addr = peerConnection->remoteAddress())
			return copyAndReturn(std::move(*addr), buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcGetSelectedCandidatePair: 获取当前选中的候选对（本地和远端候选），拷贝到 local 和 remote 参数中
int rtcGetSelectedCandidatePair(int pc, char *local, int localSize, char *remote, int remoteSize) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		Candidate localCand;
		Candidate remoteCand;
		if (!peerConnection->getSelectedCandidatePair(&localCand, &remoteCand))
			return RTC_ERR_NOT_AVAIL;

		int localRet = copyAndReturn(string(localCand), local, localSize);
		if (localRet < 0)
			return localRet;

		int remoteRet = copyAndReturn(string(remoteCand), remote, remoteSize);
		if (remoteRet < 0)
			return remoteRet;

		return std::max(localRet, remoteRet);
	});
}

// rtcIsNegotiationNeeded: 检查当前 PeerConnection 是否需要重新协商，返回 true 或 false
bool rtcIsNegotiationNeeded(int pc) {
	return wrap([&] { return getPeerConnection(pc)->negotiationNeeded() ? 0 : 1; }) == 0 ? true
	                                                                                     : false;
}

// rtcGetMaxDataChannelStream: 获取当前 PeerConnection 可用的最大数据通道编号
int rtcGetMaxDataChannelStream(int pc) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		return int(peerConnection->maxDataChannelId());
	});
}

// rtcGetRemoteMaxMessageSize: 获取远端最大消息尺寸
int rtcGetRemoteMaxMessageSize(int pc) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);
		return int(peerConnection->remoteMaxMessageSize());
	});
}

// rtcSetOpenCallback: 设置指定 id 的 Channel 打开回调，回调会在通道打开时被调用
int rtcSetOpenCallback(int id, rtcOpenCallbackFunc cb) {
	return wrap([&] {
		auto channel = getChannel(id);
		if (cb)
			channel->onOpen([id, cb]() {
				if (auto ptr = getUserPointer(id))
					cb(id, *ptr);
			});
		else
			channel->onOpen(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetClosedCallback: 设置指定 id 的 Channel 关闭回调，回调会在通道关闭时被调用
int rtcSetClosedCallback(int id, rtcClosedCallbackFunc cb) {
	return wrap([&] {
		auto channel = getChannel(id);
		if (cb)
			channel->onClosed([id, cb]() {
				if (auto ptr = getUserPointer(id))
					cb(id, *ptr);
			});
		else
			channel->onClosed(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetErrorCallback: 设置指定 id 的 Channel 错误回调，回调会在发生错误时被调用
int rtcSetErrorCallback(int id, rtcErrorCallbackFunc cb) {
	return wrap([&] {
		auto channel = getChannel(id);
		if (cb)
			channel->onError([id, cb](string error) {
				if (auto ptr = getUserPointer(id))
					cb(id, error.c_str(), *ptr);
			});
		else
			channel->onError(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetMessageCallback: 设置指定 id 的 Channel 消息回调，收到数据时调用回调，回调参数包含数据及其长度
int rtcSetMessageCallback(int id, rtcMessageCallbackFunc cb) {
	return wrap([&] {
		auto channel = getChannel(id);
		if (cb)
			channel->onMessage(
			    [id, cb](binary b) {
				    if (auto ptr = getUserPointer(id))
					    cb(id, reinterpret_cast<const char *>(b.data()), int(b.size()), *ptr);
			    },
			    [id, cb](string s) {
				    if (auto ptr = getUserPointer(id))
					    cb(id, s.c_str(), -int(s.size() + 1), *ptr);
			    });
		else
			channel->onMessage(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSendMessage: 发送消息到指定 id 的 Channel。如果 size 为正，则以 binary 数据发送；若为负则以字符串发送。
int rtcSendMessage(int id, const char *data, int size) {
	return wrap([&] {
		auto channel = getChannel(id);

		if (!data && size != 0)
			throw std::invalid_argument("Unexpected null pointer for data");

		if (size >= 0) {
			auto b = reinterpret_cast<const byte *>(data);
			channel->send(binary(b, b + size));
		} else {
			channel->send(string(data));
		}
		return RTC_ERR_SUCCESS;
	});
}

// rtcClose: 关闭指定 id 的 Channel
int rtcClose(int id) {
	return wrap([&] {
		auto channel = getChannel(id);
		channel->close();
		return RTC_ERR_SUCCESS;
	});
}

// rtcDelete: 删除指定 id 的 Channel（关闭后移除）
int rtcDelete(int id) {
	return wrap([id] {
		auto channel = getChannel(id);
		channel->close();
		eraseChannel(id);
		return RTC_ERR_SUCCESS;
	});
}

// rtcIsOpen: 检查指定 id 的 Channel 是否处于打开状态
bool rtcIsOpen(int id) {
	return wrap([id] { return getChannel(id)->isOpen() ? 0 : 1; }) == 0 ? true : false;
}

// rtcIsClosed: 检查指定 id 的 Channel 是否处于关闭状态
bool rtcIsClosed(int id) {
	return wrap([id] { return getChannel(id)->isClosed() ? 0 : 1; }) == 0 ? true : false;
}

// rtcMaxMessageSize: 获取指定 id 的 Channel 最大支持消息大小
int rtcMaxMessageSize(int id) {
	return wrap([id] {
		auto channel = getChannel(id);
		return int(channel->maxMessageSize());
	});
}

// rtcGetBufferedAmount: 获取指定 id 的 Channel 当前待发送数据的缓冲量
int rtcGetBufferedAmount(int id) {
	return wrap([id] {
		auto channel = getChannel(id);
		return int(channel->bufferedAmount());
	});
}

// rtcSetBufferedAmountLowThreshold: 设置指定 id 的 Channel 的低缓冲阈值
int rtcSetBufferedAmountLowThreshold(int id, int amount) {
	return wrap([&] {
		auto channel = getChannel(id);
		channel->setBufferedAmountLowThreshold(size_t(amount));
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetBufferedAmountLowCallback: 设置指定 id 的 Channel 低缓冲回调函数
int rtcSetBufferedAmountLowCallback(int id, rtcBufferedAmountLowCallbackFunc cb) {
	return wrap([&] {
		auto channel = getChannel(id);
		if (cb)
			channel->onBufferedAmountLow([id, cb]() {
				if (auto ptr = getUserPointer(id))
					cb(id, *ptr);
			});
		else
			channel->onBufferedAmountLow(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcGetAvailableAmount: 获取指定 id 的 Channel 可用发送缓冲量
int rtcGetAvailableAmount(int id) {
	return wrap([id] { return int(getChannel(id)->availableAmount()); });
}

// rtcSetAvailableCallback: 设置指定 id 的 Channel 可用缓冲区变化回调函数
int rtcSetAvailableCallback(int id, rtcAvailableCallbackFunc cb) {
	return wrap([&] {
		auto channel = getChannel(id);
		if (cb)
			channel->onAvailable([id, cb]() {
				if (auto ptr = getUserPointer(id))
					cb(id, *ptr);
			});
		else
			channel->onAvailable(nullptr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcReceiveMessage: 从指定 id 的 Channel 接收一条消息，拷贝数据到 buffer，并更新 size 参数。
// 如果消息是 binary，则 size 为正；如果是 string，则 size 为负。
int rtcReceiveMessage(int id, char *buffer, int *size) {
	return wrap([&] {
		auto channel = getChannel(id);

		if (!size)
			throw std::invalid_argument("Unexpected null pointer for size");

		*size = std::abs(*size);

		// peek() 查看队列头部的消息，但不移除；若为空则返回 RTC_ERR_NOT_AVAIL
		auto message = channel->peek();
		if (!message)
			return RTC_ERR_NOT_AVAIL;

		// 根据消息的实际类型（binary 或 string）拷贝数据到 buffer
		return std::visit( //
		    overloaded{
		        [&](binary b) {
			        int ret = copyAndReturn(std::move(b), buffer, *size);
			        if (ret >= 0) {
				        *size = ret;
				        if (buffer) {
					        channel->receive(); // 移除该消息
				        }

				        return RTC_ERR_SUCCESS;
			        } else {
				        *size = int(b.size());
				        return ret;
			        }
		        },
		        [&](string s) {
			        int ret = copyAndReturn(std::move(s), buffer, *size);
			        if (ret >= 0) {
				        *size = -ret; // 负值表示字符串
				        if (buffer) {
					        channel->receive(); // 移除该消息
				        }

				        return RTC_ERR_SUCCESS;
			        } else {
				        *size = -int(s.size() + 1);
				        return ret;
			        }
		        },
		    },
		    *message);
	});
}

// rtcCreateDataChannel: 创建一个数据通道，调用 rtcCreateDataChannelEx，默认 init 参数为 nullptr
int rtcCreateDataChannel(int pc, const char *label) {
	return rtcCreateDataChannelEx(pc, label, nullptr);
}

// rtcCreateDataChannelEx: 根据指定 PeerConnection ID、label 及初始化参数创建数据通道，并返回生成的唯一数据通道 ID。
// 内部将 rtcDataChannelInit 转换为 DataChannelInit 后调用 PeerConnection::createDataChannel 生成 DataChannel 对象。
int rtcCreateDataChannelEx(int pc, const char *label, const rtcDataChannelInit *init) {
	return wrap([&] {
		DataChannelInit dci = {};
		if (init) {
			auto *reliability = &init->reliability;
			dci.reliability.unordered = reliability->unordered;
			if (reliability->unreliable) {
				if (reliability->maxPacketLifeTime > 0)
					dci.reliability.maxPacketLifeTime.emplace(milliseconds(reliability->maxPacketLifeTime));
				else
					dci.reliability.maxRetransmits.emplace(reliability->maxRetransmits);
			}

			dci.negotiated = init->negotiated;
			dci.id = init->manualStream ? std::make_optional(init->stream) : nullopt;
			dci.protocol = init->protocol ? init->protocol : "";
		}

		auto peerConnection = getPeerConnection(pc);
		int dc = emplaceDataChannel(
		    peerConnection->createDataChannel(string(label ? label : ""), std::move(dci)));

		if (auto ptr = getUserPointer(pc))
			rtcSetUserPointer(dc, *ptr);

		return dc;
	});
}

// 删除指定 ID 的 DataChannel 对象：先关闭该数据通道，再从全局 dataChannelMap 中移除对应项
int rtcDeleteDataChannel(int dc) {
	// 使用 wrap 包装以捕获异常并统一返回错误码
	return wrap([dc] {
		auto dataChannel = getDataChannel(dc);
		dataChannel->close();
		eraseDataChannel(dc);
		return RTC_ERR_SUCCESS;
	});
}

// 获取指定 DataChannel 对象的流号（stream ID），如果未设置则返回 RTC_ERR_NOT_AVAIL
int rtcGetDataChannelStream(int dc) {
	return wrap([dc] {
		auto dataChannel = getDataChannel(dc);
		if (auto stream = dataChannel->stream())
			return int(*stream);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// 获取指定 DataChannel 的标签（label），拷贝到 buffer 中
int rtcGetDataChannelLabel(int dc, char *buffer, int size) {
	return wrap([&] {
		auto dataChannel = getDataChannel(dc);
		return copyAndReturn(dataChannel->label(), buffer, size);
	});
}

// 获取指定 DataChannel 的协议（protocol），拷贝到 buffer 中
int rtcGetDataChannelProtocol(int dc, char *buffer, int size) {
	return wrap([&] {
		auto dataChannel = getDataChannel(dc);
		return copyAndReturn(dataChannel->protocol(), buffer, size);
	});
}

// 获取指定 DataChannel 的可靠性设置，填充 rtcReliability 结构
int rtcGetDataChannelReliability(int dc, rtcReliability *reliability) {
	return wrap([&] {
		auto dataChannel = getDataChannel(dc);

		if (!reliability)
			throw std::invalid_argument("Unexpected null pointer for reliability");

		Reliability dcr = dataChannel->reliability();
		std::memset(reliability, 0, sizeof(*reliability));
		reliability->unordered = dcr.unordered;
		if(dcr.maxPacketLifeTime) {
			reliability->unreliable = true;
			reliability->maxPacketLifeTime = static_cast<unsigned int>(dcr.maxPacketLifeTime->count());
		} else if (dcr.maxRetransmits) {
			reliability->unreliable = true;
			reliability->maxRetransmits = *dcr.maxRetransmits;
		} else {
			reliability->unreliable = false;
		}
		return RTC_ERR_SUCCESS;
	});
}

// 添加一个媒体轨道（Track）到指定 PeerConnection 中，传入的 mediaDescriptionSdp 为媒体描述 SDP 字符串
int rtcAddTrack(int pc, const char *mediaDescriptionSdp) {
	return wrap([&] {
		if (!mediaDescriptionSdp)
			throw std::invalid_argument("Unexpected null pointer for track media description");

		auto peerConnection = getPeerConnection(pc);
		Description::Media media{string(mediaDescriptionSdp)};
		int tr = emplaceTrack(peerConnection->addTrack(std::move(media)));
		if (auto ptr = getUserPointer(pc))
			rtcSetUserPointer(tr, *ptr);

		return tr;
	});
}

// 添加 Track 的扩展接口，根据 rtcTrackInit 初始化参数创建 Track 对象
int rtcAddTrackEx(int pc, const rtcTrackInit *init) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (!init)
			throw std::invalid_argument("Unexpected null pointer for track init");

		// 根据 init->direction 设置媒体轨道的方向
		auto direction = static_cast<Description::Direction>(init->direction);

		// 如果提供了 mid，则使用；否则根据 codec 类型自动指定 "video" 或 "audio"
		string mid;
		if (init->mid) {
			mid = string(init->mid);
		} else {
			switch (init->codec) {
			case RTC_CODEC_AV1:
			case RTC_CODEC_H264:
			case RTC_CODEC_H265:
			case RTC_CODEC_VP8:
			case RTC_CODEC_VP9:
				mid = "video";
				break;
			case RTC_CODEC_OPUS:
			case RTC_CODEC_PCMU:
			case RTC_CODEC_PCMA:
			case RTC_CODEC_AAC:
				mid = "audio";
				break;
			default:
				mid = "video";
				break;
			}
		}

		int pt = init->payloadType;
		// 若提供 profile，则封装为 optional，否则为 nullopt
		auto profile = init->profile ? std::make_optional(string(init->profile)) : nullopt;

		unique_ptr<Description::Media> description;
		switch (init->codec) {
		// 针对视频编解码器，创建 Video 类型的媒体描述
		case RTC_CODEC_AV1:
		case RTC_CODEC_H264:
		case RTC_CODEC_H265:
		case RTC_CODEC_VP8:
		case RTC_CODEC_VP9: {
			auto video = std::make_unique<Description::Video>(mid, direction);
			switch (init->codec) {
			case RTC_CODEC_AV1:
				video->addAV1Codec(pt, profile);
				break;
			case RTC_CODEC_H264:
				video->addH264Codec(pt, profile);
				break;
			case RTC_CODEC_H265:
				video->addH265Codec(pt, profile);
				break;
			case RTC_CODEC_VP8:
				video->addVP8Codec(pt, profile);
				break;
			case RTC_CODEC_VP9:
				video->addVP9Codec(pt, profile);
				break;
			default:
				break;
			}
			description = std::move(video);
			break;
		}
		// 针对音频编解码器，创建 Audio 类型的媒体描述
		case RTC_CODEC_OPUS:
		case RTC_CODEC_PCMU:
		case RTC_CODEC_PCMA:
		case RTC_CODEC_AAC: {
			auto audio = std::make_unique<Description::Audio>(mid, direction);
			switch (init->codec) {
			case RTC_CODEC_OPUS:
				audio->addOpusCodec(pt, profile);
				break;
			case RTC_CODEC_PCMU:
				audio->addPCMUCodec(pt, profile);
				break;
			case RTC_CODEC_PCMA:
				audio->addPCMACodec(pt, profile);
				break;
			case RTC_CODEC_AAC:
				audio->addAACCodec(pt, profile);
				break;
			default:
				break;
			}
			description = std::move(audio);
			break;
		}
		default:
			break;
		}

		if (!description)
			throw std::invalid_argument("Unexpected codec");

		// 添加 SSRC 以及其他标识信息到媒体描述中
		description->addSSRC(init->ssrc,
		                     init->name ? std::make_optional(string(init->name)) : nullopt,
		                     init->msid ? std::make_optional(string(init->msid)) : nullopt,
		                     init->trackId ? std::make_optional(string(init->trackId)) : nullopt);

		// 添加 Track 到 PeerConnection 中，并保存生成的 Track ID
		int tr = emplaceTrack(peerConnection->addTrack(std::move(*description)));

		if (auto ptr = getUserPointer(pc))
			rtcSetUserPointer(tr, *ptr);

		return tr;
	});
}

// 删除指定 ID 的 Track 对象，先关闭该 Track，再从全局 trackMap 中移除
int rtcDeleteTrack(int tr) {
	return wrap([&] {
		auto track = getTrack(tr);
		track->close();
		eraseTrack(tr);
		return RTC_ERR_SUCCESS;
	});
}

// 获取指定 Track 的媒体描述，拷贝到 buffer 中
int rtcGetTrackDescription(int tr, char *buffer, int size) {
	return wrap([&] {
		auto track = getTrack(tr);
		return copyAndReturn(track->description(), buffer, size);
	});
}

// 获取指定 Track 的媒体标识（MID），拷贝到 buffer 中
int rtcGetTrackMid(int tr, char *buffer, int size) {
	return wrap([&] {
		auto track = getTrack(tr);
		return copyAndReturn(track->mid(), buffer, size);
	});
}

// 获取指定 Track 的方向，存入 direction 参数
int rtcGetTrackDirection(int tr, rtcDirection *direction) {
	return wrap([&] {
		if (!direction)
			throw std::invalid_argument("Unexpected null pointer for track direction");

		auto track = getTrack(tr);
		*direction = static_cast<rtcDirection>(track->direction());
		return RTC_ERR_SUCCESS;
	});
}

// 请求指定 Track 发送关键帧（keyframe），用于视频流场景
int rtcRequestKeyframe(int tr) {
	return wrap([&] {
		auto track = getTrack(tr);
		track->requestKeyframe();
		return RTC_ERR_SUCCESS;
	});
}

// 请求指定 Track 调整比特率，参数 bitrate 指定新的比特率
int rtcRequestBitrate(int tr, unsigned int bitrate) {
	return wrap([&] {
		auto track = getTrack(tr);
		track->requestBitrate(bitrate);
		return RTC_ERR_SUCCESS;
	});
}

#if RTC_ENABLE_MEDIA

// setSSRC: 辅助函数，将 SSRC 和可选的 cname、msid、trackID 添加到媒体描述中
void setSSRC(Description::Media *description, uint32_t ssrc, const char *_name, const char *_msid,
             const char *_trackID) {

	optional<string> name = nullopt;
	if (_name) {
		name = string(_name);
	}

	optional<string> msid = nullopt;
	if (_msid) {
		msid = string(_msid);
	}

	optional<string> trackID = nullopt;
	if (_trackID) {
		trackID = string(_trackID);
	}

	description->addSSRC(ssrc, name, msid, trackID);
}

// rtcCreateOpaqueMessage: 根据数据和大小创建一个不透明的消息对象（rtcMessage 类型），返回其指针
rtcMessage *rtcCreateOpaqueMessage(void *data, int size) {
	auto src = reinterpret_cast<std::byte *>(data);
	auto msg = new Message(src, src + size);
	// 降级转换为不透明 rtcMessage* 类型返回
	return reinterpret_cast<rtcMessage *>(msg);
}

// rtcDeleteOpaqueMessage: 释放由 rtcCreateOpaqueMessage 创建的不透明消息对象
void rtcDeleteOpaqueMessage(rtcMessage *msg) {
	// 先转换回真正的 Message* 类型再删除
	delete reinterpret_cast<Message *>(msg);
}

// rtcSetMediaInterceptorCallback: 设置媒体拦截回调，用于拦截并处理来自远端的媒体数据
int rtcSetMediaInterceptorCallback(int pc, rtcInterceptorCallbackFunc cb) {
	return wrap([&] {
		auto peerConnection = getPeerConnection(pc);

		if (cb == nullptr) {
			peerConnection->setMediaHandler(nullptr);
			return RTC_ERR_SUCCESS;
		}

		auto interceptor = std::make_shared<MediaInterceptor>([pc, cb](void *data, int size) {
			if (auto ptr = getUserPointer(pc))
				return cb(pc, reinterpret_cast<const char *>(data), size, *ptr);
			return data;
		});

		peerConnection->setMediaHandler(interceptor);

		return RTC_ERR_SUCCESS;
	});
}

// rtcSetH264Packetizer: 为指定 Track 设置 H264 的 RTP 封包器，传入 rtcPacketizerInit 初始化参数
int rtcSetH264Packetizer(int tr, const rtcPacketizerInit *init) {
	return wrap([&] {
		auto track = getTrack(tr);
		// 创建 RTP 配置
		auto rtpConfig = createRtpPacketizationConfig(init);
		emplaceRtpConfig(rtpConfig, tr);
		// 创建 H264 封包器，设置 NAL 分隔符及最大分片大小
		auto nalSeparator = init ? init->nalSeparator : RTC_NAL_SEPARATOR_LENGTH;
		auto maxFragmentSize = init && init->maxFragmentSize ? init->maxFragmentSize
		                                                     : RTC_DEFAULT_MAX_FRAGMENT_SIZE;
		auto packetizer = std::make_shared<H264RtpPacketizer>(
		    static_cast<rtc::NalUnit::Separator>(nalSeparator), rtpConfig, maxFragmentSize);
		track->setMediaHandler(packetizer);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetH265Packetizer: 为指定 Track 设置 H265 的 RTP 封包器
int rtcSetH265Packetizer(int tr, const rtcPacketizerInit *init) {
	return wrap([&] {
		auto track = getTrack(tr);
		// 创建 RTP 配置
		auto rtpConfig = createRtpPacketizationConfig(init);
		// 创建 H265 封包器
		auto nalSeparator = init ? init->nalSeparator : RTC_NAL_SEPARATOR_LENGTH;
		auto maxFragmentSize = init && init->maxFragmentSize ? init->maxFragmentSize
		                                                     : RTC_DEFAULT_MAX_FRAGMENT_SIZE;
		auto packetizer = std::make_shared<H265RtpPacketizer>(
		    static_cast<rtc::NalUnit::Separator>(nalSeparator), rtpConfig, maxFragmentSize);
		track->setMediaHandler(packetizer);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetAV1Packetizer: 为指定 Track 设置 AV1 的 RTP 封包器
int rtcSetAV1Packetizer(int tr, const rtcPacketizerInit *init) {
	return wrap([&] {
		auto track = getTrack(tr);
		// 创建 RTP 配置
		auto rtpConfig = createRtpPacketizationConfig(init);
		// 创建 AV1 封包器，根据 obuPacketization 参数选择封包模式
		auto maxFragmentSize = init && init->maxFragmentSize ? init->maxFragmentSize
		                                                     : RTC_DEFAULT_MAX_FRAGMENT_SIZE;
		auto packetization = init->obuPacketization == RTC_OBU_PACKETIZED_TEMPORAL_UNIT
		                         ? AV1RtpPacketizer::Packetization::TemporalUnit
		                         : AV1RtpPacketizer::Packetization::Obu;
		auto packetizer =
		    std::make_shared<AV1RtpPacketizer>(packetization, rtpConfig, maxFragmentSize);
		track->setMediaHandler(packetizer);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetOpusPacketizer: 为指定 Track 设置 Opus 封包器
int rtcSetOpusPacketizer(int tr, const rtcPacketizerInit *init) {
	return wrap([&] {
		auto track = getTrack(tr);
		// 创建 RTP 配置
		auto rtpConfig = createRtpPacketizationConfig(init);
		emplaceRtpConfig(rtpConfig, tr);
		// 创建 Opus 封包器
		auto packetizer = std::make_shared<OpusRtpPacketizer>(rtpConfig);
		track->setMediaHandler(packetizer);
		return RTC_ERR_SUCCESS;
	});
}

// rtcSetAACPacketizer: 为指定 Track 设置 AAC 封包器
int rtcSetAACPacketizer(int tr, const rtcPacketizerInit *init) {
	return wrap([&] {
		auto track = getTrack(tr);
		// 创建 RTP 配置
		auto rtpConfig = createRtpPacketizationConfig(init);
		// 创建 AAC 封包器
		auto packetizer = std::make_shared<AACRtpPacketizer>(rtpConfig);
		track->setMediaHandler(packetizer);
		return RTC_ERR_SUCCESS;
	});
}

// rtcChainRtcpReceivingSession: 为指定 Track 链接 RTCP 接收会话（用于统计、反馈等）
int rtcChainRtcpReceivingSession(int tr) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto session = std::make_shared<rtc::RtcpReceivingSession>();
		track->chainMediaHandler(session);
		return RTC_ERR_SUCCESS;
	});
}

// rtcChainRtcpSrReporter: 为指定 Track 链接 RTCP SR 上报器
int rtcChainRtcpSrReporter(int tr) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto config = getRtpConfig(tr);
		auto reporter = std::make_shared<RtcpSrReporter>(config);
		track->chainMediaHandler(reporter);
		emplaceRtcpSrReporter(reporter, tr);
		return RTC_ERR_SUCCESS;
	});
}

// rtcChainRtcpNackResponder: 为指定 Track 链接 RTCP NACK 响应器，参数指定最大存储包数
int rtcChainRtcpNackResponder(int tr, unsigned int maxStoredPacketsCount) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto responder = std::make_shared<RtcpNackResponder>(maxStoredPacketsCount);
		track->chainMediaHandler(responder);
		return RTC_ERR_SUCCESS;
	});
}

// rtcChainPliHandler: 为指定 Track 链接 PLI（Picture Loss Indication）处理器，回调在 PLI 到达时触发
int rtcChainPliHandler(int tr, rtcPliHandlerCallbackFunc cb) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto handler = std::make_shared<PliHandler>([tr, cb] {
			if (auto ptr = getUserPointer(tr))
				cb(tr, *ptr);
		});
		track->chainMediaHandler(handler);
		return RTC_ERR_SUCCESS;
	});
}

// rtcChainRembHandler: 为指定 Track 链接 REMB（Receiver Estimated Maximum Bitrate）处理器，回调返回估计比特率
int rtcChainRembHandler(int tr, rtcRembHandlerCallbackFunc cb) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto handler = std::make_shared<RembHandler>([tr, cb](unsigned int bitrate) {
			if (auto ptr = getUserPointer(tr))
				cb(tr, bitrate, *ptr);
		});
		track->chainMediaHandler(handler);
		return RTC_ERR_SUCCESS;
	});
}

// rtcTransformSecondsToTimestamp: 将秒转换为 RTP 时间戳，结果存入 timestamp 中
int rtcTransformSecondsToTimestamp(int id, double seconds, uint32_t *timestamp) {
	return wrap([&] {
		auto config = getRtpConfig(id);
		if (timestamp)
			*timestamp = config->secondsToTimestamp(seconds);

		return RTC_ERR_SUCCESS;
	});
}

// rtcTransformTimestampToSeconds: 将 RTP 时间戳转换为秒，结果存入 seconds 中
int rtcTransformTimestampToSeconds(int id, uint32_t timestamp, double *seconds) {
	return wrap([&] {
		auto config = getRtpConfig(id);
		if (seconds)
			*seconds = config->timestampToSeconds(timestamp);

		return RTC_ERR_SUCCESS;
	});
}

// rtcGetCurrentTrackTimestamp: 获取指定 Track 当前的 RTP 时间戳
int rtcGetCurrentTrackTimestamp(int id, uint32_t *timestamp) {
	return wrap([&] {
		auto config = getRtpConfig(id);
		if (timestamp)
			*timestamp = config->timestamp;

		return RTC_ERR_SUCCESS;
	});
}

// rtcSetTrackRtpTimestamp: 设置指定 Track 的 RTP 时间戳
int rtcSetTrackRtpTimestamp(int id, uint32_t timestamp) {
	return wrap([&] {
		auto config = getRtpConfig(id);
		config->timestamp = timestamp;
		return RTC_ERR_SUCCESS;
	});
}

// rtcGetLastTrackSenderReportTimestamp: 获取指定 Track 最近一次发送报告中的时间戳
int rtcGetLastTrackSenderReportTimestamp(int id, uint32_t *timestamp) {
	return wrap([&] {
		auto sender = getRtcpSrReporter(id);
		if (timestamp)
			*timestamp = sender->lastReportedTimestamp();

		return RTC_ERR_SUCCESS;
	});
}

// rtcSetNeedsToSendRtcpSr: 标记指定 Track 需要发送 RTCP SR，上报发送统计
int rtcSetNeedsToSendRtcpSr(int id) {
	return wrap([id] {
		auto sender = getRtcpSrReporter(id);
		sender->setNeedsToReport();
		return RTC_ERR_SUCCESS;
	});
}

// rtcGetTrackPayloadTypesForCodec: 获取指定 Track 中指定编解码器对应的所有负载类型（payload types），拷贝到 buffer 中
int rtcGetTrackPayloadTypesForCodec(int tr, const char *ccodec, int *buffer, int size) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto codec = lowercased(string(ccodec));
		auto description = track->description();
		std::vector<int> payloadTypes;
		for (int pt : description.payloadTypes())
			if (lowercased(description.rtpMap(pt)->format) == codec)
				payloadTypes.push_back(pt);

		return copyAndReturn(payloadTypes, buffer, size);
	});
}

// rtcGetSsrcsForTrack: 获取指定 Track 的 SSRC 列表，拷贝到 buffer 中
int rtcGetSsrcsForTrack(int tr, uint32_t *buffer, int count) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto ssrcs = track->description().getSSRCs();
		return copyAndReturn(ssrcs, buffer, count);
	});
}

// rtcGetCNameForSsrc: 获取指定 Track 中指定 SSRC 对应的 CName 字符串，拷贝到 buffer 中
int rtcGetCNameForSsrc(int tr, uint32_t ssrc, char *cname, int cnameSize) {
	return wrap([&] {
		auto track = getTrack(tr);
		auto description = track->description();
		auto optCName = description.getCNameForSsrc(ssrc);
		if (optCName.has_value()) {
			return copyAndReturn(optCName.value(), cname, cnameSize);
		} else {
			return 0;
		}
	});
}

// rtcGetSsrcsForType: 根据媒体类型和 SDP 文本，从中解析并返回对应的 SSRC 列表，拷贝到 buffer 中
int rtcGetSsrcsForType(const char *mediaType, const char *sdp, uint32_t *buffer, int bufferSize) {
	return wrap([&] {
		auto type = lowercased(string(mediaType));
		auto oldSDP = string(sdp);
		auto description = Description(oldSDP, "unspec");
		auto mediaCount = description.mediaCount();
		for (int i = 0; i < mediaCount; i++) {
			if (std::holds_alternative<Description::Media *>(description.media(i))) {
				auto media = std::get<Description::Media *>(description.media(i));
				auto currentMediaType = lowercased(media->type());
				if (currentMediaType == type) {
					auto ssrcs = media->getSSRCs();
					return copyAndReturn(ssrcs, buffer, bufferSize);
				}
			}
		}
		return 0;
	});
}

// rtcSetSsrcForType: 根据媒体类型和 SDP 文本，在对应的媒体描述中设置 SSRC，并返回更新后的 SDP 文本
int rtcSetSsrcForType(const char *mediaType, const char *sdp, char *buffer, const int bufferSize,
                      rtcSsrcForTypeInit *init) {
	return wrap([&] {
		auto type = lowercased(string(mediaType));
		auto prevSDP = string(sdp);
		auto description = Description(prevSDP, "unspec");
		auto mediaCount = description.mediaCount();
		for (int i = 0; i < mediaCount; i++) {
			if (std::holds_alternative<Description::Media *>(description.media(i))) {
				auto media = std::get<Description::Media *>(description.media(i));
				auto currentMediaType = lowercased(media->type());
				if (currentMediaType == type) {
					setSSRC(media, init->ssrc, init->name, init->msid, init->trackId);
					break;
				}
			}
		}
		return copyAndReturn(string(description), buffer, bufferSize);
	});
}

#endif // RTC_ENABLE_MEDIA

#if RTC_ENABLE_WEBSOCKET

// rtcCreateWebSocket: 创建一个 WebSocket 对象并打开连接，返回生成的唯一 WebSocket ID
int rtcCreateWebSocket(const char *url) {
	return wrap([&] {
		auto webSocket = std::make_shared<WebSocket>();
		webSocket->open(url);
		return emplaceWebSocket(webSocket);
	});
}

// rtcCreateWebSocketEx: 创建一个 WebSocket 对象，支持额外的配置参数，返回唯一 ID
int rtcCreateWebSocketEx(const char *url, const rtcWsConfiguration *config) {
	return wrap([&] {
		if (!url)
			throw std::invalid_argument("Unexpected null pointer for URL");

		if (!config)
			throw std::invalid_argument("Unexpected null pointer for config");

		WebSocket::Configuration c;
		c.disableTlsVerification = config->disableTlsVerification;

		if (config->proxyServer)
			c.proxyServer.emplace(config->proxyServer);

		for (int i = 0; i < config->protocolsCount; ++i)
			c.protocols.emplace_back(string(config->protocols[i]));

		if (config->connectionTimeoutMs > 0)
			c.connectionTimeout = milliseconds(config->connectionTimeoutMs);
		else if (config->connectionTimeoutMs < 0)
			c.connectionTimeout = milliseconds::zero();
		if (config->pingIntervalMs > 0)
			c.pingInterval = milliseconds(config->pingIntervalMs);
		else if (config->pingIntervalMs < 0)
			c.pingInterval = milliseconds::zero();
		if (config->maxOutstandingPings > 0)
			c.maxOutstandingPings = config->maxOutstandingPings;
		else if (config->maxOutstandingPings < 0)
			c.maxOutstandingPings = 0;

		if(config->maxMessageSize > 0)
			c.maxMessageSize = size_t(config->maxMessageSize);

		auto webSocket = std::make_shared<WebSocket>(std::move(c));
		webSocket->open(url);
		return emplaceWebSocket(webSocket);
	});
}

// rtcDeleteWebSocket: 删除指定 ID 的 WebSocket 对象，先关闭连接、重置回调，再从全局 map 中移除
int rtcDeleteWebSocket(int ws) {
	return wrap([&] {
		auto webSocket = getWebSocket(ws);
		webSocket->forceClose();
		webSocket->resetCallbacks(); // WebSocket 的关闭操作不会自动重置回调
		eraseWebSocket(ws);
		return RTC_ERR_SUCCESS;
	});
}

// rtcGetWebSocketRemoteAddress: 获取指定 WebSocket 的远端地址字符串，拷贝到 buffer 中
int rtcGetWebSocketRemoteAddress(int ws, char *buffer, int size) {
	return wrap([&] {
		auto webSocket = getWebSocket(ws);
		if (auto remoteAddress = webSocket->remoteAddress())
			return copyAndReturn(*remoteAddress, buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcGetWebSocketPath: 获取指定 WebSocket 的连接路径，拷贝到 buffer 中
int rtcGetWebSocketPath(int ws, char *buffer, int size) {
	return wrap([&] {
		auto webSocket = getWebSocket(ws);
		if (auto path = webSocket->path())
			return copyAndReturn(*path, buffer, size);
		else
			return RTC_ERR_NOT_AVAIL;
	});
}

// rtcCreateWebSocketServer: 创建 WebSocket 服务器，传入服务器配置及客户端回调，返回生成的服务器 ID
RTC_C_EXPORT int rtcCreateWebSocketServer(const rtcWsServerConfiguration *config,
                                          rtcWebSocketClientCallbackFunc cb) {
	return wrap([&] {
		if (!config)
			throw std::invalid_argument("Unexpected null pointer for config");

		if (!cb)
			throw std::invalid_argument("Unexpected null pointer for client callback");

		WebSocketServer::Configuration c;
		c.port = config->port;
		c.enableTls = config->enableTls;
		c.certificatePemFile = config->certificatePemFile
		                           ? make_optional(string(config->certificatePemFile))
		                           : nullopt;
		c.keyPemFile = config->keyPemFile ? make_optional(string(config->keyPemFile)) : nullopt;
		c.keyPemPass = config->keyPemPass ? make_optional(string(config->keyPemPass)) : nullopt;
		c.bindAddress = config->bindAddress ? make_optional(string(config->bindAddress)) : nullopt;

		if(config->maxMessageSize > 0)
			c.maxMessageSize = size_t(config->maxMessageSize);

		auto webSocketServer = std::make_shared<WebSocketServer>(std::move(c));
		int wsserver = emplaceWebSocketServer(webSocketServer);

		webSocketServer->onClient([wsserver, cb](shared_ptr<WebSocket> webSocket) {
			int ws = emplaceWebSocket(webSocket);
			if (auto ptr = getUserPointer(wsserver)) {
				rtcSetUserPointer(wsserver, *ptr);
				cb(wsserver, ws, *ptr);
			}
		});

		return wsserver;
	});
}

// rtcDeleteWebSocketServer: 删除指定 ID 的 WebSocket 服务器，停止服务并移除全局记录
RTC_C_EXPORT int rtcDeleteWebSocketServer(int wsserver) {
	return wrap([&] {
		auto webSocketServer = getWebSocketServer(wsserver);
		webSocketServer->onClient(nullptr);
		webSocketServer->stop();
		eraseWebSocketServer(wsserver);
		return RTC_ERR_SUCCESS;
	});
}

// rtcGetWebSocketServerPort: 获取指定 WebSocket 服务器的端口号
RTC_C_EXPORT int rtcGetWebSocketServerPort(int wsserver) {
	return wrap([&] {
		auto webSocketServer = getWebSocketServer(wsserver);
		return int(webSocketServer->port());
	});
}

#endif

// rtcPreload: 调用 rtc::Preload() 进行预加载初始化，捕获异常并记录错误
void rtcPreload() {
	try {
		rtc::Preload();
	} catch (const std::exception &e) {
		PLOG_ERROR << e.what();
	}
}

// rtcCleanup: 清理 RTC 全局对象，移除所有已注册对象并等待清理完成；如果超时则抛出错误
void rtcCleanup() {
	try {
		size_t count = eraseAll();
		if (count != 0) {
			PLOG_INFO << count << " objects were not properly destroyed before cleanup";
		}

		if (rtc::Cleanup().wait_for(10s) == std::future_status::timeout)
			throw std::runtime_error(
			    "Cleanup timeout (possible deadlock or undestructible object)");

	} catch (const std::exception &e) {
		PLOG_ERROR << e.what();
	}
}

// rtcSetSctpSettings: 设置 SCTP 的相关参数，通过 rtcSctpSettings 配置结构体转换为内部 SctpSettings 后调用 SetSctpSettings
int rtcSetSctpSettings(const rtcSctpSettings *settings) {
	return wrap([&] {
		SctpSettings s = {};

		if (settings->recvBufferSize > 0)
			s.recvBufferSize = size_t(settings->recvBufferSize);

		if (settings->sendBufferSize > 0)
			s.sendBufferSize = size_t(settings->sendBufferSize);

		if (settings->maxChunksOnQueue > 0)
			s.maxChunksOnQueue = size_t(settings->maxChunksOnQueue);

		if (settings->initialCongestionWindow > 0)
			s.initialCongestionWindow = size_t(settings->initialCongestionWindow);

		if (settings->maxBurst > 0)
			s.maxBurst = size_t(settings->maxBurst);
		else if (settings->maxBurst < 0)
			s.maxBurst = size_t(0); // 设置为 0 禁用 maxBurst

		if (settings->congestionControlModule >= 0)
			s.congestionControlModule = unsigned(settings->congestionControlModule);

		if (settings->delayedSackTimeMs > 0)
			s.delayedSackTime = milliseconds(settings->delayedSackTimeMs);
		else if (settings->delayedSackTimeMs < 0)
			s.delayedSackTime = milliseconds(0);

		if (settings->minRetransmitTimeoutMs > 0)
			s.minRetransmitTimeout = milliseconds(settings->minRetransmitTimeoutMs);

		if (settings->maxRetransmitTimeoutMs > 0)
			s.maxRetransmitTimeout = milliseconds(settings->maxRetransmitTimeoutMs);

		if (settings->initialRetransmitTimeoutMs > 0)
			s.initialRetransmitTimeout = milliseconds(settings->initialRetransmitTimeoutMs);

		if (settings->maxRetransmitAttempts > 0)
			s.maxRetransmitAttempts = settings->maxRetransmitAttempts;

		if (settings->heartbeatIntervalMs > 0)
			s.heartbeatInterval = milliseconds(settings->heartbeatIntervalMs);

		SetSctpSettings(std::move(s));
		return RTC_ERR_SUCCESS;
	});
}
