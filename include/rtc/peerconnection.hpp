/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef RTC_PEER_CONNECTION_H
#define RTC_PEER_CONNECTION_H

#include "candidate.hpp"
#include "common.hpp"
#include "configuration.hpp"
#include "datachannel.hpp"
#include "description.hpp"
#include "reliability.hpp"
#include "track.hpp"

#include <chrono>
#include <functional>

namespace rtc {

namespace impl {

struct PeerConnection;

}

// DataChannel 初始化配置结构体
struct RTC_CPP_EXPORT DataChannelInit {
	Reliability reliability = {};  // 可靠性配置
	bool negotiated = false;       // 是否手动协商通道
	optional<uint16_t> id = nullopt; // 指定通道ID（手动协商时使用）
	string protocol = "";          // 自定义协议标识
};

// 本地描述初始化配置结构体
struct RTC_CPP_EXPORT LocalDescriptionInit {
    optional<string> iceUfrag;  // 自定义 ICE 用户名片段
    optional<string> icePwd;    // 自定义 ICE 密码
};

// PeerConnection 类定义，实现 WebRTC 对等连接功能
class RTC_CPP_EXPORT PeerConnection final : CheshireCat<impl::PeerConnection> {
public:
	// 连接状态枚举
	enum class State : int {
		New = RTC_NEW,             // 初始状态
		Connecting = RTC_CONNECTING, // 连接中
		Connected = RTC_CONNECTED,   // 已连接
		Disconnected = RTC_DISCONNECTED, // 连接断开
		Failed = RTC_FAILED,        // 连接失败
		Closed = RTC_CLOSED         // 已关闭
	};

	// ICE 连接状态枚举
	enum class IceState : int {
		New = RTC_ICE_NEW,          // ICE 初始状态
		Checking = RTC_ICE_CHECKING, // 候选地址检查中
		Connected = RTC_ICE_CONNECTED, // ICE 连接成功
		Completed = RTC_ICE_COMPLETED, // ICE 完成
		Failed = RTC_ICE_FAILED,     // ICE 失败
		Disconnected = RTC_ICE_DISCONNECTED, // ICE 连接断开
		Closed = RTC_ICE_CLOSED      // ICE 已关闭
	};

	// 候选地址收集状态枚举
	enum class GatheringState : int {
		New = RTC_GATHERING_NEW,        // 未开始收集
		InProgress = RTC_GATHERING_INPROGRESS, // 收集中
		Complete = RTC_GATHERING_COMPLETE // 收集完成
	};

	// 信令状态枚举
	enum class SignalingState : int {
		Stable = RTC_SIGNALING_STABLE,              // 稳定状态
		HaveLocalOffer = RTC_SIGNALING_HAVE_LOCAL_OFFER,    // 本地提供offer
		HaveRemoteOffer = RTC_SIGNALING_HAVE_REMOTE_OFFER,  // 收到远端offer
		HaveLocalPranswer = RTC_SIGNALING_HAVE_LOCAL_PRANSWER, // 本地提供pranswer
		HaveRemotePranswer = RTC_SIGNALING_HAVE_REMOTE_PRANSWER // 收到远端pranswer
	};

	// 构造函数与析构函数
	PeerConnection();
	PeerConnection(Configuration config);
	~PeerConnection();

	// 关闭对等连接
	void close();

	// 配置信息访问
	const Configuration *config() const;  // 获取当前配置

	// 状态获取方法
	State state() const;                  // 获取当前连接状态
	IceState iceState() const;            // 获取ICE状态
	GatheringState gatheringState() const; // 获取候选收集状态
	SignalingState signalingState() const; // 获取信令状态

	// 连接状态判断
	bool negotiationNeeded() const;       // 是否需要重新协商
	bool hasMedia() const;                // 是否包含媒体流

	// 描述信息获取
	optional<Description> localDescription() const;  // 获取本地SDP描述
	optional<Description> remoteDescription() const; // 获取远端SDP描述

	// 连接参数获取
	size_t remoteMaxMessageSize() const;  // 获取远端支持的最大消息尺寸
	optional<string> localAddress() const;  // 获取本地地址
	optional<string> remoteAddress() const; // 获取远端地址
	uint16_t maxDataChannelId() const;     // 获取最大数据通道ID

	// 获取当前选择的候选对
	bool getSelectedCandidatePair(Candidate *local, Candidate *remote);

	// 信令控制方法
	void setLocalDescription(Description::Type type = Description::Type::Unspec, LocalDescriptionInit init = {}); // 设置本地描述
	void setRemoteDescription(Description description);  // 设置远端描述
	void addRemoteCandidate(Candidate candidate);        // 添加远端候选地址
	void gatherLocalCandidates(std::vector<IceServer> additionalIceServers = {}); // 收集本地候选

	// 媒体处理器管理
	void setMediaHandler(shared_ptr<MediaHandler> handler);  // 设置媒体处理器
	shared_ptr<MediaHandler> getMediaHandler();              // 获取当前媒体处理器

	// 数据通道管理
	[[nodiscard]] shared_ptr<DataChannel> createDataChannel(string label, DataChannelInit init = {}); // 创建数据通道
	void onDataChannel(std::function<void(std::shared_ptr<DataChannel> dataChannel)> callback); // 数据通道回调

	// 媒体轨道管理
	[[nodiscard]] shared_ptr<Track> addTrack(Description::Media description); // 添加媒体轨道
	void onTrack(std::function<void(std::shared_ptr<Track> track)> callback); // 媒体轨道回调

	// 事件回调设置
	void onLocalDescription(std::function<void(Description description)> callback); // 本地描述生成回调
	void onLocalCandidate(std::function<void(Candidate candidate)> callback);       // 本地候选地址生成回调
	void onStateChange(std::function<void(State state)> callback);                  // 状态变化回调
	void onIceStateChange(std::function<void(IceState state)> callback);            // ICE状态变化回调
	void onGatheringStateChange(std::function<void(GatheringState state)> callback); // 候选收集状态回调
	void onSignalingStateChange(std::function<void(SignalingState state)> callback); // 信令状态变化回调

	// 重置所有回调
	void resetCallbacks();
	// 安全验证
	CertificateFingerprint remoteFingerprint();	// 获取远端证书指纹

	// 统计信息
	void clearStats();               // 清除统计信息
	size_t bytesSent();              // 获取已发送字节数
	size_t bytesReceived();          // 获取已接收字节数
	optional<std::chrono::milliseconds> rtt(); // 获取当前往返时间
};

// 枚举类型输出操作符重载
RTC_CPP_EXPORT std::ostream &operator<<(std::ostream &out, PeerConnection::State state);
RTC_CPP_EXPORT std::ostream &operator<<(std::ostream &out, PeerConnection::IceState state);
RTC_CPP_EXPORT std::ostream &operator<<(std::ostream &out, PeerConnection::GatheringState state);
RTC_CPP_EXPORT std::ostream &operator<<(std::ostream &out, PeerConnection::SignalingState state);

} // namespace rtc

#endif