/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 * Copyright (c) 2020 Filip Klembara (in2core)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "peerconnection.hpp"
#include "common.hpp"
#include "rtp.hpp"

#include "impl/certificate.hpp"
#include "impl/dtlstransport.hpp"
#include "impl/icetransport.hpp"
#include "impl/internals.hpp"
#include "impl/peerconnection.hpp"
#include "impl/sctptransport.hpp"
#include "impl/threadpool.hpp"
#include "impl/track.hpp"

#if RTC_ENABLE_MEDIA
#include "impl/dtlssrtptransport.hpp"
#endif

#include <iomanip>
#include <set>
#include <thread>

using namespace std::placeholders;

namespace rtc {

// 默认构造函数，使用默认配置初始化 PeerConnection 对象
PeerConnection::PeerConnection() : PeerConnection(Configuration()) {}

// 构造函数，接受配置参数并初始化 PeerConnection 对象
PeerConnection::PeerConnection(Configuration config)
    : CheshireCat<impl::PeerConnection>(std::move(config)) {}

// 析构函数，关闭 PeerConnection 连接
PeerConnection::~PeerConnection() {
	try {
		impl()->remoteClose(); // 1. 远程关闭 PeerConnection 连接
	} catch (const std::exception &e) {
		PLOG_ERROR << e.what(); // 2. 捕获并记录异常信息
	}
}

// 关闭 PeerConnection 连接
void PeerConnection::close() { impl()->close(); }

// 获取当前配置
const Configuration *PeerConnection::config() const { return &impl()->config; }

// 获取当前 PeerConnection 的状态
PeerConnection::State PeerConnection::state() const { return impl()->state; }

// 获取当前 ICE 的状态
PeerConnection::IceState PeerConnection::iceState() const { return impl()->iceState; }

// 获取当前候选收集的状态
PeerConnection::GatheringState PeerConnection::gatheringState() const {
	return impl()->gatheringState;
}

// 获取当前信令状态
PeerConnection::SignalingState PeerConnection::signalingState() const {
	return impl()->signalingState;
}

// 检查是否需要重新协商
bool PeerConnection::negotiationNeeded() const {
	return impl()->negotiationNeeded();
}

// 获取本地描述
optional<Description> PeerConnection::localDescription() const {
	return impl()->localDescription();
}

// 获取远程描述
optional<Description> PeerConnection::remoteDescription() const {
	return impl()->remoteDescription();
}

// 获取远程支持的最大消息大小
size_t PeerConnection::remoteMaxMessageSize() const { return impl()->remoteMaxMessageSize(); }

// 检查是否有媒体流
bool PeerConnection::hasMedia() const {
	auto local = localDescription();
	return local && local->hasAudioOrVideo();
}

// 设置本地描述
void PeerConnection::setLocalDescription(Description::Type type, LocalDescriptionInit init) {
	std::unique_lock signalingLock(impl()->signalingMutex);
	PLOG_VERBOSE << "Setting local description, type=" << Description::typeToString(type);

	// 1. 获取当前信令状态
	SignalingState signalingState = impl()->signalingState.load();
	if (type == Description::Type::Rollback) {
		// 1.1 如果是回滚操作，则回滚本地描述
		if (signalingState == SignalingState::HaveLocalOffer ||
		    signalingState == SignalingState::HaveLocalPranswer) {
			impl()->rollbackLocalDescription();
			impl()->changeSignalingState(SignalingState::Stable);
		}
		return;
	}

	// 2. 如果未指定类型，则根据信令状态推断类型
	if (type == Description::Type::Unspec) {
		if (signalingState == SignalingState::HaveRemoteOffer)
			type = Description::Type::Answer;
		else
			type = Description::Type::Offer;
	}

	// 3. 根据当前信令状态和类型确定新的信令状态
	SignalingState newSignalingState;
	switch (signalingState) {
	case SignalingState::Stable:
		if (type != Description::Type::Offer) {
			std::ostringstream oss;
			oss << "Unexpected local desciption type " << type << " in signaling state "
			    << signalingState;
			throw std::logic_error(oss.str());
		}
		newSignalingState = SignalingState::HaveLocalOffer;
		break;

	case SignalingState::HaveRemoteOffer:
	case SignalingState::HaveLocalPranswer:
		if (type != Description::Type::Answer && type != Description::Type::Pranswer) {
			std::ostringstream oss;
			oss << "Unexpected local description type " << type
			    << " description in signaling state " << signalingState;
			throw std::logic_error(oss.str());
		}
		newSignalingState = SignalingState::Stable;
		break;

	default: {
		std::ostringstream oss;
		oss << "Unexpected local description in signaling state " << signalingState << ", ignoring";
		LOG_WARNING << oss.str();
		return;
	}
	}

	// 4. 初始化 ICE 传输层
	auto iceTransport = impl()->initIceTransport();
	if (!iceTransport)
		return; // closed

	// 5. 如果提供了自定义 ICE 属性，则设置
	if (init.iceUfrag && init.icePwd) {
		PLOG_DEBUG << "Using custom ICE attributes, ufrag=\"" << init.iceUfrag.value() << "\", pwd=\"" << init.icePwd.value() << "\"";
		iceTransport->setIceAttributes(init.iceUfrag.value(), init.icePwd.value());
	}

	// 6. 获取本地描述并处理
	Description local = iceTransport->getLocalDescription(type);
	impl()->processLocalDescription(std::move(local));

	// 7. 更新信令状态
	impl()->changeSignalingState(newSignalingState);
	signalingLock.unlock();

	// 8. 如果需要自动协商，则触发新的 offer
	if (!impl()->config.disableAutoNegotiation && newSignalingState == SignalingState::Stable) {
		if (impl()->negotiationNeeded())
			setLocalDescription(Description::Type::Offer);
	}

	// 9. 如果需要自动收集候选，则开始收集
	if (impl()->gatheringState == GatheringState::New && !impl()->config.disableAutoGathering) {
		iceTransport->gatherLocalCandidates(impl()->localBundleMid());
	}
}

// 收集本地候选
void PeerConnection::gatherLocalCandidates(std::vector<IceServer> additionalIceServers) {
	auto iceTransport = impl()->getIceTransport();
	if (!iceTransport) {
		throw std::logic_error("No IceTransport. Local Description has not been set");
	}

	// 1. 如果候选收集尚未开始，则开始收集
	if (impl()->gatheringState == GatheringState::New) {
		iceTransport->gatherLocalCandidates(impl()->localBundleMid(), additionalIceServers);
	} else {
		PLOG_WARNING << "Candidates gathering already started";
	}
}

// 设置远程描述
void PeerConnection::setRemoteDescription(Description description) {
	std::unique_lock signalingLock(impl()->signalingMutex);
	PLOG_VERBOSE << "Setting remote description: " << string(description);

	// 1. 如果是回滚操作，则回滚远程描述
	if (description.type() == Description::Type::Rollback) {
		PLOG_VERBOSE << "Rolling back pending remote description";
		impl()->changeSignalingState(SignalingState::Stable);
		return;
	}

	// 2. 验证远程描述的有效性
	impl()->validateRemoteDescription(description);

	// 3. 根据当前信令状态确定新的信令状态
	SignalingState signalingState = impl()->signalingState.load();
	SignalingState newSignalingState;
	switch (signalingState) {
	case SignalingState::Stable:
		description.hintType(Description::Type::Offer);
		if (description.type() != Description::Type::Offer) {
			std::ostringstream oss;
			oss << "Unexpected remote " << description.type() << " description in signaling state "
			    << signalingState;
			throw std::logic_error(oss.str());
		}
		newSignalingState = SignalingState::HaveRemoteOffer;
		break;

	case SignalingState::HaveLocalOffer:
		description.hintType(Description::Type::Answer);
		if (description.type() == Description::Type::Offer) {
			// 3.1 如果收到 offer，则回滚本地描述
			impl()->rollbackLocalDescription();
			impl()->changeSignalingState(SignalingState::Stable);
			signalingState = SignalingState::Stable;
			newSignalingState = SignalingState::HaveRemoteOffer;
			break;
		}
		if (description.type() != Description::Type::Answer &&
		    description.type() != Description::Type::Pranswer) {
			std::ostringstream oss;
			oss << "Unexpected remote " << description.type() << " description in signaling state "
			    << signalingState;
			throw std::logic_error(oss.str());
		}
		newSignalingState = SignalingState::Stable;
		break;

	case SignalingState::HaveRemotePranswer:
		description.hintType(Description::Type::Answer);
		if (description.type() != Description::Type::Answer &&
		    description.type() != Description::Type::Pranswer) {
			std::ostringstream oss;
			oss << "Unexpected remote " << description.type() << " description in signaling state "
			    << signalingState;
			throw std::logic_error(oss.str());
		}
		newSignalingState = SignalingState::Stable;
		break;

	default: {
		std::ostringstream oss;
		oss << "Unexpected remote description in signaling state " << signalingState;
		throw std::logic_error(oss.str());
	}
	}

	// 4. 提取远程候选
	auto remoteCandidates = description.extractCandidates();

	// 5. 初始化 ICE 传输层
	auto iceTransport = impl()->initIceTransport();
	if (!iceTransport)
		return; // closed

	// 6. 设置远程描述
	iceTransport->setRemoteDescription(description); // ICE transport might reject the description

	// 7. 处理远程描述
	impl()->processRemoteDescription(std::move(description));
	impl()->changeSignalingState(newSignalingState);
	signalingLock.unlock();

	// 8. 添加远程候选
	for (const auto &candidate : remoteCandidates)
		addRemoteCandidate(candidate);

	// 9. 如果需要自动协商，则触发新的 offer 或 answer
	if (!impl()->config.disableAutoNegotiation) {
		switch (newSignalingState) {
		case SignalingState::Stable:
			if (impl()->negotiationNeeded())
				setLocalDescription(Description::Type::Offer);
			break;

		case SignalingState::HaveRemoteOffer:
			setLocalDescription(Description::Type::Answer);
			break;

		default:
			break;
		}
	}
}

// 添加远程候选
void PeerConnection::addRemoteCandidate(Candidate candidate) {
	std::unique_lock signalingLock(impl()->signalingMutex);
	PLOG_VERBOSE << "Adding remote candidate: " << string(candidate);
	impl()->processRemoteCandidate(std::move(candidate));
}

// 设置媒体处理器
void PeerConnection::setMediaHandler(shared_ptr<MediaHandler> handler) {
	impl()->setMediaHandler(std::move(handler));
};

// 获取媒体处理器
shared_ptr<MediaHandler> PeerConnection::getMediaHandler() { return impl()->getMediaHandler(); };

// 获取本地地址
optional<string> PeerConnection::localAddress() const {
	auto iceTransport = impl()->getIceTransport();
	return iceTransport ? iceTransport->getLocalAddress() : nullopt;
}

// 获取远程地址
optional<string> PeerConnection::remoteAddress() const {
	auto iceTransport = impl()->getIceTransport();
	return iceTransport ? iceTransport->getRemoteAddress() : nullopt;
}

// 获取最大 DataChannel ID
uint16_t PeerConnection::maxDataChannelId() const { return impl()->maxDataChannelStream(); }

// 创建 DataChannel
shared_ptr<DataChannel> PeerConnection::createDataChannel(string label, DataChannelInit init) {
	auto channelImpl = impl()->emplaceDataChannel(std::move(label), std::move(init));
	auto channel = std::make_shared<DataChannel>(channelImpl);

	// 如果需要自动协商，则触发新的 offer
	if (!impl()->config.disableAutoNegotiation && impl()->signalingState.load() == SignalingState::Stable) {
		if (impl()->negotiationNeeded())
			setLocalDescription(Description::Type::Offer);
	}

	return channel;
}

// 设置 DataChannel 回调
void PeerConnection::onDataChannel(
    std::function<void(shared_ptr<DataChannel> dataChannel)> callback) {
	impl()->dataChannelCallback = callback;
	impl()->flushPendingDataChannels();
}

// 添加 Track
std::shared_ptr<Track> PeerConnection::addTrack(Description::Media description) {
	auto trackImpl = impl()->emplaceTrack(std::move(description));
	auto track = std::make_shared<Track>(trackImpl);

	return track;
}

// 设置 Track 回调
void PeerConnection::onTrack(std::function<void(std::shared_ptr<Track>)> callback) {
	impl()->trackCallback = callback;
	impl()->flushPendingTracks();
}

// 设置本地描述回调
void PeerConnection::onLocalDescription(std::function<void(Description description)> callback) {
	impl()->localDescriptionCallback = callback;
}

// 设置本地候选回调
void PeerConnection::onLocalCandidate(std::function<void(Candidate candidate)> callback) {
	impl()->localCandidateCallback = callback;
}

// 设置状态变化回调
void PeerConnection::onStateChange(std::function<void(State state)> callback) {
	impl()->stateChangeCallback = callback;
}

// 设置 ICE 状态变化回调
void PeerConnection::onIceStateChange(std::function<void(IceState state)> callback) {
	impl()->iceStateChangeCallback = callback;
}

// 设置候选收集状态变化回调
void PeerConnection::onGatheringStateChange(std::function<void(GatheringState state)> callback) {
	impl()->gatheringStateChangeCallback = callback;
}

// 设置信令状态变化回调
void PeerConnection::onSignalingStateChange(std::function<void(SignalingState state)> callback) {
	impl()->signalingStateChangeCallback = callback;
}

// 重置所有回调
void PeerConnection::resetCallbacks() { impl()->resetCallbacks(); }

// 获取选中的候选对
bool PeerConnection::getSelectedCandidatePair(Candidate *local, Candidate *remote) {
	auto iceTransport = impl()->getIceTransport();
	return iceTransport ? iceTransport->getSelectedCandidatePair(local, remote) : false;
}

// 清除统计信息
void PeerConnection::clearStats() {
	if (auto sctpTransport = impl()->getSctpTransport())
		return sctpTransport->clearStats();
}

// 获取发送的字节数
size_t PeerConnection::bytesSent() {
	auto sctpTransport = impl()->getSctpTransport();
	return sctpTransport ? sctpTransport->bytesSent() : 0;
}

// 获取接收的字节数
size_t PeerConnection::bytesReceived() {
	auto sctpTransport = impl()->getSctpTransport();
	return sctpTransport ? sctpTransport->bytesReceived() : 0;
}

// 获取往返时间 (RTT)
optional<std::chrono::milliseconds> PeerConnection::rtt() {
	auto sctpTransport = impl()->getSctpTransport();
	return sctpTransport ? sctpTransport->rtt() : nullopt;
}

// 获取远程证书指纹
CertificateFingerprint PeerConnection::remoteFingerprint() {
	return impl()->remoteFingerprint();
}

// 重载 << 操作符，用于输出 PeerConnection 状态
std::ostream &operator<<(std::ostream &out, PeerConnection::State state) {
	using State = PeerConnection::State;
	const char *str;
	switch (state) {
	case State::New:
		str = "new";
		break;
	case State::Connecting:
		str = "connecting";
		break;
	case State::Connected:
		str = "connected";
		break;
	case State::Disconnected:
		str = "disconnected";
		break;
	case State::Failed:
		str = "failed";
		break;
	case State::Closed:
		str = "closed";
		break;
	default:
		str = "unknown";
		break;
	}
	return out << str;
}

// 重载 << 操作符，用于输出 ICE 状态
std::ostream &operator<<(std::ostream &out, PeerConnection::IceState state) {
	using IceState = PeerConnection::IceState;
	const char *str;
	switch (state) {
	case IceState::New:
		str = "new";
		break;
	case IceState::Checking:
		str = "checking";
		break;
	case IceState::Connected:
		str = "connected";
		break;
	case IceState::Completed:
		str = "completed";
		break;
	case IceState::Failed:
		str = "failed";
		break;
	case IceState::Disconnected:
		str = "disconnected";
		break;
	case IceState::Closed:
		str = "closed";
		break;
	default:
		str = "unknown";
		break;
	}
	return out << str;
}

// 重载 << 操作符，用于输出候选收集状态
std::ostream &operator<<(std::ostream &out, PeerConnection::GatheringState state) {
	using GatheringState = PeerConnection::GatheringState;
	const char *str;
	switch (state) {
	case GatheringState::New:
		str = "new";
		break;
	case GatheringState::InProgress:
		str = "in-progress";
		break;
	case GatheringState::Complete:
		str = "complete";
		break;
	default:
		str = "unknown";
		break;
	}
	return out << str;
}

std::ostream &operator<<(std::ostream &out, PeerConnection::SignalingState state) {
	using SignalingState = PeerConnection::SignalingState;
	const char *str;
	switch (state) {
	case SignalingState::Stable:
		str = "stable";
		break;
	case SignalingState::HaveLocalOffer:
		str = "have-local-offer";
		break;
	case SignalingState::HaveRemoteOffer:
		str = "have-remote-offer";
		break;
	case SignalingState::HaveLocalPranswer:
		str = "have-local-pranswer";
		break;
	case SignalingState::HaveRemotePranswer:
		str = "have-remote-pranswer";
		break;
	default:
		str = "unknown";
		break;
	}
	return out << str;
}

} // namespace rtc
