/**
 * Copyright (c) 2019-2021 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "datachannel.hpp"
#include "common.hpp"
#include "internals.hpp"
#include "logcounter.hpp"
#include "peerconnection.hpp"
#include "sctptransport.hpp"
#include "utils.hpp"
#include "rtc/datachannel.hpp"
#include "rtc/track.hpp"

#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

using std::chrono::milliseconds;

namespace rtc::impl {

using utils::to_uint16;
using utils::to_uint32;

// 数据通道建立协议（RFC 8832）消息类型定义
// RFC文档：https://www.rfc-editor.org/rfc/rfc8832.html
// Messages for the DataChannel establishment protocol (RFC 8832)
// See https://www.rfc-editor.org/rfc/rfc8832.html

// 消息类型枚举
enum MessageType : uint8_t {
	MESSAGE_OPEN_REQUEST = 0x00,
	MESSAGE_OPEN_RESPONSE = 0x01,
	MESSAGE_ACK = 0x02,
	MESSAGE_OPEN = 0x03
};

// 通道可靠性类型枚举
enum ChannelType : uint8_t {
	CHANNEL_RELIABLE = 0x00,                // 完全可靠传输
	CHANNEL_PARTIAL_RELIABLE_REXMIT = 0x01,  // 有限重传次数
	CHANNEL_PARTIAL_RELIABLE_TIMED = 0x02    // 有限传输时间
};

#pragma pack(push, 1)
// OPEN消息结构定义（网络字节序）
struct OpenMessage {
	uint8_t type = MESSAGE_OPEN;       // 消息类型
	uint8_t channelType;               // 通道可靠性类型
	uint16_t priority;                 // 优先级（网络字节序）
	uint32_t reliabilityParameter;     // 可靠性参数（网络字节序）
	uint16_t labelLength;              // 标签长度（网络字节序）
	uint16_t protocolLength;           // 协议长度（网络字节序）
	// 后续字段：
	// uint8_t[labelLength] label       // 标签数据
	// uint8_t[protocolLength] protocol // 协议数据
};

// ACK消息结构定义
struct AckMessage {
	uint8_t type = MESSAGE_ACK;        // 消息类型
};
#pragma pack(pop)

// 判断消息是否为OPEN消息
bool DataChannel::IsOpenMessage(message_ptr message) {
	// 1. 检查消息类型是否为控制消息
	if (message->type != Message::Control)
		return false;

	// 2. 检查第一个字节是否为OPEN类型
	auto raw = reinterpret_cast<const uint8_t *>(message->data());
	return !message->empty() && raw[0] == MESSAGE_OPEN;
}

// DataChannel构造函数
DataChannel::DataChannel(weak_ptr<PeerConnection> pc, string label, string protocol,
                         Reliability reliability)
    : mPeerConnection(pc), mLabel(std::move(label)), mProtocol(std::move(protocol)),
      mRecvQueue(RECV_QUEUE_LIMIT, message_size_func) {

	// 参数校验：两种可靠性参数不能同时设置
	if(reliability.maxPacketLifeTime && reliability.maxRetransmits)
		throw std::invalid_argument("Both maxPacketLifeTime and maxRetransmits are set");

    // 创建可靠性配置的共享指针
    mReliability = std::make_shared<Reliability>(std::move(reliability));
}

// DataChannel析构函数
DataChannel::~DataChannel() {
	PLOG_VERBOSE << "Destroying DataChannel";
	try {
		close();  // 尝试关闭通道
	} catch (const std::exception &e) {
		PLOG_ERROR << e.what();
	}
}

// 关闭数据通道
void DataChannel::close() {
	PLOG_VERBOSE << "Closing DataChannel";

	shared_ptr<SctpTransport> transport;
	{
		std::shared_lock lock(mMutex);
		transport = mSctpTransport.lock();
	}

	// 原子操作标记关闭状态
	if (!mIsClosed.exchange(true)) {
		// 1. 关闭底层SCTP流
		if (transport && mStream.has_value())
			transport->closeStream(mStream.value());

		// 2. 触发关闭事件
		triggerClosed();
	}

	// 3. 重置所有回调
	resetCallbacks();
}

// 远程关闭处理
void DataChannel::remoteClose() { close(); }

// 接收消息方法
optional<message_variant> DataChannel::receive() {
	auto next = mRecvQueue.pop();
	return next ? std::make_optional(to_variant(std::move(**next))) : nullopt;
}

// 查看下一条消息
optional<message_variant> DataChannel::peek() {
	auto next = mRecvQueue.peek();
	return next ? std::make_optional(to_variant(**next)) : nullopt;
}

// 获取可接收消息数量
size_t DataChannel::availableAmount() const { return mRecvQueue.amount(); }

// 获取流ID
optional<uint16_t> DataChannel::stream() const {
	std::shared_lock lock(mMutex);
	return mStream;
}

// 获取标签
string DataChannel::label() const {
	std::shared_lock lock(mMutex);
	return mLabel;
}

// 获取协议名称
string DataChannel::protocol() const {
	std::shared_lock lock(mMutex);
	return mProtocol;
}

// 获取可靠性配置
Reliability DataChannel::reliability() const {
	std::shared_lock lock(mMutex);
	return *mReliability;
}

// 判断通道是否打开
bool DataChannel::isOpen(void) const { return !mIsClosed && mIsOpen; }

// 判断通道是否关闭
bool DataChannel::isClosed(void) const { return mIsClosed; }

// 获取最大消息尺寸
size_t DataChannel::maxMessageSize() const {
	auto pc = mPeerConnection.lock();
	return pc ? pc->remoteMaxMessageSize() : DEFAULT_REMOTE_MAX_MESSAGE_SIZE;
}

// 分配流ID
void DataChannel::assignStream(uint16_t stream) {
	std::unique_lock lock(mMutex);

	if (mStream.has_value())
		throw std::logic_error("DataChannel already has a stream assigned");

	mStream = stream;
}

// 打开数据通道
void DataChannel::open(shared_ptr<SctpTransport> transport) {
	{
		std::unique_lock lock(mMutex);
		mSctpTransport = transport;
	}

	// 1. 原子操作标记打开状态
	if (!mIsClosed && !mIsOpen.exchange(true))
		// 2. 触发打开事件
		triggerOpen();
}

// 处理OPEN消息（基类默认实现）
void DataChannel::processOpenMessage(message_ptr) {
	PLOG_WARNING << "Received an open message for a user-negotiated DataChannel, ignoring";
}

// 发送消息方法
bool DataChannel::outgoing(message_ptr message) {
	shared_ptr<SctpTransport> transport;
	{
		std::shared_lock lock(mMutex);
		transport = mSctpTransport.lock();

		// 1. 前置条件检查
		if (mIsClosed)
			throw std::runtime_error("DataChannel is closed");

		if (!transport)
			throw std::runtime_error("DataChannel not open");

		if (!mStream.has_value())
			throw std::logic_error("DataChannel has no stream assigned");

		// 2. 消息尺寸校验
		if (message->size() > maxMessageSize())
			throw std::invalid_argument("Message size exceeds limit");

		// 3. 设置消息可靠性参数
		message->reliability = mIsOpen ? mReliability : nullptr;
		message->stream = mStream.value();
	}

	// 4. 通过SCTP传输发送消息
	return transport->send(message);
}

// 处理接收到的消息
void DataChannel::incoming(message_ptr message) {
	if (!message || mIsClosed)
		return;

	// 根据消息类型处理
	switch (message->type) {
	case Message::Control: {
		if (message->size() == 0)
			break; // 忽略空控制消息
		auto raw = reinterpret_cast<const uint8_t *>(message->data());
		switch (raw[0]) {
		case MESSAGE_OPEN:
			// 1. 处理OPEN消息
			processOpenMessage(message);
			break;
		case MESSAGE_ACK:
			// 2. 处理ACK消息
			if (!mIsOpen.exchange(true)) {
				triggerOpen();
			}
			break;
		default:
			// 忽略未知控制消息
			break;
		}
		break;
	}
	case Message::Reset:
		// 3. 处理连接重置
		remoteClose();
		break;
	case Message::String:
	case Message::Binary:
		// 4. 存储应用层消息
		mRecvQueue.push(message);
		triggerAvailable(mRecvQueue.size());
		break;
	default:
		// 忽略未知类型消息
		break;
	}
}

/********** OutgoingDataChannel **********/

// 发送方向数据通道构造函数
OutgoingDataChannel::OutgoingDataChannel(weak_ptr<PeerConnection> pc, string label, string protocol,
                                         Reliability reliability)
    : DataChannel(pc, std::move(label), std::move(protocol), std::move(reliability)) {}

OutgoingDataChannel::~OutgoingDataChannel() {}

// 打开发送通道实现
void OutgoingDataChannel::open(shared_ptr<SctpTransport> transport) {
	std::unique_lock lock(mMutex);
	mSctpTransport = transport;

	// 1. 流ID必须已分配
	if (!mStream.has_value())
		throw std::runtime_error("DataChannel has no stream assigned");

	// 2. 确定通道可靠性类型
	uint8_t channelType;
	uint32_t reliabilityParameter;
	if (mReliability->maxPacketLifeTime) {
		channelType = CHANNEL_PARTIAL_RELIABLE_TIMED;
		reliabilityParameter = to_uint32(mReliability->maxPacketLifeTime->count());
	} else if (mReliability->maxRetransmits) {
		channelType = CHANNEL_PARTIAL_RELIABLE_REXMIT;
		reliabilityParameter = to_uint32(*mReliability->maxRetransmits);
	}
	// 兼容旧版本配置
	else
		switch (mReliability->typeDeprecated) {
		case Reliability::Type::Rexmit:
			channelType = CHANNEL_PARTIAL_RELIABLE_REXMIT;
			reliabilityParameter = to_uint32(std::max(std::get<int>(mReliability->rexmit), 0));
			break;

		case Reliability::Type::Timed:
			channelType = CHANNEL_PARTIAL_RELIABLE_TIMED;
			reliabilityParameter = to_uint32(std::get<milliseconds>(mReliability->rexmit).count());
			break;

		default:
			channelType = CHANNEL_RELIABLE;
			reliabilityParameter = 0;
			break;
		}

	// 3. 设置无序传输标志
	if (mReliability->unordered)
		channelType |= 0x80;

	// 4. 构造OPEN消息
	const size_t len = sizeof(OpenMessage) + mLabel.size() + mProtocol.size();
	binary buffer(len, byte(0));
	auto &open = *reinterpret_cast<OpenMessage *>(buffer.data());
	open.type = MESSAGE_OPEN;
	open.channelType = channelType;
	open.priority = htons(0);  // 转换为网络字节序
	open.reliabilityParameter = htonl(reliabilityParameter);
	open.labelLength = htons(to_uint16(mLabel.size()));
	open.protocolLength = htons(to_uint16(mProtocol.size()));

	// 5. 填充标签和协议数据
	auto end = reinterpret_cast<char *>(buffer.data() + sizeof(OpenMessage));
	std::copy(mLabel.begin(), mLabel.end(), end);
	std::copy(mProtocol.begin(), mProtocol.end(), end + mLabel.size());

	lock.unlock();

	// 6. 发送OPEN消息
	transport->send(make_message(buffer.begin(), buffer.end(), Message::Control, mStream.value()));
}

// 处理OPEN消息（发送端忽略）
void OutgoingDataChannel::processOpenMessage(message_ptr) {
	PLOG_WARNING << "Received an open message for a locally-created DataChannel, ignoring";
}

/********** IncomingDataChannel **********/

// 接收方向数据通道构造函数
IncomingDataChannel::IncomingDataChannel(weak_ptr<PeerConnection> pc,
                                         weak_ptr<SctpTransport> transport)
    : DataChannel(pc, "", "", {}) {

	mSctpTransport = transport;
}

IncomingDataChannel::~IncomingDataChannel() {}

// 打开接收通道实现（空实现）
void IncomingDataChannel::open(shared_ptr<SctpTransport>) {
	// 接收端不需要主动打开
}

// 处理接收到的OPEN消息
void IncomingDataChannel::processOpenMessage(message_ptr message) {
	std::unique_lock lock(mMutex);
	auto transport = mSctpTransport.lock();
	// 1. 传输层必须存在
	if (!transport)
		throw std::logic_error("DataChannel has no transport");

	// 2. 必须已分配流ID
	if (!mStream.has_value())
		throw std::logic_error("DataChannel has no stream assigned");

	// 3. 校验消息长度
	if (message->size() < sizeof(OpenMessage))
		throw std::invalid_argument("DataChannel open message too small");

	// 4. 解析OPEN消息头
	OpenMessage open = *reinterpret_cast<const OpenMessage *>(message->data());
	// 转换网络字节序到主机字节序
	open.priority = ntohs(open.priority);
	open.reliabilityParameter = ntohl(open.reliabilityParameter);
	open.labelLength = ntohs(open.labelLength);
	open.protocolLength = ntohs(open.protocolLength);

	// 5. 校验消息完整性
	if (message->size() < sizeof(OpenMessage) + size_t(open.labelLength + open.protocolLength))
		throw std::invalid_argument("DataChannel open message truncated");

	// 6. 提取标签和协议
	auto end = reinterpret_cast<const char *>(message->data() + sizeof(OpenMessage));
	mLabel.assign(end, open.labelLength);
	mProtocol.assign(end + open.labelLength, open.protocolLength);

	// 7. 解析可靠性配置
	mReliability->unordered = (open.channelType & 0x80) != 0;
	mReliability->maxPacketLifeTime.reset();
	mReliability->maxRetransmits.reset();
	switch (open.channelType & 0x7F) {
	case CHANNEL_PARTIAL_RELIABLE_REXMIT:
		mReliability->maxRetransmits.emplace(open.reliabilityParameter);
		break;
	case CHANNEL_PARTIAL_RELIABLE_TIMED:
		mReliability->maxPacketLifeTime.emplace(milliseconds(open.reliabilityParameter));
		break;
	default:
		break;
	}

	// Deprecated
	// 兼容旧版本配置解析
	switch (open.channelType & 0x7F) {
	case CHANNEL_PARTIAL_RELIABLE_REXMIT:
		mReliability->typeDeprecated = Reliability::Type::Rexmit;
		mReliability->rexmit = int(open.reliabilityParameter);
		break;
	case CHANNEL_PARTIAL_RELIABLE_TIMED:
		mReliability->typeDeprecated = Reliability::Type::Timed;
		mReliability->rexmit = milliseconds(open.reliabilityParameter);
		break;
	default:
		mReliability->typeDeprecated = Reliability::Type::Reliable;
		mReliability->rexmit = int(0);
	}

	lock.unlock();

	// 8. 构造ACK响应
	binary buffer(sizeof(AckMessage), byte(0));
	auto &ack = *reinterpret_cast<AckMessage *>(buffer.data());
	ack.type = MESSAGE_ACK;

	// 9. 发送ACK响应
	transport->send(make_message(buffer.begin(), buffer.end(), Message::Control, mStream.value()));

	// 10. 标记通道为打开状态
	if (!mIsOpen.exchange(true))
		triggerOpen();
}

} // namespace rtc::impl