/**
 * Copyright (c) 2020-2021 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#if RTC_ENABLE_WEBSOCKET

#include "websocket.hpp"
#include "common.hpp"

#include "impl/internals.hpp"
#include "impl/websocket.hpp"

namespace rtc {

// WebSocket 默认构造函数，使用默认配置初始化 WebSocket 对象
WebSocket::WebSocket() : WebSocket(Configuration()) {}

// WebSocket 构造函数，接受配置参数并初始化 WebSocket 对象
WebSocket::WebSocket(Configuration config)
    : CheshireCat<impl::WebSocket>(std::move(config)),
      Channel(std::dynamic_pointer_cast<impl::Channel>(CheshireCat<impl::WebSocket>::impl())) {}

// WebSocket 构造函数，接受一个实现类的指针并初始化 WebSocket 对象
WebSocket::WebSocket(impl_ptr<impl::WebSocket> impl)
    : CheshireCat<impl::WebSocket>(std::move(impl)),
      Channel(std::dynamic_pointer_cast<impl::Channel>(CheshireCat<impl::WebSocket>::impl())) {}

// WebSocket 析构函数，关闭 WebSocket 连接并重置回调函数
WebSocket::~WebSocket() {
	try {
		// 1. 远程关闭 WebSocket 连接
		impl()->remoteClose();
		// 2. 重置回调函数，防止资源泄漏
		impl()->resetCallbacks(); // not done by impl::WebSocket
	} catch (const std::exception &e) {
		// 3. 捕获并记录异常信息
		PLOG_ERROR << e.what();
	}
}

// 获取当前 WebSocket 的状态
WebSocket::State WebSocket::readyState() const { return impl()->state; }

// 判断 WebSocket 是否处于打开状态
bool WebSocket::isOpen() const { return impl()->state.load() == State::Open; }

// 判断 WebSocket 是否处于关闭状态
bool WebSocket::isClosed() const { return impl()->state.load() == State::Closed; }

// 获取 WebSocket 支持的最大消息大小
size_t WebSocket::maxMessageSize() const { return impl()->maxMessageSize(); }

// 打开 WebSocket 连接，传入目标 URL
void WebSocket::open(const string &url) { impl()->open(url); }

// 关闭 WebSocket 连接
void WebSocket::close() { impl()->close(); }

// 强制关闭 WebSocket 连接
void WebSocket::forceClose() { impl()->remoteClose(); }

// 发送消息，支持多种消息类型
bool WebSocket::send(message_variant data) {
	// 1. 将消息打包并发送
	return impl()->outgoing(make_message(std::move(data)));
}

// 发送二进制数据
bool WebSocket::send(const byte *data, size_t size) {
	// 1. 将二进制数据打包并发送
	return impl()->outgoing(make_message(data, data + size, Message::Binary));
}

// 获取远程地址
optional<string> WebSocket::remoteAddress() const {
	// 1. 获取 TCP 传输层对象
	auto tcpTransport = impl()->getTcpTransport();
	// 2. 返回远程地址
	return tcpTransport ? make_optional(tcpTransport->remoteAddress()) : nullopt;
}

// 获取 WebSocket 连接的路径
optional<string> WebSocket::path() const {
	// 1. 获取当前状态
	auto state = impl()->state.load();
	// 2. 获取握手信息
	auto handshake = impl()->getWsHandshake();
	// 3. 返回路径
	return state != State::Connecting && handshake ? make_optional(handshake->path()) : nullopt;
}

// 重载 << 操作符，用于输出 WebSocket 状态
std::ostream &operator<<(std::ostream &out, WebSocket::State state) {
	using State = WebSocket::State;
	const char *str;
	switch (state) {
	case State::Connecting:
		str = "connecting";
		break;
	case State::Open:
		str = "open";
		break;
	case State::Closing:
		str = "closing";
		break;
	case State::Closed:
		str = "closed";
		break;
	default:
		str = "unknown";
		break;
	}
	// 1. 根据状态返回对应的字符串描述
	return out << str;
}

} // namespace rtc

#endif