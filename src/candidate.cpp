/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "candidate.hpp"

#include "impl/internals.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>
#include <unordered_map>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <sys/types.h>

using std::array;
using std::string;

namespace {

// 1. 判断字符串是否以指定前缀开始
inline bool match_prefix(const string &str, const string &prefix) {
	// 如果 str 的长度大于等于前缀长度，并且前缀与 str 开始部分匹配，则返回 true
	return str.size() >= prefix.size() &&
	       std::mismatch(prefix.begin(), prefix.end(), str.begin()).first == prefix.end();
}

// 2. 去除字符串开头的空白字符
inline void trim_begin(string &str) {
	// 使用 std::find_if 找到第一个非空白字符的位置，并删除之前的所有字符
	str.erase(str.begin(),
	          std::find_if(str.begin(), str.end(), [](char c) { return !std::isspace(c); }));
}

// 3. 去除字符串末尾的空白字符
inline void trim_end(string &str) {
	// 利用 reverse iterator 从后往前查找第一个非空白字符，并删除之后的字符
	str.erase(
	    std::find_if(str.rbegin(), str.rend(), [](char c) { return !std::isspace(c); }).base(),
	    str.end());
}

} // namespace

namespace rtc {

// 4. Candidate 构造函数：设置默认值，表示未解析的候选
Candidate::Candidate()
    : mFoundation("none"), mComponent(0), mPriority(0), mTypeString("unknown"),
      mTransportString("unknown"), mType(Type::Unknown), mTransportType(TransportType::Unknown),
      mNode("0.0.0.0"), mService("9"), mFamily(Family::Unresolved), mPort(0) {}

// 5. 根据候选字符串构造 Candidate 对象（调用默认构造后再解析）
Candidate::Candidate(string candidate) : Candidate() {
	if (!candidate.empty())
		parse(std::move(candidate));
}

// 6. 同时设置候选和媒体标识 mid 的构造函数
Candidate::Candidate(string candidate, string mid) : Candidate() {
	if (!candidate.empty())
		parse(std::move(candidate));
	if (!mid.empty())
		mMid.emplace(std::move(mid));
}

// 7. 解析候选字符串，提取各个字段（参照 RFC 8839 格式）
//    在实际 P2P 连接中，这个函数用于将 SDP 中的 candidate 行解析成内部表示
void Candidate::parse(string candidate) {
	using TypeMap_t = std::unordered_map<string, Type>;
	using TcpTypeMap_t = std::unordered_map<string, TransportType>;

	// 7.1 定义候选类型映射，将字符串映射到枚举类型
	static const TypeMap_t TypeMap = {{"host", Type::Host},
	                                  {"srflx", Type::ServerReflexive},
	                                  {"prflx", Type::PeerReflexive},
	                                  {"relay", Type::Relayed}};

	// 7.2 定义 TCP 类型映射（TCP active、passive、so）
	static const TcpTypeMap_t TcpTypeMap = {{"active", TransportType::TcpActive},
	                                        {"passive", TransportType::TcpPassive},
	                                        {"so", TransportType::TcpSo}};

	// 7.3 去掉 candidate 行前缀，如 "a=" 和 "candidate:"
	const std::array prefixes{"a=", "candidate:"};
	for (string prefix : prefixes)
		if (match_prefix(candidate, prefix))
			candidate.erase(0, prefix.size());

	PLOG_VERBOSE << "Parsing candidate: " << candidate;

	// 7.4 通过 istringstream 解析各个字段：foundation, component, transport, priority, node, service, "typ", typeString
	std::istringstream iss(candidate);
	string typ_;
	if (!(iss >> mFoundation >> mComponent >> mTransportString >> mPriority &&
	      iss >> mNode >> mService >> typ_ >> mTypeString && typ_ == "typ"))
		throw std::invalid_argument("Invalid candidate format");

	// 7.5 读取剩余部分作为尾部参数（可能包含 tcptype 等信息），并去除首尾空白
	std::getline(iss, mTail);
	trim_begin(mTail);
	trim_end(mTail);

	// 7.6 根据解析的类型字符串设置枚举类型
	if (auto it = TypeMap.find(mTypeString); it != TypeMap.end())
		mType = it->second;
	else
		mType = Type::Unknown;

	// 7.7 根据传输协议设置传输类型
	if (mTransportString == "UDP" || mTransportString == "udp") {
		mTransportType = TransportType::Udp;
	} else if (mTransportString == "TCP" || mTransportString == "tcp") {
		// 7.7.1 对于 TCP，再从尾部解析 tcptype 信息
		std::istringstream tiss(mTail);
		string tcptype_, tcptype;
		if (tiss >> tcptype_ >> tcptype && tcptype_ == "tcptype") {
			if (auto it = TcpTypeMap.find(tcptype); it != TcpTypeMap.end())
				mTransportType = it->second;
			else
				mTransportType = TransportType::TcpUnknown;

		} else {
			mTransportType = TransportType::TcpUnknown;
		}
	} else {
		mTransportType = TransportType::Unknown;
	}
}

// 8. hintMid：如果尚未设置 mid，则设置媒体标识，用于候选与媒体轨道之间的关联
void Candidate::hintMid(string mid) {
	if (!mMid)
		mMid.emplace(std::move(mid));
}

// 9. changeAddress 重载：修改候选地址，使用新的地址（字符串或端口）
//    在 P2P 连接中，候选地址可能因网络变动而需要更新
void Candidate::changeAddress(string addr) { changeAddress(std::move(addr), mService); }

void Candidate::changeAddress(string addr, uint16_t port) {
	changeAddress(std::move(addr), std::to_string(port));
}

void Candidate::changeAddress(string addr, string service) {
	mNode = std::move(addr);
	mService = std::move(service);

	mFamily = Family::Unresolved;
	mAddress.clear();
	mPort = 0;

	if (!resolve(ResolveMode::Simple))
		throw std::invalid_argument("Invalid candidate address \"" + addr + ":" + service + "\"");
}

// 10. resolve：解析候选地址，将 mNode 和 mService 解析为实际 IP 地址和端口
//     模式 Simple 表示不做 DNS 查询，只解析数字地址；Lookup 则可能进行更深层的解析
bool Candidate::resolve(ResolveMode mode) {
	PLOG_VERBOSE << "Resolving candidate (mode="
	             << (mode == ResolveMode::Simple ? "simple" : "lookup") << "): " << mNode << ' '
	             << mService;

	// 10.1 设置 addrinfo 提示，根据传输协议选择 SOCK_DGRAM 或 SOCK_STREAM
	struct addrinfo hints = {};
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_ADDRCONFIG;
	if (mTransportType == TransportType::Udp) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else if (mTransportType != TransportType::Unknown) {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}

	if (mode == ResolveMode::Simple)
		hints.ai_flags |= AI_NUMERICHOST;

	// 10.2 调用 getaddrinfo 解析地址
	struct addrinfo *result = nullptr;
	if (getaddrinfo(mNode.c_str(), mService.c_str(), &hints, &result) == 0) {
		// 10.3 遍历解析结果，取第一个 IPv4 或 IPv6 地址
		for (auto p = result; p; p = p->ai_next) {
			if (p->ai_family == AF_INET || p->ai_family == AF_INET6) {
				char nodebuffer[MAX_NUMERICNODE_LEN];
				char servbuffer[MAX_NUMERICSERV_LEN];
				if (getnameinfo(p->ai_addr, socklen_t(p->ai_addrlen), nodebuffer,
				                MAX_NUMERICNODE_LEN, servbuffer, MAX_NUMERICSERV_LEN,
				                NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
					try {
						mPort = uint16_t(std::stoul(servbuffer));
					} catch (...) {
						return false;
					}
					mAddress = nodebuffer;
					mFamily = p->ai_family == AF_INET6 ? Family::Ipv6 : Family::Ipv4;
					PLOG_VERBOSE << "Resolved candidate: " << mAddress << ' ' << mPort;
					break;
				}
			}
		}

		freeaddrinfo(result);
	}

	return mFamily != Family::Unresolved;
}

// 11. 以下为各 getter 和操作符重载，用于 Candidate 的输出和比较
Candidate::Type Candidate::type() const { return mType; }

Candidate::TransportType Candidate::transportType() const { return mTransportType; }

uint32_t Candidate::priority() const { return mPriority; }

string Candidate::candidate() const {
	const char sp{' '};
	std::ostringstream oss;
	oss << "candidate:";
	oss << mFoundation << sp << mComponent << sp << mTransportString << sp << mPriority << sp;
	// 11.1 根据是否解析成功，选择输出解析后的地址和端口，或原始的 mNode 和 mService
	if (isResolved())
		oss << mAddress << sp << mPort;
	else
		oss << mNode << sp << mService;

	oss << sp << "typ" << sp << mTypeString;

	if (!mTail.empty())
		oss << sp << mTail;

	return oss.str();
}

string Candidate::mid() const { return mMid.value_or("0"); }

Candidate::operator string() const {
	std::ostringstream line;
	line << "a=" << candidate();
	return line.str();
}

bool Candidate::operator==(const Candidate &other) const {
	return (mFoundation == other.mFoundation && mService == other.mService && mNode == other.mNode);
}

bool Candidate::operator!=(const Candidate &other) const {
	return mFoundation != other.mFoundation;
}

bool Candidate::isResolved() const { return mFamily != Family::Unresolved; }

Candidate::Family Candidate::family() const { return mFamily; }

optional<string> Candidate::address() const {
	return isResolved() ? std::make_optional(mAddress) : nullopt;
}

optional<uint16_t> Candidate::port() const {
	return isResolved() ? std::make_optional(mPort) : nullopt;
}

std::ostream &operator<<(std::ostream &out, const Candidate &candidate) {
	return out << string(candidate);
}

std::ostream &operator<<(std::ostream &out, const Candidate::Type &type) {
	switch (type) {
	case Candidate::Type::Host:
		return out << "host";
	case Candidate::Type::PeerReflexive:
		return out << "prflx";
	case Candidate::Type::ServerReflexive:
		return out << "srflx";
	case Candidate::Type::Relayed:
		return out << "relay";
	default:
		return out << "unknown";
	}
}

std::ostream &operator<<(std::ostream &out, const Candidate::TransportType &transportType) {
	switch (transportType) {
	case Candidate::TransportType::Udp:
		return out << "UDP";
	case Candidate::TransportType::TcpActive:
		return out << "TCP_active";
	case Candidate::TransportType::TcpPassive:
		return out << "TCP_passive";
	case Candidate::TransportType::TcpSo:
		return out << "TCP_so";
	case Candidate::TransportType::TcpUnknown:
		return out << "TCP_unknown";
	default:
		return out << "unknown";
	}
}

} // namespace rtc
