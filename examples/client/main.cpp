/**
 * libdatachannel client example
 * Copyright (c) 2019-2020 Paul-Louis Ageneau
 * Copyright (c) 2019 Murat Dogan
 * Copyright (c) 2020 Will Munn
 * Copyright (c) 2020 Nico Chatzi
 * Copyright (c) 2020 Lara Mackey
 * Copyright (c) 2020 Erik Cota-Robles
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "rtc/rtc.hpp"

#include "parse_cl.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <thread>
#include <unordered_map>
using namespace std;

using namespace std::chrono_literals;
using std::shared_ptr;
using std::weak_ptr;
template <class T> weak_ptr<T> make_weak_ptr(shared_ptr<T> ptr) { return ptr; }

using nlohmann::json;

std::string localId;
std::unordered_map<std::string, shared_ptr<rtc::PeerConnection>> peerConnectionMap;
std::unordered_map<std::string, shared_ptr<rtc::DataChannel>> dataChannelMap;

shared_ptr<rtc::PeerConnection> createPeerConnection(const rtc::Configuration &config,
                                                     weak_ptr<rtc::WebSocket> wws, std::string id);
std::string randomId(size_t length);

int main(int argc, char **argv) try {
	Cmdline params(argc, argv);

	// rtc::InitLogger(rtc::LogLevel::Error);

	// 配置ICE服务器，默认是google的 "stun:stun.l.google.com:19302"
	rtc::Configuration config;
	std::string stunServer = "";
	if (params.noStun()) {
		std::cout
		    << "No STUN server is configured. Only local hosts and public IP addresses supported."
		    << std::endl;
	} else {
		if (params.stunServer().substr(0, 5).compare("stun:") != 0) {
			stunServer = "stun:";
		}
		stunServer += params.stunServer() + ":" + std::to_string(params.stunPort());
		std::cout << "STUN server is " << stunServer << std::endl;
		config.iceServers.emplace_back(stunServer);
	}

	// 配置UDP多路复用（节省端口），后续研究一下
	if (params.udpMux()) {
		std::cout << "ICE UDP mux enabled" << std::endl;
		config.enableIceUdpMux = true;
	}

	localId = params.localId().empty() ? randomId(4) : params.localId();
	std::cout << "The local ID is " << localId << std::endl;

	//xy:2.创建WebSocket用于信令传输
	auto ws = std::make_shared<rtc::WebSocket>();

	std::promise<void> wsPromise;
	auto wsFuture = wsPromise.get_future();

	ws->onOpen([&wsPromise]() {
		std::cout << "WebSocket connected, signaling ready" << std::endl;
		wsPromise.set_value();
	});

	ws->onError([&wsPromise](std::string s) {
		std::cout << "WebSocket error" << std::endl;
		wsPromise.set_exception(std::make_exception_ptr(std::runtime_error(s)));
	});

	ws->onClosed([]() { std::cout << "WebSocket closed" << std::endl; });

	ws->onMessage([&config, wws = make_weak_ptr(ws)](auto data) {
		// data holds either std::string or rtc::binary
		//2.1 只处理文本消息（JSON格式）
		if (!std::holds_alternative<std::string>(data))
			return;
		std::cout << "【receive】:" << std::get<std::string>(data) << std::endl;
		json message = json::parse(std::get<std::string>(data));

		//2.2 消息必须包含id字段（对方节点ID
		auto it = message.find("id");
		if (it == message.end())
			return;

		auto id = it->get<std::string>();

		it = message.find("type");
		if (it == message.end())
			return;

		auto type = it->get<std::string>();

		//2.3 查找或创建PeerConnection
		shared_ptr<rtc::PeerConnection> pc;
		if (auto jt = peerConnectionMap.find(id); jt != peerConnectionMap.end()) {
			//2.4 已有连接 复用
			pc = jt->second;
		} else if (type == "offer") {
			//2.4 收到Offer表示对方主动连接 新建
			std::cout << "Answering to " + id << std::endl;
			pc = createPeerConnection(config, wws, id);
		} else {
			return;
		}

		//2.5 处理不同类型信令
		if (type == "offer" || type == "answer") {
			//2.6 设置远端SDP描述
			auto sdp = message["description"].get<std::string>();
			pc->setRemoteDescription(rtc::Description(sdp, type));
		} else if (type == "candidate") {
			//2.6 添加远端ICE候选
			auto sdp = message["candidate"].get<std::string>();
			auto mid = message["mid"].get<std::string>();
			pc->addRemoteCandidate(rtc::Candidate(sdp, mid));
		}
	});

	// 连接WebSocket信令服务器
	const std::string wsPrefix =
	    params.webSocketServer().find("://") == std::string::npos ? "ws://" : "";
	const std::string url = wsPrefix + params.webSocketServer() + ":" +
	                        std::to_string(params.webSocketPort()) + "/" + localId;

	std::cout << "WebSocket URL is " << url << std::endl;
	ws->open(url);

	std::cout << "Waiting for signaling to be connected..." << std::endl;
	wsFuture.get();// 直到ws onOpen为止才往下走

	// while (true) {
		std::string id;
		std::cout << "Enter a remote ID to send an offer:" << std::endl;
		std::cin >> id;
		std::cin.ignore();

		if (id.empty())
			// break;
			abort();

		if (id == localId) {
			std::cout << "Invalid remote ID (This is the local ID)" << std::endl;
			// continue;
			abort();
		}

		std::cout << "Offering to " + id << std::endl;
		auto pc = createPeerConnection(config, ws, id);

		// We are the offerer, so create a data channel to initiate the process
		const std::string label = "test";
		std::cout << "Creating DataChannel with label \"" << label << "\"" << std::endl;
		auto dc = pc->createDataChannel(label);

		dc->onOpen([id, wdc = make_weak_ptr(dc)]() {
			std::cout << "DataChannel from " << id << " open" << std::endl;
			if (auto dc = wdc.lock())
				dc->send("Hello from " + localId);
		});

		dc->onClosed([id]() { std::cout << "DataChannel from " << id << " closed" << std::endl; });
// FILE* file = fopen("recv.h264", "wb+");

		dc->onMessage([id, wdc = make_weak_ptr(dc)](auto data) {
			// data holds either std::string or rtc::binary
			if (std::holds_alternative<std::string>(data))
				std::cout << "Message from " << id << " received: " << std::get<std::string>(data)
				          << std::endl;
			else
				std::cout << "Binary message from " << id
				          << " received, size=" << std::get<rtc::binary>(data).size() << std::endl;
		});

		dataChannelMap.emplace(id, dc);


	// 6. 创建视频媒体描述，设置为仅接收模式
	// rtc::Description::Video media("video", rtc::Description::Direction::RecvOnly);
	// media.addH264Codec(96); // 添加 H.264 编解码器
	// media.setBitrate(3000); // 设置比特率为 3Mbps
	//
	// // 7. 将视频媒体描述添加到 PeerConnection 中
	// auto track = pc->addTrack(media);
	//
	// // 8. 创建 RTCP 接收会话，并设置为视频轨道的媒体处理器
	// auto session = std::make_shared<rtc::RtcpReceivingSession>();
	// track->setMediaHandler(session);
	//
	// // 9. 设置视频轨道消息回调，用于接收 RTP 数据包
	// track->onMessage(
	// 	[session, f](rtc::binary message) {
	// 		cout << "xy: recevie track msg: " << int(message.size()) << endl;
	// 		// 9.1 将接收到的 RTP 数据包通过 UDP 发送到指定地址
	// 			if(f) {
	// 				cout << "xy: recevie track write to file" << endl;
	// 				fwrite(message.data(), int(message.size()), 1, f);
	// 			}
	// 	},
	// 	[] (std::string str) {
	// 		cout << "xy: recevie str: " << str << endl;
	//
	// 	});
	// pc->setLocalDescription();

	shared_ptr<rtc::Track> t2;
	FILE* f = fopen("recv.h264", "wb+");

	pc->onTrack([&t2, &f](shared_ptr<rtc::Track> track) {
		std::atomic_store(&t2, track);

		t2->onOpen([&t2]() { cout << "Track 2: Track with mid \"" << t2->mid() << "\" is open" << endl; });

		t2->onClosed(
			[&t2]() { cout << "Track 2: Track with mid \"" << t2->mid() << "\" is closed" << endl; });

		t2->onMessage(
		[/*session,*/ f](rtc::binary message) {
			cout << "xy: recevie track msg: " << int(message.size()) << endl;
			// 9.1 将接收到的 RTP 数据包通过 UDP 发送到指定地址
				if(f) {
					cout << "xy: recevie track write to file" << endl;
					fwrite(message.data(), int(message.size()), 1, f);
				}
		},
		[] (std::string str) {
			cout << "xy: recevie str: " << str << endl;

		});
		t2->onFrame([](rtc::binary data, rtc::FrameInfo frame) {
			cout << "xy: recevie onFrame" << data.size() << ", " << frame.timestamp << endl;

		});

		cout << "xy: on track!!!" << endl;
	});


	std::cout << "Cleaning up..." << std::endl;

	dataChannelMap.clear();
	peerConnectionMap.clear();
	std::this_thread::sleep_for(std::chrono::seconds(1000));
	return 0;

} catch (const std::exception &e) {
	std::cout << "Error: " << e.what() << std::endl;
	dataChannelMap.clear();
	peerConnectionMap.clear();
	return -1;
}

// Create and setup a PeerConnection
//两种情况，主动输入id，然后发送给ws
//从ws收到offer消息，给对方返回。
shared_ptr<rtc::PeerConnection> createPeerConnection(const rtc::Configuration &config,
                                                     weak_ptr<rtc::WebSocket> wws, std::string id) {
	auto pc = std::make_shared<rtc::PeerConnection>(config);

	pc->onStateChange(
	    [](rtc::PeerConnection::State state) { std::cout << "State: " << state << std::endl; });

	pc->onGatheringStateChange([](rtc::PeerConnection::GatheringState state) {
		std::cout << "Gathering State: " << state << std::endl;
	});

	pc->onLocalDescription([wws, id](rtc::Description description) {
		json message = {{"id", id},
		                {"type", description.typeString()},
		                {"description", std::string(description)}};
		std::string str = message.dump();
		cout << "[onLocalDescription] pc onLocalDescription" << message.dump() << endl;

		if (auto ws = wws.lock())
			ws->send(message.dump());
	});

	pc->onLocalCandidate([wws, id](rtc::Candidate candidate) {
		json message = {{"id", id},
		                {"type", "candidate"},
		                {"candidate", std::string(candidate)},
		                {"mid", candidate.mid()}};

		if (auto ws = wws.lock())
			ws->send(message.dump());
	});

	pc->onDataChannel([id](shared_ptr<rtc::DataChannel> dc) {
		std::cout << "DataChannel from " << id << " received with label \"" << dc->label() << "\""
		          << std::endl;

		dc->onOpen([wdc = make_weak_ptr(dc)]() {
			if (auto dc = wdc.lock())
				dc->send("Hello from " + localId);
		});

		dc->onClosed([id]() { std::cout << "DataChannel from " << id << " closed" << std::endl; });

		dc->onMessage([id](auto data) {
			// data holds either std::string or rtc::binary
			if (std::holds_alternative<std::string>(data))
				std::cout << "Message from " << id << " received: " << std::get<std::string>(data)
				          << std::endl;
			else
				std::cout << "Binary message from " << id
				          << " received, size=" << std::get<rtc::binary>(data).size() << std::endl;
		});

		dataChannelMap.emplace(id, dc);
	});

	peerConnectionMap.emplace(id, pc);
	return pc;
};

// Helper function to generate a random ID
std::string randomId(size_t length) {
	using std::chrono::high_resolution_clock;
	static thread_local std::mt19937 rng(
	    static_cast<unsigned int>(high_resolution_clock::now().time_since_epoch().count()));
	static const std::string characters(
	    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
	std::string id(length, '0');
	std::uniform_int_distribution<int> uniform(0, int(characters.size() - 1));
	std::generate(id.begin(), id.end(), [&]() { return characters.at(uniform(rng)); });
	return "bbbb";
}
