/**
 * libdatachannel media receiver example
 * Copyright (c) 2020 Staz Modrzynski
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "rtc/rtc.hpp"

#include <iostream>
#include <memory>
#include <utility>

#include <nlohmann/json.hpp>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
typedef int SOCKET;
#endif

using nlohmann::json;

// 主函数，实现 WebRTC 媒体接收功能
int main() {
	try {
		// 1. 初始化日志系统，设置日志级别为 Debug
		rtc::InitLogger(rtc::LogLevel::Debug);

		// 2. 创建 PeerConnection 对象
		auto pc = std::make_shared<rtc::PeerConnection>();

		// 3. 设置 PeerConnection 状态变化回调
		pc->onStateChange(
		    [](rtc::PeerConnection::State state) { std::cout << "State: " << state << std::endl; });

		// 4. 设置 ICE 候选收集状态变化回调
		pc->onGatheringStateChange([pc](rtc::PeerConnection::GatheringState state) {
			std::cout << "Gathering State: " << state << std::endl;
			if (state == rtc::PeerConnection::GatheringState::Complete) {
				// 4.1 当候选收集完成时，输出本地 SDP 描述
				auto description = pc->localDescription();
				json message = {{"type", description->typeString()},
				                {"sdp", std::string(description.value())}};
				std::cout << message << std::endl;
			}
		});

		// 5. 创建 UDP 套接字，用于接收 RTP 数据包
		SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
		sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // 绑定到本地回环地址
		addr.sin_port = htons(5000); // 绑定到端口 5000

		// 6. 创建视频媒体描述，设置为仅接收模式
		rtc::Description::Video media("video", rtc::Description::Direction::RecvOnly);
		media.addH264Codec(96); // 添加 H.264 编解码器
		media.setBitrate(3000); // 设置比特率为 3Mbps

		// 7. 将视频媒体描述添加到 PeerConnection 中
		auto track = pc->addTrack(media);

		// 8. 创建 RTCP 接收会话，并设置为视频轨道的媒体处理器
		auto session = std::make_shared<rtc::RtcpReceivingSession>();
		track->setMediaHandler(session);

		// 9. 设置视频轨道消息回调，用于接收 RTP 数据包
		track->onMessage(
		    [session, sock, addr](rtc::binary message) {
			    // 9.1 将接收到的 RTP 数据包通过 UDP 发送到指定地址
			    sendto(sock, reinterpret_cast<const char *>(message.data()), int(message.size()), 0,
			           reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
		    },
		    nullptr);

		// 10. 设置本地 SDP 描述
		pc->setLocalDescription();

		// 11. 提示用户输入浏览器的 SDP 应答
		std::cout << "Expect RTP video traffic on localhost:5000" << std::endl;
		std::cout << "Please copy/paste the answer provided by the browser: " << std::endl;
		std::string sdp;
		std::getline(std::cin, sdp);

		// 12. 解析浏览器的 SDP 应答并设置为远程描述
		std::cout << "Got answer" << sdp << std::endl;
		json j = json::parse(sdp);
		rtc::Description answer(j["sdp"].get<std::string>(), j["type"].get<std::string>());
		pc->setRemoteDescription(answer);

		// 13. 等待用户输入以退出程序
		std::cout << "Press any key to exit." << std::endl;
		char dummy;
		std::cin >> dummy;

	} catch (const std::exception &e) {
		// 14. 捕获并输出异常信息
		std::cerr << "Error: " << e.what() << std::endl;
	}
}