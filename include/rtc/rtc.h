/**
 * Copyright (c) 2019-2021 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// 该文件定义了 libdatachannel 的 C API 接口，所有接口仅做新增注释，不修改原有代码

#ifndef RTC_C_API
#define RTC_C_API

#include "version.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#ifdef RTC_STATIC
#define RTC_C_EXPORT
#else // dynamic library
#ifdef _WIN32
#ifdef RTC_EXPORTS
#define RTC_C_EXPORT __declspec(dllexport) // building the library
#else
#define RTC_C_EXPORT __declspec(dllimport) // using the library
#endif
#else // not WIN32
#define RTC_C_EXPORT
#endif
#endif

#ifndef RTC_ENABLE_WEBSOCKET
#define RTC_ENABLE_WEBSOCKET 1
#endif

#ifndef RTC_ENABLE_MEDIA
#define RTC_ENABLE_MEDIA 1
#endif

#define RTC_DEFAULT_MTU 1280 // IPv6 minimum guaranteed MTU
// 默认 MTU 值用于确定数据包的最大传输单元

#if RTC_ENABLE_MEDIA
#define RTC_DEFAULT_MAX_FRAGMENT_SIZE ((uint16_t)(RTC_DEFAULT_MTU - 12 - 8 - 40)) // SRTP/UDP/IPv6
#define RTC_DEFAULT_MAX_STORED_PACKET_COUNT 512
// Deprecated, do not use
#define RTC_DEFAULT_MAXIMUM_FRAGMENT_SIZE RTC_DEFAULT_MAX_FRAGMENT_SIZE
#define RTC_DEFAULT_MAXIMUM_PACKET_COUNT_FOR_NACK_CACHE RTC_DEFAULT_MAX_STORED_PACKET_COUNT
// 上述宏定义用于媒体传输相关的默认参数
#endif

#ifdef _WIN32
#ifdef CAPI_STDCALL
#define RTC_API __stdcall
#else
#define RTC_API
#endif
#else // not WIN32
#define RTC_API
#endif

#if defined(__GNUC__) || defined(__clang__)
#define RTC_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define RTC_DEPRECATED __declspec(deprecated)
#else
#define DEPRECATED
#endif
// 定义了编译器相关的弃用属性

// libdatachannel C API
// 以下为 RTC 状态、ICE 状态、信令状态等枚举及相关类型定义

typedef enum {
	RTC_NEW = 0,
	RTC_CONNECTING = 1,
	RTC_CONNECTED = 2,
	RTC_DISCONNECTED = 3,
	RTC_FAILED = 4,
	RTC_CLOSED = 5
} rtcState;
// rtcState 表示 PeerConnection 的整体状态

typedef enum {
	RTC_ICE_NEW = 0,
	RTC_ICE_CHECKING = 1,
	RTC_ICE_CONNECTED = 2,
	RTC_ICE_COMPLETED = 3,
	RTC_ICE_FAILED = 4,
	RTC_ICE_DISCONNECTED = 5,
	RTC_ICE_CLOSED = 6
} rtcIceState;
// rtcIceState 用于表示 ICE 过程中的状态

typedef enum {
	RTC_GATHERING_NEW = 0,
	RTC_GATHERING_INPROGRESS = 1,
	RTC_GATHERING_COMPLETE = 2
} rtcGatheringState;
// rtcGatheringState 表示 ICE 候选收集状态

typedef enum {
	RTC_SIGNALING_STABLE = 0,
	RTC_SIGNALING_HAVE_LOCAL_OFFER = 1,
	RTC_SIGNALING_HAVE_REMOTE_OFFER = 2,
	RTC_SIGNALING_HAVE_LOCAL_PRANSWER = 3,
	RTC_SIGNALING_HAVE_REMOTE_PRANSWER = 4,
} rtcSignalingState;
// rtcSignalingState 表示 SDP 信令交换的状态

typedef enum { // Don't change, it must match plog severity
	RTC_LOG_NONE = 0,
	RTC_LOG_FATAL = 1,
	RTC_LOG_ERROR = 2,
	RTC_LOG_WARNING = 3,
	RTC_LOG_INFO = 4,
	RTC_LOG_DEBUG = 5,
	RTC_LOG_VERBOSE = 6
} rtcLogLevel;
// rtcLogLevel 用于设置日志输出级别

typedef enum {
	RTC_CERTIFICATE_DEFAULT = 0, // ECDSA
	RTC_CERTIFICATE_ECDSA = 1,
	RTC_CERTIFICATE_RSA = 2,
} rtcCertificateType;
// rtcCertificateType 表示证书类型

typedef enum {
	// video
	RTC_CODEC_H264 = 0,
	RTC_CODEC_VP8 = 1,
	RTC_CODEC_VP9 = 2,
	RTC_CODEC_H265 = 3,
	RTC_CODEC_AV1 = 4,

	// audio
	RTC_CODEC_OPUS = 128,
	RTC_CODEC_PCMU = 129,
	RTC_CODEC_PCMA = 130,
	RTC_CODEC_AAC = 131,
} rtcCodec;
// rtcCodec 枚举区分视频与音频编解码器

typedef enum {
	RTC_DIRECTION_UNKNOWN = 0,
	RTC_DIRECTION_SENDONLY = 1,
	RTC_DIRECTION_RECVONLY = 2,
	RTC_DIRECTION_SENDRECV = 3,
	RTC_DIRECTION_INACTIVE = 4
} rtcDirection;
// rtcDirection 表示媒体传输的方向

typedef enum { RTC_TRANSPORT_POLICY_ALL = 0, RTC_TRANSPORT_POLICY_RELAY = 1 } rtcTransportPolicy;
// rtcTransportPolicy 指定 ICE 的传输策略

#define RTC_ERR_SUCCESS 0
#define RTC_ERR_INVALID -1   // invalid argument
#define RTC_ERR_FAILURE -2   // runtime error
#define RTC_ERR_NOT_AVAIL -3 // element not available
#define RTC_ERR_TOO_SMALL -4 // buffer too small
// 定义了各种错误码

// 回调函数类型定义
typedef void(RTC_API *rtcLogCallbackFunc)(rtcLogLevel level, const char *message);
typedef void(RTC_API *rtcDescriptionCallbackFunc)(int pc, const char *sdp, const char *type,
                                                  void *ptr);
typedef void(RTC_API *rtcCandidateCallbackFunc)(int pc, const char *cand, const char *mid,
                                                void *ptr);
typedef void(RTC_API *rtcStateChangeCallbackFunc)(int pc, rtcState state, void *ptr);
typedef void(RTC_API *rtcIceStateChangeCallbackFunc)(int pc, rtcIceState state, void *ptr);
typedef void(RTC_API *rtcGatheringStateCallbackFunc)(int pc, rtcGatheringState state, void *ptr);
typedef void(RTC_API *rtcSignalingStateCallbackFunc)(int pc, rtcSignalingState state, void *ptr);
typedef void(RTC_API *rtcDataChannelCallbackFunc)(int pc, int dc, void *ptr);
typedef void(RTC_API *rtcTrackCallbackFunc)(int pc, int tr, void *ptr);
typedef void(RTC_API *rtcOpenCallbackFunc)(int id, void *ptr);
typedef void(RTC_API *rtcClosedCallbackFunc)(int id, void *ptr);
typedef void(RTC_API *rtcErrorCallbackFunc)(int id, const char *error, void *ptr);
typedef void(RTC_API *rtcMessageCallbackFunc)(int id, const char *message, int size, void *ptr);
typedef void *(RTC_API *rtcInterceptorCallbackFunc)(int pc, const char *message, int size,
                                                    void *ptr);
typedef void(RTC_API *rtcBufferedAmountLowCallbackFunc)(int id, void *ptr);
typedef void(RTC_API *rtcAvailableCallbackFunc)(int id, void *ptr);
typedef void(RTC_API *rtcPliHandlerCallbackFunc)(int tr, void *ptr);
typedef void(RTC_API *rtcRembHandlerCallbackFunc)(int tr, unsigned int bitrate, void *ptr);
// 上述回调函数用于各个状态变化和事件通知

// Log
// 以下接口用于日志初始化

// NULL cb on the first call will log to stdout
RTC_C_EXPORT void rtcInitLogger(rtcLogLevel level, rtcLogCallbackFunc cb);

// User pointer
RTC_C_EXPORT void rtcSetUserPointer(int id, void *ptr);
RTC_C_EXPORT void *rtcGetUserPointer(int i);
// 用户指针接口用于设置和获取与对象 ID 相关的用户数据

// PeerConnection
// 以下结构体和接口用于创建和管理 PeerConnection

typedef struct {
	const char **iceServers;
	int iceServersCount;
	const char *proxyServer; // libnice only
	const char *bindAddress; // libjuice only, NULL means any
	rtcCertificateType certificateType;
	rtcTransportPolicy iceTransportPolicy;
	bool enableIceTcp;    // libnice only
	bool enableIceUdpMux; // libjuice only
	bool disableAutoNegotiation;
	bool forceMediaTransport;
	uint16_t portRangeBegin; // 0 means automatic
	uint16_t portRangeEnd;   // 0 means automatic
	int mtu;                 // <= 0 means automatic
	int maxMessageSize;      // <= 0 means default
} rtcConfiguration;
// rtcConfiguration 定义了创建 PeerConnection 时需要的参数

RTC_C_EXPORT int rtcCreatePeerConnection(const rtcConfiguration *config); // returns pc id
RTC_C_EXPORT int rtcClosePeerConnection(int pc);
RTC_C_EXPORT int rtcDeletePeerConnection(int pc);
// PeerConnection 的创建、关闭和删除接口

RTC_C_EXPORT int rtcSetLocalDescriptionCallback(int pc, rtcDescriptionCallbackFunc cb);
RTC_C_EXPORT int rtcSetLocalCandidateCallback(int pc, rtcCandidateCallbackFunc cb);
RTC_C_EXPORT int rtcSetStateChangeCallback(int pc, rtcStateChangeCallbackFunc cb);
RTC_C_EXPORT int rtcSetIceStateChangeCallback(int pc, rtcIceStateChangeCallbackFunc cb);
RTC_C_EXPORT int rtcSetGatheringStateChangeCallback(int pc, rtcGatheringStateCallbackFunc cb);
RTC_C_EXPORT int rtcSetSignalingStateChangeCallback(int pc, rtcSignalingStateCallbackFunc cb);
// 设置 PeerConnection 状态变化及候选收集、信令状态变化的回调

RTC_C_EXPORT int rtcSetLocalDescription(int pc, const char *type);
RTC_C_EXPORT int rtcSetRemoteDescription(int pc, const char *sdp, const char *type);
RTC_C_EXPORT int rtcAddRemoteCandidate(int pc, const char *cand, const char *mid);
// SDP 描述与候选的设置接口

RTC_C_EXPORT int rtcGetLocalDescription(int pc, char *buffer, int size);
RTC_C_EXPORT int rtcGetRemoteDescription(int pc, char *buffer, int size);

RTC_C_EXPORT int rtcGetLocalDescriptionType(int pc, char *buffer, int size);
RTC_C_EXPORT int rtcGetRemoteDescriptionType(int pc, char *buffer, int size);
// 获取本地和远端 SDP 描述及其类型的接口

RTC_C_EXPORT int rtcGetLocalAddress(int pc, char *buffer, int size);
RTC_C_EXPORT int rtcGetRemoteAddress(int pc, char *buffer, int size);
// 获取 PeerConnection 的本地和远端地址

RTC_C_EXPORT int rtcGetSelectedCandidatePair(int pc, char *local, int localSize, char *remote,
                                             int remoteSize);
// 获取当前选中的候选对

RTC_C_EXPORT bool rtcIsNegotiationNeeded(int pc);
// 判断是否需要重新协商

RTC_C_EXPORT int rtcGetMaxDataChannelStream(int pc);
RTC_C_EXPORT int rtcGetRemoteMaxMessageSize(int pc);
// 数据通道相关信息接口

// DataChannel, Track, and WebSocket common API
// 以下接口为数据通道、媒体轨道和 WebSocket 的通用接口

RTC_C_EXPORT int rtcSetOpenCallback(int id, rtcOpenCallbackFunc cb);
RTC_C_EXPORT int rtcSetClosedCallback(int id, rtcClosedCallbackFunc cb);
RTC_C_EXPORT int rtcSetErrorCallback(int id, rtcErrorCallbackFunc cb);
RTC_C_EXPORT int rtcSetMessageCallback(int id, rtcMessageCallbackFunc cb);
RTC_C_EXPORT int rtcSendMessage(int id, const char *data, int size);
RTC_C_EXPORT int rtcClose(int id);
RTC_C_EXPORT int rtcDelete(int id);
RTC_C_EXPORT bool rtcIsOpen(int id);
RTC_C_EXPORT bool rtcIsClosed(int id);
// 用于设置对象事件回调、发送消息、关闭和删除对象，以及状态查询

RTC_C_EXPORT int rtcMaxMessageSize(int id);
RTC_C_EXPORT int rtcGetBufferedAmount(int id); // total size buffered to send
RTC_C_EXPORT int rtcSetBufferedAmountLowThreshold(int id, int amount);
RTC_C_EXPORT int rtcSetBufferedAmountLowCallback(int id, rtcBufferedAmountLowCallbackFunc cb);
// 发送缓冲区相关接口

// DataChannel, Track, and WebSocket common extended API
// 以下扩展接口用于获取接收缓冲区可用量及设置相关回调
RTC_C_EXPORT int rtcGetAvailableAmount(int id); // total size available to receive
RTC_C_EXPORT int rtcSetAvailableCallback(int id, rtcAvailableCallbackFunc cb);
RTC_C_EXPORT int rtcReceiveMessage(int id, char *buffer, int *size);
// rtcReceiveMessage 接口根据消息类型返回正数（binary）或负数（字符串）的长度

// DataChannel
// 以下接口为 DataChannel 专用接口

typedef struct {
	bool unordered;
	bool unreliable;
	unsigned int maxPacketLifeTime; // ignored if reliable
	unsigned int maxRetransmits;    // ignored if reliable
} rtcReliability;
// rtcReliability 描述数据通道的传输可靠性配置

typedef struct {
	rtcReliability reliability;
	const char *protocol; // empty string if NULL
	bool negotiated;
	bool manualStream;
	uint16_t stream; // numeric ID 0-65534, ignored if manualStream is false
} rtcDataChannelInit;
// rtcDataChannelInit 用于初始化数据通道

RTC_C_EXPORT int rtcSetDataChannelCallback(int pc, rtcDataChannelCallbackFunc cb);
RTC_C_EXPORT int rtcCreateDataChannel(int pc, const char *label); // returns dc id
RTC_C_EXPORT int rtcCreateDataChannelEx(int pc, const char *label,
                                        const rtcDataChannelInit *init); // returns dc id
RTC_C_EXPORT int rtcDeleteDataChannel(int dc);

RTC_C_EXPORT int rtcGetDataChannelStream(int dc);
RTC_C_EXPORT int rtcGetDataChannelLabel(int dc, char *buffer, int size);
RTC_C_EXPORT int rtcGetDataChannelProtocol(int dc, char *buffer, int size);
RTC_C_EXPORT int rtcGetDataChannelReliability(int dc, rtcReliability *reliability);
// 上述接口用于数据通道的创建、删除及信息查询

// Track
// 以下接口为媒体轨道（Track）接口

typedef struct {
	rtcDirection direction;
	rtcCodec codec;
	int payloadType;
	uint32_t ssrc;
	const char *mid;
	const char *name;    // optional
	const char *msid;    // optional
	const char *trackId; // optional, track ID used in MSID
	const char *profile; // optional, codec profile
} rtcTrackInit;
// rtcTrackInit 定义了创建媒体轨道时的参数

RTC_C_EXPORT int rtcSetTrackCallback(int pc, rtcTrackCallbackFunc cb);
RTC_C_EXPORT int rtcAddTrack(int pc, const char *mediaDescriptionSdp); // returns tr id
RTC_C_EXPORT int rtcAddTrackEx(int pc, const rtcTrackInit *init);      // returns tr id
RTC_C_EXPORT int rtcDeleteTrack(int tr);

RTC_C_EXPORT int rtcGetTrackDescription(int tr, char *buffer, int size);
RTC_C_EXPORT int rtcGetTrackMid(int tr, char *buffer, int size);
RTC_C_EXPORT int rtcGetTrackDirection(int tr, rtcDirection *direction);

RTC_C_EXPORT int rtcRequestKeyframe(int tr);    // 请求视频轨道发送关键帧
RTC_C_EXPORT int rtcRequestBitrate(int tr, unsigned int bitrate); // 请求轨道调整比特率
// 轨道接口包括创建、删除、获取描述、请求关键帧及比特率调整

#if RTC_ENABLE_MEDIA

// Media
// 以下接口仅在启用媒体支持时有效，用于媒体相关的 RTP 封包及 RTCP 处理

// Define how OBUs are packetizied in a AV1 Sample
typedef enum {
	RTC_OBU_PACKETIZED_OBU = 0,
	RTC_OBU_PACKETIZED_TEMPORAL_UNIT = 1,
} rtcObuPacketization;
// rtcObuPacketization 定义 AV1 封包方式

// Define how NAL units are separated in a H264/H265 sample
typedef enum {
	RTC_NAL_SEPARATOR_LENGTH = 0,               // first 4 bytes are NAL unit length
	RTC_NAL_SEPARATOR_LONG_START_SEQUENCE = 1,  // 0x00, 0x00, 0x00, 0x01
	RTC_NAL_SEPARATOR_SHORT_START_SEQUENCE = 2, // 0x00, 0x00, 0x01
	RTC_NAL_SEPARATOR_START_SEQUENCE = 3,       // long or short start sequence
} rtcNalUnitSeparator;
// rtcNalUnitSeparator 定义 H264/H265 的 NAL 分隔符格式

typedef struct {
	uint32_t ssrc;
	const char *cname;
	uint8_t payloadType;
	uint32_t clockRate;
	uint16_t sequenceNumber;
	uint32_t timestamp;

	// H264, H265, AV1
	uint16_t maxFragmentSize; // Maximum fragment size, 0 means default

	// H264/H265 only
	rtcNalUnitSeparator nalSeparator; // NAL unit separator

	// AV1 only
	rtcObuPacketization obuPacketization; // OBU paketization for AV1 samples

	uint8_t playoutDelayId;
	uint16_t playoutDelayMin;
	uint16_t playoutDelayMax;
} rtcPacketizerInit;

// Deprecated, do not use
typedef rtcPacketizerInit rtcPacketizationHandlerInit;

typedef struct {
	uint32_t ssrc;
	const char *name;    // optional
	const char *msid;    // optional
	const char *trackId; // optional, track ID used in MSID
} rtcSsrcForTypeInit;
// rtcSsrcForTypeInit 用于为指定媒体类型设置 SSRC

// Opaque type used (via rtcMessage*) to reference an rtc::Message
typedef void *rtcMessage;
// rtcMessage 为不透明消息类型，内部通过 rtc::Message 实现

// Allocate a new opaque message.
// Must be explicitly freed by rtcDeleteOpaqueMessage() unless
// explicitly returned by a media interceptor callback;
RTC_C_EXPORT rtcMessage *rtcCreateOpaqueMessage(void *data, int size);
RTC_C_EXPORT void rtcDeleteOpaqueMessage(rtcMessage *msg);
// 用于创建和删除不透明消息对象

// Set MediaInterceptor on peer connection
RTC_C_EXPORT int rtcSetMediaInterceptorCallback(int id, rtcInterceptorCallbackFunc cb);
// 设置媒体拦截器回调，可对接收到的媒体数据进行处理

// Set a packetizer on track
RTC_C_EXPORT int rtcSetH264Packetizer(int tr, const rtcPacketizerInit *init);
RTC_C_EXPORT int rtcSetH265Packetizer(int tr, const rtcPacketizerInit *init);
RTC_C_EXPORT int rtcSetAV1Packetizer(int tr, const rtcPacketizerInit *init);
RTC_C_EXPORT int rtcSetOpusPacketizer(int tr, const rtcPacketizerInit *init);
RTC_C_EXPORT int rtcSetAACPacketizer(int tr, const rtcPacketizerInit *init);
// 设置各类 RTP 封包器以支持不同编解码器

// Deprecated, do not use
RTC_DEPRECATED static inline int
rtcSetH264PacketizationHandler(int tr, const rtcPacketizationHandlerInit *init) {
	return rtcSetH264Packetizer(tr, init);
}
RTC_DEPRECATED static inline int
rtcSetH265PacketizationHandler(int tr, const rtcPacketizationHandlerInit *init) {
	return rtcSetH265Packetizer(tr, init);
}
RTC_DEPRECATED static inline int
rtcSetAV1PacketizationHandler(int tr, const rtcPacketizationHandlerInit *init) {
	return rtcSetAV1Packetizer(tr, init);
}
RTC_DEPRECATED static inline int
rtcSetOpusPacketizationHandler(int tr, const rtcPacketizationHandlerInit *init) {
	return rtcSetOpusPacketizer(tr, init);
}
RTC_DEPRECATED static inline int
rtcSetAACPacketizationHandler(int tr, const rtcPacketizationHandlerInit *init) {
	return rtcSetAACPacketizer(tr, init);
}
// 上述弃用接口仅用于向后兼容，请使用新版接口

// Chain RtcpReceivingSession on track
RTC_C_EXPORT int rtcChainRtcpReceivingSession(int tr);

// Chain RtcpSrReporter on track
RTC_C_EXPORT int rtcChainRtcpSrReporter(int tr);

// Chain RtcpNackResponder on track
RTC_C_EXPORT int rtcChainRtcpNackResponder(int tr, unsigned int maxStoredPacketsCount);

// Chain PliHandler on track
RTC_C_EXPORT int rtcChainPliHandler(int tr, rtcPliHandlerCallbackFunc cb);

// Chain RembHandler on track
RTC_C_EXPORT int rtcChainRembHandler(int tr, rtcRembHandlerCallbackFunc cb);

// Transform seconds to timestamp using track's clock rate, result is written to timestamp
RTC_C_EXPORT int rtcTransformSecondsToTimestamp(int id, double seconds, uint32_t *timestamp);
// 这些接口用于在 Track 上链接 RTCP/PLI/REMB 等处理器

// Transform timestamp to seconds using track's clock rate, result is written to seconds
RTC_C_EXPORT int rtcTransformTimestampToSeconds(int id, uint32_t timestamp, double *seconds);

// Get current timestamp, result is written to timestamp
RTC_C_EXPORT int rtcGetCurrentTrackTimestamp(int id, uint32_t *timestamp);

// Set RTP timestamp for track identified by given id
RTC_C_EXPORT int rtcSetTrackRtpTimestamp(int id, uint32_t timestamp);

// Get timestamp of last RTCP SR, result is written to timestamp
RTC_C_EXPORT int rtcGetLastTrackSenderReportTimestamp(int id, uint32_t *timestamp);

// Set NeedsToReport flag in RtcpSrReporter handler identified by given track id
RTC_C_EXPORT int rtcSetNeedsToSendRtcpSr(int id);
// 上述接口用于 RTP 时间戳转换及 RTCP SR 发送控制

// Get all available payload types for given codec and stores them in buffer, does nothing if
// buffer is NULL
int rtcGetTrackPayloadTypesForCodec(int tr, const char *ccodec, int *buffer, int size);

// Get all SSRCs for given track
int rtcGetSsrcsForTrack(int tr, uint32_t *buffer, int count);

// Get CName for SSRC
int rtcGetCNameForSsrc(int tr, uint32_t ssrc, char *cname, int cnameSize);

// Get all SSRCs for given media type in given SDP
int rtcGetSsrcsForType(const char *mediaType, const char *sdp, uint32_t *buffer, int bufferSize);

// Set SSRC for given media type in given SDP
int rtcSetSsrcForType(const char *mediaType, const char *sdp, char *buffer, const int bufferSize,
                      rtcSsrcForTypeInit *init);
// 上述接口用于查询和设置 SSRC 及 CName 信息

#endif // RTC_ENABLE_MEDIA

#if RTC_ENABLE_WEBSOCKET

// WebSocket
// 以下接口用于 WebSocket 的创建、删除以及获取连接信息

typedef struct {
	bool disableTlsVerification; // if true, don't verify the TLS certificate
	const char *proxyServer;     // only non-authenticated http supported for now
	const char **protocols;
	int protocolsCount;
	int connectionTimeoutMs; // in milliseconds, 0 means default, < 0 means disabled
	int pingIntervalMs;      // in milliseconds, 0 means default, < 0 means disabled
	int maxOutstandingPings; // 0 means default, < 0 means disabled
	int maxMessageSize;      // <= 0 means default
} rtcWsConfiguration;

RTC_C_EXPORT int rtcCreateWebSocket(const char *url); // returns ws id
RTC_C_EXPORT int rtcCreateWebSocketEx(const char *url, const rtcWsConfiguration *config);
RTC_C_EXPORT int rtcDeleteWebSocket(int ws);

RTC_C_EXPORT int rtcGetWebSocketRemoteAddress(int ws, char *buffer, int size);
RTC_C_EXPORT int rtcGetWebSocketPath(int ws, char *buffer, int size);

// WebSocketServer
// 以下接口用于 WebSocket 服务器的创建、删除和端口获取

typedef void(RTC_API *rtcWebSocketClientCallbackFunc)(int wsserver, int ws, void *ptr);

typedef struct {
	uint16_t port;                  // 0 means automatic selection
	bool enableTls;                 // if true, enable TLS (WSS)
	const char *certificatePemFile; // NULL for autogenerated certificate
	const char *keyPemFile;         // NULL for autogenerated certificate
	const char *keyPemPass;         // NULL if no pass
	const char *bindAddress;        // NULL for any
	int connectionTimeoutMs;        // in milliseconds, 0 means default, < 0 means disabled
	int maxMessageSize;             // <= 0 means default
} rtcWsServerConfiguration;
// rtcWsServerConfiguration 定义 WebSocket 服务器的配置参数

RTC_C_EXPORT int rtcCreateWebSocketServer(const rtcWsServerConfiguration *config,
                                          rtcWebSocketClientCallbackFunc cb); // returns wsserver id
RTC_C_EXPORT int rtcDeleteWebSocketServer(int wsserver);

RTC_C_EXPORT int rtcGetWebSocketServerPort(int wsserver);
// WebSocketServer 接口

#endif

// Optional global preload and cleanup
// 以下接口用于全局预加载和清理 RTC 资源

RTC_C_EXPORT void rtcPreload(void);
RTC_C_EXPORT void rtcCleanup(void);

// SCTP global settings
// 以下结构体及接口用于配置 SCTP 参数，新创建的 PeerConnection 将使用这些设置

typedef struct {
	int recvBufferSize;          // in bytes, <= 0 means optimized default
	int sendBufferSize;          // in bytes, <= 0 means optimized default
	int maxChunksOnQueue;        // in chunks, <= 0 means optimized default
	int initialCongestionWindow; // in MTUs, <= 0 means optimized default
	int maxBurst;                // in MTUs, 0 means optimized default, < 0 means disabled
	int congestionControlModule; // 0: RFC2581 (default), 1: HSTCP, 2: H-TCP, 3: RTCC
	int delayedSackTimeMs;       // in milliseconds, 0 means optimized default, < 0 means disabled
	int minRetransmitTimeoutMs;  // in milliseconds, <= 0 means optimized default
	int maxRetransmitTimeoutMs;  // in milliseconds, <= 0 means optimized default
	int initialRetransmitTimeoutMs; // in milliseconds, <= 0 means optimized default
	int maxRetransmitAttempts;      // number of retransmissions, <= 0 means optimized default
	int heartbeatIntervalMs;        // in milliseconds, <= 0 means optimized default
} rtcSctpSettings;
// rtcSctpSettings 定义了 SCTP 协议的各种调优参数

// Note: SCTP settings apply to newly-created PeerConnections only
RTC_C_EXPORT int rtcSetSctpSettings(const rtcSctpSettings *settings);
// rtcSetSctpSettings 用于设置 SCTP 参数

#ifdef __cplusplus
} // extern "C"
#endif

#endif
