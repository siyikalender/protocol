/// \file constants.hpp
/// Constant declarations for IPV4 stack implementation
/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>
*/
/// \author Selcuk Iyikalender
/// \author Claude Opus 5.5 <noreply@anthropic.com>
/// \date   2022
#ifndef PROTOCOL_IPV4_CONSTANTS_HPP
#define PROTOCOL_IPV4_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

namespace protocol
{

namespace ipv4
{

constexpr uint8_t   ICMP = 0x01;
constexpr uint8_t   TCP  = 0x06;
constexpr uint8_t   UDP  = 0x11;

constexpr std::size_t c_min_eth_frame_size      = 60;   // without FCS
constexpr std::size_t c_max_eth_frame_size      = 1514; // without FCS, no VLAN tag
constexpr std::size_t c_max_udp_payload_size    = c_max_eth_frame_size - 14 - 20 - 8; // 1472

constexpr std::size_t c_interface_table_size    = 1;
constexpr std::size_t c_arp_table_size          = 4;
constexpr std::size_t c_udp_ports_table_size    = 8;

// The settings below can be changed per target without editing this file,
// with a compile definition seen by the library and the application alike
// (e.g. target_compile_definitions(protocol_ipv4 PUBLIC ...) in CMake).

#ifndef PROTOCOL_IPV4_PACKET_POOL_SIZE
#define PROTOCOL_IPV4_PACKET_POOL_SIZE        6
#endif

#ifndef PROTOCOL_IPV4_PACKET_BLOCK_ALIGNMENT
#define PROTOCOL_IPV4_PACKET_BLOCK_ALIGNMENT  32
#endif

#ifndef PROTOCOL_IPV4_PACKET_HEADROOM
#define PROTOCOL_IPV4_PACKET_HEADROOM         2
#endif

#ifndef PROTOCOL_IPV4_TCP_CONNECTIONS
#define PROTOCOL_IPV4_TCP_CONNECTIONS         4
#endif

#ifndef PROTOCOL_IPV4_TCP_LISTENERS
#define PROTOCOL_IPV4_TCP_LISTENERS           3
#endif

#ifndef PROTOCOL_IPV4_TCP_RX_SEGMENTS
#define PROTOCOL_IPV4_TCP_RX_SEGMENTS         4
#endif

#ifndef PROTOCOL_IPV4_TCP_TX_SEGMENTS
#define PROTOCOL_IPV4_TCP_TX_SEGMENTS         4
#endif

#ifndef PROTOCOL_IPV4_VERIFY_RX_CHECKSUMS
#define PROTOCOL_IPV4_VERIFY_RX_CHECKSUMS     1
#endif

/// Packet pool: every frame, received or sent, lives in one block of the
/// pool. Memory = c_packet_pool_size * c_packet_block_size (+4 bytes each).
/// With step_dma() the RX ring holds blocks too: see stack.hpp.
constexpr std::size_t c_packet_pool_size        = PROTOCOL_IPV4_PACKET_POOL_SIZE;
/// A multiple of 32 (Cortex-M7 cache line) and of 16 (Kinetis ENET receive
/// buffer size rule), large enough for the headroom plus a full frame
constexpr std::size_t c_packet_block_size       = 1536;
constexpr std::size_t c_packet_block_alignment  = PROTOCOL_IPV4_PACKET_BLOCK_ALIGNMENT;
/// Bytes before the frame in a block. 2 puts the IP header on a 4 byte
/// boundary, which only matters for the application's payload: the stack
/// reads headers byte by byte. DMA drivers use 0, so frames start on the
/// block's aligned address (Kinetis ENET and STM32F7 ETH alike).
constexpr std::size_t c_packet_headroom         = PROTOCOL_IPV4_PACKET_HEADROOM;

/// Reserves between the two directions:
///   - a received datagram is queued on its port only when one block for
///     the next frame plus c_tx_reserved_blocks stay free: ports nobody
///     reads cannot stop sending, nor make the stack deaf to ARP and ping,
///   - udp::allocate()/send() leave c_rx_reserved_blocks free: a burst of
///     sends cannot stop reception (ARP and ping replies are made in the
///     received block).
constexpr std::size_t c_tx_reserved_blocks      = 1;
constexpr std::size_t c_rx_reserved_blocks      = 1;
static_assert(c_rx_reserved_blocks >= 1, "one block is always needed to read a frame");

/// Datagrams waiting on one bound port until the application reads them
constexpr std::size_t c_udp_rx_queue_depth      = 2;
/// Datagrams waiting to be sent (e.g. for an ARP reply)
constexpr std::size_t c_tx_queue_size           = 4;
/// step_dma(): finished frames the driver refused (TX ring full), sent first
/// at the next step. ARP and ping replies beyond this are dropped.
constexpr std::size_t c_tx_waiting_size         = 2;

/// ARP: a request is repeated after this interval, in the unit of the clock
/// given to step() (milliseconds suggested) or in calls of step() when step()
/// has no clock. Datagrams waiting for a host that did not answer
/// c_arp_max_requests requests are dropped.
constexpr std::uint32_t c_arp_retry_interval    = 1000;
constexpr std::uint8_t  c_arp_max_requests      = 3;

/// Checks the IP, ICMP and UDP checksums of received packets in software.
/// Set to false when the MAC checks them and drops bad frames itself
/// (checksum offload), so the work is not done twice.
constexpr bool          c_verify_rx_checksums   = PROTOCOL_IPV4_VERIFY_RX_CHECKSUMS != 0;

/// TCP. 0 connections leaves TCP out of the build.
///   c_tcp_connections   connections at a time, accepted and opened together
///   c_tcp_listeners     ports listened on at a time
///   c_tcp_backlog       connections a listener holds until accept() takes
///                       them (handshakes going on included)
///   c_tcp_rx_segments   blocks a connection keeps received data in: its
///                       receive window is c_tcp_rx_segments * c_tcp_mss
///   c_tcp_tx_segments   blocks a connection keeps data to send and data sent
///                       but not yet acknowledged in
constexpr std::size_t   c_tcp_connections       = PROTOCOL_IPV4_TCP_CONNECTIONS;
constexpr std::size_t   c_tcp_listeners         = PROTOCOL_IPV4_TCP_LISTENERS;
constexpr std::size_t   c_tcp_backlog           = 2;
constexpr std::size_t   c_tcp_rx_segments       = PROTOCOL_IPV4_TCP_RX_SEGMENTS;
constexpr std::size_t   c_tcp_tx_segments       = PROTOCOL_IPV4_TCP_TX_SEGMENTS;
/// Largest segment sent or announced: a full Ethernet frame
constexpr std::size_t   c_tcp_mss               = c_max_eth_frame_size - 14 - 20 - 20;  // 1460

/// TCP timers, in the unit of the clock given to step() (milliseconds), or
/// in calls of step() without a clock. RFC 6298 asks for a minimum RTO of
/// 1 s; on a LAN 200 ms (as Linux) recovers much faster.
constexpr std::uint32_t c_tcp_rto_initial       = 1000;
constexpr std::uint32_t c_tcp_rto_min           = 200;
constexpr std::uint32_t c_tcp_rto_max           = 60000;
constexpr std::uint8_t  c_tcp_max_retransmits   = 8;
/// Tail loss probe (RFC 8985 7): the probe timeout is twice the smoothed
/// RTT, at least c_tcp_pto_min, plus the longest delayed ACK the peer may
/// take when only one segment is out
constexpr std::uint32_t c_tcp_pto_min           = 10;
constexpr std::uint32_t c_tcp_delayed_ack_max   = 200;
/// TIME-WAIT. RFC 9293 asks for 2 MSL (4 minutes); embedded stacks keep it
/// short to reuse their few connections.
constexpr std::uint32_t c_tcp_time_wait         = 2000;

static_assert(c_tcp_connections < 256 && c_tcp_listeners < 256);
static_assert(c_tcp_connections == 0 || (c_tcp_rx_segments >= 1 && c_tcp_tx_segments >= 2),
              "a TCP connection needs a block to receive in and two to send in (data and FIN)");
static_assert(c_packet_block_size >= c_packet_headroom + c_max_eth_frame_size);
static_assert(c_packet_pool_size > c_tx_reserved_blocks + c_rx_reserved_blocks);
static_assert(c_arp_retry_interval > 0);

} // namespace ipv4

} // namespace protocol

//  PROTOCOL_IPV4_CONSTANTS_HPP
#endif 
