/// \file internal.hpp
/// What the parts of the IPv4 stack share with each other (stack.cpp,
/// tcp.cpp). Not for applications.
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
/// \author Claude Opus 5.5 <noreply@anthropic.com>
/// \date   2026

#ifndef PROTOCOL_IPV4_INTERNAL_HPP
#define PROTOCOL_IPV4_INTERNAL_HPP

#include <cstddef>
#include <cstdint>
#include <optional>

#include "protocol/ipv4/stack.hpp"
#include "protocol/ipv4/wire.hpp"

namespace protocol
{

namespace ipv4
{

namespace internal
{

inline const ethernet::address c_broadcast_hw{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline const address           c_broadcast_ip{0xFF, 0xFF, 0xFF, 0xFF};
inline const address           c_unspecified_ip{0, 0, 0, 0};

extern statistics     g_stats;
/// The tick of the step running now
extern std::uint32_t  g_now;

// ---- frames -----------------------------------------------------------------

/// Bytes in front of the valid range of the block
std::size_t front_room(packet_id p);

/// Zero pads a frame to the Ethernet minimum
void pad(packet_id p);

void write_ethernet_header(std::uint8_t* e, const ethernet::address& destination,
                           const interface& itf, std::uint16_t type);

/// A 20 byte IPv4 header from the interface to destination
void write_ipv4_header(std::uint8_t* h, const interface& itf, const address& destination,
                       std::uint8_t protocol, std::size_t payload_length);

// ---- ARP table --------------------------------------------------------------

arp_table_entry* find_arp_entry(const address& a);
arp_table_entry* insert_arp_entry(const address& ip_addr, const ethernet::address& hw_addr,
                                  bool complete);
void             touch(arp_table_entry& e);

// ---- who owns a block ---------------------------------------------------------
//
// A frame given to the driver is "in flight" until the driver is done with
// it. TCP "pins" the blocks of segments it may have to send again. A block
// goes back to the pool when it is neither.

/// The frame leaves the stack for the driver
void emit(packet_id p);
/// The driver is done with the frame
void sent(packet_id p);
bool in_flight(packet_id p);

void pin(packet_id p);
void unpin(packet_id p);

// ---- received packets ---------------------------------------------------------

enum class verdict
{
  drop,     ///< free the block
  keep,     ///< the block was queued
  reply     ///< the block now holds a frame to send
};

verdict invalid();
verdict not_for_us();

// ---- TCP (tcp.cpp) --------------------------------------------------------------

/// A segment for us; the block's valid range is the TCP header and data
verdict tcp_process(interface_designator id, const interface& itf, packet_id p,
                    std::uint8_t* e, const std::uint8_t* h);

/// The next TCP frame to send on the interface
std::optional<packet_id> tcp_next_frame(interface_designator id, std::uint32_t tick);

/// A connection waits for the hardware address of a
bool tcp_waiting_for(const address& a);

/// a never answered ARP: its connections fail
void tcp_arp_failed(const address& a);

void tcp_initialize();

} // namespace internal

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_INTERNAL_HPP
#endif
