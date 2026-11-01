/// \file types.hpp
/// Type definitions for IPV4 stack implementation
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

#ifndef PROTOCOL_IPV4_TYPES_HPP
#define PROTOCOL_IPV4_TYPES_HPP

#include "constants.hpp"
#include "packet_pool.hpp"

#include <array>
#include <cstdint>
#include <optional>

#include "bit/field.hpp"
#include "bit/pack.hpp"
#include "bit/storage.hpp"
#include "haluj/bounded/vector.hpp"
#include "haluj/ring_buffer.hpp"

#include "../ethernet/address.hpp"
#include "../ipv4/address.hpp"

namespace protocol
{

namespace ipv4
{

struct endpoint
{
  address           ip_addr{};
  uint16_t          port = 0;

  friend constexpr bool operator==(const endpoint&, const endpoint&) = default;
};

struct interface
{
  ethernet::address hw_addr{};
  address           ip_addr{};
};

typedef std::size_t                 interface_designator;
typedef std::optional<std::size_t>  endpoint_designator;

using packet_pool_type =
  packet_pool
  <
    c_packet_pool_size,
    c_packet_block_size,
    c_packet_block_alignment,
    c_packet_headroom
  >;

struct arp_table_entry
{
  /// complete: the hardware address is known. An entry made for a datagram
  /// to an unknown host stays incomplete until the host answers.
  struct complete : bit::field<0> {};

  using flags_t = bit::storage<bit::pack<uint8_t, complete>>;

  bool is_complete() const    { return flags.test<complete>(); }
  void set_complete()         { flags.set<complete>(); }

  ethernet::address   hw_addr{};
  address             ip_addr{};
  flags_t             flags{};
  /// Stamp of the last use: the least recently used entry is replaced
  /// when the table is full
  uint32_t            last_used = 0;
  /// Incomplete entries: tick of the last request and how many were sent
  uint32_t            last_request = 0;
  uint8_t             requests = 0;
};

/// Received datagrams of a bound port, in arrival order
using packet_queue =
  haluj::ring_buffer<std::array<packet_id, c_udp_rx_queue_depth>>;

struct port_descriptor
{
  interface_designator  intf = 0;
  uint16_t              port = 0;
  packet_queue          rx{};
};

/// A datagram with its headers still to be written. The payload is in the
/// block, the rest is here until the destination hardware address is known.
struct tx_entry
{
  packet_id             id{};
  interface_designator  intf = 0;
  uint16_t              source_port = 0;
  endpoint              remote{};
};

/// Counters, for diagnostics
struct statistics
{
  uint32_t rx_frames            = 0;
  uint32_t rx_no_buffer         = 0;  ///< a frame waited, the pool was empty
  uint32_t rx_invalid           = 0;  ///< malformed, bad length or checksum
  uint32_t rx_not_for_us        = 0;  ///< other address, type, protocol
  uint32_t rx_no_port           = 0;  ///< UDP to a port nobody bound
  uint32_t rx_queue_full        = 0;  ///< the port's queue was full
  uint32_t tx_frames            = 0;
  uint32_t tx_no_buffer         = 0;  ///< send()/allocate() found the pool empty
  uint32_t tx_queue_full        = 0;
  uint32_t tx_arp_timeout       = 0;  ///< dropped, the host never answered
  uint32_t tx_busy              = 0;  ///< step_dma(): the driver refused a frame
  uint32_t tx_reply_dropped     = 0;  ///< step_dma(): a reply found no room to wait
  uint32_t tcp_retransmits      = 0;  ///< TCP segments sent again
  uint32_t tcp_rx_refused       = 0;  ///< TCP data dropped: no room
  uint32_t tcp_rx_out_of_order  = 0;  ///< TCP segments kept ahead of a gap
  uint32_t tcp_resets_sent      = 0;
};

typedef std::array<interface, c_interface_table_size>                   interface_container;
typedef haluj::bounded::vector<arp_table_entry, c_arp_table_size>       arp_table_type;
typedef haluj::bounded::vector<port_descriptor, c_udp_ports_table_size> udp_ports_table_type;
typedef haluj::bounded::vector<tx_entry, c_tx_queue_size>               tx_queue_type;

} // namespace ipv4

} // namespace protocol

//  PROTOCOL_IPV4_TYPES_HPP
#endif
