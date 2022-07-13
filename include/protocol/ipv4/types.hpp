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
/// \date   2022

#ifndef PROTOCOL_IPV4_TYPES_HPP
#define PROTOCOL_IPV4_TYPES_HPP

#include "constants.hpp"

#include <optional>
#include <array>

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
  
template<typename T>
using reference =
  std::optional
  <
    std::reference_wrapper<T>
  >;

template<typename T>
using ring_buffer =
  haluj::ring_buffer
  <
    std::array<T, 2>
  >;

struct endpoint
{
  address           ip_addr;
  uint16_t          port;
};

struct eth_packet_header
{
  ethernet::address   dest_hw_addr;
  ethernet::address   source_hw_addr;
  uint16_t            type;
};

struct ip_packet
{
  uint8_t         version_length;
  uint8_t         diff_serv;
  uint16_t        total_length;
  ///
  uint16_t        identification;
  uint16_t        flags_fragment_offset;
  ///
  uint8_t         ttl;
  uint8_t         protocol;
  uint16_t        checksum;
  ///
  address         src_ip;
  ///
  address         dest_ip;
};

struct udp_packet
{
  uint16_t src_port;
  uint16_t dest_port;
  ///
  uint16_t length;
  uint16_t checksum;
};

struct arp_packet
{
  uint16_t      htype;
  uint16_t      ptype;
  /// 
  uint8_t       hlen;
  uint8_t       plen;
  uint16_t      opcode;
  ///
  ethernet::address   sender_hw_addr;
  address             sender_ip_addr;
  ethernet::address   target_hw_addr;
  address             target_ip_addr;
};

struct icmp_packet
{
  uint8_t     type;
  uint8_t     code;
  uint16_t    checksum;
  uint16_t    identifier;
  uint16_t    sequence_number;
};

struct context
{
  uint8_t             *ptr        = nullptr;
  uint8_t             *last       = nullptr;
  ethernet::address   remote_hw_addr;  
};

struct valid    : bit::field<0> {};
struct pending  : bit::field<1> {};
struct transmit : bit::field<2> {};

using  descriptor_flags_t =
  bit::storage
  <
    bit::pack
    <
      uint8_t,
      valid,
      pending,
      transmit
    >
  >;

typedef std::array<uint8_t, c_rx_buffer_size>           payload_buffer_container;
typedef std::array<uint8_t, c_rx_buffer_size>::iterator payload_buffer_iterator;

struct buffer_descriptor
{
  payload_buffer_iterator   first;
  payload_buffer_iterator   last;
  std::size_t               size;
  ipv4::endpoint            remote;
  uint16_t                  port;       
  uint8_t                   ip_protocol;
  descriptor_flags_t        flags;
};

typedef reference<buffer_descriptor>                              buffer_descriptor_ref;
typedef std::array<buffer_descriptor, c_buffer_descriptor_size>   buffer_descriptor_container;

struct interface
{
  ethernet::address                             hw_addr;
  address                                       ip_addr;
  payload_buffer_container                      rx_payload_buffer;
  payload_buffer_container                      tx_payload_buffer;
  buffer_descriptor_container                   rx_buffer_descriptors;
  buffer_descriptor_container                   tx_buffer_descriptors;
  std::array<uint8_t, c_max_eth_frame_size>     rx_frame_buffer;
  std::array<uint8_t, c_max_eth_frame_size>     tx_frame_buffer;
  std::size_t                                   rx_frame_size;
  std::size_t                                   tx_frame_size;
};

typedef reference<interface>                interface_ref;

struct arp_table_entry
{
  /// Types
  struct complete : bit::field<0> {};
  
  using  flags_pack_t =
    bit::pack
    <
      uint8_t,
      complete
    >;
    
  using flags_t = 
    bit::storage<flags_pack_t>;
    
  /// Constructors
  
  arp_table_entry()
  {}

  arp_table_entry(const arp_table_entry& other)
  : hw_addr(other.hw_addr),
    ip_addr(other.ip_addr),
    flags(other.flags)
  {}

  arp_table_entry
  (
    const ethernet::address&  hwa,
    const address&            ipa,
    const bool                f_complete
  )
  : hw_addr(hwa),
    ip_addr(ipa)
  {
    if(f_complete)
      flags.set<complete>();
    else
      flags.clear<complete>();
  }

  /// Methods
  
  bool is_complete() const
  {
    return flags.test<complete>();
  }
  
  void set_complete()
  {
    flags.set<complete>();
  }

  void clear_complete()
  {
    flags.clear<complete>();
  }
  
  /// Member Variables

  ethernet::address   hw_addr;
  address             ip_addr;
  /// complete flag indicates if the ARP entry has definite hw addr and 
  /// ip addr. In case of sending of a ARP request this flag shall remain 
  /// 0 until the response
  flags_t             flags;
  /// elapsed is not implemented yet. It shall be used to determine the time for 
  /// incomplete entry. 
  // time_point       elapsed;
};

typedef reference<arp_table_entry>                arp_table_entry_ref;

struct port_descriptor
{
  port_descriptor()
  {}
  
  port_descriptor
  (
    interface&  i,
    uint16_t    p
  )
  : intf_ref(i),
    port(p)
  {}

  port_descriptor&
  operator=(const port_descriptor& other)
  {
    intf_ref  = other.intf_ref;
    port      = other.port;
    return *this;
  }
  
  interface_ref                       intf_ref;
  uint16_t                            port;
  ring_buffer<buffer_descriptor_ref>  rx_buffer_descriptor_refs;
};

typedef std::array<interface, c_interface_table_size>                   interface_container;
typedef haluj::bounded::vector<arp_table_entry, c_arp_table_size>       arp_table_type;
typedef haluj::bounded::vector<port_descriptor, c_udp_ports_table_size> udp_ports_table_type;
typedef std::size_t                                                     interface_designator;
typedef std::optional<std::size_t>                                      endpoint_designator;

} // namespace ipv4

} // namespace protocol

//  PROTOCOL_IPV4_TYPES_HPP
#endif 
