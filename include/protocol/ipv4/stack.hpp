/// \file stack.hpp
/// Header for IPV4 stack implementation
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

#ifndef PROTOCOL_IPV4_HPP
#define PROTOCOL_IPV4_HPP

#include <cstdint>
#include <optional>
#include <array>

#include "haluj/bounded/vector.hpp"
#include "haluj/ring_buffer.hpp"
#include "../ethernet/address.hpp"
#include "../ipv4/address.hpp"

#ifndef DEBUG

#define ntohs(inval) BSWAP16(inval)
#define htons(inval) BSWAP16(inval)

#define ntohl(inval) BSWAP32(inval)
#define htonl(inval) BSWAP32(inval)

#define TRACE(P)

#else

#include <iostream>

inline uint16_t ntohs(uint16_t   p_value)
{
  uint8_t *ptr = reinterpret_cast<uint8_t*>(&p_value);
  uint8_t tmp  = ptr[0];
  ptr[0] = ptr[1];
  ptr[1] = tmp;
  return p_value;
}

inline uint16_t htons(uint16_t   p_value)
{
  return ntohs(p_value);
}

#define TRACE(P) std::cout<<P

#endif

namespace protocol
{

namespace ipv4
{

struct endpoint
{
  address           ip_addr;
  uint16_t          port;
};

constexpr uint8_t   PROTOCOL_ICMP = 0x01;
constexpr uint8_t   PROTOCOL_TCP  = 0x06;
constexpr uint8_t   PROTOCOL_UDP  = 0x11;

constexpr std::size_t c_min_eth_frame_size    = 60;   // without crc
constexpr std::size_t c_max_eth_frame_size    = 1518; // without crc
constexpr std::size_t c_interface_table_size  = 1;
constexpr std::size_t c_arp_table_size        = 4;
constexpr std::size_t c_udp_ports_table_size  = 8;
constexpr std::size_t c_rx_buffer_size        = 2048U;
constexpr std::size_t c_tx_buffer_size        = 2048U;

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

struct buffer_descriptor
{
  std::size_t     first;
  std::size_t     last;
  std::size_t     size;
  ipv4::endpoint  remote;
  uint16_t        port;       
  uint8_t         ip_protocol;
};

struct interface
{
  ethernet::address                                     hw_addr;
  address                                               ip_addr;
  std::array<uint8_t, c_rx_buffer_size>                 rx_payload_buffer;
  std::array<uint8_t, c_tx_buffer_size>                 tx_payload_buffer;
  haluj::ring_buffer<std::array<buffer_descriptor, 4>>  rx_buffer_descriptors;
  haluj::ring_buffer<std::array<buffer_descriptor, 4>>  tx_buffer_descriptors;
  std::array<uint8_t, c_max_eth_frame_size>             rx_frame_buffer;
  std::array<uint8_t, c_max_eth_frame_size>             tx_frame_buffer;
  std::size_t                                           rx_frame_size;
  std::size_t                                           tx_frame_size;
};

struct arp_table_entry
{
  ethernet::address   hw_addr;
  address             ip_addr;
};

struct port_descriptor
{
  std::size_t     ifd;
  uint16_t        port;
};

typedef std::array<interface, c_interface_table_size>                   interface_container_type;
typedef haluj::bounded::vector<arp_table_entry, c_arp_table_size>       arp_table_type;
typedef haluj::bounded::vector<port_descriptor, c_udp_ports_table_size> udp_ports_table_type;
typedef std::size_t                                                     interface_designator;
typedef std::optional<std::size_t>                                      endpoint_designator;

extern interface_container_type   g_interfaces;
extern arp_table_type             g_arp_table; 
extern udp_ports_table_type       g_udp_ports; 
extern std::size_t                g_ip_identification;

struct checksum
{
  void append(const uint16_t p_value)
  {
    sum += p_value;
  }

  template<typename T>
  void append(const T *p_ptr, const unsigned p_size_in_bytes)
  {
    const uint16_t  *ptr = reinterpret_cast<const uint16_t*>(p_ptr);
    unsigned  size = p_size_in_bytes >> 1;
    
    for (unsigned u = 0; u < size; u++, ptr++)
    {
      sum += *ptr;
    }
    
    if ((p_size_in_bytes & 0x01) == 0x01)
    {
      sum += *reinterpret_cast<const uint8_t*>(ptr);
    }
  }
  
  uint16_t finalize()
  {
    while(sum >> 16)
    {
      sum = (sum >> 16) + (sum & 0xFFFF); 
    }
    return ~sum;
  }
  
  unsigned sum = 0U;
};

extern void
process_received_frame
(
  interface&  i, 
  bool        p_soft_address_match,
  bool        p_allow_broadcast
);

extern void 
write_udp_packet
(
  interface&          i, 
  buffer_descriptor&  bd
);

template
<
  typename IsRxAvailableFunction,
  typename ReadFunction,
  typename WriteFunction
>
inline void 
step
(
  IsRxAvailableFunction   is_rx_available,
  ReadFunction            read,
  WriteFunction           write
)
{
  for(auto &i : g_interfaces)
  {
    if (is_rx_available())
    {
      i.rx_frame_size = 
        read
        (
          i.rx_frame_buffer, 
          i.rx_frame_buffer.size()
        );
      
      if (i.rx_frame_size > 0)
      {
        process_received_frame(i, true, true);
      }
      else
      {
        TRACE("ERROR ! Packet read\n");
      }
    }
    
    if (i.tx_frame_size > 0u)
    {
      // Immediate response for ARP and ICMP are priority
      write
      (
        i.tx_frame_buffer, 
        i.tx_frame_size
      );
      
      i.tx_frame_size = 0U;
    }
    else
    {
      // No immediate response is required. Process user packets per step (! TO-DO:Check tx busy)
      TRACE(__FUNCTION__ << ": Process user packets\n");
      
      while(!i.tx_buffer_descriptors.empty())
      {
        auto &bd = i.tx_buffer_descriptors.front();

        TRACE(__FUNCTION__ << ": Process paket\n");
        
        switch(bd.ip_protocol)
        {
          default:break;
          case PROTOCOL_UDP:
            TRACE(__FUNCTION__ << ": Paket is UDP\n");

            write_udp_packet(i, bd);
            
            write
            (
              i.tx_frame_buffer, 
              i.tx_frame_size
            );
            
            break;
        }
        
        i.tx_buffer_descriptors.pop();
      }
    }
  }
}

extern void 
initialize();

extern bool
set
(
  const interface_designator  id,
  ethernet::address           hw_addr, 
  ipv4::address               ip_addr
);

namespace udp
{

extern endpoint_designator
bind
(
  const interface_designator  id,
  const uint16_t              port
);

extern std::size_t 
received_length
(
  const endpoint_designator&  ed
);

extern std::size_t
receive
(
  const endpoint_designator&  ed,
  uint8_t*                    data,
  const std::size_t           size,
  endpoint&                   remote
);

extern void
send
(
  const endpoint_designator&  ed,
  const uint8_t               *data,
  const std::size_t           size,
  const endpoint&             remote
);

} // namespace udp  

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_HPP
#endif
