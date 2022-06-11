/// \file stack.cpp
/// Source for IPV4 stack implementation
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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <functional>
#include <tuple>

#include "protocol/ipv4/stack.hpp"

namespace protocol
{

namespace ipv4
{

interface_container_type      g_interfaces;
arp_table_type                g_arp_table; 
udp_ports_table_type          g_udp_ports; 
std::size_t                   g_ip_identification;

uint16_t calculate_checksum(uint16_t *ptr, unsigned size)
{
  unsigned i;
  unsigned sum = 0;

  for (i = 0; i < (size >> 1); i++, ptr++)
  {
    sum += *ptr;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);

  return ~sum;
}

template
<
  typename DstContainer,
  typename SrcContainer
>
std::size_t
copy_from_payload_buffer
(
  DstContainer&       dest, 
  const SrcContainer& src, 
  std::size_t         size, 
  std::size_t         first
)
{
  std::size_t last = first + size;

  if (last <= src.size())
  {
    std::memcpy(&dest[0], &src[first], size);
  }
  else
  {
    last -= src.size();
    auto n = size - last;
    std::memcpy(&dest[0], &src[first], n);
    std::memcpy(&dest[n], &src[0],     last);
  }
  
  return last;
}

template
<
  typename DstContainer,
  typename SrcContainer
>
std::size_t
copy_to_payload_buffer
(
  DstContainer&       dest, 
  const SrcContainer& src, 
  std::size_t         size, 
  std::size_t         first
)
{
  std::size_t last = first + size;

  if (last <= dest.size())
  {
    std::memcpy(&dest[first], &src[0], size);
  }
  else
  {
    last -= dest.size();
    auto n = size - last;
    std::memcpy(&dest[first], &src[0], n);
    std::memcpy(&dest[0],     &src[n], last);
  }
  
  return last;
}

void 
write_arp_response
(
  interface&          i,
  const context&      ctxt, 
  const arp_packet*   in_arp_ptr
)
{
  i.tx_frame_size = sizeof(eth_packet_header) + sizeof(arp_packet);
  
  uint8_t           *ptr  = &i.tx_frame_buffer[0];
  eth_packet_header *eth  = (eth_packet_header*) ptr;
  arp_packet        *arp  = (arp_packet*) (ptr + sizeof(eth_packet_header));

  eth->dest_hw_addr       = ctxt.remote_hw_addr;
  eth->source_hw_addr     = i.hw_addr;
  eth->type               = htons(0x806);
  
  arp->htype              = htons(0x0001);
  arp->ptype              = htons(0x0800);
  arp->hlen               = 6;
  arp->plen               = 4;
  arp->opcode             = htons(0x0002);
  
  arp->sender_hw_addr     = i.hw_addr;
  arp->sender_ip_addr     = i.ip_addr;
  arp->target_hw_addr     = in_arp_ptr->sender_hw_addr;
  arp->target_ip_addr     = in_arp_ptr->sender_ip_addr;
  
  TRACE("My HW Addr : " << i.hw_addr << "\n");
}

void 
write_icmp_echo_packet
(
  interface&        i,
  const context&    ctxt,
  ip_packet         *in_ip_ptr,
  icmp_packet       *in_icmp_ptr
)
{
  std::size_t         echo_size = ctxt.last - ctxt.ptr;

  i.tx_frame_size = sizeof(ip_packet) + 
                    sizeof(eth_packet_header) + 
                    sizeof(icmp_packet) +
                    echo_size;
                    
  TRACE(__FUNCTION__ << ":" <<  i.tx_frame_size << "\n");
  
  unsigned char       *ptr  = (unsigned char*) &i.tx_frame_buffer[0];
  eth_packet_header   *eth  = (eth_packet_header*) ptr;
  ip_packet           *ip   = (ip_packet*) (ptr + sizeof(eth_packet_header));
  icmp_packet         *icmp = (icmp_packet*) (ptr + sizeof(ip_packet) + sizeof(eth_packet_header));
  uint8_t             *echo = (uint8_t*) (ptr + sizeof(ip_packet) + sizeof(eth_packet_header) + sizeof(icmp_packet));

  eth->dest_hw_addr         = ctxt.remote_hw_addr;
  eth->source_hw_addr       = i.hw_addr;

  eth->type                 = htons(0x800);
  ip->version_length        = 0x45;
  ip->diff_serv             = 0;
  ip->total_length          = htons(i.tx_frame_size - sizeof(eth_packet_header));
  ip->identification        = htons(g_ip_identification++);
  ip->flags_fragment_offset = 0;
  ip->protocol              = PROTOCOL_ICMP;
  ip->ttl                   = 0x80;
  ip->src_ip                = i.ip_addr;
  ip->dest_ip               = in_ip_ptr->src_ip;
  ip->checksum              = 0;
  ip->checksum              = calculate_checksum( (uint16_t *) ip, 20);
  icmp->type                = 0;
  icmp->code                = 0;
  icmp->checksum            = 0; // default
  icmp->identifier          = in_icmp_ptr->identifier;
  icmp->sequence_number     = in_icmp_ptr->sequence_number;

  std::memcpy(echo, ctxt.ptr, echo_size);

  icmp->checksum            = calculate_checksum( (uint16_t *) icmp, sizeof(icmp_packet) + echo_size);
}

std::optional<arp_table_entry*>
find_arp_entry
(
  const address& a
)
{
  std::optional<arp_table_entry*>  result;
  
  auto it = std::find_if
  (
    std::begin(g_arp_table), 
    std::end(g_arp_table),
    [a](auto &b) -> bool
    {
      return b.ip_addr == a;
    }
  );

  if (it != std::end(g_arp_table))
  {
    result = &(*it);
  }
  
  return result;
}

void 
write_udp_packet
(
  interface&          i, 
  buffer_descriptor&  bd
)
{
  auto e = find_arp_entry(bd.remote.ip_addr);
  
  if ( e )
  {
    TRACE("Found in ARP Table\n");

    std::size_t len = 
      sizeof(ip_packet) + 
      sizeof(eth_packet_header) + 
      sizeof(udp_packet) + 
      bd.size;

    if (len <= c_max_eth_frame_size)
    {
      unsigned char       *ptr      = (unsigned char*) &i.tx_frame_buffer[0];
      eth_packet_header   *eth      = (eth_packet_header*) ptr;
      ip_packet           *ip       = (ip_packet*) (ptr + sizeof(eth_packet_header));
      udp_packet          *udp      = (udp_packet*) (ptr + sizeof(ip_packet) + sizeof(eth_packet_header));
      unsigned char       *payload  = (ptr +  sizeof(ip_packet) + sizeof(eth_packet_header) + sizeof(udp_packet));
      
      i.tx_frame_size = len;
      
      eth->dest_hw_addr         = (*e)->hw_addr;
      eth->source_hw_addr       = i.hw_addr;

      eth->type                 = htons(0x800);
      ip->version_length        = 0x45;
      ip->diff_serv             = 0;
      ip->total_length          = htons(i.tx_frame_size - sizeof(eth_packet_header));
      ip->identification        = htons(g_ip_identification++);
      ip->flags_fragment_offset = 0x0040;
      ip->protocol              = PROTOCOL_UDP;
      ip->ttl                   = 0x80;
      ip->src_ip                = i.ip_addr;
      ip->dest_ip               = bd.remote.ip_addr;
      ip->checksum              = 0;
      ip->checksum              = calculate_checksum( (uint16_t *) ip, 20);

      udp->src_port             = htons(bd.port);
      udp->dest_port            = htons(bd.remote.port);
      udp->length               = htons(sizeof(udp_packet) + bd.size);
      udp->checksum             = 0;

      auto &bd  = i.tx_buffer_descriptors.front();

      auto read_size = std::min(i.tx_frame_size, bd.size);

      copy_from_payload_buffer
      (
        payload, 
        i.tx_payload_buffer, 
        read_size, 
        bd.first
      );

      checksum    udp_checksum;
      // psuedo header 
      udp_checksum.append(&ip->src_ip, sizeof(ip->src_ip));
      udp_checksum.append(&ip->dest_ip, sizeof(ip->src_ip));
      udp_checksum.append(htons(uint16_t(ip->protocol)));
      udp_checksum.append(udp->length);
      udp_checksum.append(udp, sizeof(udp_packet) + bd.size);
      udp->checksum             = udp_checksum.finalize();
      
      TRACE("UDP packet size:" << bd.size << "\n");
    }
    else
    {
      TRACE("UDP packet too big:" << bd.size << "\n");
    }
  }
  else
  {
    TRACE("Not found in ARP Table\n");
  }
}

void
process_arp_packet
(
  interface&  i,
  context&          ctxt
)
{
  // TO-DO size_check
  arp_packet   *arp;
  
  TRACE(__FUNCTION__ << "\n");

  arp = (arp_packet*) ctxt.ptr;

  arp->htype  = ntohs(arp->htype);
  arp->ptype  = ntohs(arp->ptype);
  arp->opcode = ntohs(arp->opcode);
  
  TRACE("Target IP (" << arp->target_ip_addr << ") == My IP(" << i.ip_addr << ")\n");

  if (arp->opcode == 1 &&
      arp->htype  == 1 &&
      arp->ptype  == 0x800 &&
      arp->hlen   == 6 &&
      arp->plen   == 4 &&
      arp->target_ip_addr == i.ip_addr)
  {
    auto e = 
      haluj::bounded::push_back
      (
        g_arp_table,
        arp_table_entry
        {
          arp->sender_hw_addr,
          arp->sender_ip_addr
        }
      );

    if (e)
    {
      TRACE("ARP Entry added\n");
    }
    else
    {
      TRACE("ARP Entry add failed\n");
    }
    
    write_arp_response(i, ctxt, arp);
  }
  else if (arp->opcode == 2)
  {
    // Response
  }
}

void 
process_icmp_packet
(
  interface&  i,
  context&          ctxt,
  ip_packet*        ip_ptr
)
{
  // TO-DO size_check
  icmp_packet   *icmp_ptr = (icmp_packet*) (ctxt.ptr);
  // incoming->icmp = icmp;
  ctxt.ptr  += sizeof(icmp_packet);

  if (icmp_ptr->type == 0x08)
  {
    write_icmp_echo_packet( i, ctxt, ip_ptr, icmp_ptr );
  }
}

void 
process_udp_packet
(
  interface&  i,
  context&          ctxt, 
  ip_packet*        ip_ptr
)
{
  udp_packet      *udp_ptr;
  unsigned        size;

  udp_ptr   = (udp_packet*) ctxt.ptr;
  ctxt.ptr += sizeof(udp_packet);

  size            = ip_ptr->total_length;
  size            -= 28;

  udp_ptr->src_port   = ntohs(udp_ptr->src_port);
  udp_ptr->dest_port  = ntohs(udp_ptr->dest_port);
  udp_ptr->length     = ntohs(udp_ptr->length);
  udp_ptr->length     -= 8;
  
  auto it = 
    std::find_if
    (
      std::begin(g_udp_ports),
      std::end(g_udp_ports),
      [&](auto &p)
      {
        return p.port == udp_ptr->dest_port;
      }
    );

  TRACE(__FUNCTION__ << "\n");
  TRACE("UDP SRC PORT:" << udp_ptr->src_port << "\n");
  TRACE("UDP DST PORT:" << udp_ptr->dest_port << "\n");

  if 
  ( 
    ( it != std::end(g_udp_ports) ) && 
    ( udp_ptr->length == size )
  )
  {
    TRACE("UDP Valid\n");
    
    auto first = (i.rx_buffer_descriptors.size() > 0) ? i.rx_buffer_descriptors.back().last : 0;
    auto last  = copy_to_payload_buffer(i.rx_payload_buffer, ctxt.ptr, size, first);

    if (!i.rx_buffer_descriptors.full())
    {
      i.rx_buffer_descriptors.push
      (
        buffer_descriptor
        {
          first, 
          last,
          size,
          endpoint
          {
            ip_ptr->src_ip,
            udp_ptr->src_port
          },
          udp_ptr->src_port,
          protocol::ipv4::PROTOCOL_UDP
        }
      );
    }
    else
    {
      TRACE("ERROR! Overflow");
    }
  }
  else
  {
    TRACE("UDP Invalid\n");
  }
}

inline void 
process_ip_packet
(
  interface&  i,
  context&    ctxt
)
{
  ip_packet    *ip;

  /*incoming->ip   =*/ ip = (ip_packet*) ctxt.ptr;
  ctxt.ptr  += sizeof(ip_packet);

  if((ip->version_length == 0x45) &&
     (ip->diff_serv == 0) &&
     ((ip->flags_fragment_offset == 0) || 
      (ip->flags_fragment_offset == 0x0040)))
  {
    ip->total_length = ntohs(ip->total_length);
    
    TRACE("IP Packet Total Length:" << ip->total_length << "\n");
    TRACE("IP DEST IP:" << ip->dest_ip << "\n");
    TRACE("IP SRC  IP:" << ip->src_ip << "\n");
    TRACE("IP PROTO  :" << uint32_t(ip->protocol) << "\n");

    if (ip->dest_ip == g_interfaces[0].ip_addr)
    {
      if (ip->protocol == PROTOCOL_UDP) 
      {
        process_udp_packet(i, ctxt, ip);
      }
      else if (ip->protocol == PROTOCOL_ICMP) 
      {
        process_icmp_packet(i, ctxt, ip);
      }
    }
  }
  else
  {
    // Not supported IP header
  }
}

void
process_received_frame
(
  interface&  i, 
  bool        p_soft_address_match,
  bool        p_allow_broadcast
)
{
  context             ctxt;
  eth_packet_header   *eth ;
  static ethernet::address  broadcast_hw_addr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  TRACE(__FUNCTION__ << "\n");

  TRACE("RX length:" << i.rx_frame_size << "\n");

  i.tx_frame_size = 0;

  ctxt.ptr              = i.rx_frame_buffer.begin();
  ctxt.last             = i.rx_frame_buffer.begin() + i.rx_frame_size;
  eth                   = (eth_packet_header*) ctxt.ptr;
  
  ctxt.ptr  += sizeof(eth_packet_header);

  TRACE("Dest Addr :" << eth->dest_hw_addr << "\n");
  TRACE("Src Addr  :" << eth->source_hw_addr << "\n");
  TRACE("Type      :" << std::hex << eth->type << "(N) -> " << ntohs(eth->type) << std::dec << "(H) \n");

  if 
  (
    (i.rx_frame_size >= c_min_eth_frame_size) && 
    (i.rx_frame_size <= c_max_eth_frame_size)
  )
  {    
    ctxt.remote_hw_addr = eth->source_hw_addr;

    if 
    ( 
      (p_allow_broadcast && (broadcast_hw_addr == eth->dest_hw_addr)) ||
      (p_soft_address_match && (g_interfaces[0].hw_addr == eth->dest_hw_addr)) 
    )
    {
      TRACE("Valid Frame\n");
      switch(ntohs(eth->type))
      {
      case 0x0800:
        TRACE("IPv4 packet\n");
        process_ip_packet(i, ctxt);
        break;  
      case 0x0806:
        TRACE("ARP packet\n");
        process_arp_packet(i, ctxt);
        break;  
      default:
        break;
      }
    }
    else
    {
      // Unsupported Frame
    }
  }
  else
  {
      TRACE("Ethernet frame size less than 60\n");
  }
}

void 
initialize()
{}

bool
set
(
  const interface_designator  id,
  ethernet::address           hw_addr, 
  ipv4::address               ip_addr
)
{
  bool result = false;

  if (id < c_interface_table_size)
  {
    auto &n = g_interfaces[id];
    n.hw_addr = hw_addr;
    n.ip_addr = ip_addr;
    result = true;
  }
 
  return result;
}

namespace udp
{

endpoint_designator
bind
(
  const interface_designator id,
  const uint16_t    port
)
{
  endpoint_designator  result;

  TRACE("Binding " << port << " to " << id << "\n");
  
  if ( id < c_interface_table_size )
  {

    auto e = 
      haluj::bounded::push_back
        (
          g_udp_ports, 
          port_descriptor{id, port}
        );
    
    if (e)
    {
      result = g_udp_ports.size() - 1;
    }
  }
  // Return the interface index
  return result;
}

std::size_t 
received_length
(
  const endpoint_designator& ed
)
{
  std::size_t result = 0;
  
  if (ed && *ed < g_udp_ports.size() )
  {
    auto &p = g_udp_ports[*ed];
    
    if (p.ifd < g_interfaces.size())
    {
      interface &i = g_interfaces[p.ifd];
      
      TRACE( __FUNCTION__ << " i.rx_buffer_descriptor.size() " << i.rx_buffer_descriptors.size() << " \n" );
      
      if (!i.rx_buffer_descriptors.empty())
      {
        auto &bd = i.rx_buffer_descriptors.front();
        result = bd.size;
      }
    }
    else
    {
      TRACE("Endpoint invalid");
    }
  }
  
  return result;
}

std::size_t
receive
(
  const endpoint_designator&  ed,
  uint8_t*                    data,
  const std::size_t           size,
  endpoint&                   remote
)
{
  std::size_t  result = 0;
  
  if (ed && *ed < g_udp_ports.size() )
  {
    auto &p   = g_udp_ports[*ed];
    
    if (p.ifd < g_interfaces.size())
    {
      interface &i = g_interfaces[p.ifd];
      
      if ( !i.rx_buffer_descriptors.empty() )
      {
        auto &bd  = i.rx_buffer_descriptors.front();

        auto read_size = std::min(size, bd.size);

        copy_from_payload_buffer
        (
          data, 
          i.rx_payload_buffer, 
          read_size, 
          bd.first
        );
        
        remote = bd.remote;

        i.rx_buffer_descriptors.pop();

        result = read_size;
      }
    }
    else
    {
      TRACE("Endpoint invalid");
    }
  }
  
  return result;
}

void
send
(
  const endpoint_designator&  ed,
  const uint8_t               *data,
  const std::size_t           size,
  const endpoint&             remote
)
{
  if (ed)
  {
    // get port descriptor
    auto &p   = g_udp_ports[*ed];
    
    if (p.ifd < g_interfaces.size())
    {
      interface &i = g_interfaces[p.ifd];
      
      auto first = (i.tx_buffer_descriptors.size() > 0) ? i.tx_buffer_descriptors.back().last : 0;
      auto last  = copy_to_payload_buffer(i.tx_payload_buffer, data, size, first);

      if (!i.tx_buffer_descriptors.full())
      {
        i.tx_buffer_descriptors.push
        (
          buffer_descriptor
          {
            first, 
            last,
            size,
            remote,
            p.port,
            protocol::ipv4::PROTOCOL_UDP
          }
        );      
      } 
      else
      {
        TRACE("ERROR! Transmit overflow\n");
      }
    }
  }
  else
  {
    TRACE("Endpoint invalid\n");
  }
}

} // namespace udp

} // namespace ipv4

} // namespace protocol

