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

#include "types.hpp"
#include "defs.hpp"

#ifndef DEBUG

#include "builtin.h"

#define ntohs(inval) BSWAP16(inval)
#define htons(inval) BSWAP16(inval)

#define ntohl(inval) BSWAP32(inval)
#define htonl(inval) BSWAP32(inval)

#else

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

extern interface_container        g_interfaces;
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
  arp_table_entry&    e, 
  buffer_descriptor&  bd  
);

extern void 
write_arp_packet
(
  interface&          i,
  arp_table_entry&    e,
  const bool          is_response
);

extern arp_table_entry_ref
find_arp_entry
(
  const address& a
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
    i.tx_frame_size = 0U;

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
      // Altough, fixed priority is not the best idea
      write
      (
        i.tx_frame_buffer, 
        i.tx_frame_size
      );
    }
    else
    {
      // No immediate response is required. Process user packets per step (! TO-DO:Check tx busy)
      TRACE(__FUNCTION__ << ": Process user packets\n");

      for (auto &bd : i.tx_buffer_descriptors)
      {
        auto &f = bd.flags;
        
        if (f.test<valid>())
        {
          TRACE(__FUNCTION__ << ": Process paket\n");
          
          switch(bd.ip_protocol)
          {
            default:
              f.clear<valid, pending>();
              break;
            case UDP:
              TRACE(__FUNCTION__ << ": Paket is UDP\n");
              {
                auto e_ref = find_arp_entry(bd.remote.ip_addr);
                
                if ( e_ref )
                {
                  arp_table_entry &e = *e_ref;
                  
                  TRACE(__FUNCTION__ << ": Found in ARP Table\n");
                  
                  if ( e.is_complete() )
                  {
                    TRACE(__FUNCTION__ << ": and ARP entry is complete\n");
                    
                    write_udp_packet(i, e, bd);
                    
                    f.clear<valid>();
                  }
                  else
                  {
                    TRACE(__FUNCTION__ << ": ARP entry is incomplete\n");
                    // TO-DO... while waiting for response
                    //   retry or remove entry
                  }
                }
                else
                {
                  TRACE(__FUNCTION__ << ": Not in ARP table\n");

                  auto r = haluj::bounded::push_back
                  (
                    g_arp_table,
                    arp_table_entry
                    {
                      {0xFF, 0xFF, 0XFF, 0xFF, 0xFF, 0XFF},
                      bd.remote.ip_addr,
                      false
                    }
                  );

                  if (r)
                  {
                    write_arp_packet(i, g_arp_table.back(), false);
                  }
                }
              }
              
              if (i.tx_frame_size > 0)
              {
                write
                (
                  i.tx_frame_buffer, 
                  i.tx_frame_size
                );
              }

              break;
          }
        }
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

extern std::size_t
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
