/// \file wire.hpp
/// Header layouts, byte order and the Internet checksum.
///
/// Headers are read and written byte by byte at fixed offsets instead of
/// casting the buffer to a struct pointer: that is well defined C++ (no
/// strict aliasing or alignment trouble, e.g. on Cortex-M0) and independent
/// of the byte order of the processor, so no ntohs/htons is needed.
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

#ifndef PROTOCOL_IPV4_WIRE_HPP
#define PROTOCOL_IPV4_WIRE_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "bit/field.hpp"
#include "bit/pack.hpp"
#include "bit/storage.hpp"

namespace protocol
{

namespace ipv4
{

namespace wire
{

// ---- byte order: network order is big endian ------------------------------

constexpr std::uint16_t load16(const std::uint8_t* p)
{
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

constexpr void store16(std::uint8_t* p, const std::uint16_t v)
{
  p[0] = static_cast<std::uint8_t>(v >> 8);
  p[1] = static_cast<std::uint8_t>(v);
}

constexpr std::uint32_t load32(const std::uint8_t* p)
{
  return (std::uint32_t(load16(p)) << 16) | load16(p + 2);
}

constexpr void store32(std::uint8_t* p, const std::uint32_t v)
{
  store16(p, static_cast<std::uint16_t>(v >> 16));
  store16(p + 2, static_cast<std::uint16_t>(v));
}

/// Reads an address (Ethernet or IPv4), e.g. load<ipv4::address>(p)
template<typename Address>
constexpr Address load(const std::uint8_t* p)
{
  Address a{};
  std::copy_n(p, a.size(), a.begin());
  return a;
}

template<typename Address>
constexpr void store(std::uint8_t* p, const Address& a)
{
  std::copy(a.begin(), a.end(), p);
}

// ---- Internet checksum (RFC 1071) -----------------------------------------

/// Sums big endian 16 bit words. Pieces of odd length may follow each other:
/// a byte left over from one piece pairs with the first byte of the next.
class internet_checksum
{
public:
  constexpr internet_checksum& add(std::span<const std::uint8_t> bytes)
  {
    for (const std::uint8_t b : bytes)
    {
      m_sum += m_odd ? b : static_cast<std::uint32_t>(b << 8);
      m_odd = !m_odd;
    }
    return *this;
  }

  constexpr internet_checksum& add16(const std::uint16_t v)
  {
    m_sum += v;
    return *this;
  }

  /// The value to put in a checksum field
  constexpr std::uint16_t result() const
  {
    std::uint32_t s = m_sum;
    while (s >> 16)
      s = (s & 0xFFFFU) + (s >> 16);
    return static_cast<std::uint16_t>(~s);
  }

  /// A header with its checksum field filled in sums to zero
  constexpr bool verifies() const { return result() == 0; }

private:
  std::uint32_t m_sum = 0;
  bool          m_odd = false;
};

// ---- Ethernet II ----------------------------------------------------------

namespace eth
{
  constexpr std::size_t   destination = 0;
  constexpr std::size_t   source      = 6;
  constexpr std::size_t   type        = 12;
  constexpr std::size_t   size        = 14;

  constexpr std::uint16_t type_ipv4   = 0x0800;
  constexpr std::uint16_t type_arp    = 0x0806;
}

// ---- ARP (Ethernet / IPv4 only) -------------------------------------------

namespace arp
{
  constexpr std::size_t   hardware_type   = 0;
  constexpr std::size_t   protocol_type   = 2;
  constexpr std::size_t   hardware_length = 4;
  constexpr std::size_t   protocol_length = 5;
  constexpr std::size_t   opcode          = 6;
  constexpr std::size_t   sender_hw       = 8;
  constexpr std::size_t   sender_ip       = 14;
  constexpr std::size_t   target_hw       = 18;
  constexpr std::size_t   target_ip       = 24;
  constexpr std::size_t   size            = 28;

  constexpr std::uint16_t request         = 1;
  constexpr std::uint16_t reply           = 2;
}

// ---- IPv4 -----------------------------------------------------------------

namespace ip
{
  constexpr std::size_t   version_ihl     = 0;
  constexpr std::size_t   tos             = 1;
  constexpr std::size_t   total_length    = 2;
  constexpr std::size_t   identification  = 4;
  constexpr std::size_t   flags_fragment  = 6;
  constexpr std::size_t   ttl             = 8;
  constexpr std::size_t   protocol        = 9;
  constexpr std::size_t   checksum        = 10;
  constexpr std::size_t   source          = 12;
  constexpr std::size_t   destination     = 16;
  constexpr std::size_t   min_size        = 20;

  constexpr std::uint8_t  icmp            = 0x01;
  constexpr std::uint8_t  tcp             = 0x06;
  constexpr std::uint8_t  udp             = 0x11;

  /// The first byte: version (high nibble) and header length in 32 bit
  /// words (low nibble)
  struct ihl     : bit::field<0, 3> {};
  struct version : bit::field<4, 7> {};
  using version_ihl_t = bit::storage<bit::pack<std::uint8_t, ihl, version>>;

  /// The 16 bit word at flags_fragment
  struct fragment_offset : bit::field<0, 12> {};
  struct more_fragments  : bit::field<13> {};
  struct dont_fragment   : bit::field<14> {};
  using flags_fragment_t =
    bit::storage<bit::pack<std::uint16_t, fragment_offset, more_fragments, dont_fragment>>;
}

// ---- UDP ------------------------------------------------------------------

namespace udp
{
  constexpr std::size_t source_port      = 0;
  constexpr std::size_t destination_port = 2;
  constexpr std::size_t length           = 4;
  constexpr std::size_t checksum         = 6;
  constexpr std::size_t size             = 8;
}

// ---- TCP (RFC 9293) --------------------------------------------------------

namespace tcp
{
  constexpr std::size_t source_port      = 0;
  constexpr std::size_t destination_port = 2;
  constexpr std::size_t sequence         = 4;
  constexpr std::size_t acknowledgment   = 8;
  constexpr std::size_t offset           = 12;
  constexpr std::size_t control          = 13;
  constexpr std::size_t window           = 14;
  constexpr std::size_t checksum         = 16;
  constexpr std::size_t urgent           = 18;
  constexpr std::size_t min_size         = 20;

  /// The byte at offset: header length in 32 bit words (high nibble)
  struct data_offset : bit::field<4, 7> {};
  using offset_t = bit::storage<bit::pack<std::uint8_t, data_offset>>;

  /// The control bits at control
  struct FIN : bit::field<0> {};
  struct SYN : bit::field<1> {};
  struct RST : bit::field<2> {};
  struct PSH : bit::field<3> {};
  struct ACK : bit::field<4> {};
  struct URG : bit::field<5> {};
  using control_t = bit::storage<bit::pack<std::uint8_t, FIN, SYN, RST, PSH, ACK, URG>>;

  /// Options
  constexpr std::uint8_t option_end        = 0;
  constexpr std::uint8_t option_nop        = 1;
  constexpr std::uint8_t option_mss        = 2;
  constexpr std::size_t  option_mss_size   = 4;
  constexpr std::uint8_t option_sack_permitted      = 4;   // RFC 2018
  constexpr std::size_t  option_sack_permitted_size = 2;
  constexpr std::uint8_t option_sack                = 5;
  constexpr std::size_t  max_sack_blocks            = 4;   // 40 bytes of options
}

// ---- ICMP -----------------------------------------------------------------

namespace icmp
{
  constexpr std::size_t  type         = 0;
  constexpr std::size_t  code         = 1;
  constexpr std::size_t  checksum     = 2;
  constexpr std::size_t  size         = 8;

  constexpr std::uint8_t echo_reply   = 0;
  constexpr std::uint8_t echo_request = 8;
}

} // namespace wire

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_WIRE_HPP
#endif
