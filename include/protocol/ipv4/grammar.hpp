/// \file grammar.hpp
/// Received headers described as grammars of haluj::parser, field by field
/// in the order of their specification.
///
/// A grammar takes the fields out of a header and checks what is fixed in
/// it (a type, a length). What depends on several fields or on the packet
/// around the header (checksums, lengths against the frame, fragments) is
/// checked by the code that uses the header.
///
/// Each parse function fills its output only when the whole header
/// matched, and ignores the bytes after the header.
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

#ifndef PROTOCOL_IPV4_GRAMMAR_HPP
#define PROTOCOL_IPV4_GRAMMAR_HPP

#include <cstddef>
#include <cstdint>
#include <iterator>

#include "haluj/parser.hpp"

#include "../ethernet/address.hpp"
#include "address.hpp"
#include "wire.hpp"

namespace protocol
{

namespace ipv4
{

namespace grammar
{

/// A field of N bytes. Of fixed width: a sequence of such fields is checked
/// for length once.
template<std::size_t N>
constexpr auto bytes()
{
  return haluj::field<N>();
}

/// Runs rule over the range; on a match out becomes value
template<typename Rule, typename Range, typename Value>
constexpr bool parse(const Rule& rule, const Range& range, const Value& value, Value& out)
{
  auto first = std::begin(range);

  if (!rule.accept(first, std::end(range)))
    return false;

  out = value;
  return true;
}

// ---- ARP (RFC 826) ------------------------------------------------------------

struct arp_packet
{
  std::uint16_t     opcode = 0;
  ethernet::address sender_hw{};
  address           sender_ip{};
  address           target_ip{};
};

/// An ARP packet for IPv4 over Ethernet
template<typename Range>
constexpr bool parse_arp(const Range& packet, arp_packet& out)
{
  using namespace haluj;

  arp_packet p;

  const auto rule =
    seq
    (
      be16(1),                                        // ar$hrd  hardware address space: Ethernet
      be16(wire::eth::type_ipv4),                     // ar$pro  protocol address space: IPv4
      u8(6),                                          // ar$hln  hardware address length
      u8(4),                                          // ar$pln  protocol address length
      action(bytes<2>(), store_be(p.opcode)),           // ar$op   REQUEST or REPLY
      action(bytes<6>(), store_bytes(p.sender_hw)),     // ar$sha
      action(bytes<4>(), store_bytes(p.sender_ip)),     // ar$spa
      bytes<6>(),                                       // ar$tha  not needed
      action(bytes<4>(), store_bytes(p.target_ip))      // ar$tpa
    );

  return parse(rule, packet, p, out);
}

// ---- IPv4 header (RFC 791) -------------------------------------------------------

struct ipv4_header
{
  std::uint8_t      version         = 0;
  std::uint8_t      ihl             = 0;    ///< header length in 32 bit words
  std::uint16_t     total_length    = 0;
  std::uint16_t     flags_fragment  = 0;
  std::uint8_t      protocol        = 0;
  address           source{};
  address           destination{};

  constexpr std::size_t header_length() const { return ihl * 4U; }
};

/// An IPv4 header with its options. Version, IHL, lengths, checksum and
/// fragments are for the caller to check.
template<typename Range>
constexpr bool parse_ipv4_header(const Range& packet, ipv4_header& out)
{
  using namespace haluj;

  ipv4_header h;
  int         options = 0;   // bytes of options, from the IHL

  const auto version_ihl = [&](auto first, auto)
  {
    const wire::ip::version_ihl_t v(static_cast<std::uint8_t>(*first));
    h.version = static_cast<std::uint8_t>(v.value_of<wire::ip::version>());
    h.ihl     = static_cast<std::uint8_t>(v.value_of<wire::ip::ihl>());
    options   = static_cast<int>(h.ihl) * 4 - static_cast<int>(wire::ip::min_size);
  };

  // The fixed part: one length check for all its fields
  const auto fixed_part =
    seq
    (
      action(bytes<1>(), version_ihl),                    // Version, IHL
      bytes<1>(),                                         // Type of Service
      action(bytes<2>(), store_be(h.total_length)),       // Total Length
      bytes<2>(),                                         // Identification
      action(bytes<2>(), store_be(h.flags_fragment)),     // Flags, Fragment Offset
      bytes<1>(),                                         // Time to Live
      action(bytes<1>(), store_be(h.protocol)),           // Protocol
      bytes<2>(),                                         // Header Checksum
      action(bytes<4>(), store_bytes(h.source)),          // Source Address
      action(bytes<4>(), store_bytes(h.destination))      // Destination Address
    );

  const auto rule = seq(fixed_part, vt(options, anychar()));   // Options (none when IHL <= 5)

  return parse(rule, packet, h, out);
}

// ---- UDP header (RFC 768) ----------------------------------------------------------

struct udp_header
{
  std::uint16_t source_port       = 0;
  std::uint16_t destination_port  = 0;
  std::uint16_t length            = 0;
  std::uint16_t checksum          = 0;
};

template<typename Range>
constexpr bool parse_udp_header(const Range& datagram, udp_header& out)
{
  using namespace haluj;

  udp_header u;

  const auto rule =
    seq
    (
      action(bytes<2>(), store_be(u.source_port)),        // Source Port
      action(bytes<2>(), store_be(u.destination_port)),   // Destination Port
      action(bytes<2>(), store_be(u.length)),             // Length
      action(bytes<2>(), store_be(u.checksum))            // Checksum
    );

  return parse(rule, datagram, u, out);
}

// ---- ICMP echo request (RFC 792) -----------------------------------------------

/// An echo request: type 8, code 0, then checksum, identifier, sequence
/// number and data, which the reply keeps as they are
template<typename Range>
constexpr bool parse_icmp_echo_request(const Range& message)
{
  using namespace haluj;

  const auto rule =
    seq
    (
      u8(wire::icmp::echo_request),   // Type
      u8(0),                          // Code
      bytes<2>(),                       // Checksum
      bytes<2>(),                       // Identifier
      bytes<2>()                        // Sequence Number
    );

  auto first = std::begin(message);
  return rule.accept(first, std::end(message));
}

} // namespace grammar

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_GRAMMAR_HPP
#endif
