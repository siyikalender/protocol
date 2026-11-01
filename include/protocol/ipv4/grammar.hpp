/// \file grammar.hpp
/// Received headers described as grammars of haluj::parser, field by field
/// in the order of their specification.
///
/// haluj::parser works on any iterator; its character rules suit text, so
/// the few rules binary headers need are here: a byte or a big endian word
/// of a given value, a field skipped, and a field copied out.
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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <span>

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

// ---- binary rules ----------------------------------------------------------

/// One byte of the given value. haluj::ch() compares with a char, which is
/// signed on some targets: a byte above 0x7F would never match.
struct byte_p
{
  std::uint8_t value;

  template<typename Iterator>
  constexpr bool accept(Iterator& first, Iterator last) const
  {
    if (first == last || static_cast<std::uint8_t>(*first) != value)
      return false;
    ++first;
    return true;
  }
};

constexpr byte_p byte(std::uint8_t value) { return {value}; }

/// A big endian 16 bit word of the given value
struct be16_p
{
  std::uint16_t value;

  template<typename Iterator>
  constexpr bool accept(Iterator& first, Iterator last) const
  {
    return byte_p{static_cast<std::uint8_t>(value >> 8)}.accept(first, last) &&
           byte_p{static_cast<std::uint8_t>(value)}.accept(first, last);
  }
};

constexpr be16_p be16(std::uint16_t value) { return {value}; }

namespace grammar_detail
{
  /// Takes n elements when there are that many, in one step for random
  /// access iterators (one bounds check per field, not per byte)
  template<typename Iterator>
  constexpr bool take(Iterator& first, Iterator last, std::size_t n)
  {
    if constexpr (std::random_access_iterator<Iterator>)
    {
      if (static_cast<std::size_t>(last - first) < n)
        return false;
      first += static_cast<std::ptrdiff_t>(n);
      return true;
    }
    else
    {
      Iterator at = first;
      for (; n > 0; --n, ++at)
        if (at == last)
          return false;
      first = at;
      return true;
    }
  }
} // namespace grammar_detail

/// A field of N bytes whose value does not matter here
template<std::size_t N>
struct skip_p
{
  template<typename Iterator>
  constexpr bool accept(Iterator& first, Iterator last) const
  {
    return grammar_detail::take(first, last, N);
  }
};

template<std::size_t N>
constexpr skip_p<N> skip() { return {}; }

/// A field copied to an address (Ethernet or IPv4) when it matched
template<typename Address>
struct into_p
{
  Address& out;

  template<typename Iterator>
  constexpr bool accept(Iterator& first, Iterator last) const
  {
    const Iterator at = first;
    if (!grammar_detail::take(first, last, out.size()))
      return false;
    std::copy_n(at, out.size(), out.begin());
    return true;
  }
};

template<typename Address>
constexpr into_p<Address> into(Address& out) { return {out}; }

/// A big endian 16 bit field of any value, stored in out
struct be16_into_p
{
  std::uint16_t& out;

  template<typename Iterator>
  constexpr bool accept(Iterator& first, Iterator last) const
  {
    Iterator at = first;
    if (!grammar_detail::take(first, last, 2))
      return false;
    const auto high = static_cast<std::uint8_t>(*at);
    ++at;
    out = static_cast<std::uint16_t>((high << 8) | static_cast<std::uint8_t>(*at));
    return true;
  }
};

constexpr be16_into_p be16_into(std::uint16_t& out) { return {out}; }

// ---- ARP (RFC 826) ------------------------------------------------------------

struct arp_packet
{
  std::uint16_t     opcode = 0;
  ethernet::address sender_hw{};
  address           sender_ip{};
  address           target_ip{};
};

/// An ARP packet for IPv4 over Ethernet. Fills \p out only when the whole
/// packet matches; bytes after the packet (Ethernet padding) are ignored.
template<typename Range>
constexpr bool parse_arp(const Range& packet, arp_packet& out)
{
  using haluj::seq;

  arp_packet p;

  const auto rule =
    seq
    (
      be16(1),                    // ar$hrd  hardware address space: Ethernet
      be16(wire::eth::type_ipv4), // ar$pro  protocol address space: IPv4
      byte(6),                    // ar$hln  hardware address length
      byte(4),                    // ar$pln  protocol address length
      be16_into(p.opcode),        // ar$op   ares_op$REQUEST | ares_op$REPLY
      into(p.sender_hw),          // ar$sha
      into(p.sender_ip),          // ar$spa
      skip<6>(),                  // ar$tha  not needed: our own address, or unknown
      into(p.target_ip)           // ar$tpa
    );

  auto first = std::begin(packet);

  if (!rule.accept(first, std::end(packet)))
    return false;

  out = p;
  return true;
}

// ---- ICMP echo request (RFC 792) -----------------------------------------------

/// An echo request: type 8, code 0, checksum, identifier, sequence number,
/// data. The checksum covers the whole message, so it is checked apart.
template<typename Range>
constexpr bool parse_icmp_echo_request(const Range& message)
{
  using haluj::seq;

  const auto rule =
    seq
    (
      byte(wire::icmp::echo_request), // type
      byte(0),                        // code
      skip<2>(),                      // checksum
      skip<2>(),                      // identifier
      skip<2>(),                      // sequence number
      haluj::rest()                   // data
    );

  auto first = std::begin(message);
  return rule.accept(first, std::end(message));
}

} // namespace grammar

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_GRAMMAR_HPP
#endif
