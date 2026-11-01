/// \file test_grammar.cpp
/// Tests of the header grammars on their own
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

#include <array>
#include <cstdint>
#include <deque>
#include <span>
#include <vector>

#include "protocol/ipv4/grammar.hpp"

#include "check.hpp"

using namespace protocol::ipv4;

namespace
{

// An ARP request from 10.0.0.1 asking for 10.0.0.2 (RFC 826 field order)
constexpr std::array<std::uint8_t, 28> c_request =
{
  0x00, 0x01,  0x08, 0x00,  6,  4,  0x00, 0x01,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,   10, 0, 0, 1,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   10, 0, 0, 2
};

// The grammar runs at compile time too
static_assert([]
{
  grammar::arp_packet p;
  return grammar::parse_arp(c_request, p) &&
         p.opcode == 1 &&
         p.sender_ip == address{10, 0, 0, 1} &&
         p.target_ip == address{10, 0, 0, 2} &&
         p.sender_hw == protocol::ethernet::address{2, 0, 0, 0, 0, 1};
}());

// An IPv4 header with one word of options (IHL 6), then a UDP header
constexpr std::array<std::uint8_t, 32> c_ipv4_udp =
{
  0x46, 0xB8, 0x00, 0x20,   0x12, 0x34, 0x40, 0x00,   64, 17, 0x00, 0x00,
  10, 0, 0, 1,              10, 0, 0, 2,
  0x01, 0x01, 0x01, 0x00,                             // options: NOP NOP NOP EOL
  0x1F, 0x40, 0x00, 0x07,   0x00, 0x08, 0xAB, 0xCD    // UDP 8000 -> 7, length 8
};

static_assert([]
{
  grammar::ipv4_header h;
  return grammar::parse_ipv4_header(c_ipv4_udp, h) &&
         h.version == 4 && h.ihl == 6 && h.header_length() == 24 &&
         h.total_length == 32 && h.flags_fragment == 0x4000 && h.protocol == 17 &&
         h.source == address{10, 0, 0, 1} && h.destination == address{10, 0, 0, 2};
}());

static_assert([]
{
  grammar::udp_header u;
  return grammar::parse_udp_header(std::span(c_ipv4_udp).subspan(24), u) &&
         u.source_port == 8000 && u.destination_port == 7 &&
         u.length == 8 && u.checksum == 0xABCD;
}());

static_assert(grammar::parse_icmp_echo_request(std::array<std::uint8_t, 8>{8, 0, 0, 0, 0, 1, 0, 2}));
static_assert(!grammar::parse_icmp_echo_request(std::array<std::uint8_t, 8>{0, 0, 0, 0, 0, 1, 0, 2}));
static_assert(!grammar::parse_icmp_echo_request(std::array<std::uint8_t, 7>{8, 0, 0, 0, 0, 1, 0}));

} // namespace

int main()
{
  // Ethernet padding after the packet is ignored
  {
    std::vector<std::uint8_t> padded(c_request.begin(), c_request.end());
    padded.resize(46, 0);
    grammar::arp_packet p;
    PROTOCOL_CHECK(grammar::parse_arp(padded, p) && p.target_ip == address{10, 0, 0, 2});
  }

  // Every prefix is too short, and leaves the output as it was
  for (std::size_t n = 0; n < c_request.size(); ++n)
  {
    std::vector<std::uint8_t> cut(c_request.begin(), c_request.begin() + std::ptrdiff_t(n));
    grammar::arp_packet p;
    p.opcode = 0x55;
    PROTOCOL_CHECK(!grammar::parse_arp(cut, p));
    PROTOCOL_CHECK(p.opcode == 0x55 && p.sender_ip == address{});
  }

  // Each fixed field is checked: a byte above 0x7F as well
  for (std::size_t i : {0U, 1U, 2U, 3U, 4U, 5U})
  {
    auto bad = c_request;
    bad[i] ^= 0x80;
    grammar::arp_packet p;
    PROTOCOL_CHECK(!grammar::parse_arp(bad, p));
  }

  // Any iterator works: a std::deque is not even contiguous
  {
    std::deque<std::uint8_t> d(c_request.begin(), c_request.end());
    grammar::arp_packet p;
    PROTOCOL_CHECK(grammar::parse_arp(d, p) && p.sender_ip == address{10, 0, 0, 1});
  }

  // IPv4: the options the IHL announces must be there
  for (std::size_t n = 20; n < 24; ++n)
  {
    grammar::ipv4_header h;
    PROTOCOL_CHECK(!grammar::parse_ipv4_header(std::span(c_ipv4_udp).first(n), h));
  }

  // IPv4: an IHL below 5 still reads the fixed header; the caller rejects it
  {
    auto bad = c_ipv4_udp;
    bad[0] = 0x43;
    grammar::ipv4_header h;
    PROTOCOL_CHECK(grammar::parse_ipv4_header(bad, h) && h.ihl == 3 && h.header_length() < 20);
  }

  // UDP: 8 bytes or nothing
  for (std::size_t n = 0; n < 8; ++n)
  {
    grammar::udp_header u;
    u.length = 0x55;
    PROTOCOL_CHECK(!grammar::parse_udp_header(std::span(c_ipv4_udp).subspan(24, n), u));
    PROTOCOL_CHECK(u.length == 0x55);
  }

  return protocol_test::report("test_grammar");
}
