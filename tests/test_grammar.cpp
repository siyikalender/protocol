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

  return protocol_test::report("test_grammar");
}
