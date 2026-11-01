/// \file test_behaviour.cpp
/// Behaviour tests of the IPv4 stack through its public API only: frames go
/// in through step()'s read function and come out through its write function.
/// Each test case runs in its own process (the stack state is global), the
/// case name is the first command line argument.
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

#include <cstring>
#include <deque>
#include <string_view>

#include "protocol/ipv4/stack.hpp"

#include "check.hpp"
#include "frames.hpp"

using namespace protocol;
using frames::bytes;

namespace
{

std::deque<bytes>  g_rx;   // frames waiting to be read by the stack
std::vector<bytes> g_tx;   // frames written by the stack

void run_step()
{
  ipv4::step
  (
    [] { return !g_rx.empty(); },
    [](auto& buffer, std::size_t capacity) -> std::size_t
    {
      bytes f = g_rx.front();
      g_rx.pop_front();
      if (f.size() > capacity) return 0;
      std::copy(f.begin(), f.end(), buffer.begin());
      return f.size();
    },
    [](auto& buffer, std::size_t size) -> std::size_t
    {
      g_tx.emplace_back(buffer.begin(), buffer.begin() + std::ptrdiff_t(size));
      return size;
    }
  );
}

/// Feed frames and step until all are read, then a few more steps
void deliver(std::initializer_list<bytes> fs, int extra_steps = 2)
{
  for (auto& f : fs) g_rx.push_back(f);
  while (!g_rx.empty()) run_step();
  for (int k = 0; k < extra_steps; ++k) run_step();
}

void setup()
{
  ipv4::initialize();
  ipv4::set(0, frames::stack_mac, frames::stack_ip);
}

std::size_t count_tx(auto predicate)
{
  return std::size_t(std::count_if(g_tx.begin(), g_tx.end(), predicate));
}

// --------------------------------------------------------------------------

/// Every host asking for our address gets a reply, however many hosts there are
void arp_reply_to_many_hosts()
{
  setup();
  for (std::uint8_t h = 10; h < 26; ++h)
  {
    g_tx.clear();
    deliver({frames::arp_request(h)});
    PROTOCOL_CHECK(count_tx([&](const bytes& f)
    {
      return frames::is_arp(f, 2) && frames::arp_target_ip(f) == frames::host_ip(h);
    }) == 1);
  }
}

/// A burst of datagrams of varying sizes, each read before the next arrives,
/// never exhausts the stack's memory
void udp_receive_mixed_sizes()
{
  setup();
  auto ed = ipv4::udp::bind(0, 8000);
  PROTOCOL_CHECK(ed.has_value());

  const std::size_t sizes[] = {10, 300, 100, 1000, 50, 1400, 1, 1472, 700};
  std::uint8_t buffer[2048];

  for (int round = 0; round < 10; ++round)
  {
    for (std::size_t n : sizes)
    {
      bytes data = frames::pattern(n, std::uint8_t(round));
      deliver({frames::udp_frame(10, 5000, 8000, data)}, 0);

      PROTOCOL_CHECK(ipv4::udp::received_length(ed) == n);

      ipv4::endpoint remote{};
      std::size_t got = ipv4::udp::receive(ed, buffer, sizeof buffer, remote);
      PROTOCOL_CHECK(got == n);
      PROTOCOL_CHECK(std::memcmp(buffer, data.data(), n) == 0);
      PROTOCOL_CHECK(remote.ip_addr == frames::host_ip(10));
      PROTOCOL_CHECK(remote.port == 5000);
    }
  }
}

/// Two datagrams waiting on a port come out in order
void udp_receive_queued_in_order()
{
  setup();
  auto ed = ipv4::udp::bind(0, 8000);
  deliver({frames::udp_frame(10, 1, 8000, frames::pattern(20, 1)),
           frames::udp_frame(11, 2, 8000, frames::pattern(30, 2))});

  std::uint8_t buffer[64];
  ipv4::endpoint remote{};
  PROTOCOL_CHECK(ipv4::udp::receive(ed, buffer, sizeof buffer, remote) == 20);
  PROTOCOL_CHECK(remote.port == 1);
  PROTOCOL_CHECK(ipv4::udp::receive(ed, buffer, sizeof buffer, remote) == 30);
  PROTOCOL_CHECK(remote.port == 2);
  PROTOCOL_CHECK(ipv4::udp::received_length(ed) == 0);
}

/// An IP total length larger than what arrived is dropped, never read past
/// the received frame
void udp_lying_total_length_dropped()
{
  setup();
  auto ed = ipv4::udp::bind(0, 8000);

  frames::ip_options lie;
  lie.total_length = 1400;
  deliver({frames::udp_frame(10, 1, 8000, frames::pattern(18), lie)});
  PROTOCOL_CHECK(ipv4::udp::received_length(ed) == 0);

  lie.total_length = 2028;
  deliver({frames::udp_frame(10, 1, 8000, frames::pattern(18), lie)});
  PROTOCOL_CHECK(ipv4::udp::received_length(ed) == 0);

  // The UDP length agrees with the lie and the UDP checksum is off: only
  // comparing with the received frame size catches it
  for (std::uint16_t total : {std::uint16_t(1400), std::uint16_t(2028)})
  {
    lie.total_length = total;
    bytes f = frames::udp_frame(10, 1, 8000, frames::pattern(18), lie);
    frames::put16(f, 38, std::uint16_t(total - 20));
    frames::put16(f, 40, 0);
    deliver({f});
    PROTOCOL_CHECK(ipv4::udp::received_length(ed) == 0);
  }
}

/// A datagram with a broken IP header checksum is dropped
void udp_bad_ip_checksum_dropped()
{
  setup();
  auto ed = ipv4::udp::bind(0, 8000);
  frames::ip_options bad;
  bad.bad_checksum = true;
  deliver({frames::udp_frame(10, 1, 8000, frames::pattern(18), bad)});
  PROTOCOL_CHECK(ipv4::udp::received_length(ed) == 0);
}

/// DSCP / ECN marked datagrams are delivered
void udp_with_tos_delivered()
{
  setup();
  auto ed = ipv4::udp::bind(0, 8000);
  frames::ip_options o;
  o.tos = 0xB8;   // DSCP EF
  deliver({frames::udp_frame(10, 1, 8000, frames::pattern(18), o)});
  PROTOCOL_CHECK(ipv4::udp::received_length(ed) == 18);
}

/// Every datagram sent goes out exactly once with valid checksums
void udp_send_once_with_valid_checksums()
{
  setup();
  auto ed = ipv4::udp::bind(0, 8000);
  deliver({frames::arp_request(10)});   // the stack learns host 10
  g_tx.clear();

  bytes a = frames::pattern(5, 1), b = frames::pattern(301, 2), c = frames::pattern(7, 3);
  ipv4::udp::send(ed, a.data(), a.size(), {frames::host_ip(10), 9000});
  ipv4::udp::send(ed, b.data(), b.size(), {frames::host_ip(77), 9000});  // unknown
  deliver({});
  ipv4::udp::send(ed, c.data(), c.size(), {frames::host_ip(10), 9001});
  deliver({});

  auto udp_to = [](std::uint16_t port)
  {
    return [port](const bytes& f)
    {
      return frames::is_ipv4(f, 17) && frames::get16(f, 36) == port;
    };
  };
  PROTOCOL_CHECK(count_tx(udp_to(9000)) == 1);
  PROTOCOL_CHECK(count_tx(udp_to(9001)) == 1);
  PROTOCOL_CHECK(count_tx([](const bytes& f)
  {
    return frames::is_arp(f, 1) && frames::arp_target_ip(f) == frames::host_ip(77);
  }) >= 1);

  for (auto& f : g_tx)
  {
    if (frames::is_ipv4(f, 17))
    {
      PROTOCOL_CHECK(frames::udp_valid(f));
      PROTOCOL_CHECK(frames::get16(f, 34) == 8000);
      bytes p = frames::udp_payload(f);
      PROTOCOL_CHECK((p == a || p == c));
    }
  }

  // Host 77 answers: the waiting datagram goes out
  g_tx.clear();
  deliver({frames::arp_reply(77)});
  PROTOCOL_CHECK(count_tx(udp_to(9000)) == 1);
  for (auto& f : g_tx)
    if (frames::is_ipv4(f, 17))
      PROTOCOL_CHECK(frames::udp_payload(f) == b);
}

/// The echo reply carries exactly the echo data, never the Ethernet padding
void icmp_echo_small_padded()
{
  setup();
  deliver({frames::icmp_echo(10, 0x200, 9, frames::pattern(4))});
  PROTOCOL_CHECK(g_tx.size() == 1);
  if (g_tx.size() != 1) return;
  const bytes& r = g_tx[0];
  PROTOCOL_CHECK(frames::is_ipv4(r, 1));
  PROTOCOL_CHECK(frames::ipv4_valid(r));
  PROTOCOL_CHECK(frames::get16(r, 16) == 20 + 8 + 4);
  PROTOCOL_CHECK(r[34] == 0);
  PROTOCOL_CHECK(frames::fold(frames::sum16(&r[34], 12)) == 0);
  PROTOCOL_CHECK(bytes(r.begin() + 42, r.begin() + 46) == frames::pattern(4));
}

void icmp_echo_large()
{
  setup();
  deliver({frames::icmp_echo(10, 1, 2, frames::pattern(1000))});
  PROTOCOL_CHECK(g_tx.size() == 1);
  if (g_tx.size() != 1) return;
  const bytes& r = g_tx[0];
  PROTOCOL_CHECK(frames::ipv4_valid(r));
  PROTOCOL_CHECK(frames::get16(r, 16) == 1028);
  PROTOCOL_CHECK(frames::fold(frames::sum16(&r[34], 1008)) == 0);
  PROTOCOL_CHECK(bytes(r.begin() + 42, r.begin() + 1042) == frames::pattern(1000));
  PROTOCOL_CHECK((std::equal(r.begin(), r.begin() + 6, frames::host_mac(10).begin())));
}

struct test_case { std::string_view name; void (*run)(); };

const test_case g_cases[] =
{
  {"arp_reply_to_many_hosts",            arp_reply_to_many_hosts},
  {"udp_receive_mixed_sizes",            udp_receive_mixed_sizes},
  {"udp_receive_queued_in_order",        udp_receive_queued_in_order},
  {"udp_lying_total_length_dropped",     udp_lying_total_length_dropped},
  {"udp_bad_ip_checksum_dropped",        udp_bad_ip_checksum_dropped},
  {"udp_with_tos_delivered",             udp_with_tos_delivered},
  {"udp_send_once_with_valid_checksums", udp_send_once_with_valid_checksums},
  {"icmp_echo_small_padded",             icmp_echo_small_padded},
  {"icmp_echo_large",                    icmp_echo_large},
};

} // namespace

int main(int argc, char** argv)
{
  if (argc < 2)
  {
    for (auto& c : g_cases) std::printf("%.*s\n", int(c.name.size()), c.name.data());
    return 0;
  }

  for (auto& c : g_cases)
  {
    if (c.name == argv[1])
    {
      c.run();
      return protocol_test::report(argv[1]);
    }
  }

  std::fprintf(stderr, "unknown test case %s\n", argv[1]);
  return 2;
}
