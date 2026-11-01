/// \file test_api.cpp
/// Tests of the zero copy UDP API, the pool reserves and ARP retries.
/// Each test case runs in its own process, the case name is the first
/// command line argument.
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

std::deque<bytes>  g_rx;
std::vector<bytes> g_tx;
std::uint32_t      g_now = 0;    // milliseconds

auto rx_available = [] { return !g_rx.empty(); };

auto read_frame = [](auto& buffer, std::size_t capacity) -> std::size_t
{
  bytes f = g_rx.front();
  g_rx.pop_front();
  if (f.size() > capacity) return 0;
  std::copy(f.begin(), f.end(), buffer.begin());
  return f.size();
};

auto write_frame = [](auto& frame, std::size_t size)
{
  g_tx.emplace_back(frame.begin(), frame.begin() + std::ptrdiff_t(size));
};

void run_step()      { ipv4::step(rx_available, read_frame, write_frame, [] { return g_now; }); }
void run_step_untimed() { ipv4::step(rx_available, read_frame, write_frame); }

void deliver(std::initializer_list<bytes> fs, int extra_steps = 1)
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

bool all_blocks_free()
{
  return ipv4::g_packet_pool.available() == ipv4::c_packet_pool_size;
}

std::size_t count_arp_requests_for(std::uint8_t h)
{
  return std::size_t(std::count_if(g_tx.begin(), g_tx.end(), [&](const bytes& f)
  {
    return frames::is_arp(f, 1) && frames::arp_target_ip(f) == frames::host_ip(h);
  }));
}

// --------------------------------------------------------------------------

/// A datagram is read and answered without a single copy: the reply is
/// built in the block the datagram arrived in
void zero_copy_echo()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  deliver({frames::arp_request(10)});
  g_tx.clear();

  bytes data = frames::pattern(200, 5);
  deliver({frames::udp_frame(10, 4000, 7, data)}, 0);

  auto d = ipv4::udp::receive(ed);
  PROTOCOL_CHECK(d.has_value());
  if (!d) return;
  PROTOCOL_CHECK(d->size() == 200);
  PROTOCOL_CHECK(std::equal(data.begin(), data.end(), d->data().begin()));
  PROTOCOL_CHECK(d->remote == (ipv4::endpoint{frames::host_ip(10), 4000}));

  d->buffer.data()[0] ^= 0xFF;                       // answer with a change
  PROTOCOL_CHECK(ipv4::udp::send(ed, std::move(d->buffer), d->remote));
  PROTOCOL_CHECK(!d->buffer);                        // the stack owns it now

  deliver({});
  PROTOCOL_CHECK(g_tx.size() == 1);
  if (g_tx.size() != 1) return;
  PROTOCOL_CHECK(frames::udp_valid(g_tx[0]));
  bytes expected = data;
  expected[0] ^= 0xFF;
  PROTOCOL_CHECK(frames::udp_payload(g_tx[0]) == expected);
  PROTOCOL_CHECK(frames::get16(g_tx[0], 34) == 7);
  PROTOCOL_CHECK(frames::get16(g_tx[0], 36) == 4000);
  PROTOCOL_CHECK(all_blocks_free());
}

/// allocate() hands out a block to write the payload into; dropping the
/// packet without sending gives the block back
void allocate_and_drop()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  {
    auto p = ipv4::udp::allocate(ed, 100);
    PROTOCOL_CHECK(p.has_value() && p->size() == 100);
    PROTOCOL_CHECK(!all_blocks_free());
  }
  PROTOCOL_CHECK(all_blocks_free());

  PROTOCOL_CHECK(!ipv4::udp::allocate(ed, ipv4::c_max_udp_payload_size + 1));
  PROTOCOL_CHECK(ipv4::udp::allocate(ed, ipv4::c_max_udp_payload_size).has_value());
  PROTOCOL_CHECK(all_blocks_free());
}

/// Ports nobody reads fill their queues, yet sending still works and the
/// pool is never taken completely by received datagrams
void reserves_keep_both_directions_alive()
{
  setup();
  // Every port the table holds: their queues together outgrow the pool
  constexpr std::size_t n = ipv4::c_udp_ports_table_size;
  static_assert(n * ipv4::c_udp_rx_queue_depth > ipv4::c_packet_pool_size);
  ipv4::endpoint_designator ports[n];
  for (std::uint16_t i = 0; i < n; ++i)
    ports[i] = ipv4::udp::bind(0, std::uint16_t(1000 + i));
  deliver({frames::arp_request(10)});

  for (std::size_t k = 0; k < ipv4::c_udp_rx_queue_depth + 1; ++k)
    for (std::uint16_t i = 0; i < n; ++i)
      deliver({frames::udp_frame(10, 1, std::uint16_t(1000 + i), frames::pattern(50))}, 0);

  PROTOCOL_CHECK(ipv4::g_packet_pool.available() == ipv4::c_tx_reserved_blocks + 1);
  PROTOCOL_CHECK(ipv4::stats().rx_no_buffer > 0);

  // Still answers ARP and ping
  g_tx.clear();
  deliver({frames::arp_request(11), frames::icmp_echo(10, 1, 1, frames::pattern(8))});
  PROTOCOL_CHECK(g_tx.size() == 2);

  g_tx.clear();
  bytes m = frames::pattern(10);
  PROTOCOL_CHECK(ipv4::udp::send(ports[0], m.data(), m.size(), {frames::host_ip(10), 9}) == 10);
  deliver({});
  PROTOCOL_CHECK(g_tx.size() == 1 && frames::udp_valid(g_tx[0]));

  // Reading the queues gives every block back
  for (auto& p : ports)
    while (ipv4::udp::receive(p)) {}
  PROTOCOL_CHECK(all_blocks_free());
}

/// A host that never answers: 3 requests one interval apart, then the
/// datagram is dropped and its block freed
void arp_retry_then_timeout()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  bytes m = frames::pattern(10);
  ipv4::udp::send(ed, m.data(), m.size(), {frames::host_ip(99), 9});

  for (g_now = 0; g_now <= 5000; g_now += 100)
    run_step();

  PROTOCOL_CHECK(count_arp_requests_for(99) == ipv4::c_arp_max_requests);
  PROTOCOL_CHECK(ipv4::stats().tx_arp_timeout == 1);
  PROTOCOL_CHECK(all_blocks_free());
  PROTOCOL_CHECK(ipv4::g_arp_table.empty());
}

/// The same without a clock: the interval counts calls of step()
void arp_retry_without_clock()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  bytes m = frames::pattern(10);
  ipv4::udp::send(ed, m.data(), m.size(), {frames::host_ip(99), 9});

  for (std::uint32_t k = 0; k < 5 * ipv4::c_arp_retry_interval; ++k)
    run_step_untimed();

  PROTOCOL_CHECK(count_arp_requests_for(99) == ipv4::c_arp_max_requests);
  PROTOCOL_CHECK(all_blocks_free());
}

/// A host answering the second request gets its datagrams, in order
void arp_answer_after_retry()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  for (std::uint8_t i = 0; i < 3; ++i)
  {
    bytes m(4, i);
    ipv4::udp::send(ed, m.data(), m.size(), {frames::host_ip(42), 9});
  }
  for (g_now = 0; g_now <= 1200; g_now += 100)
    run_step();
  PROTOCOL_CHECK(count_arp_requests_for(42) == 2);   // one request for all three

  g_tx.clear();
  deliver({frames::arp_reply(42)});
  PROTOCOL_CHECK(g_tx.size() == 3);
  for (std::size_t i = 0; i < g_tx.size(); ++i)
    PROTOCOL_CHECK(frames::udp_payload(g_tx[i]) == bytes(4, std::uint8_t(i)));
  PROTOCOL_CHECK(all_blocks_free());
}

/// Broadcast datagrams go out without ARP and are received
void broadcast()
{
  setup();
  auto ed = ipv4::udp::bind(0, 67);
  bytes m = frames::pattern(30);
  ipv4::udp::send(ed, m.data(), m.size(), {{255, 255, 255, 255}, 68});
  deliver({});
  PROTOCOL_CHECK(g_tx.size() == 1);
  if (g_tx.size() == 1)
  {
    PROTOCOL_CHECK(frames::udp_valid(g_tx[0]));
    PROTOCOL_CHECK((std::all_of(g_tx[0].begin(), g_tx[0].begin() + 6,
                                [](std::uint8_t b) { return b == 0xFF; })));
  }

  frames::ip_options o;
  o.dest = {255, 255, 255, 255};
  deliver({frames::udp_frame(10, 68, 67, m, o)});
  PROTOCOL_CHECK(ipv4::udp::received_length(ed) == 30);
}

void bind_rules()
{
  setup();
  PROTOCOL_CHECK(ipv4::udp::bind(0, 7).has_value());
  PROTOCOL_CHECK(!ipv4::udp::bind(0, 7).has_value());
  PROTOCOL_CHECK(!ipv4::udp::bind(5, 8).has_value());
}

/// Short frames go out padded to the Ethernet minimum
void short_frames_padded()
{
  setup();
  deliver({frames::arp_request(10)});
  PROTOCOL_CHECK(g_tx.size() == 1 && g_tx[0].size() == 60);
}

/// No traffic pattern leaks a block
void no_leaks()
{
  setup();
  auto ed = ipv4::udp::bind(0, 8000);
  std::uint8_t buffer[1500];
  ipv4::endpoint remote;

  for (int round = 0; round < 50; ++round)
  {
    g_now += 10;
    deliver({frames::arp_request(std::uint8_t(10 + round % 20)),
             frames::icmp_echo(10, 1, std::uint16_t(round), frames::pattern(std::size_t(round * 20))),
             frames::udp_frame(11, 1, 8000, frames::pattern(std::size_t(round * 25))),
             frames::udp_frame(11, 1, 8001, frames::pattern(10))});
    ipv4::udp::receive(ed, buffer, sizeof buffer, remote);
    ipv4::udp::send(ed, buffer, 20, {frames::host_ip(std::uint8_t(10 + round % 30)), 9});
  }
  g_now += 10000;
  for (int k = 0; k < 10; ++k) { g_now += 2000; run_step(); }

  PROTOCOL_CHECK(all_blocks_free());
}

struct test_case { std::string_view name; void (*run)(); };

const test_case g_cases[] =
{
  {"zero_copy_echo",                       zero_copy_echo},
  {"allocate_and_drop",                    allocate_and_drop},
  {"reserves_keep_both_directions_alive",  reserves_keep_both_directions_alive},
  {"arp_retry_then_timeout",               arp_retry_then_timeout},
  {"arp_retry_without_clock",              arp_retry_without_clock},
  {"arp_answer_after_retry",               arp_answer_after_retry},
  {"broadcast",                            broadcast},
  {"bind_rules",                           bind_rules},
  {"short_frames_padded",                  short_frames_padded},
  {"no_leaks",                             no_leaks},
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
