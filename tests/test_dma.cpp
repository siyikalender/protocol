/// \file test_dma.cpp
/// Tests of step_dma() with a simulated MAC: an RX descriptor ring that
/// always holds pool blocks and a TX ring whose frames complete only when
/// the test says so. Each test case runs in its own process, the case name
/// is the first command line argument.
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
#include <deque>
#include <span>
#include <string_view>

#include "protocol/ipv4/stack.hpp"

#include "check.hpp"
#include "frames.hpp"

using namespace protocol;
using frames::bytes;

namespace
{

constexpr std::size_t c_rx_descriptors = 3;

/// The MAC and its driver, as a real one would work on descriptor rings
struct simulated_mac
{
  struct rx_descriptor
  {
    ipv4::packet_id id{};
    bool            full = false;   // the DMA wrote a frame, the driver has not taken it
    std::size_t     size = 0;
  };

  struct tx_descriptor
  {
    ipv4::packet_id                 id{};
    std::span<const std::uint8_t>   frame;
  };

  std::array<rx_descriptor, c_rx_descriptors> rx{};
  std::size_t                 rx_hw = 0, rx_sw = 0;
  std::size_t                 rx_overruns = 0;   // the ring was full
  std::size_t                 rx_dropped  = 0;   // no fresh block

  std::deque<tx_descriptor>   tx_ring;
  std::size_t                 tx_capacity = 4;
  std::deque<ipv4::packet_id> tx_done;
  std::vector<bytes>          wire;               // frames that went out

  // ---- driver ---------------------------------------------------------

  void arm()
  {
    for (auto& d : rx)
    {
      auto p = ipv4::dma::acquire();
      PROTOCOL_CHECK(p.has_value());
      d = {*p, false, 0};
    }
  }

  std::optional<ipv4::rx_frame> receive()
  {
    while (rx[rx_sw].full)
    {
      rx_descriptor& d = rx[rx_sw];
      rx_sw = (rx_sw + 1) % rx.size();
      d.full = false;                       // re-armed: the DMA owns it again

      if (auto fresh = ipv4::dma::acquire())
      {
        ipv4::rx_frame frame{d.id, d.size};
        d.id = *fresh;                      // swap
        return frame;
      }
      ++rx_dropped;                         // same block stays, frame lost
    }
    return std::nullopt;
  }

  bool transmit(ipv4::packet_id p, std::span<const std::uint8_t> frame)
  {
    if (tx_ring.size() >= tx_capacity)
      return false;
    tx_ring.push_back({p, frame});
    return true;
  }

  std::optional<ipv4::packet_id> reclaim()
  {
    if (tx_done.empty())
      return std::nullopt;
    auto p = tx_done.front();
    tx_done.pop_front();
    return p;
  }

  // ---- hardware -------------------------------------------------------

  /// A frame arrives on the wire
  void arrive(const bytes& f)
  {
    rx_descriptor& d = rx[rx_hw];
    if (d.full)
    {
      ++rx_overruns;
      return;
    }
    auto buffer = ipv4::dma::receive_buffer(d.id);
    std::copy(f.begin(), f.end(), buffer.begin());
    d.size = f.size();
    d.full = true;
    rx_hw  = (rx_hw + 1) % rx.size();
  }

  /// The MAC sends n frames from the TX ring. The bytes are read only now,
  /// as a DMA does: a block changed or reused before this shows up.
  void send_out(std::size_t n = ~std::size_t(0))
  {
    while (n-- > 0 && !tx_ring.empty())
    {
      wire.emplace_back(tx_ring.front().frame.begin(), tx_ring.front().frame.end());
      tx_done.push_back(tx_ring.front().id);
      tx_ring.pop_front();
    }
  }
};

simulated_mac g_mac;
std::uint32_t g_now = 0;

void run_step()
{
  ipv4::step_dma
  (
    []                                     { return g_mac.receive(); },
    [](ipv4::packet_id p, auto frame)      { return g_mac.transmit(p, frame); },
    []                                     { return g_mac.reclaim(); },
    []                                     { return g_now; }
  );
}

void setup(std::size_t tx_capacity = 4)
{
  ipv4::initialize();
  ipv4::set(0, frames::stack_mac, frames::stack_ip);
  g_mac = simulated_mac{};
  g_mac.tx_capacity = tx_capacity;
  g_mac.arm();
}

/// Frames in, steps, the MAC sends everything, steps again
void exchange(std::initializer_list<bytes> fs)
{
  for (auto& f : fs)
  {
    g_mac.arrive(f);
    run_step();
  }
  for (int k = 0; k < 4; ++k)
  {
    run_step();
    g_mac.send_out();
  }
  run_step();
}

/// Every block is free except those armed on the RX ring
bool no_leak()
{
  return ipv4::g_packet_pool.available() == ipv4::c_packet_pool_size - c_rx_descriptors;
}

std::size_t count(auto predicate)
{
  return std::size_t(std::count_if(g_mac.wire.begin(), g_mac.wire.end(), predicate));
}

// --------------------------------------------------------------------------

void dma_arp_and_ping()
{
  setup();
  exchange({frames::arp_request(10), frames::icmp_echo(10, 1, 1, frames::pattern(100))});

  PROTOCOL_CHECK(g_mac.wire.size() == 2);
  PROTOCOL_CHECK(count([](const bytes& f) { return frames::is_arp(f, 2); }) == 1);
  PROTOCOL_CHECK(count([](const bytes& f)
  {
    return frames::is_ipv4(f, 1) && frames::ipv4_valid(f) &&
           bytes(f.begin() + 42, f.begin() + 142) == frames::pattern(100);
  }) == 1);
  PROTOCOL_CHECK(no_leak());
}

/// The received block travels to the application and back out without a copy
void dma_zero_copy_echo()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  exchange({frames::arp_request(10)});
  g_mac.wire.clear();

  bytes data = frames::pattern(1000, 3);
  g_mac.arrive(frames::udp_frame(10, 5555, 7, data));
  run_step();

  auto d = ipv4::udp::receive(ed);
  PROTOCOL_CHECK(d.has_value());
  if (!d) return;
  PROTOCOL_CHECK(std::equal(data.begin(), data.end(), d->data().begin(), d->data().end()));

  const auto block = *d->buffer.id();
  PROTOCOL_CHECK(ipv4::udp::send(ed, std::move(d->buffer), d->remote));
  run_step();
  PROTOCOL_CHECK(g_mac.tx_ring.size() == 1);
  PROTOCOL_CHECK(g_mac.tx_ring.size() == 1 && g_mac.tx_ring.front().id == block);

  g_mac.send_out();
  run_step();

  PROTOCOL_CHECK(g_mac.wire.size() == 1);
  if (g_mac.wire.size() == 1)
  {
    PROTOCOL_CHECK(frames::udp_valid(g_mac.wire[0]));
    PROTOCOL_CHECK(frames::udp_payload(g_mac.wire[0]) == data);
  }
  PROTOCOL_CHECK(no_leak());
}

/// A datagram that came with IP options goes back out with its frame on the
/// block's aligned start, as DMAs want it
void dma_echo_with_ip_options()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  exchange({frames::arp_request(10)});
  g_mac.wire.clear();

  bytes data = frames::pattern(64, 9);
  frames::ip_options o;
  o.option_words = 3;
  g_mac.arrive(frames::udp_frame(10, 5555, 7, data, o));
  run_step();

  auto d = ipv4::udp::receive(ed);
  PROTOCOL_CHECK(d.has_value() && d->size() == 64);
  if (!d) return;
  PROTOCOL_CHECK(d->remote == (ipv4::endpoint{frames::host_ip(10), 5555}));

  const auto block = *d->buffer.id();
  ipv4::udp::send(ed, std::move(d->buffer), d->remote);
  run_step();
  PROTOCOL_CHECK(g_mac.tx_ring.size() == 1);
  if (g_mac.tx_ring.size() != 1) return;
  PROTOCOL_CHECK(g_mac.tx_ring.front().id == block);
  PROTOCOL_CHECK(g_mac.tx_ring.front().frame.data() ==
                 ipv4::dma::storage(block).data() + ipv4::c_packet_headroom);

  g_mac.send_out();
  run_step();
  PROTOCOL_CHECK(g_mac.wire.size() == 1 && frames::udp_valid(g_mac.wire[0]));
  PROTOCOL_CHECK(g_mac.wire.size() == 1 && frames::udp_payload(g_mac.wire[0]) == data);
  PROTOCOL_CHECK(no_leak());
}

/// A full TX ring loses nothing: the frames wait and go out in order, once
void dma_tx_ring_full()
{
  setup(1);
  auto ed = ipv4::udp::bind(0, 7);
  exchange({frames::arp_request(10)});
  g_mac.wire.clear();

  // As many as the pool allows: the RX ring holds c_rx_descriptors blocks
  // and c_rx_reserved_blocks stay for reception
  const std::size_t room =
    ipv4::c_packet_pool_size - c_rx_descriptors - ipv4::c_rx_reserved_blocks;
  std::uint8_t sent = 0;

  for (std::uint8_t i = 0; i < 4; ++i)
  {
    bytes m(8, i);
    if (ipv4::udp::send(ed, m.data(), m.size(), {frames::host_ip(10), 9}) == 8)
      ++sent;
  }
  PROTOCOL_CHECK(sent == std::min<std::size_t>(4, room));
  PROTOCOL_CHECK(ipv4::stats().tx_no_buffer == 4U - sent);

  for (int k = 0; k < 3; ++k)
    run_step();                               // the MAC sends nothing yet
  PROTOCOL_CHECK(g_mac.tx_ring.size() == 1);
  PROTOCOL_CHECK(ipv4::stats().tx_busy > 0);

  for (int k = 0; k < 10; ++k)
  {
    g_mac.send_out(1);
    run_step();
  }

  PROTOCOL_CHECK(g_mac.wire.size() == sent);
  for (std::size_t i = 0; i < g_mac.wire.size(); ++i)
  {
    PROTOCOL_CHECK(frames::udp_valid(g_mac.wire[i]));
    PROTOCOL_CHECK(frames::udp_payload(g_mac.wire[i]) == bytes(8, std::uint8_t(i)));
  }
  PROTOCOL_CHECK(no_leak());
}

/// While the TX ring is stuck, replies wait up to c_tx_waiting_size and the
/// rest are dropped, never leaked
void dma_replies_while_tx_stuck()
{
  setup(1);
  for (std::uint16_t i = 0; i < 6; ++i)
  {
    g_mac.arrive(frames::icmp_echo(10, 1, i, frames::pattern(10)));
    run_step();
  }
  PROTOCOL_CHECK(g_mac.tx_ring.size() == 1);

  for (int k = 0; k < 10; ++k)
  {
    g_mac.send_out();
    run_step();
  }
  // Each request was answered, or dropped at the ring (no fresh block) or
  // while waiting: none is lost silently, no block leaks
  PROTOCOL_CHECK(g_mac.wire.size() >= 1);
  PROTOCOL_CHECK(g_mac.wire.size() <= 1 + ipv4::c_tx_waiting_size);
  PROTOCOL_CHECK(g_mac.wire.size() + g_mac.rx_dropped + ipv4::stats().tx_reply_dropped == 6);
  PROTOCOL_CHECK(no_leak());
}

/// Ports nobody reads: the overload is cut at the ring, ARP keeps working
/// and sending still works
void dma_overload_cut_at_ring()
{
  setup();
  ipv4::endpoint_designator ports[4];
  for (std::uint16_t i = 0; i < 4; ++i)
    ports[i] = ipv4::udp::bind(0, std::uint16_t(100 + i));

  for (int round = 0; round < 20; ++round)
  {
    g_mac.arrive(frames::arp_request(std::uint8_t(20 + round % 10)));
    for (std::uint16_t i = 0; i < 4; ++i)
      g_mac.arrive(frames::udp_frame(10, 1, std::uint16_t(100 + i), frames::pattern(300)));
    run_step();
    g_mac.send_out();
    run_step();

    PROTOCOL_CHECK(ipv4::g_packet_pool.available() >= ipv4::c_tx_reserved_blocks);
  }

  PROTOCOL_CHECK(g_mac.rx_dropped + g_mac.rx_overruns > 0);
  // The ARP request arrived first in every round, so it got into the ring
  // and was answered every time
  PROTOCOL_CHECK(count([](const bytes& f) { return frames::is_arp(f, 2); }) == 20);

  g_mac.wire.clear();
  exchange({frames::arp_request(10)});
  PROTOCOL_CHECK(g_mac.wire.size() == 1);

  bytes m = frames::pattern(10);
  PROTOCOL_CHECK(ipv4::udp::send(ports[0], m.data(), m.size(), {frames::host_ip(10), 9}) == 10);
  exchange({});
  PROTOCOL_CHECK(g_mac.wire.size() == 2);

  for (auto& p : ports)
    while (ipv4::udp::receive(p)) {}
  PROTOCOL_CHECK(no_leak());
}

/// ARP retries and the timeout with blocks owned by the TX ring in between
void dma_arp_timeout()
{
  setup();
  auto ed = ipv4::udp::bind(0, 7);
  bytes m = frames::pattern(10);
  ipv4::udp::send(ed, m.data(), m.size(), {frames::host_ip(99), 9});

  for (g_now = 0; g_now <= 5000; g_now += 100)
  {
    run_step();
    g_mac.send_out();
  }
  run_step();

  PROTOCOL_CHECK(count([](const bytes& f)
  {
    return frames::is_arp(f, 1) && frames::arp_target_ip(f) == frames::host_ip(99);
  }) == ipv4::c_arp_max_requests);
  PROTOCOL_CHECK(ipv4::stats().tx_arp_timeout == 1);
  PROTOCOL_CHECK(no_leak());
}

struct test_case { std::string_view name; void (*run)(); };

const test_case g_cases[] =
{
  {"dma_arp_and_ping",            dma_arp_and_ping},
  {"dma_zero_copy_echo",          dma_zero_copy_echo},
  {"dma_echo_with_ip_options",    dma_echo_with_ip_options},
  {"dma_tx_ring_full",            dma_tx_ring_full},
  {"dma_replies_while_tx_stuck",  dma_replies_while_tx_stuck},
  {"dma_overload_cut_at_ring",    dma_overload_cut_at_ring},
  {"dma_arp_timeout",             dma_arp_timeout},
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
