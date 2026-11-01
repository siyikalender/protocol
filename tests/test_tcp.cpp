/// \file test_tcp.cpp
/// TCP, frame by frame: the cases a real peer seldom shows on demand (RST
/// rules, timers, zero window, closing orders, DMA ownership). Each case runs
/// in its own process, the case name is the first command line argument.
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

#include <deque>
#include <string_view>

#include "protocol/ipv4/stack.hpp"
#include "protocol/ipv4/tcp.hpp"

#include "check.hpp"
#include "frames.hpp"

using namespace protocol;
using frames::bytes;
using frames::tcp_frame;
using frames::FIN; using frames::SYN; using frames::RST; using frames::ACK; using frames::PSH;

namespace
{

std::deque<bytes>  g_rx;
std::vector<bytes> g_tx;
std::uint32_t      g_now = 0;

void run_step()
{
  ipv4::step([] { return !g_rx.empty(); },
             [](auto& buffer, std::size_t capacity) -> std::size_t
             {
               bytes f = g_rx.front();
               g_rx.pop_front();
               if (f.size() > capacity) return 0;
               std::copy(f.begin(), f.end(), buffer.begin());
               return f.size();
             },
             [](auto& frame, std::size_t size)
             {
               g_tx.emplace_back(frame.begin(), frame.begin() + std::ptrdiff_t(size));
             },
             [] { return g_now; });
}

void deliver(std::initializer_list<bytes> fs)
{
  for (auto& f : fs) g_rx.push_back(f);
  while (!g_rx.empty()) run_step();
  run_step();
}

/// Time passes, a step every 10 ms
void wait(std::uint32_t ms)
{
  for (std::uint32_t t = 0; t < ms; t += 10)
  {
    g_now += 10;
    run_step();
  }
}

void setup()
{
  ipv4::initialize();
  ipv4::set(0, frames::stack_mac, frames::stack_ip);
  g_tx.clear();
  g_now = 1000;
}

std::vector<frames::tcp_seen> segments()
{
  std::vector<frames::tcp_seen> r;
  for (auto& f : g_tx)
    if (auto s = frames::parse_tcp(f))
      r.push_back(*s);
  return r;
}

bool all_blocks_free()
{
  return ipv4::g_packet_pool.available() == ipv4::c_packet_pool_size;
}

bytes slice(const bytes& stream, std::size_t from, std::size_t n);
bytes read_all(ipv4::tcp::connection c);

/// The far end of a connection, written by hand
struct peer
{
  std::uint8_t  host  = 10;
  std::uint16_t port  = 40000;
  std::uint16_t local = 0;      ///< the stack's port
  std::uint32_t seq   = 5000;   ///< next sequence number we send
  std::uint32_t ack   = 0;      ///< next sequence number we expect

  bytes segment(std::uint8_t flags, const bytes& data = {}, std::uint16_t window = 8192,
                std::vector<std::uint32_t> sack = {})
  {
    bytes f = tcp_frame(host, port, local, seq, ack, flags, data, {window, 0, false, std::move(sack)});
    seq += std::uint32_t(data.size()) + ((flags & (SYN | FIN)) ? 1U : 0U);
    return f;
  }
};

/// The handshake with a listener on port; the connection accepted
std::optional<ipv4::tcp::connection> open_passive(ipv4::tcp::listener l, std::uint16_t port, peer& p,
                                                  bool sack = false)
{
  p.local = port;
  g_tx.clear();
  deliver({tcp_frame(p.host, p.port, port, p.seq, 0, SYN, {}, {8192, 1460, sack})});
  p.seq += 1;

  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1);
  if (s.size() != 1) return std::nullopt;
  PROTOCOL_CHECK(s[0].flags == (SYN | ACK));
  PROTOCOL_CHECK(s[0].ack == p.seq);
  PROTOCOL_CHECK(s[0].mss == 1460);
  PROTOCOL_CHECK(s[0].sack_permitted == sack);   // only when offered
  PROTOCOL_CHECK(s[0].window > 0);
  PROTOCOL_CHECK(s[0].checksum_ok);
  p.ack = s[0].seq + 1;

  PROTOCOL_CHECK(!ipv4::tcp::accept(l).has_value());   // not before the handshake ends
  g_tx.clear();
  deliver({p.segment(ACK)});
  return ipv4::tcp::accept(l);
}

// --------------------------------------------------------------------------

void tcp_passive_open_and_data()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = open_passive(*l, 80, p);
  PROTOCOL_CHECK(c.has_value());
  if (!c) return;
  PROTOCOL_CHECK(ipv4::tcp::state(*c) == ipv4::tcp::status::established);
  PROTOCOL_CHECK((ipv4::tcp::remote(*c) == ipv4::endpoint{frames::host_ip(10), 40000}));

  // Peer -> stack
  g_tx.clear();
  deliver({p.segment(ACK | PSH, frames::pattern(100, 1))});
  PROTOCOL_CHECK(ipv4::tcp::received_length(*c) == 100);
  auto s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == p.seq);         // acknowledged

  std::uint8_t buffer[200];
  PROTOCOL_CHECK(ipv4::tcp::receive(*c, buffer, 60) == 60);
  PROTOCOL_CHECK(ipv4::tcp::receive(*c, buffer + 60, 140) == 40);
  PROTOCOL_CHECK(bytes(buffer, buffer + 100) == frames::pattern(100, 1));

  // Stack -> peer
  g_tx.clear();
  const bytes out = frames::pattern(3000, 2);
  PROTOCOL_CHECK(ipv4::tcp::send(*c, out.data(), out.size()) == out.size());
  run_step(); run_step(); run_step();
  s = segments();
  bytes seen;
  for (auto& x : s)
  {
    PROTOCOL_CHECK(x.checksum_ok && (x.flags & ACK) && x.ack == p.seq);
    seen.insert(seen.end(), x.data.begin(), x.data.end());
  }
  PROTOCOL_CHECK(seen == out);
  PROTOCOL_CHECK(s.size() == 3);                               // 1460 + 1460 + 80
  PROTOCOL_CHECK(s.size() == 3 && s[0].data.size() == 1460 && s[0].seq == p.ack);

  // Acknowledged: the blocks go back
  p.ack += std::uint32_t(out.size());
  deliver({p.segment(ACK)});
  PROTOCOL_CHECK(ipv4::g_packet_pool.available() == ipv4::c_packet_pool_size);
}

void tcp_reset_for_closed_port()
{
  setup();
  deliver({tcp_frame(10, 40000, 81, 777, 0, SYN)});
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1);
  if (s.size() == 1)
  {
    PROTOCOL_CHECK(s[0].flags == (RST | ACK) && s[0].seq == 0 && s[0].ack == 778);
    PROTOCOL_CHECK(s[0].sport == 81 && s[0].dport == 40000);
  }

  g_tx.clear();
  deliver({tcp_frame(10, 40000, 81, 777, 123456, ACK)});
  s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].flags == RST && s[0].seq == 123456);

  // A RST never gets an answer
  g_tx.clear();
  deliver({tcp_frame(10, 40000, 81, 777, 0, RST)});
  PROTOCOL_CHECK(segments().empty());
  PROTOCOL_CHECK(all_blocks_free());
}

void tcp_rfc5961_challenges()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  // A RST in the window but not exactly next: challenge ACK, no reset
  g_tx.clear();
  deliver({tcp_frame(10, 40000, 80, p.seq + 100, 0, RST)});
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].flags == ACK && s[0].ack == p.seq);
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::established);

  // A SYN on the connection: challenge ACK
  g_tx.clear();
  deliver({tcp_frame(10, 40000, 80, p.seq + 7, 0, SYN)});
  s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].flags == ACK && s[0].ack == p.seq);
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::established);

  // Exactly the next sequence number: reset
  g_tx.clear();
  deliver({tcp_frame(10, 40000, 80, p.seq, 0, RST)});
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::reset);
  PROTOCOL_CHECK(segments().empty());
  ipv4::tcp::close(c);
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::closed);
  PROTOCOL_CHECK(all_blocks_free());
}

void tcp_retransmission_and_timeout()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  g_tx.clear();
  const bytes out = frames::pattern(100, 3);
  ipv4::tcp::send(c, out.data(), out.size());
  run_step();

  // Never acknowledged: sent again, each time after twice as long
  std::vector<std::uint32_t> times;
  std::size_t seen = segments().size();
  for (int i = 0; i < 20000 && ipv4::tcp::state(c) == ipv4::tcp::status::established; ++i)
  {
    g_now += 10;
    run_step();
    const auto s = segments();
    if (s.size() > seen)
    {
      seen = s.size();
      if (!(s.back().flags & RST))
      {
        PROTOCOL_CHECK(s.back().data == out && s.back().seq == p.ack);
        times.push_back(g_now);
      }
    }
  }

  PROTOCOL_CHECK(times.size() == ipv4::c_tcp_max_retransmits);
  for (std::size_t i = 2; i < times.size(); ++i)
    PROTOCOL_CHECK(times[i] - times[i - 1] >= 2 * (times[i - 1] - times[i - 2]) - 20);

  // Then the connection times out with a RST
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::timed_out);
  const auto s = segments();
  PROTOCOL_CHECK(!s.empty() && (s.back().flags & RST));
  ipv4::tcp::close(c);
  PROTOCOL_CHECK(all_blocks_free());
}

void tcp_fast_retransmit()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  const bytes out = frames::pattern(4000, 4);
  ipv4::tcp::send(c, out.data(), out.size());
  run_step(); run_step(); run_step();
  g_tx.clear();

  // The first segment was lost: three duplicate ACKs
  deliver({p.segment(ACK), p.segment(ACK), p.segment(ACK)});
  auto s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().seq == p.ack && s.back().data.size() == 1460);
  PROTOCOL_CHECK(ipv4::stats().tcp_retransmits == 1);

  // A partial ACK (RFC 6582): the next hole goes at once, without a timeout
  g_tx.clear();
  p.ack += 1460;
  deliver({p.segment(ACK)});
  s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].seq == p.ack && s[0].data.size() == 1460);
  PROTOCOL_CHECK(ipv4::stats().tcp_retransmits == 2);

  // All acknowledged: recovery ends, nothing more is sent
  g_tx.clear();
  p.ack += 4000 - 1460;
  deliver({p.segment(ACK)});
  wait(ipv4::c_tcp_rto_initial * 2);
  PROTOCOL_CHECK(segments().empty());
  PROTOCOL_CHECK(ipv4::stats().tcp_retransmits == 2);
}

/// Two segments out: one duplicate ACK is all the peer can send (RFC 5827)
void tcp_early_retransmit()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  const bytes out = frames::pattern(2000, 4);
  ipv4::tcp::send(c, out.data(), out.size());
  run_step(); run_step();
  g_tx.clear();

  deliver({p.segment(ACK)});
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].seq == p.ack && s[0].data.size() == 1460);
  PROTOCOL_CHECK(ipv4::stats().tcp_retransmits == 1);
}

/// SACK (RFC 2018): the stack tells which segments it keeps out of order
void tcp_sack_receiver()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p, true);

  const bytes         stream = frames::pattern(400, 5);
  const std::uint32_t first  = p.seq;
  auto at = [&](std::size_t from, std::size_t n)
  {
    p.seq = first + std::uint32_t(from);
    return p.segment(ACK, slice(stream, from, n));
  };

  g_tx.clear();
  deliver({at(300, 100)});
  deliver({at(100, 100)});
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 2);
  if (s.size() != 2) return;
  PROTOCOL_CHECK(s[0].ack == first && s[0].data.empty());
  PROTOCOL_CHECK((s[0].sack == std::vector<std::uint32_t>{first + 300, first + 400}));
  // The latest first, then the others
  PROTOCOL_CHECK((s[1].sack == std::vector<std::uint32_t>{first + 100, first + 200, first + 300, first + 400}));

  g_tx.clear();
  deliver({at(0, 100)});        // [0, 200) now; [300, 400) still waits
  s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == first + 200);
  PROTOCOL_CHECK((s.back().sack == std::vector<std::uint32_t>{first + 300, first + 400}));

  g_tx.clear();
  deliver({at(200, 100)});
  s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == first + 400 && s.back().sack.empty());
  PROTOCOL_CHECK(read_all(c) == stream);
}

/// SACK (RFC 2018, RFC 6675): what the peer has is not sent again; a hole
/// is, as soon as enough after it has arrived, even told in one ACK
void tcp_sack_sender()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p, true);

  const bytes out = frames::pattern(4000, 4);          // 1460, 1460, 1080
  ipv4::tcp::send(c, out.data(), out.size());
  run_step(); run_step(); run_step();
  const std::uint32_t a = p.ack, b = a + 1460, e = a + 4000;

  // One ACK (with data of its own) tells the 2nd and 3rd arrived
  g_tx.clear();
  deliver({p.segment(ACK, frames::pattern(10, 1), 8192, {b, e})});
  auto s = segments();
  PROTOCOL_CHECK(!s.empty() && s.front().seq == a && s.front().data.size() == 1460);
  for (const auto& seen : s)
    PROTOCOL_CHECK(seen.data.empty() || seen.seq == a);
  PROTOCOL_CHECK(ipv4::stats().tcp_retransmits == 1);

  // Everything acknowledged: nothing more goes
  g_tx.clear();
  p.ack = e;
  deliver({p.segment(ACK)});
  wait(ipv4::c_tcp_rto_initial * 2);
  PROTOCOL_CHECK(segments().empty());
  PROTOCOL_CHECK(ipv4::stats().tcp_retransmits == 1);
}

void tcp_zero_window_probe()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  // The peer's window closes
  deliver({p.segment(ACK, {}, 0)});
  g_tx.clear();
  const bytes out = frames::pattern(500, 5);
  ipv4::tcp::send(c, out.data(), out.size());
  run_step();
  PROTOCOL_CHECK(segments().empty());                          // no data into a closed window

  wait(1500);
  auto s = segments();
  PROTOCOL_CHECK(!s.empty());
  for (auto& x : s)                                            // probes only: old sequence number
    PROTOCOL_CHECK(x.data.empty() && x.seq == p.ack - 1 && x.flags == ACK);

  // The window opens: the data goes
  g_tx.clear();
  deliver({p.segment(ACK, {}, 8192)});
  s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].data == out);
}

void tcp_peer_closes_first()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  g_tx.clear();
  deliver({p.segment(ACK | FIN)});
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::peer_closed);
  auto s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == p.seq);         // the FIN acknowledged

  // Data can still go the other way
  const bytes out = frames::pattern(10, 6);
  PROTOCOL_CHECK(ipv4::tcp::send(c, out.data(), out.size()) == 10);

  g_tx.clear();
  ipv4::tcp::close(c);                                         // LAST-ACK
  run_step(); run_step();
  s = segments();
  PROTOCOL_CHECK(!s.empty() && (s.back().flags & FIN));
  PROTOCOL_CHECK(s.size() == 1 && s[0].data == out);           // FIN rides on the data

  p.ack += 11;
  deliver({p.segment(ACK)});
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::closed);
  PROTOCOL_CHECK(all_blocks_free());
}

void tcp_we_close_first()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  g_tx.clear();
  ipv4::tcp::close(c);                                         // FIN-WAIT-1
  run_step();
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].flags == (FIN | ACK) && s[0].seq == p.ack);
  p.ack += 1;

  deliver({p.segment(ACK)});                                   // FIN-WAIT-2
  g_tx.clear();
  deliver({p.segment(ACK | FIN)});                             // TIME-WAIT
  s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == p.seq);

  // The place is held through TIME-WAIT, then freed
  wait(ipv4::c_tcp_time_wait + 100);
  PROTOCOL_CHECK(all_blocks_free());

  // A new connection from the same peer port works
  peer q;
  q.seq = 90000;
  PROTOCOL_CHECK(open_passive(*l, 80, q).has_value());
}

/// Bytes [from, from + n) of a stream
bytes slice(const bytes& stream, std::size_t from, std::size_t n)
{
  return bytes(stream.begin() + std::ptrdiff_t(from), stream.begin() + std::ptrdiff_t(from + n));
}

bytes read_all(ipv4::tcp::connection c)
{
  bytes b(ipv4::tcp::received_length(c));
  b.resize(ipv4::tcp::receive(c, b.data(), b.size()));
  return b;
}

void tcp_out_of_order_reassembly()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  const bytes         stream = frames::pattern(450, 7);
  const std::uint32_t first  = p.seq;
  auto at = [&](std::size_t from, std::size_t n)
  {
    p.seq = first + std::uint32_t(from);
    return p.segment(ACK, slice(stream, from, n));
  };

  // Two segments ahead of a gap: kept, each answered by a duplicate ACK
  g_tx.clear();
  deliver({at(200, 100), at(100, 100), at(100, 100)});          // the last one twice
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 3);
  for (const auto& seen : s)
    PROTOCOL_CHECK(seen.ack == first);
  PROTOCOL_CHECK(ipv4::tcp::received_length(c) == 0);
  PROTOCOL_CHECK(ipv4::stats().tcp_rx_out_of_order == 2);

  // The gap filled: everything is received and acknowledged at once
  g_tx.clear();
  deliver({at(0, 100)});
  s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == first + 300);
  PROTOCOL_CHECK(read_all(c) == slice(stream, 0, 300));

  // Overlapping: [350, 450) waits, [300, 400) fills the gap and half of it
  deliver({at(350, 100), at(300, 100)});
  PROTOCOL_CHECK(read_all(c) == slice(stream, 300, 150));
  s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == first + 450);
  PROTOCOL_CHECK(ipv4::stats().tcp_rx_refused == 0);

  ipv4::tcp::close(c);
  run_step();
  p.seq = first + 450;
  p.ack += 1;
  deliver({p.segment(ACK | FIN)});
  wait(ipv4::c_tcp_time_wait + 10);
  PROTOCOL_CHECK(all_blocks_free());
}

void tcp_out_of_order_fin()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  const bytes         stream = frames::pattern(200, 9);
  const std::uint32_t first  = p.seq;

  p.seq = first + 100;
  deliver({p.segment(ACK | FIN, slice(stream, 100, 100))});   // the end comes first
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::established);

  g_tx.clear();
  p.seq = first;
  deliver({p.segment(ACK, slice(stream, 0, 100))});
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::peer_closed);
  auto s = segments();
  PROTOCOL_CHECK(!s.empty() && s.back().ack == first + 201);   // data and FIN
  PROTOCOL_CHECK(read_all(c) == stream);

  ipv4::tcp::close(c);
  run_step();
  p.seq = first + 201;
  p.ack += 1;
  deliver({p.segment(ACK)});
  PROTOCOL_CHECK(ipv4::tcp::state(c) == ipv4::tcp::status::closed);
  PROTOCOL_CHECK(all_blocks_free());
}

/// Blocks kept out of order are given up for data in order
void tcp_out_of_order_eviction()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  const bytes         stream = frames::pattern(100 * (ipv4::c_tcp_rx_segments + 1), 3);
  const std::uint32_t first  = p.seq;

  for (std::size_t i = 1; i <= ipv4::c_tcp_rx_segments; ++i)
  {
    p.seq = first + std::uint32_t(100 * i);
    deliver({p.segment(ACK, slice(stream, 100 * i, 100))});
  }

  // Every block the connection may take is out of order: the in order
  // segment still gets in, the one furthest ahead goes
  g_tx.clear();
  p.seq = first;
  deliver({p.segment(ACK, slice(stream, 0, 100))});
  const auto s = segments();
  PROTOCOL_CHECK(!s.empty());
  const std::uint32_t acked = s.back().ack - first;
  PROTOCOL_CHECK(acked >= 100 && acked < stream.size() && acked % 100 == 0);
  PROTOCOL_CHECK(read_all(c) == slice(stream, 0, acked));
  PROTOCOL_CHECK(ipv4::stats().tcp_rx_refused == 0);

  ipv4::tcp::abort(c);
  run_step();
  PROTOCOL_CHECK(all_blocks_free());
}

void tcp_backlog_and_table_limits()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);

  // Backlog of 2: the third SYN is not answered (the peer tries again)
  for (std::uint16_t port = 40000; port < 40003; ++port)
  {
    g_tx.clear();
    deliver({tcp_frame(10, port, 80, 100, 0, SYN)});
    PROTOCOL_CHECK(segments().size() == (port < 40000 + ipv4::c_tcp_backlog ? 1U : 0U));
  }

  // Stopping the listener resets what it held
  ipv4::tcp::stop(*l);
  run_step(); run_step();
  PROTOCOL_CHECK(all_blocks_free());
  PROTOCOL_CHECK(ipv4::tcp::listen(0, 80).has_value());
}

void tcp_active_open_with_arp()
{
  setup();
  auto c = ipv4::tcp::connect(0, {frames::host_ip(20), 9000});
  PROTOCOL_CHECK(c.has_value());
  if (!c) return;
  PROTOCOL_CHECK(ipv4::tcp::state(*c) == ipv4::tcp::status::connecting);

  run_step();
  PROTOCOL_CHECK(g_tx.size() == 1 && frames::is_arp(g_tx[0], 1));   // who is 10.0.0.20?

  g_tx.clear();
  deliver({frames::arp_reply(20)});
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].flags == SYN && s[0].mss == 1460 && s[0].dport == 9000);
  if (s.size() != 1) return;

  peer p;
  p.host  = 20;
  p.port  = 9000;
  p.local = s[0].sport;
  p.ack   = s[0].seq + 1;
  g_tx.clear();
  deliver({tcp_frame(20, 9000, p.local, p.seq, p.ack, SYN | ACK, {}, {8192, 1000})});
  p.seq += 1;
  PROTOCOL_CHECK(ipv4::tcp::state(*c) == ipv4::tcp::status::established);
  s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].flags == ACK && s[0].ack == p.seq);

  // The peer's MSS of 1000 is kept to
  g_tx.clear();
  const bytes out = frames::pattern(2500, 9);
  ipv4::tcp::send(*c, out.data(), out.size());
  run_step(); run_step(); run_step();
  s = segments();
  PROTOCOL_CHECK(s.size() == 3 && s[0].data.size() == 1000 && s[2].data.size() == 500);
}

void tcp_connect_host_never_answers()
{
  setup();
  auto c = ipv4::tcp::connect(0, {frames::host_ip(21), 9000});
  wait(5000);
  PROTOCOL_CHECK(ipv4::tcp::state(*c) == ipv4::tcp::status::timed_out);
  ipv4::tcp::close(*c);
  PROTOCOL_CHECK(all_blocks_free());
}

void tcp_zero_copy_api()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);
  peer p;
  auto c = *open_passive(*l, 80, p);

  deliver({p.segment(ACK, frames::pattern(300, 10))});
  auto in = ipv4::tcp::receive(c);
  PROTOCOL_CHECK(in.has_value() && in->size() == 300);
  PROTOCOL_CHECK(ipv4::tcp::received_length(c) == 0);

  // Sent back in the block it came in
  g_tx.clear();
  PROTOCOL_CHECK(ipv4::tcp::send(c, std::move(*in)));
  run_step();
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1 && s[0].data == frames::pattern(300, 10));

  auto out = ipv4::tcp::allocate(c, 64);
  PROTOCOL_CHECK(out.has_value() && out->size() == 64);
  std::fill(out->data().begin(), out->data().end(), std::uint8_t(0x5A));
  PROTOCOL_CHECK(ipv4::tcp::send(c, std::move(*out)));
  run_step();
  s = segments();
  PROTOCOL_CHECK(s.size() == 2 && s[1].data == bytes(64, 0x5A));
}

/// With step_dma(), a segment the driver still holds is not written again
/// until the driver gives it back
void tcp_dma_in_flight()
{
  setup();
  auto l = ipv4::tcp::listen(0, 80);

  struct ring { ipv4::packet_id id; std::span<const std::uint8_t> frame; };
  std::deque<ring>            tx_ring;
  std::deque<ipv4::packet_id> done;
  std::deque<ipv4::packet_id> rx_ring;
  auto arm = [&] { while (rx_ring.size() < 2) if (auto p = ipv4::dma::acquire()) rx_ring.push_back(*p); else break; };
  arm();

  auto dma_step = [&]
  {
    ipv4::step_dma(
      [&]() -> std::optional<ipv4::rx_frame>
      {
        if (g_rx.empty() || rx_ring.empty()) return std::nullopt;
        auto id = rx_ring.front(); rx_ring.pop_front();
        bytes f = g_rx.front(); g_rx.pop_front();
        std::copy(f.begin(), f.end(), ipv4::dma::receive_buffer(id).begin());
        arm();
        return ipv4::rx_frame{id, f.size()};
      },
      [&](ipv4::packet_id id, auto frame) { tx_ring.push_back({id, frame}); return true; },
      [&]() -> std::optional<ipv4::packet_id>
      {
        if (done.empty()) return std::nullopt;
        auto id = done.front(); done.pop_front(); return id;
      },
      [] { return g_now; });
  };
  auto send_out = [&]
  {
    while (!tx_ring.empty())
    {
      g_tx.emplace_back(tx_ring.front().frame.begin(), tx_ring.front().frame.end());
      done.push_back(tx_ring.front().id);
      tx_ring.pop_front();
    }
  };

  peer p;
  p.local = 80;
  g_rx.push_back(tcp_frame(10, p.port, 80, p.seq, 0, SYN, {}, {8192, 1460}));
  dma_step(); send_out(); dma_step();
  p.seq += 1;
  auto s = segments();
  PROTOCOL_CHECK(s.size() == 1);
  if (s.size() != 1) return;
  p.ack = s[0].seq + 1;
  g_rx.push_back(p.segment(ACK));
  dma_step();
  auto c = ipv4::tcp::accept(*l);
  PROTOCOL_CHECK(c.has_value());
  if (!c) return;

  g_tx.clear();
  const bytes out = frames::pattern(100, 11);
  ipv4::tcp::send(*c, out.data(), out.size());
  dma_step();
  PROTOCOL_CHECK(tx_ring.size() == 1);

  // The RTO passes while the driver still has the frame: nothing new
  for (int i = 0; i < 300; ++i) { g_now += 10; dma_step(); }
  PROTOCOL_CHECK(tx_ring.size() == 1);

  // The driver gives it back: now it goes again, from the same block
  send_out();
  dma_step();
  PROTOCOL_CHECK(tx_ring.size() == 1);
  send_out();
  s = segments();
  PROTOCOL_CHECK(s.size() == 2 && s[0].data == out && s[1].data == out && s[0].seq == s[1].seq);

  // Acknowledged: back to the pool once the driver let it go
  g_rx.push_back(tcp_frame(10, p.port, 80, p.seq, p.ack + 100, ACK));
  dma_step(); send_out(); dma_step();
  PROTOCOL_CHECK(ipv4::g_packet_pool.available() + rx_ring.size() == ipv4::c_packet_pool_size);
}

struct test_case { std::string_view name; void (*run)(); };

const test_case g_cases[] =
{
  {"tcp_passive_open_and_data",      tcp_passive_open_and_data},
  {"tcp_reset_for_closed_port",      tcp_reset_for_closed_port},
  {"tcp_rfc5961_challenges",         tcp_rfc5961_challenges},
  {"tcp_retransmission_and_timeout", tcp_retransmission_and_timeout},
  {"tcp_fast_retransmit",            tcp_fast_retransmit},
  {"tcp_zero_window_probe",          tcp_zero_window_probe},
  {"tcp_peer_closes_first",          tcp_peer_closes_first},
  {"tcp_we_close_first",             tcp_we_close_first},
  {"tcp_early_retransmit",           tcp_early_retransmit},
  {"tcp_sack_receiver",              tcp_sack_receiver},
  {"tcp_sack_sender",                tcp_sack_sender},
  {"tcp_out_of_order_reassembly",    tcp_out_of_order_reassembly},
  {"tcp_out_of_order_fin",           tcp_out_of_order_fin},
  {"tcp_out_of_order_eviction",      tcp_out_of_order_eviction},
  {"tcp_backlog_and_table_limits",   tcp_backlog_and_table_limits},
  {"tcp_active_open_with_arp",       tcp_active_open_with_arp},
  {"tcp_connect_host_never_answers", tcp_connect_host_never_answers},
  {"tcp_zero_copy_api",              tcp_zero_copy_api},
  {"tcp_dma_in_flight",              tcp_dma_in_flight},
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
