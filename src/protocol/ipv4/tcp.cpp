/// \file tcp.cpp
/// TCP (RFC 9293), with the protections of RFC 5961, the retransmission
/// timer of RFC 6298 and the initial sequence numbers of RFC 6528.
///
/// The section numbers in the comments are those of RFC 9293.
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

#include <algorithm>
#include <array>
#include <cstring>

#include "protocol/ipv4/tcp.hpp"

#if PROTOCOL_IPV4_TCP_CONNECTIONS > 0

#include "protocol/ipv4/grammar.hpp"
#include "internal.hpp"

#include "bit/field.hpp"
#include "bit/pack.hpp"
#include "bit/storage.hpp"
#include "haluj/bounded/vector.hpp"
#include "haluj/ring_buffer.hpp"

namespace protocol
{

namespace ipv4
{

namespace internal
{

namespace
{

namespace eth = wire::eth;
namespace ip  = wire::ip;
using wire::internet_checksum;
using wire::load;
using wire::store16;
using wire::store32;
using wire::tcp::control_t;

// ---- sequence numbers (3.4): compared modulo 2^32 ----------------------------

constexpr bool seq_lt(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) < 0; }
constexpr bool seq_le(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) <= 0; }
constexpr bool seq_gt(std::uint32_t a, std::uint32_t b) { return seq_lt(b, a); }
constexpr bool seq_ge(std::uint32_t a, std::uint32_t b) { return seq_le(b, a); }

// ---- connection state (3.3.2) -----------------------------------------------------

enum class tcp_state : std::uint8_t
{
  closed,
  syn_sent,
  syn_received,
  established,
  fin_wait_1,
  fin_wait_2,
  close_wait,
  closing,
  last_ack,
  time_wait
};

/// A segment to send, or sent and not acknowledged yet. SYN and FIN take a
/// sequence number each, like a byte of data.
struct seg_syn            : bit::field<0> {};
struct seg_fin            : bit::field<1> {};
struct seg_sent           : bit::field<2> {};
struct seg_retransmitted  : bit::field<3> {};
struct seg_sacked         : bit::field<4> {};   ///< the peer has it (RFC 2018)
struct seg_resent         : bit::field<5> {};   ///< sent again in this recovery
using  seg_flags_t = bit::storage<bit::pack<std::uint8_t, seg_syn, seg_fin, seg_sent, seg_retransmitted,
                                            seg_sacked, seg_resent>>;

struct tx_segment
{
  packet_id     id{};
  std::uint32_t seq     = 0;
  std::uint16_t offset  = 0;   ///< where its data starts in the block
  std::uint16_t length  = 0;   ///< bytes of data
  seg_flags_t   flags{};

  std::uint32_t space() const
  {
    return length + (flags.test<seg_syn>() ? 1U : 0U) + (flags.test<seg_fin>() ? 1U : 0U);
  }

  std::uint32_t end() const { return seq + space(); }
};

/// tcb::listener: 0 for none, else the listener's index + 1 (so a table of
/// all zeros is a table of free places, in .bss)
constexpr std::uint8_t c_no_listener = 0;

/// Payload offset of a data segment: a frame without TCP options starts at
/// the headroom, where the DMA wants its alignment
constexpr std::size_t c_data_offset = c_packet_headroom + eth::size + ip::min_size + wire::tcp::min_size;
/// A SYN carries the MSS and SACK-permitted options (8 bytes with padding)
constexpr std::size_t c_syn_options = 8;
constexpr std::size_t c_syn_offset  = c_data_offset + c_syn_options;

static_assert(c_data_offset + c_tcp_mss <= c_packet_block_size);

/// Data received ahead of a gap, kept until the gap is filled
struct ooo_segment
{
  packet_id     id;
  std::uint32_t seq;
  bool          fin;      ///< a FIN follows the data
};

/// Transmission control block (3.3.1)
struct tcb
{
  tcp_state             state       = tcp_state::closed;
  std::uint8_t          generation  = 0;
  bool                  app_owned   = false;          ///< the application holds a handle
  std::uint8_t          listener    = c_no_listener;  ///< not accepted yet: its listener + 1
  ipv4::tcp::status           error       = ipv4::tcp::status::closed;

  interface_designator  intf        = 0;
  std::uint16_t         local_port  = 0;
  endpoint              remote{};
  ethernet::address     remote_hw{};
  bool                  hw_known    = false;
  bool                  sack_ok     = false;          ///< both ends sent SACK-permitted

  // Send sequence variables (3.3.1)
  std::uint32_t         iss = 0, snd_una = 0, snd_nxt = 0, snd_wnd = 0, snd_wl1 = 0, snd_wl2 = 0;
  std::uint16_t         snd_mss     = 0;              ///< set when the connection starts
  haluj::bounded::vector<tx_segment, c_tcp_tx_segments> tx;
  bool                  fin_wanted  = false;          ///< close(): FIN after the data
  bool                  fin_queued  = false;
  bool                  fin_sent    = false;

  // Receive sequence variables
  std::uint32_t         irs = 0, rcv_nxt = 0;
  std::uint32_t         rcv_adv     = 0;              ///< right edge of the window announced
  haluj::bounded::vector<packet_id, c_tcp_rx_segments> rx;
  std::size_t           rx_bytes    = 0;
  /// Out of order, by sequence number; shares the c_tcp_rx_segments blocks
  /// with rx
  haluj::bounded::vector<ooo_segment, c_tcp_rx_segments> ooo;
  std::uint32_t         ooo_last    = 0;              ///< the latest kept: its SACK block goes first

  // Control segments to send
  bool                  ack_now     = false;
  std::uint8_t          dupacks_owed = 0;            ///< RFC 5681 4.2: one ACK alone per segment out of order
  bool                  rst_now     = false;

  // Retransmission and persist timer (RFC 6298)
  std::uint32_t         rto         = 0;              ///< set when the connection starts
  std::uint32_t         timer_start = 0;
  bool                  timer_running = false;
  std::uint8_t          retransmits = 0;
  std::uint32_t         srtt        = 0;
  std::uint32_t         rttvar      = 0;
  bool                  rtt_valid   = false;
  bool                  rtt_timing  = false;
  std::uint32_t         rtt_seq     = 0;
  std::uint32_t         rtt_start   = 0;
  std::uint8_t          dupacks     = 0;
  bool                  in_recovery = false;          ///< RFC 6582: until recover is acknowledged
  bool                  probe_sent  = false;          ///< RFC 8985: a tail loss probe waits for its ACK
  std::uint32_t         last_send   = 0;              ///< when data went last
  std::uint32_t         recover     = 0;
  bool                  probe_now   = false;

  std::uint32_t         time_wait_start = 0;

  bool used() const
  {
    return state != tcp_state::closed || app_owned || listener != c_no_listener || rst_now;
  }

  bool synchronized() const
  {
    return state != tcp_state::closed && state != tcp_state::syn_sent &&
           state != tcp_state::syn_received;
  }

  std::uint16_t mss() const
  {
    return static_cast<std::uint16_t>(std::min<std::size_t>(snd_mss, c_tcp_mss));
  }

  /// The sequence number of the next segment queued
  std::uint32_t queue_end() const
  {
    return tx.empty() ? snd_nxt : tx.back().end();
  }

  /// Data received is dropped: the application closed and reads no more
  bool discards() const
  {
    return !app_owned && listener == c_no_listener;
  }
};

struct listener_slot
{
  bool                  used = false;
  interface_designator  intf = 0;
  std::uint16_t         port = 0;
  /// Established, waiting for accept()
  haluj::ring_buffer<std::array<ipv4::tcp::connection, c_tcp_backlog>> ready{};
};

std::array<tcb, c_tcp_connections>          g_tcb{};
std::array<listener_slot, c_tcp_listeners>  g_listeners{};
std::uint64_t                               g_secret     = 0x9E3779B97F4A7C15ULL;
std::uint16_t                               g_next_port  = 49152;
std::size_t                                 g_round      = 0;

// ---- helpers ------------------------------------------------------------------------

std::uint64_t mix(std::uint64_t x)
{
  // splitmix64 finaliser
  x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
  x ^= x >> 27; x *= 0x94D049BB133111EBULL;
  x ^= x >> 31;
  return x;
}

/// RFC 6528: ISN = M + F(local address and port, remote address and port,
/// secret), M a 4 microsecond timer (the clock counts milliseconds)
std::uint32_t initial_sequence(const tcb& c)
{
  const interface& itf = g_interfaces[c.intf];
  std::uint64_t x = g_secret;
  x = mix(x ^ ((std::uint64_t(to_u32(itf.ip_addr)) << 32) | to_u32(c.remote.ip_addr)));
  x = mix(x ^ ((std::uint64_t(c.local_port) << 16) | c.remote.port));
  return static_cast<std::uint32_t>(x) + g_now * 250U;
}

tcb* find_tcb(interface_designator id, std::uint16_t local_port, const endpoint& remote)
{
  for (auto& c : g_tcb)
  {
    if (c.used() && c.state != tcp_state::closed && c.intf == id &&
        c.local_port == local_port && c.remote == remote)
    {
      return &c;
    }
  }
  return nullptr;
}

listener_slot* find_listener(interface_designator id, std::uint16_t port)
{
  for (auto& l : g_listeners)
    if (l.used && l.intf == id && l.port == port)
      return &l;
  return nullptr;
}

std::uint8_t index_of(const listener_slot& l)
{
  return static_cast<std::uint8_t>(&l - g_listeners.data());
}

std::uint8_t index_of(const tcb& c)
{
  return static_cast<std::uint8_t>(&c - g_tcb.data());
}

ipv4::tcp::connection handle_of(const tcb& c)
{
  return {index_of(c), c.generation};
}

tcb* from_handle(ipv4::tcp::connection h)
{
  if (h.index >= g_tcb.size())
    return nullptr;
  tcb& c = g_tcb[h.index];
  return (c.generation == h.generation && c.app_owned) ? &c : nullptr;
}

/// A free control block, reset
tcb* allocate_tcb()
{
  for (auto& c : g_tcb)
  {
    if (!c.used())
    {
      const std::uint8_t generation = static_cast<std::uint8_t>(c.generation + 1);
      c = tcb{};
      c.generation = generation;
      c.snd_mss    = 536;                 // RFC 9293 3.7.1: without the MSS option
      c.rto        = c_tcp_rto_initial;
      return &c;
    }
  }
  return nullptr;
}

/// Gives back every block of the connection
void drop_buffers(tcb& c)
{
  for (packet_id p : c.rx)
    g_packet_pool.release(p);
  c.rx.clear();
  c.rx_bytes = 0;

  for (auto& o : c.ooo)
    g_packet_pool.release(o.id);
  c.ooo.clear();

  for (auto& s : c.tx)
    unpin(s.id);
  c.tx.clear();
}

/// The connection is over: CLOSED. The place is free again unless the
/// application still holds a handle (it then sees why it ended).
void end(tcb& c, ipv4::tcp::status why)
{
  drop_buffers(c);
  c.state         = tcp_state::closed;
  c.error         = why;
  c.timer_running = false;
  c.ack_now       = false;
  c.dupacks_owed  = 0;
  c.listener      = c_no_listener;   // never accepted: nobody will
}

constexpr std::uint32_t c_rx_capacity = c_tcp_rx_segments * c_tcp_mss;

/// Bytes the connection can surely keep: a full segment for every block it
/// may still take. Counting blocks, not bytes: a block partly read is still
/// taken, so the bytes read from it give no room yet.
std::uint32_t receive_space(const tcb& c)
{
  const std::size_t slots = c_tcp_rx_segments - c.rx.size() - c.ooo.size();
  const std::size_t pool  = g_packet_pool.available() > c_tx_reserved_blocks + 1
                              ? g_packet_pool.available() - c_tx_reserved_blocks - 1 : 0;
  return static_cast<std::uint32_t>(std::min(slots, pool) * c_tcp_mss);
}

/// The current receive window; never moves the right edge left, and grows
/// it only by at least a segment or half the buffer (receiver side silly
/// window avoidance, 3.8.6.2.2)
std::uint16_t receive_window(tcb& c)
{
  const std::uint32_t free    = receive_space(c);
  const std::uint32_t current = seq_gt(c.rcv_adv, c.rcv_nxt) ? c.rcv_adv - c.rcv_nxt : 0;
  const std::uint32_t step    = std::min<std::uint32_t>(c_tcp_mss, c_rx_capacity / 2);
  const std::uint32_t window  = std::min<std::uint32_t>(free >= current + step ? free : current, 0xFFFF);

  c.rcv_adv = c.rcv_nxt + window;
  return static_cast<std::uint16_t>(window);
}

// ---- building segments ------------------------------------------------------------

struct segment_fields
{
  std::uint16_t local_port  = 0;
  endpoint      remote{};
  std::uint32_t seq         = 0;
  std::uint32_t ack         = 0;
  std::uint8_t  control     = 0;
  std::uint16_t window      = 0;
  bool          syn_options = false;      ///< MSS, and SACK-permitted when sack_permitted
  bool          sack_permitted = false;
  std::uint8_t  sack_blocks = 0;
  const std::uint32_t* sack = nullptr;    ///< left and right edges
};

constexpr std::size_t sack_option_size(std::size_t blocks)
{
  return blocks == 0 ? 0 : 4 + 8 * blocks;     // NOP, NOP, kind, length, edges
}

/// Puts the TCP, IP and Ethernet headers in front of the block's payload
void write_segment(packet_id p, const interface& itf, const ethernet::address& hw,
                   const segment_fields& f)
{
  const std::size_t header_length = wire::tcp::min_size +
                                    (f.syn_options ? c_syn_options : sack_option_size(f.sack_blocks));
  const std::size_t length        = header_length + g_packet_pool.data(p).size();

  // Every segment's data sits at c_data_offset or c_syn_offset: the headers
  // always have room
  std::uint8_t* t = g_packet_pool.push_header(p, header_length);
  std::uint8_t* h = g_packet_pool.push_header(p, ip::min_size);
  std::uint8_t* e = g_packet_pool.push_header(p, eth::size);
  if (t == nullptr || h == nullptr || e == nullptr)
    return;

  store16(t + wire::tcp::source_port,      f.local_port);
  store16(t + wire::tcp::destination_port, f.remote.port);
  store32(t + wire::tcp::sequence,         f.seq);
  store32(t + wire::tcp::acknowledgment,   f.ack);
  t[wire::tcp::offset]  = wire::tcp::offset_t().assign<wire::tcp::data_offset>(header_length / 4).value();
  t[wire::tcp::control] = f.control;
  store16(t + wire::tcp::window,   f.window);
  store16(t + wire::tcp::checksum, 0);
  store16(t + wire::tcp::urgent,   0);

  if (f.syn_options)
  {
    t[20] = wire::tcp::option_mss;
    t[21] = wire::tcp::option_mss_size;
    store16(t + 22, static_cast<std::uint16_t>(c_tcp_mss));
    t[24] = wire::tcp::option_nop;
    t[25] = wire::tcp::option_nop;
    t[26] = f.sack_permitted ? wire::tcp::option_sack_permitted        : wire::tcp::option_nop;
    t[27] = f.sack_permitted ? wire::tcp::option_sack_permitted_size   : wire::tcp::option_nop;
  }
  else if (f.sack_blocks > 0)
  {
    t[20] = wire::tcp::option_nop;
    t[21] = wire::tcp::option_nop;
    t[22] = wire::tcp::option_sack;
    t[23] = static_cast<std::uint8_t>(2 + 8 * f.sack_blocks);
    for (std::size_t i = 0; i < 2U * f.sack_blocks; ++i)
      store32(t + 24 + 4 * i, f.sack[i]);
  }

  write_ipv4_header(h, itf, f.remote.ip_addr, ip::tcp, length);

  store16(t + wire::tcp::checksum,
          internet_checksum()
            .add({h + ip::source, 8})
            .add16(ip::tcp)
            .add16(static_cast<std::uint16_t>(length))
            .add({t, length})
            .result());

  write_ethernet_header(e, hw, itf, eth::type_ipv4);
  pad(p);
}

/// SACK blocks of the data kept out of order: the one with the latest
/// segment first (RFC 2018 4), then the others in order
struct sack_list
{
  std::uint8_t  blocks = 0;
  std::uint32_t edges[2 * wire::tcp::max_sack_blocks]{};
};

sack_list sack_of(const tcb& c)
{
  sack_list l;
  if (!c.sack_ok)
    return l;

  std::uint32_t ranges[2 * c_tcp_rx_segments];
  std::size_t   n     = 0;
  std::size_t   first = 0;
  for (const auto& o : c.ooo)
  {
    const std::uint32_t end = o.seq + static_cast<std::uint32_t>(g_packet_pool.data(o.id).size());
    if (n > 0 && seq_le(o.seq, ranges[2 * n - 1]))
    {
      if (seq_gt(end, ranges[2 * n - 1]))
        ranges[2 * n - 1] = end;
    }
    else
    {
      ranges[2 * n]     = o.seq;
      ranges[2 * n + 1] = end;
      ++n;
    }
    if (o.seq == c.ooo_last)
      first = n - 1;
  }

  auto add = [&](std::size_t i)
  {
    if (l.blocks < wire::tcp::max_sack_blocks && ranges[2 * i] != ranges[2 * i + 1])
    {
      l.edges[2 * l.blocks]     = ranges[2 * i];
      l.edges[2 * l.blocks + 1] = ranges[2 * i + 1];
      ++l.blocks;
    }
  };
  if (n > 0)
    add(first);
  for (std::size_t i = 0; i < n; ++i)
    if (i != first)
      add(i);
  return l;
}

/// A segment of the connection: its current ACK and window
void write_segment(tcb& c, packet_id p, std::uint32_t seq, control_t control, bool syn,
                   const sack_list* sack = nullptr)
{
  segment_fields f;
  f.local_port     = c.local_port;
  f.remote         = c.remote;
  f.seq            = seq;
  f.control        = control.value();
  f.syn_options    = syn;
  f.sack_permitted = c.state == tcp_state::syn_sent || c.sack_ok;   // offered, or answered
  if (sack != nullptr)
  {
    f.sack_blocks = sack->blocks;
    f.sack        = sack->edges;
  }

  if (control.test<wire::tcp::ACK>())
    f.ack = c.rcv_nxt;

  if (!control.test<wire::tcp::RST>())
    f.window = receive_window(c);

  write_segment(p, g_interfaces[c.intf], c.remote_hw, f);
}

/// A segment with no data (ACK, RST, window probe) in a fresh block
std::optional<packet_id> control_segment(tcb& c, std::uint32_t seq, control_t control)
{
  auto p = g_packet_pool.acquire();
  if (!p)
    return std::nullopt;

  // SACK blocks on ACKs while data waits out of order; their room is taken
  // after the payload offset, the frame starts that much later
  const sack_list sack = control.test<wire::tcp::RST>() ? sack_list{} : sack_of(c);
  g_packet_pool.set(*p, c_data_offset + sack_option_size(sack.blocks), 0);
  write_segment(c, *p, seq, control, false, &sack);
  return p;
}

// ---- send queue ---------------------------------------------------------------------

/// Queues an empty segment for SYN or FIN in p
void queue_control(tcb& c, packet_id p, bool syn)
{
  tx_segment s;
  s.id     = p;
  s.seq    = c.queue_end();
  s.offset = static_cast<std::uint16_t>(syn ? c_syn_offset : c_data_offset);
  s.length = 0;
  if (syn)
    s.flags.set<seg_syn>();
  else
    s.flags.set<seg_fin>();

  g_packet_pool.set(p, s.offset, 0);
  pin(p);
  c.tx.push_back(s);
}

/// Sends the first unacknowledged segment again
void retransmit_first(tcb& c)
{
  if (c.tx.empty() || !c.tx.front().flags.test<seg_sent>())
    return;
  c.tx.front().flags.clear<seg_sent>().set<seg_retransmitted>().set<seg_resent>();
  c.rtt_timing = false;   // Karn: no RTT sample from a segment sent twice
  ++g_stats.tcp_retransmits;
}

/// Marks the segments the SACK blocks cover; true when any is new
bool update_scoreboard(tcb& c, const grammar::tcp_header& th)
{
  bool more = false;
  for (std::size_t b = 0; b < th.sack_blocks; ++b)
  {
    const std::uint32_t left = th.sack[2 * b], right = th.sack[2 * b + 1];
    if (!seq_lt(left, right) || seq_le(right, c.snd_una) || seq_gt(right, c.snd_nxt))
      continue;               // D-SACK (RFC 2883) or nonsense

    for (auto& s : c.tx)
    {
      if (s.flags.test<seg_sent>() && !s.flags.test<seg_sacked>() && s.length > 0 &&
          seq_ge(s.seq, left) && seq_le(s.seq + s.length, right))
      {
        s.flags.set<seg_sacked>();
        more = true;
      }
    }
  }
  return more;
}

/// In recovery: every hole below data the peer has is sent again, once
/// (RFC 6675 NextSeg; a hole is a whole segment here)
void resend_holes(tcb& c)
{
  std::size_t highest = c.tx.size();
  for (std::size_t i = c.tx.size(); i-- > 0;)
  {
    if (c.tx[i].flags.test<seg_sacked>())
    {
      highest = i;
      break;
    }
  }
  if (highest == c.tx.size())
    return;

  for (std::size_t i = 0; i < highest; ++i)
  {
    tx_segment& s = c.tx[i];
    if (s.flags.test<seg_sent>() && !s.flags.test<seg_sacked>() && !s.flags.test<seg_resent>())
    {
      s.flags.clear<seg_sent>().set<seg_retransmitted>().set<seg_resent>();
      c.rtt_timing = false;
      ++g_stats.tcp_retransmits;
    }
  }
}

/// RFC 6298 2.2 / 2.3
void rtt_sample(tcb& c, std::uint32_t r)
{
  if (!c.rtt_valid)
  {
    c.srtt      = r;
    c.rttvar    = r / 2;
    c.rtt_valid = true;
  }
  else
  {
    const std::uint32_t delta = c.srtt > r ? c.srtt - r : r - c.srtt;
    c.rttvar = (3 * c.rttvar + delta) / 4;
    c.srtt   = (7 * c.srtt + r) / 8;
  }

  c.rto = std::clamp<std::uint32_t>(c.srtt + std::max<std::uint32_t>(1, 4 * c.rttvar),
                                    c_tcp_rto_min, c_tcp_rto_max);
}

/// The peer acknowledged everything before ack (3.10.7.4, fifth check)
void acknowledge(tcb& c, std::uint32_t ack)
{
  if (c.rtt_timing && seq_ge(ack, c.rtt_seq))
  {
    rtt_sample(c, g_now - c.rtt_start);
    c.rtt_timing = false;
  }

  // RFC 6582 3.2: an ACK short of recover shows the next hole
  bool partial = false;
  if (c.in_recovery)
  {
    if (seq_ge(ack, c.recover))
      c.in_recovery = false;
    else
      partial = true;
  }

  while (!c.tx.empty())
  {
    tx_segment& s = c.tx.front();

    if (seq_le(s.end(), ack))
    {
      unpin(s.id);
      for (std::size_t j = 0; j + 1 < c.tx.size(); ++j)
        c.tx[j] = c.tx[j + 1];
      c.tx.pop_back();
      continue;
    }

    if (seq_gt(ack, s.seq) && !s.flags.test<seg_syn>())
    {
      // Part of the data: what is left is sent again if needed
      const std::uint32_t k = std::min<std::uint32_t>(ack - s.seq, s.length);
      s.seq    += k;
      s.offset  = static_cast<std::uint16_t>(s.offset + k);
      s.length  = static_cast<std::uint16_t>(s.length - k);
    }
    break;
  }

  c.snd_una     = ack;
  c.probe_sent  = false;
  c.retransmits = 0;
  c.dupacks     = 0;
  c.rto         = c.rtt_valid ? c.rto : c_tcp_rto_initial;

  if (c.snd_una == c.snd_nxt)
    c.timer_running = false;
  else
    c.timer_start = g_now;          // RFC 6298 5.3

  if (partial)
  {
    if (!c.tx.empty() && !c.tx.front().flags.test<seg_resent>())
      retransmit_first(c);
    resend_holes(c);
  }
}

/// Duplicate ACKs that show a loss: three (RFC 5681), fewer when fewer
/// segments are out to cause them (early retransmit, RFC 5827)
std::uint8_t duplicate_threshold(const tcb& c)
{
  const auto out = std::count_if(c.tx.begin(), c.tx.end(), [](const tx_segment& s)
                                 { return s.flags.test<seg_sent>() && s.length > 0; });
  return out >= 4 || out < 2 ? 3 : static_cast<std::uint8_t>(out - 1);
}

/// Fast retransmit; recovery lasts until all sent now is acknowledged
void enter_recovery(tcb& c)
{
  for (auto& s : c.tx)
    s.flags.clear<seg_resent>();
  retransmit_first(c);
  resend_holes(c);
  c.in_recovery = true;
  c.recover     = c.snd_nxt;
}

bool fin_acknowledged(const tcb& c)
{
  return c.fin_sent && c.snd_una == c.snd_nxt;
}

void enter_time_wait(tcb& c)
{
  c.state           = tcp_state::time_wait;
  c.time_wait_start = g_now;
  c.timer_running   = false;
}

/// Established after the handshake: an accepted connection waits for
/// accept()
void established(tcb& c, const grammar::tcp_header& th)
{
  c.state   = tcp_state::established;
  c.snd_wnd = th.window;
  c.snd_wl1 = th.sequence;
  c.snd_wl2 = th.acknowledgment;

  if (c.listener != c_no_listener)
    g_listeners[c.listener - 1].ready.try_push(handle_of(c));   // room: backlog counted at SYN
}

/// Received data in order: kept in the block, or copied to the end of the
/// last block when it fits there (small segments do not take a block each)
enum class stored { copied, kept, refused, duplicate };

/// Frees the block of the out of order segment furthest ahead: in order
/// data, or data nearer the gap, needs it more
bool evict_out_of_order(tcb& c)
{
  if (c.ooo.empty())
    return false;
  g_packet_pool.release(c.ooo.back().id);
  c.ooo.pop_back();
  return true;
}

/// fresh: the block has just come in (not from the out of order queue), so
/// the pool must spare it
stored store_data(tcb& c, packet_id p, bool fresh = true)
{
  const auto data = g_packet_pool.data(p);

  if (!c.rx.empty())
  {
    const packet_id     tail  = c.rx.back();
    const auto          t     = g_packet_pool.data(tail);
    const std::size_t   start = static_cast<std::size_t>(t.data() - g_packet_pool.base(tail));
    const std::size_t   end   = start + t.size();

    if (data.size() <= c_packet_block_size - end)
    {
      std::memcpy(g_packet_pool.base(tail) + end, data.data(), data.size());
      g_packet_pool.set(tail, start, t.size() + data.size());
      c.rx_bytes += data.size();
      return stored::copied;
    }
  }

  // The same rule as UDP: the next frame and the transmit reserve stay
  while (c.rx.size() + c.ooo.size() >= c_tcp_rx_segments ||
         (fresh && g_packet_pool.available() < c_tx_reserved_blocks + 1))
  {
    if (!evict_out_of_order(c))
      return stored::refused;
  }

  c.rx.push_back(p);
  c.rx_bytes += data.size();
  return stored::kept;
}

/// The FIN came in order (3.10.7.4, eighth check)
void fin_arrived(tcb& c)
{
  c.rcv_nxt += 1;
  c.ack_now  = true;

  // Nothing comes after the FIN
  while (evict_out_of_order(c)) {}

  switch (c.state)
  {
    case tcp_state::established:
      c.state = tcp_state::close_wait;
      break;
    case tcp_state::fin_wait_1:
      if (fin_acknowledged(c))
        enter_time_wait(c);
      else
        c.state = tcp_state::closing;
      break;
    case tcp_state::fin_wait_2:
    case tcp_state::time_wait:
      enter_time_wait(c);
      break;
    default:
      break;
  }
}

/// Keeps a segment that came ahead of a gap (its payload in p, starting at
/// seq)
stored store_out_of_order(tcb& c, packet_id p, std::uint32_t seq, bool fin)
{
  std::uint32_t length = static_cast<std::uint32_t>(g_packet_pool.data(p).size());

  // Only what the window announced
  const std::uint32_t room = seq_gt(c.rcv_adv, seq) ? c.rcv_adv - seq : 0;
  if (length > room)
  {
    length = room;
    fin    = false;
    g_packet_pool.trim(p, length);
  }
  if (length == 0 && !fin)
    return stored::refused;

  // Where it goes; nothing new when a segment kept already covers it
  std::size_t at = 0;
  for (; at < c.ooo.size(); ++at)
  {
    const ooo_segment&  o     = c.ooo[at];
    const std::uint32_t o_end = o.seq + static_cast<std::uint32_t>(g_packet_pool.data(o.id).size());

    if (seq_le(o.seq, seq) && seq_ge(o_end, seq + length) && (o.fin || !fin || o_end != seq + length))
      return stored::duplicate;
    if (seq_gt(o.seq, seq))
      break;
  }

  // Room: the block of a segment further ahead is given up for it
  while (c.rx.size() + c.ooo.size() >= c_tcp_rx_segments ||
         g_packet_pool.available() < c_tx_reserved_blocks + 1)
  {
    if (at >= c.ooo.size())
      return stored::refused;
    evict_out_of_order(c);
  }

  c.ooo_last = seq;
  c.ooo.push_back({p, seq, fin});
  for (std::size_t j = c.ooo.size() - 1; j > at; --j)
    c.ooo[j] = c.ooo[j - 1];
  c.ooo[at] = {p, seq, fin};

  ++g_stats.tcp_rx_out_of_order;
  return stored::kept;
}

/// rcv_nxt moved: the segments kept that now follow it are received
void deliver_out_of_order(tcb& c)
{
  while (!c.ooo.empty() && seq_le(c.ooo.front().seq, c.rcv_nxt))
  {
    const ooo_segment o = c.ooo.front();
    for (std::size_t j = 0; j + 1 < c.ooo.size(); ++j)
      c.ooo[j] = c.ooo[j + 1];
    c.ooo.pop_back();

    const std::uint32_t length = static_cast<std::uint32_t>(g_packet_pool.data(o.id).size());
    const std::uint32_t end    = o.seq + length;
    const std::uint32_t skip   = c.rcv_nxt - o.seq;

    if (seq_gt(end, c.rcv_nxt))
    {
      g_packet_pool.pull_header(o.id, skip);
      const stored s = c.discards() ? stored::copied : store_data(c, o.id, false);
      if (s != stored::kept)
        g_packet_pool.release(o.id);
      if (s == stored::refused)       // never: its slot was given back above
      {
        ++g_stats.tcp_rx_refused;
        while (evict_out_of_order(c)) {}
        return;
      }
      c.rcv_nxt = end;
    }
    else
    {
      g_packet_pool.release(o.id);
    }

    if (o.fin && end == c.rcv_nxt)
    {
      fin_arrived(c);
      return;
    }
  }
}

/// An answer to a segment for no connection (3.10.7.1), written in the
/// segment's own block
verdict reset_reply(const interface& itf, packet_id p, const ethernet::address& hw,
                    const endpoint& remote, const grammar::tcp_header& th, std::size_t data_length)
{
  const control_t in = th.flags();

  segment_fields f;
  f.local_port = th.destination_port;
  f.remote     = remote;

  if (in.test<wire::tcp::ACK>())
  {
    f.seq     = th.acknowledgment;
    f.control = control_t().set<wire::tcp::RST>().value();
  }
  else
  {
    f.seq     = 0;
    f.ack     = th.sequence + static_cast<std::uint32_t>(data_length) +
                (in.test<wire::tcp::SYN>() ? 1U : 0U) + (in.test<wire::tcp::FIN>() ? 1U : 0U);
    f.control = control_t().set<wire::tcp::RST, wire::tcp::ACK>().value();
  }

  g_packet_pool.set(p, c_data_offset, 0);
  write_segment(p, itf, hw, f);
  ++g_stats.tcp_resets_sent;
  return verdict::reply;
}

std::size_t embryonic_and_ready(std::uint8_t listener_index)
{
  return static_cast<std::size_t>(std::count_if(g_tcb.begin(), g_tcb.end(),
    [&](const tcb& c) { return c.listener == listener_index + 1; }));
}

/// LISTEN (3.10.7.2): a SYN opens a connection in SYN-RECEIVED; the SYN's
/// block becomes the SYN,ACK
verdict passive_open(interface_designator id, listener_slot& l, packet_id p,
                     const ethernet::address& hw, const endpoint& remote,
                     const grammar::tcp_header& th)
{
  const std::uint8_t li = index_of(l);

  // A full backlog drops the SYN: the peer tries again later
  if (embryonic_and_ready(li) >= c_tcp_backlog)
    return verdict::drop;

  tcb* c = allocate_tcb();
  if (c == nullptr)
    return verdict::drop;

  c->state      = tcp_state::syn_received;
  c->listener   = static_cast<std::uint8_t>(li + 1);
  c->intf       = id;
  c->local_port = l.port;
  c->remote     = remote;
  c->remote_hw  = hw;
  c->hw_known   = true;
  c->irs        = th.sequence;
  c->rcv_nxt    = th.sequence + 1;
  c->rcv_adv    = c->rcv_nxt;
  c->iss        = initial_sequence(*c);
  c->snd_una    = c->iss;
  c->snd_nxt    = c->iss;
  c->snd_wnd    = th.window;
  c->snd_wl1    = th.sequence;
  if (th.mss != 0)
    c->snd_mss  = th.mss;
  c->sack_ok    = th.sack_permitted;

  queue_control(*c, p, true);   // SYN,ACK; data in the SYN is not kept
  return verdict::keep;
}

// ---- a segment for a connection (3.10.7.3 / 3.10.7.4) ----------------------------------

/// The ACK of a segment in a synchronized state (3.10.7.4, fifth check).
/// False when the segment ends the connection or goes no further.
bool process_ack(tcb& c, const grammar::tcp_header& th, std::uint32_t seg_len)
{
  const std::uint32_t seq = th.sequence;
  const std::uint32_t ack = th.acknowledgment;

  if (seq_gt(ack, c.snd_nxt))
  {
    c.ack_now = true;                   // acknowledges what was not sent
    return false;
  }

  const std::uint32_t una = c.snd_una;
  if (seq_gt(ack, c.snd_una))
    acknowledge(c, ack);

  // An ACK with new SACK information counts as a duplicate even when it
  // carries data or a new window (RFC 6675 2)
  const bool sacked_more = c.sack_ok && update_scoreboard(c, th);

  if (ack == una && c.snd_una != c.snd_nxt &&
      (sacked_more || (seg_len == 0 && th.window == c.snd_wnd)))
  {
    // Duplicate ACK: enough in a row, the first segment was lost
    if (c.dupacks < 0xFF)
      ++c.dupacks;
    if (!c.in_recovery && c.dupacks >= duplicate_threshold(c))
      enter_recovery(c);
  }

  // The first segment is lost when enough after it have arrived
  // (RFC 6675 IsLost), however many ACKs told so
  if (!c.in_recovery && sacked_more)
  {
    const auto sacked = std::count_if(c.tx.begin(), c.tx.end(), [](const tx_segment& s)
                                      { return s.flags.test<seg_sacked>(); });
    if (sacked >= duplicate_threshold(c))
      enter_recovery(c);
  }
  else if (c.in_recovery && sacked_more)
  {
    resend_holes(c);
  }

  // Window update
  if (seq_lt(c.snd_wl1, seq) || (c.snd_wl1 == seq && seq_le(c.snd_wl2, ack)))
  {
    c.snd_wnd = th.window;
    c.snd_wl1 = seq;
    c.snd_wl2 = ack;
  }

  switch (c.state)
  {
    case tcp_state::fin_wait_1:
      if (fin_acknowledged(c))
        c.state = tcp_state::fin_wait_2;
      break;
    case tcp_state::closing:
      if (fin_acknowledged(c))
        enter_time_wait(c);
      break;
    case tcp_state::last_ack:
      if (fin_acknowledged(c))
      {
        end(c, ipv4::tcp::status::closed);
        return false;
      }
      break;
    default:
      break;
  }
  return true;
}

verdict segment_arrives(tcb& c, packet_id p, const grammar::tcp_header& th,
                        std::size_t data_length)
{
  const control_t     in      = th.flags();
  const std::uint32_t seq     = th.sequence;
  const std::uint32_t seg_len = static_cast<std::uint32_t>(data_length) +
                                (in.test<wire::tcp::SYN>() ? 1U : 0U) +
                                (in.test<wire::tcp::FIN>() ? 1U : 0U);

  // ---- SYN-SENT (3.10.7.3) ----
  if (c.state == tcp_state::syn_sent)
  {
    const bool ack_ok = in.test<wire::tcp::ACK>() &&
                        seq_gt(th.acknowledgment, c.iss) && seq_le(th.acknowledgment, c.snd_nxt);

    if (in.test<wire::tcp::ACK>() && !ack_ok)
    {
      if (in.test<wire::tcp::RST>())
        return verdict::drop;
      return reset_reply(g_interfaces[c.intf], p, c.remote_hw, c.remote, th, data_length);
    }

    if (in.test<wire::tcp::RST>())
    {
      if (ack_ok)
        end(c, ipv4::tcp::status::reset);
      return verdict::drop;
    }

    if (in.test<wire::tcp::SYN>())
    {
      c.irs     = seq;
      c.rcv_nxt = seq + 1;
      c.rcv_adv = c.rcv_nxt;
      if (th.mss != 0)
        c.snd_mss = th.mss;
      c.sack_ok = th.sack_permitted;

      if (ack_ok)
      {
        acknowledge(c, th.acknowledgment);
        established(c, th);
        c.ack_now = true;
      }
      else
      {
        // Simultaneous open: our SYN goes again as SYN,ACK
        c.state = tcp_state::syn_received;
        retransmit_first(c);
      }
    }
    return verdict::drop;
  }

  // ---- first: sequence number ----
  const std::uint32_t window = seq_gt(c.rcv_adv, c.rcv_nxt) ? c.rcv_adv - c.rcv_nxt : 0;

  const auto in_window = [&](std::uint32_t s)
  {
    return seq_le(c.rcv_nxt, s) && seq_lt(s, c.rcv_nxt + window);
  };

  bool acceptable;
  if (seg_len == 0)
    acceptable = (window == 0) ? seq == c.rcv_nxt : in_window(seq);
  else
    acceptable = window != 0 && (in_window(seq) || in_window(seq + seg_len - 1));

  // The peer's SYN again: our SYN,ACK was lost
  if (c.state == tcp_state::syn_received && in.test<wire::tcp::SYN>() &&
      !in.test<wire::tcp::ACK>() && seq == c.irs)
  {
    retransmit_first(c);
    return verdict::drop;
  }

  if (!acceptable)
  {
    if (!in.test<wire::tcp::RST>())
    {
      // "Special allowance should be made to accept valid ACKs" (3.10.7.4):
      // with a full receive buffer every segment is out of the window, yet
      // its ACK must still open ours, or both sides wait for each other
      if (in.test<wire::tcp::ACK>() && !in.test<wire::tcp::SYN>() && c.synchronized())
        process_ack(c, th, seg_len);
      c.ack_now = true;
    }
    return verdict::drop;
  }

  // ---- second: RST (RFC 5961 3.2: exactly the next sequence number) ----
  if (in.test<wire::tcp::RST>())
  {
    if (seq == c.rcv_nxt)
      end(c, ipv4::tcp::status::reset);
    else
      c.ack_now = true;                 // challenge ACK
    return verdict::drop;
  }

  // ---- fourth: SYN (RFC 5961 4.2) ----
  if (in.test<wire::tcp::SYN>())
  {
    c.ack_now = true;                   // challenge ACK
    return verdict::drop;
  }

  // ---- fifth: ACK ----
  if (!in.test<wire::tcp::ACK>())
    return verdict::drop;

  const std::uint32_t ack = th.acknowledgment;

  if (c.state == tcp_state::syn_received)
  {
    if (!(seq_lt(c.snd_una, ack) && seq_le(ack, c.snd_nxt)))
      return reset_reply(g_interfaces[c.intf], p, c.remote_hw, c.remote, th, data_length);
    acknowledge(c, ack);
    established(c, th);
  }
  else if (!process_ack(c, th, seg_len))
  {
    return verdict::drop;
  }

  // ---- seventh: data ----
  verdict    v            = verdict::drop;
  bool       fin_in_order = seq_le(seq, c.rcv_nxt);
  const bool takes_data   = c.state == tcp_state::established ||
                            c.state == tcp_state::fin_wait_1 ||
                            c.state == tcp_state::fin_wait_2;

  if (seq_gt(seq, c.rcv_nxt) && (data_length > 0 || in.test<wire::tcp::FIN>()))
  {
    // Out of order: kept for later; the ACK of what we have makes the
    // peer's duplicate ACKs start its fast retransmit
    if (takes_data && !c.discards())
    {
      const stored s = store_out_of_order(c, p, seq, in.test<wire::tcp::FIN>());
      if (c.dupacks_owed < 3)
        ++c.dupacks_owed;
      if (s == stored::kept)
        v = verdict::keep;
      else if (s == stored::refused)
        ++g_stats.tcp_rx_refused;
    }
    c.ack_now = true;
    return v;
  }

  if (data_length > 0)
  {
    if (!takes_data)
    {
      c.ack_now    = true;              // no more data expected
      fin_in_order = false;
    }
    else
    {
      const std::uint32_t skip   = c.rcv_nxt - seq;       // received before
      std::uint32_t       usable = static_cast<std::uint32_t>(data_length) - std::min<std::uint32_t>(skip, static_cast<std::uint32_t>(data_length));
      const std::uint32_t room   = seq_gt(c.rcv_adv, c.rcv_nxt) ? c.rcv_adv - c.rcv_nxt : 0;

      if (usable > room)
      {
        usable       = room;
        fin_in_order = false;           // the FIN lies past what we take
      }

      if (usable > 0)
      {
        g_packet_pool.pull_header(p, skip);
        g_packet_pool.trim(p, usable);

        stored s = stored::copied;
        if (!c.discards())
          s = store_data(c, p);

        if (s == stored::refused)
        {
          ++g_stats.tcp_rx_refused;
          fin_in_order = false;
        }
        else
        {
          c.rcv_nxt += usable;
          if (s == stored::kept)
            v = verdict::keep;
        }
      }
      c.ack_now = true;
    }
  }

  // ---- eighth: FIN, in order only ----
  if (in.test<wire::tcp::FIN>() && fin_in_order &&
      seq + static_cast<std::uint32_t>(data_length) == c.rcv_nxt)
    fin_arrived(c);
  else if (!c.ooo.empty())
    deliver_out_of_order(c);

  return v;
}

// ---- timers and sending -------------------------------------------------------------

void run_timers(tcb& c)
{
  if (c.state == tcp_state::time_wait)
  {
    if (g_now - c.time_wait_start >= c_tcp_time_wait)
      end(c, ipv4::tcp::status::closed);
    return;
  }

  const bool in_flight_data = c.snd_una != c.snd_nxt;
  const bool unsent = std::any_of(c.tx.begin(), c.tx.end(),
                                  [](const tx_segment& s) { return !s.flags.test<seg_sent>(); });
  const bool persist = !in_flight_data && c.snd_wnd == 0 && unsent && c.synchronized();

  if (!in_flight_data && !persist)
  {
    c.timer_running = false;
    return;
  }

  if (!c.timer_running)
  {
    c.timer_running = true;
    c.timer_start   = g_now;
    return;
  }

  // Tail loss probe (RFC 8985 7): before the timeout, the last segment
  // again, so the peer's ACK (with SACK) shows what is missing at the end.
  // In recovery the first hole goes again instead: with few segments out,
  // a lost retransmission leaves nothing that could bring an ACK (RFC 8985
  // keeps probes out of recovery; a duplicate costs one segment, a timeout
  // costs at least c_tcp_rto_min). With SACK only, once per new ACK.
  if (!persist && c.sack_ok && c.rtt_valid && !c.probe_sent && c.synchronized())
  {
    const auto sent = std::count_if(c.tx.begin(), c.tx.end(), [](const tx_segment& s)
                                    { return s.flags.test<seg_sent>() && s.length > 0; });
    std::uint32_t pto = std::max(2 * c.srtt, c_tcp_pto_min);
    if (sent == 1)
      pto += c_tcp_delayed_ack_max;

    if (sent > 0 && pto < c.rto && g_now - c.last_send >= pto)
    {
      for (std::size_t k = 0; k < c.tx.size(); ++k)
      {
        tx_segment& s = c.tx[c.in_recovery ? k : c.tx.size() - 1 - k];
        if (s.flags.test<seg_sent>() && !s.flags.test<seg_sacked>() && s.length > 0)
        {
          s.flags.clear<seg_sent>().set<seg_retransmitted>();
          c.rtt_timing = false;
          ++g_stats.tcp_retransmits;
          ++g_stats.tcp_loss_probes;
          break;
        }
      }
      c.probe_sent  = true;
      c.timer_start = g_now;      // the timeout counts from the probe
      return;
    }
  }

  if (g_now - c.timer_start < c.rto)
    return;

  c.timer_start = g_now;
  c.rto         = std::min<std::uint32_t>(c.rto * 2, c_tcp_rto_max);   // RFC 6298 5.5

  if (persist)
  {
    c.probe_now = true;   // window probe (3.8.6.1); the peer has not gone
    return;
  }

  if (++c.retransmits > c_tcp_max_retransmits)
  {
    if (c.synchronized())
      c.rst_now = true;
    end(c, ipv4::tcp::status::timed_out);
    return;
  }

  c.dupacks = 0;
  for (auto& s : c.tx)
    s.flags.clear<seg_sacked>();    // RFC 2018 8: the peer may have dropped them
  enter_recovery(c);      // RFC 6582: partial ACKs after a timeout too
}

/// The FIN close() asked for, after the data queued
void queue_fin(tcb& c)
{
  if (!c.fin_wanted || c.fin_queued)
    return;

  if (!c.tx.empty())
  {
    tx_segment& last = c.tx.back();
    if (!last.flags.test<seg_sent>() && !last.flags.test<seg_syn>() && !in_flight(last.id))
    {
      last.flags.set<seg_fin>();
      c.fin_queued = true;
      return;
    }
  }

  if (c.tx.full())
    return;

  if (auto p = g_packet_pool.acquire())
  {
    queue_control(c, *p, false);
    c.fin_queued = true;
  }
}

/// The next segment of the send queue that may go: one sent again, or new
/// data inside the peer's window
std::optional<packet_id> next_segment(tcb& c)
{
  for (std::size_t i = 0; i < c.tx.size(); ++i)
  {
    tx_segment& s = c.tx[i];

    if (s.flags.test<seg_sent>())
      continue;

    if (in_flight(s.id))
      return std::nullopt;      // the driver still has its previous copy

    const bool is_new = !seq_lt(s.seq, c.snd_nxt);

    if (!s.flags.test<seg_syn>() && !c.synchronized() && c.state != tcp_state::syn_received)
      return std::nullopt;

    if (is_new && s.length > 0 && seq_gt(s.seq + s.length, c.snd_una + c.snd_wnd))
      return std::nullopt;      // outside the peer's window

    control_t control;
    if (!(c.state == tcp_state::syn_sent && s.flags.test<seg_syn>()))
      control.set<wire::tcp::ACK>();
    if (s.flags.test<seg_syn>())
      control.set<wire::tcp::SYN>();
    if (s.flags.test<seg_fin>())
      control.set<wire::tcp::FIN>();
    if (s.length > 0 && (i + 1 == c.tx.size() || c.tx[i + 1].flags.test<seg_sent>()))
      control.set<wire::tcp::PSH>();

    g_packet_pool.set(s.id, s.offset, s.length);
    write_segment(c, s.id, s.seq, control, s.flags.test<seg_syn>());
    s.flags.set<seg_sent>();
    c.last_send = g_now;

    if (is_new)
    {
      c.snd_nxt = s.end();
      if (!c.rtt_timing && !s.flags.test<seg_retransmitted>())
      {
        c.rtt_timing = true;
        c.rtt_seq    = s.end();
        c.rtt_start  = g_now;
      }
    }

    if (s.flags.test<seg_fin>())
      c.fin_sent = true;

    if (!c.timer_running)
    {
      c.timer_running = true;
      c.timer_start   = g_now;
    }

    c.ack_now = false;          // the segment carries the ACK
    return s.id;
  }

  return std::nullopt;
}

std::optional<packet_id> next_frame(tcb& c)
{
  // Waiting for the peer's hardware address (connect())
  if (!c.hw_known && c.state == tcp_state::syn_sent)
  {
    arp_table_entry* e = find_arp_entry(c.remote.ip_addr);

    if (e != nullptr && e->is_complete())
    {
      c.remote_hw = e->hw_addr;
      c.hw_known  = true;
    }
    else
    {
      if (e == nullptr)
        insert_arp_entry(c.remote.ip_addr, ethernet::address{}, false);
      return std::nullopt;
    }
  }

  if (c.rst_now)
  {
    // abort() or too many retransmissions: one RST, then the place is free
    auto p = control_segment(c, c.snd_nxt, control_t().set<wire::tcp::RST>());
    if (p)
    {
      c.rst_now = false;
      ++g_stats.tcp_resets_sent;
    }
    return p;
  }

  if (c.state == tcp_state::closed)
    return std::nullopt;

  run_timers(c);

  if (c.state == tcp_state::closed)
    return next_frame(c);       // timed out: its RST

  queue_fin(c);

  // Duplicate ACKs go without data: a peer counts only those (RFC 5681 2)
  if (c.dupacks_owed > 0 && c.synchronized())
  {
    auto p = control_segment(c, c.snd_nxt, control_t().set<wire::tcp::ACK>());
    if (p)
    {
      --c.dupacks_owed;
      c.ack_now = false;
    }
    return p;
  }

  if (auto p = next_segment(c))
    return p;

  if (c.probe_now && c.synchronized())
  {
    // An old sequence number makes the peer answer with its window
    auto p = control_segment(c, c.snd_nxt - 1, control_t().set<wire::tcp::ACK>());
    if (p)
      c.probe_now = false;
    return p;
  }

  if (c.ack_now && c.state != tcp_state::closed && c.state != tcp_state::syn_sent)
  {
    auto p = control_segment(c, c.snd_nxt, control_t().set<wire::tcp::ACK>());
    if (p)
      c.ack_now = false;
    return p;
  }

  return std::nullopt;
}

} // namespace

// ---- hooks of the stack ---------------------------------------------------------------

verdict tcp_process(interface_designator id, const interface& itf, packet_id p,
                    std::uint8_t* e, const std::uint8_t* h)
{
  const auto segment = g_packet_pool.data(p);

  grammar::tcp_header th;

  if (!grammar::parse_tcp_header(segment, th))
    return invalid();

  const std::size_t header_length = th.header_length();

  if (header_length < wire::tcp::min_size || header_length > segment.size())
    return invalid();

  if (c_verify_rx_checksums)
  {
    const bool ok = internet_checksum()
                      .add({h + ip::source, 8})
                      .add16(ip::tcp)
                      .add16(static_cast<std::uint16_t>(segment.size()))
                      .add(segment)
                      .verifies();
    if (!ok)
      return invalid();
  }

  const endpoint          remote{load<address>(h + ip::source), th.source_port};
  const ethernet::address hw     = load<ethernet::address>(e + eth::source);
  const std::size_t       data_length = segment.size() - header_length;

  g_packet_pool.pull_header(p, header_length);

  if (tcb* c = find_tcb(id, th.destination_port, remote))
    return segment_arrives(*c, p, th, data_length);

  const control_t in = th.flags();

  if (in.test<wire::tcp::RST>())
    return verdict::drop;

  if (listener_slot* l = find_listener(id, th.destination_port))
  {
    if (in.test<wire::tcp::ACK>())
      return reset_reply(itf, p, hw, remote, th, data_length);
    if (in.test<wire::tcp::SYN>())
      return passive_open(id, *l, p, hw, remote, th);
    return verdict::drop;
  }

  return reset_reply(itf, p, hw, remote, th, data_length);
}

std::optional<packet_id> tcp_next_frame(interface_designator id, std::uint32_t)
{
  // Round robin, so one busy connection does not starve the others
  for (std::size_t n = 0; n < g_tcb.size(); ++n)
  {
    tcb& c = g_tcb[(g_round + n) % g_tcb.size()];

    if (!c.used() || c.intf != id)
      continue;

    if (auto p = next_frame(c))
    {
      g_round = (g_round + n + 1) % g_tcb.size();
      return p;
    }
  }
  return std::nullopt;
}

bool tcp_waiting_for(const address& a)
{
  return std::any_of(g_tcb.begin(), g_tcb.end(), [&](const tcb& c)
  {
    return c.state == tcp_state::syn_sent && !c.hw_known && c.remote.ip_addr == a;
  });
}

void tcp_arp_failed(const address& a)
{
  for (auto& c : g_tcb)
    if (c.state == tcp_state::syn_sent && !c.hw_known && c.remote.ip_addr == a)
      end(c, ipv4::tcp::status::timed_out);
}

void tcp_initialize()
{
  for (auto& c : g_tcb)
  {
    const std::uint8_t generation = c.generation;
    c = tcb{};
    c.generation = generation;
  }
  for (auto& l : g_listeners)
    l = listener_slot{};
  g_round = 0;
}

} // namespace internal

// ---- application interface ------------------------------------------------------------

namespace tcp
{

using namespace internal;

std::optional<listener> listen(interface_designator id, std::uint16_t port)
{
  if (id >= c_interface_table_size || port == 0 || find_listener(id, port) != nullptr)
    return std::nullopt;

  for (auto& l : g_listeners)
  {
    if (!l.used)
    {
      l = listener_slot{};
      l.used = true;
      l.intf = id;
      l.port = port;
      return listener{index_of(l)};
    }
  }
  return std::nullopt;
}

void stop(listener l)
{
  if (l.index >= g_listeners.size())
    return;

  // Connections not accepted yet go with it
  for (auto& c : g_tcb)
  {
    if (c.listener == l.index + 1)
    {
      if (c.synchronized())
        c.rst_now = true;
      end(c, status::reset);
    }
  }
  g_listeners[l.index] = listener_slot{};
}

std::optional<connection> accept(listener l)
{
  if (l.index >= g_listeners.size() || !g_listeners[l.index].used)
    return std::nullopt;

  connection h;
  while (g_listeners[l.index].ready.try_pop(h))
  {
    tcb& c = g_tcb[h.index];
    if (c.generation == h.generation && c.listener == l.index + 1 && c.state != tcp_state::closed)
    {
      c.listener  = c_no_listener;
      c.app_owned = true;
      return h;
    }
  }
  return std::nullopt;
}

std::optional<connection> connect(interface_designator id, const endpoint& remote,
                                  std::uint16_t local_port)
{
  if (id >= c_interface_table_size || remote.port == 0 || remote.ip_addr == c_broadcast_ip)
    return std::nullopt;

  if (local_port == 0)
  {
    // An ephemeral port no connection or listener uses
    for (int tries = 0; tries < 16384 && local_port == 0; ++tries)
    {
      const std::uint16_t port = g_next_port;
      g_next_port = (g_next_port == 65535) ? 49152 : static_cast<std::uint16_t>(g_next_port + 1);

      const bool taken =
        find_listener(id, port) != nullptr ||
        std::any_of(g_tcb.begin(), g_tcb.end(),
                    [&](const tcb& c) { return c.used() && c.local_port == port; });
      if (!taken)
        local_port = port;
    }
    if (local_port == 0)
      return std::nullopt;
  }
  else if (find_tcb(id, local_port, remote) != nullptr)
  {
    return std::nullopt;
  }

  auto p = g_packet_pool.acquire(c_rx_reserved_blocks);
  if (!p)
  {
    ++g_stats.tx_no_buffer;
    return std::nullopt;
  }

  tcb* c = allocate_tcb();
  if (c == nullptr)
  {
    g_packet_pool.release(*p);
    return std::nullopt;
  }

  c->state      = tcp_state::syn_sent;
  c->app_owned  = true;
  c->intf       = id;
  c->local_port = local_port;
  c->remote     = remote;
  c->iss        = initial_sequence(*c);
  c->snd_una    = c->iss;
  c->snd_nxt    = c->iss;

  if (arp_table_entry* e = find_arp_entry(remote.ip_addr); e != nullptr && e->is_complete())
  {
    c->remote_hw = e->hw_addr;
    c->hw_known  = true;
    touch(*e);
  }
  else if (e == nullptr)
  {
    insert_arp_entry(remote.ip_addr, ethernet::address{}, false);   // asked for at the next step
  }

  queue_control(*c, *p, true);   // SYN
  return handle_of(*c);
}

status state(connection h)
{
  const tcb* c = from_handle(h);

  if (c == nullptr)
    return status::closed;

  switch (c->state)
  {
    case tcp_state::closed:       return c->error;
    case tcp_state::syn_sent:
    case tcp_state::syn_received: return status::connecting;
    case tcp_state::established:
    case tcp_state::fin_wait_1:
    case tcp_state::fin_wait_2:   return status::established;
    case tcp_state::close_wait:   return status::peer_closed;
    default:                      return status::closing;
  }
}

std::optional<endpoint> remote(connection h)
{
  const tcb* c = from_handle(h);
  if (c == nullptr)
    return std::nullopt;
  return c->remote;
}

std::size_t received_length(connection h)
{
  const tcb* c = from_handle(h);
  return c != nullptr ? c->rx_bytes : 0;
}

namespace
{

/// After reading: a window opened by at least a segment is announced at
/// once (3.8.6.2.2)
void reading_done(tcb& c)
{
  const std::uint32_t free    = receive_space(c);
  const std::uint32_t current = seq_gt(c.rcv_adv, c.rcv_nxt) ? c.rcv_adv - c.rcv_nxt : 0;

  if (c.synchronized() && free >= current + std::min<std::uint32_t>(c_tcp_mss, c_rx_capacity / 2))
    c.ack_now = true;
}

void pop_front_rx(tcb& c)
{
  for (std::size_t j = 0; j + 1 < c.rx.size(); ++j)
    c.rx[j] = c.rx[j + 1];
  c.rx.pop_back();
}

} // namespace

std::size_t receive(connection h, std::uint8_t* data, std::size_t size)
{
  tcb* c = from_handle(h);
  if (c == nullptr)
    return 0;

  std::size_t done = 0;

  while (done < size && !c->rx.empty())
  {
    const packet_id   p = c->rx.front();
    const auto        d = g_packet_pool.data(p);
    const std::size_t n = std::min(size - done, d.size());

    std::memcpy(data + done, d.data(), n);
    g_packet_pool.pull_header(p, n);
    done += n;

    if (g_packet_pool.data(p).empty())
    {
      g_packet_pool.release(p);
      pop_front_rx(*c);
    }
  }

  c->rx_bytes -= done;
  if (done > 0)
    reading_done(*c);
  return done;
}

std::optional<packet> receive(connection h)
{
  tcb* c = from_handle(h);
  if (c == nullptr || c->rx.empty())
    return std::nullopt;

  const packet_id p = c->rx.front();
  pop_front_rx(*c);
  c->rx_bytes -= g_packet_pool.data(p).size();
  reading_done(*c);
  return packet(p);
}

namespace
{

bool can_send(const tcb& c)
{
  return (c.state == tcp_state::established || c.state == tcp_state::close_wait) && !c.fin_wanted;
}

/// Blocks data to send leaves free: the next received frame and, while a
/// connection has an open receive window and no block for the next segment
/// in order to land in, one block for it (blocks kept out of order are
/// given up for it anyway). The windows may promise more; keeping more here
/// (one per connection, or per segment) starves sending in a small pool,
/// and a segment refused comes again soon (SACK, fast retransmit).
std::size_t send_keep()
{
  bool promised = false;
  for (const tcb& c : g_tcb)
  {
    if (!(c.state == tcp_state::established || c.state == tcp_state::fin_wait_1 ||
          c.state == tcp_state::fin_wait_2) || c.discards() || !c.ooo.empty() ||
        !seq_gt(c.rcv_adv, c.rcv_nxt))
      continue;

    std::uint32_t window = c.rcv_adv - c.rcv_nxt;
    if (!c.rx.empty())
    {
      const auto        t   = g_packet_pool.data(c.rx.back());
      const std::size_t end = static_cast<std::size_t>(t.data() - g_packet_pool.base(c.rx.back())) + t.size();
      const std::size_t tail = c_packet_block_size - end;
      window = window > tail ? static_cast<std::uint32_t>(window - tail) : 0;
    }
    if (window > 0)
    {
      promised = true;
      break;
    }
  }
  // Keeping a received block leaves the transmit reserve and the next
  // frame (store_data()): with a promise, the transmit reserve stays too
  return c_rx_reserved_blocks + (promised ? c_tx_reserved_blocks + 1 : 0);
}

/// Room at the end of the last segment not sent yet
std::size_t tail_room(const tcb& c)
{
  if (c.tx.empty())
    return 0;
  const tx_segment& s = c.tx.back();
  if (s.flags.test<seg_sent>() || s.flags.test<seg_syn>() || s.flags.test<seg_fin>() || in_flight(s.id))
    return 0;
  return c.mss() > s.length ? c.mss() - s.length : 0;
}

void push_data_segment(tcb& c, packet_id p, std::size_t length)
{
  tx_segment s;
  s.id     = p;
  s.seq    = c.queue_end();
  s.offset = static_cast<std::uint16_t>(c_data_offset);
  s.length = static_cast<std::uint16_t>(length);
  pin(p);
  c.tx.push_back(s);
}

} // namespace

std::size_t send_space(connection h)
{
  const tcb* c = from_handle(h);
  if (c == nullptr || !can_send(*c))
    return 0;

  const std::size_t keep        = send_keep();
  const std::size_t blocks_free = g_packet_pool.available() > keep ? g_packet_pool.available() - keep : 0;
  const std::size_t slots = std::min(c->tx.capacity() - c->tx.size(), blocks_free);
  return tail_room(*c) + slots * c->mss();
}

std::size_t send(connection h, const std::uint8_t* data, std::size_t size)
{
  tcb* c = from_handle(h);
  if (c == nullptr || !can_send(*c))
    return 0;

  std::size_t done = 0;

  // First fill the last segment not sent yet
  if (const std::size_t room = tail_room(*c); room > 0 && size > 0)
  {
    tx_segment&       s = c->tx.back();
    const std::size_t n = std::min(room, size);
    std::memcpy(g_packet_pool.base(s.id) + s.offset + s.length, data, n);
    s.length = static_cast<std::uint16_t>(s.length + n);
    done     = n;
  }

  while (done < size && !c->tx.full())
  {
    auto p = g_packet_pool.acquire(send_keep());
    if (!p)
    {
      ++g_stats.tx_no_buffer;
      break;
    }

    const std::size_t n = std::min<std::size_t>(size - done, c->mss());
    std::memcpy(g_packet_pool.base(*p) + c_data_offset, data + done, n);
    push_data_segment(*c, *p, n);
    done += n;
  }

  return done;
}

std::optional<packet> allocate(connection h, std::size_t size)
{
  const tcb* c = from_handle(h);
  if (c == nullptr || size > c->mss())
    return std::nullopt;

  auto p = g_packet_pool.acquire(send_keep());
  if (!p)
  {
    ++g_stats.tx_no_buffer;
    return std::nullopt;
  }

  g_packet_pool.set(*p, c_data_offset, size);
  return packet(*p);
}

bool send(connection h, packet&& data)
{
  tcb* c = from_handle(h);
  if (c == nullptr || !can_send(*c) || !data || c->tx.full() || data.size() > c->mss())
    return false;

  const packet_id   p    = *data.id();
  const auto        d    = g_packet_pool.data(p);
  const std::size_t size = d.size();

  if (front_room(p) != c_data_offset)
  {
    // A block received with other headers: its data moves to where the
    // frame of a segment starts at the headroom
    std::memmove(g_packet_pool.base(p) + c_data_offset, d.data(), size);
  }

  push_data_segment(*c, p, size);
  data.detach();
  return true;
}

void close(connection h)
{
  tcb* c = from_handle(h);
  if (c == nullptr)
    return;

  c->app_owned = false;

  // Data received and not read is dropped
  for (packet_id p : c->rx)
    g_packet_pool.release(p);
  c->rx.clear();
  c->rx_bytes = 0;
  for (auto& o : c->ooo)
    g_packet_pool.release(o.id);
  c->ooo.clear();

  switch (c->state)
  {
    case tcp_state::syn_sent:
      end(*c, status::closed);
      break;
    case tcp_state::syn_received:
    case tcp_state::established:
      c->fin_wanted = true;
      c->state      = tcp_state::fin_wait_1;
      break;
    case tcp_state::close_wait:
      c->fin_wanted = true;
      c->state      = tcp_state::last_ack;
      break;
    default:
      break;           // closing already, or closed: the place is free now
  }
}

void abort(connection h)
{
  tcb* c = from_handle(h);
  if (c == nullptr)
    return;

  c->app_owned = false;

  if (c->synchronized() && c->state != tcp_state::time_wait)
    c->rst_now = true;
  end(*c, status::reset);
}

void set_secret(std::uint64_t secret)
{
  g_secret = secret;
}

} // namespace tcp

} // namespace ipv4

} // namespace protocol

#else   // PROTOCOL_IPV4_TCP_CONNECTIONS == 0: TCP left out, the calls do nothing

#include "internal.hpp"

namespace protocol::ipv4
{

namespace internal
{

verdict tcp_process(interface_designator, const interface&, packet_id, std::uint8_t*, const std::uint8_t*)
{
  return not_for_us();
}

std::optional<packet_id> tcp_next_frame(interface_designator, std::uint32_t) { return std::nullopt; }
bool tcp_waiting_for(const address&) { return false; }
void tcp_arp_failed(const address&) {}
void tcp_initialize() {}

} // namespace internal

namespace tcp
{

std::optional<listener>   listen(interface_designator, std::uint16_t) { return std::nullopt; }
void                      stop(listener) {}
std::optional<connection> accept(listener) { return std::nullopt; }
std::optional<connection> connect(interface_designator, const endpoint&, std::uint16_t) { return std::nullopt; }
status                    state(connection) { return status::closed; }
std::optional<endpoint>   remote(connection) { return std::nullopt; }
std::size_t               received_length(connection) { return 0; }
std::size_t               receive(connection, std::uint8_t*, std::size_t) { return 0; }
std::optional<packet>     receive(connection) { return std::nullopt; }
std::size_t               send_space(connection) { return 0; }
std::size_t               send(connection, const std::uint8_t*, std::size_t) { return 0; }
std::optional<packet>     allocate(connection, std::size_t) { return std::nullopt; }
bool                      send(connection, packet&&) { return false; }
void                      close(connection) {}
void                      abort(connection) {}
void                      set_secret(std::uint64_t) {}

} // namespace tcp

} // namespace protocol::ipv4

#endif
