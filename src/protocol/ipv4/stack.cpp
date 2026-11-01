/// \file stack.cpp
/// Source for IPV4 stack implementation
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
/// \author Selcuk Iyikalender
/// \date   2022

#include <algorithm>
#include <cstdint>
#include <cstring>

#include "protocol/ipv4/stack.hpp"
#include "protocol/ipv4/wire.hpp"

namespace protocol
{

namespace ipv4
{

/// Lets the pool go to a memory section of its own, e.g. one the MPU maps
/// non cacheable for the Ethernet DMA (STM32F7):
///   -DPROTOCOL_IPV4_PACKET_POOL_ATTRIBUTES='__attribute__((section(".eth_ram")))'
/// The section need not be zeroed at start up: initialize() resets the pool.
#ifndef PROTOCOL_IPV4_PACKET_POOL_ATTRIBUTES
#define PROTOCOL_IPV4_PACKET_POOL_ATTRIBUTES
#endif

PROTOCOL_IPV4_PACKET_POOL_ATTRIBUTES
constinit packet_pool_type    g_packet_pool{};
interface_container           g_interfaces{};
arp_table_type                g_arp_table;
udp_ports_table_type          g_udp_ports;

namespace
{

using namespace wire;

tx_queue_type     g_tx_queue;
haluj::ring_buffer<std::array<packet_id, c_tx_waiting_size>> g_tx_waiting;
statistics        g_stats;
std::uint16_t     g_ip_identification = 0;
std::uint32_t     g_lru_clock         = 0;
std::uint32_t     g_step_counter      = 0;

const ethernet::address c_broadcast_hw{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const address           c_broadcast_ip{0xFF, 0xFF, 0xFF, 0xFF};
const address           c_unspecified_ip{0, 0, 0, 0};

constexpr std::uint16_t c_dont_fragment =
  ip::flags_fragment_t().set<ip::dont_fragment>().value();
constexpr std::uint8_t  c_ttl = 128;

/// Every frame starts at the headroom, so its IP header is at a fixed place
std::uint8_t* ip_header_of(packet_id p)
{
  return g_packet_pool.base(p) + c_packet_headroom + eth::size;
}

std::size_t front_room(packet_id p)
{
  return static_cast<std::size_t>(g_packet_pool.data(p).data() - g_packet_pool.base(p));
}

/// Zero pads a frame to the Ethernet minimum, so drivers that do not pad
/// short frames send valid ones
void pad(packet_id p)
{
  auto frame = g_packet_pool.data(p);
  if (frame.size() < c_min_eth_frame_size)
  {
    std::uint8_t* d = frame.data();      // the block has room after the frame
    std::fill(d + frame.size(), d + c_min_eth_frame_size, std::uint8_t(0));
    g_packet_pool.set(p, front_room(p), c_min_eth_frame_size);
  }
}

void write_ethernet_header
(
  std::uint8_t*             e,
  const ethernet::address&  destination,
  const interface&          itf,
  std::uint16_t             type
)
{
  store(e + eth::destination, destination);
  store(e + eth::source, itf.hw_addr);
  store16(e + eth::type, type);
}

// ---- ARP table ------------------------------------------------------------

arp_table_entry* find_arp_entry(const address& a)
{
  auto it = std::find_if(g_arp_table.begin(), g_arp_table.end(),
                         [&](const arp_table_entry& e) { return e.ip_addr == a; });
  return it != g_arp_table.end() ? &*it : nullptr;
}

void touch(arp_table_entry& e)
{
  e.last_used = ++g_lru_clock;
}

bool is_datagram_waiting_for(const address& a)
{
  return std::any_of(g_tx_queue.begin(), g_tx_queue.end(),
                     [&](const tx_entry& t) { return t.remote.ip_addr == a; });
}

/// Adds an entry. When the table is full, the least recently used entry
/// that no datagram waits for is replaced. nullptr when every entry has a
/// datagram waiting.
arp_table_entry* insert_arp_entry
(
  const address&            ip_addr,
  const ethernet::address&  hw_addr,
  bool                      complete
)
{
  arp_table_entry entry;
  entry.ip_addr = ip_addr;
  entry.hw_addr = hw_addr;
  if (complete)
    entry.set_complete();
  touch(entry);

  if (haluj::bounded::push_back(g_arp_table, entry))
    return &g_arp_table.back();

  arp_table_entry* victim = nullptr;

  for (auto& e : g_arp_table)
  {
    // The difference keeps the order right when the stamp wraps around
    if (!is_datagram_waiting_for(e.ip_addr) &&
        (victim == nullptr || std::int32_t(e.last_used - victim->last_used) < 0))
    {
      victim = &e;
    }
  }

  if (victim != nullptr)
    *victim = entry;

  return victim;
}

void erase_arp_entry(std::size_t index)
{
  g_arp_table[index] = g_arp_table.back();
  g_arp_table.pop_back();
}

// ---- transmit queue ---------------------------------------------------------

/// Keeps the order of the others: datagrams to one host go out in order
void erase_tx_entry(std::size_t index)
{
  for (std::size_t j = index; j + 1 < g_tx_queue.size(); ++j)
    g_tx_queue[j] = g_tx_queue[j + 1];
  g_tx_queue.pop_back();
}

void drop_datagrams_waiting_for(const address& a)
{
  for (std::size_t i = g_tx_queue.size(); i-- > 0; )
  {
    if (g_tx_queue[i].remote.ip_addr == a)
    {
      g_packet_pool.release(g_tx_queue[i].id);
      ++g_stats.tx_arp_timeout;
      erase_tx_entry(i);
    }
  }
}

/// Puts the UDP, IP and Ethernet headers in front of the payload
void write_udp_frame(const interface& itf, const tx_entry& t, const ethernet::address& hw)
{
  const packet_id   p           = t.id;
  const std::size_t udp_length  = wire::udp::size + g_packet_pool.data(p).size();

  // Every frame starts at the headroom, where a DMA wants its alignment. A
  // datagram sent back in its received block normally already does; one
  // that came with IP options is moved there (the only copy, and rare).
  constexpr std::size_t payload_offset =
    c_packet_headroom + eth::size + ip::min_size + wire::udp::size;

  if (front_room(p) != payload_offset)
  {
    const auto payload = g_packet_pool.data(p);
    std::memmove(g_packet_pool.base(p) + payload_offset, payload.data(), payload.size());
    g_packet_pool.set(p, payload_offset, payload.size());
  }

  std::uint8_t* u = g_packet_pool.push_header(p, wire::udp::size);
  store16(u + wire::udp::source_port,      t.source_port);
  store16(u + wire::udp::destination_port, t.remote.port);
  store16(u + wire::udp::length,           std::uint16_t(udp_length));
  store16(u + wire::udp::checksum,         0);

  std::uint8_t* h = g_packet_pool.push_header(p, ip::min_size);
  h[ip::version_ihl] = ip::version_ihl_t().assign<ip::version, 4>().assign<ip::ihl, 5>().value();
  h[ip::tos]         = 0;
  store16(h + ip::total_length,   std::uint16_t(ip::min_size + udp_length));
  store16(h + ip::identification, g_ip_identification++);
  store16(h + ip::flags_fragment, c_dont_fragment);
  h[ip::ttl]         = c_ttl;
  h[ip::protocol]    = ip::udp;
  store16(h + ip::checksum, 0);
  store(h + ip::source,      itf.ip_addr);
  store(h + ip::destination, t.remote.ip_addr);
  store16(h + ip::checksum, internet_checksum().add({h, ip::min_size}).result());

  // Pseudo header: source and destination addresses, protocol, UDP length
  std::uint16_t c = internet_checksum()
                      .add({h + ip::source, 8})
                      .add16(ip::udp)
                      .add16(std::uint16_t(udp_length))
                      .add({u, udp_length})
                      .result();
  store16(u + wire::udp::checksum, c == 0 ? 0xFFFF : c);

  write_ethernet_header(g_packet_pool.push_header(p, eth::size), hw, itf, eth::type_ipv4);
  pad(p);
}

void write_arp_request(const interface& itf, packet_id p, const address& target)
{
  g_packet_pool.set(p, c_packet_headroom, eth::size + arp::size);

  std::uint8_t* e = g_packet_pool.data(p).data();
  write_ethernet_header(e, c_broadcast_hw, itf, eth::type_arp);

  std::uint8_t* a = e + eth::size;
  store16(a + arp::hardware_type, 1);
  store16(a + arp::protocol_type, eth::type_ipv4);
  a[arp::hardware_length] = 6;
  a[arp::protocol_length] = 4;
  store16(a + arp::opcode, arp::request);
  store(a + arp::sender_hw, itf.hw_addr);
  store(a + arp::sender_ip, itf.ip_addr);
  store(a + arp::target_hw, ethernet::address{});
  store(a + arp::target_ip, target);
  pad(p);
}

// ---- receive ------------------------------------------------------------------

enum class verdict
{
  drop,     ///< free the block
  keep,     ///< the block was queued on a port
  reply     ///< the block now holds a reply to send
};

verdict invalid()     { ++g_stats.rx_invalid;    return verdict::drop; }
verdict not_for_us()  { ++g_stats.rx_not_for_us; return verdict::drop; }

verdict process_arp(const interface& itf, packet_id p, std::uint8_t* e)
{
  std::uint8_t* a = g_packet_pool.pull_header(p, arp::size);

  if (a == nullptr)
    return invalid();

  if (load16(a + arp::hardware_type) != 1 ||
      load16(a + arp::protocol_type) != eth::type_ipv4 ||
      a[arp::hardware_length] != 6 ||
      a[arp::protocol_length] != 4)
  {
    return invalid();
  }

  const auto  sender_hw = load<ethernet::address>(a + arp::sender_hw);
  const auto  sender_ip = load<address>(a + arp::sender_ip);
  const auto  target_ip = load<address>(a + arp::target_ip);
  const auto  opcode    = load16(a + arp::opcode);

  // RFC 826: an entry for the sender is updated whoever the packet is for
  bool known = false;

  if (sender_ip != c_unspecified_ip)
  {
    if (arp_table_entry* entry = find_arp_entry(sender_ip))
    {
      entry->hw_addr  = sender_hw;
      entry->requests = 0;
      entry->set_complete();
      touch(*entry);
      known = true;
    }
  }

  if (target_ip != itf.ip_addr)
    return not_for_us();

  if (!known && sender_ip != c_unspecified_ip)
    insert_arp_entry(sender_ip, sender_hw, true);

  if (opcode != arp::request)
    return verdict::drop;

  // The request becomes the reply in place. Answered even when the table is
  // full: the asking host must be able to reach us.
  store16(a + arp::opcode, arp::reply);
  store(a + arp::target_hw, sender_hw);
  store(a + arp::target_ip, sender_ip);
  store(a + arp::sender_hw, itf.hw_addr);
  store(a + arp::sender_ip, itf.ip_addr);
  write_ethernet_header(e, sender_hw, itf, eth::type_arp);

  g_packet_pool.set(p, c_packet_headroom, eth::size + arp::size);
  pad(p);
  return verdict::reply;
}

verdict process_icmp
(
  const interface&  itf,
  packet_id         p,
  std::uint8_t*     e,
  std::uint8_t*     h,
  std::size_t       header_length
)
{
  std::span<std::uint8_t> m = g_packet_pool.data(p);

  if (m.size() < icmp::size)
    return invalid();

  if (c_verify_rx_checksums && !internet_checksum().add(m).verifies())
    return invalid();

  if (m[icmp::type] != icmp::echo_request || m[icmp::code] != 0)
    return not_for_us();

  // The request becomes the reply in place: the echo data stays where it is
  m[icmp::type] = icmp::echo_reply;
  store16(m.data() + icmp::checksum, 0);
  store16(m.data() + icmp::checksum, internet_checksum().add(m).result());

  const auto requester = load<address>(h + ip::source);
  store(h + ip::destination, requester);
  store(h + ip::source,      itf.ip_addr);
  store16(h + ip::identification, g_ip_identification++);
  h[ip::ttl] = c_ttl;
  store16(h + ip::checksum, 0);
  store16(h + ip::checksum, internet_checksum().add({h, header_length}).result());

  write_ethernet_header(e, load<ethernet::address>(e + eth::source), itf, eth::type_ipv4);

  g_packet_pool.set(p, c_packet_headroom, eth::size + header_length + m.size());
  pad(p);
  return verdict::reply;
}

verdict process_udp(interface_designator id, packet_id p, const std::uint8_t* h)
{
  std::span<std::uint8_t> u = g_packet_pool.data(p);

  if (u.size() < wire::udp::size)
    return invalid();

  const std::size_t length = load16(u.data() + wire::udp::length);

  if (length < wire::udp::size || length > u.size())
    return invalid();

  if (c_verify_rx_checksums &&
      load16(u.data() + wire::udp::checksum) != 0)  // 0: the sender left it out
  {
    const bool ok = internet_checksum()
                      .add({h + ip::source, 8})
                      .add16(ip::udp)
                      .add16(std::uint16_t(length))
                      .add(u.first(length))
                      .verifies();
    if (!ok)
      return invalid();
  }

  const std::uint16_t destination_port = load16(u.data() + wire::udp::destination_port);

  auto port = std::find_if(g_udp_ports.begin(), g_udp_ports.end(),
                           [&](const port_descriptor& d)
                           {
                             return d.intf == id && d.port == destination_port;
                           });

  if (port == g_udp_ports.end())
  {
    ++g_stats.rx_no_port;
    return verdict::drop;
  }

  if (port->rx.full())
  {
    ++g_stats.rx_queue_full;
    return verdict::drop;
  }

  // Keeping this block must leave one for the next received frame and the
  // transmit reserve: queued datagrams never make the stack deaf to ARP
  if (g_packet_pool.available() < c_tx_reserved_blocks + 1)
  {
    ++g_stats.rx_no_buffer;
    return verdict::drop;
  }

  // Only the payload stays valid; the headers stay in front of it, where
  // receive() finds the remote address and send() can reuse the room
  g_packet_pool.pull_header(p, wire::udp::size);
  g_packet_pool.trim(p, length - wire::udp::size);
  port->rx.push(p);
  return verdict::keep;
}

verdict process_ipv4(interface_designator id, const interface& itf, packet_id p, std::uint8_t* e)
{
  std::span<std::uint8_t> packet = g_packet_pool.data(p);
  std::uint8_t*           h      = packet.data();

  if (packet.size() < ip::min_size)
    return invalid();

  const ip::version_ihl_t vi(h[ip::version_ihl]);
  const std::size_t       header_length = vi.value_of<ip::ihl>() * 4U;
  const std::size_t       total_length  = load16(h + ip::total_length);

  if (vi.value_of<ip::version>() != 4 ||
      header_length < ip::min_size ||
      total_length < header_length ||
      total_length > packet.size())        // never trust a length the frame does not hold
  {
    return invalid();
  }

  if (c_verify_rx_checksums && !internet_checksum().add({h, header_length}).verifies())
    return invalid();

  // Fragments are not reassembled
  const ip::flags_fragment_t ff(load16(h + ip::flags_fragment));
  if (ff.test<ip::more_fragments>() || ff.value_of<ip::fragment_offset>() != 0)
    return not_for_us();

  const auto destination = load<address>(h + ip::destination);
  const bool unicast     = destination == itf.ip_addr;

  if (!unicast && destination != c_broadcast_ip)
    return not_for_us();

  g_packet_pool.trim(p, total_length);      // drops the Ethernet padding
  g_packet_pool.pull_header(p, header_length);

  switch (h[ip::protocol])
  {
    case ip::udp:
      return process_udp(id, p, h);
    case ip::icmp:
      return unicast ? process_icmp(itf, p, e, h, header_length) : not_for_us();
    default:
      return not_for_us();
  }
}

port_descriptor* port_of(const endpoint_designator& ed)
{
  return (ed && *ed < g_udp_ports.size()) ? &g_udp_ports[*ed] : nullptr;
}

} // namespace

// ---- step() internals ---------------------------------------------------------

namespace detail
{

std::uint32_t count_step()
{
  return g_step_counter++;
}

std::optional<packet_id> acquire_receive_block()
{
  // Reading a frame only borrows a block; the reserves are applied when a
  // block is kept (process_udp, udp::allocate)
  auto p = g_packet_pool.acquire();
  if (!p)
    ++g_stats.rx_no_buffer;
  return p;
}

std::span<std::uint8_t> receive_buffer(packet_id p)
{
  return g_packet_pool.frame_buffer(p).first(c_max_eth_frame_size);
}

std::optional<packet_id>
process_received_frame(interface_designator id, packet_id p, std::size_t size)
{
  ++g_stats.rx_frames;

  verdict v = verdict::drop;

  if (size < eth::size || size > c_max_eth_frame_size || id >= c_interface_table_size)
  {
    v = invalid();
  }
  else
  {
    const interface& itf = g_interfaces[id];

    g_packet_pool.set(p, c_packet_headroom, size);
    std::uint8_t* e = g_packet_pool.pull_header(p, eth::size);

    const auto destination = load<ethernet::address>(e + eth::destination);

    if (destination != itf.hw_addr && destination != c_broadcast_hw)
    {
      v = not_for_us();
    }
    else
    {
      switch (load16(e + eth::type))
      {
        case eth::type_arp:   v = process_arp(itf, p, e);       break;
        case eth::type_ipv4:  v = process_ipv4(id, itf, p, e);  break;
        default:              v = not_for_us();                 break;
      }
    }
  }

  switch (v)
  {
    case verdict::reply:
      return p;
    case verdict::keep:
      break;
    case verdict::drop:
      g_packet_pool.release(p);
      break;
  }
  return std::nullopt;
}

std::optional<packet_id> next_transmit_frame(interface_designator id, std::uint32_t tick)
{
  if (id >= c_interface_table_size)
    return std::nullopt;

  const interface& itf = g_interfaces[id];

  // Datagrams whose destination hardware address is known go out first
  for (std::size_t i = 0; i < g_tx_queue.size(); ++i)
  {
    const tx_entry& t = g_tx_queue[i];

    if (t.intf != id)
      continue;

    if (t.remote.ip_addr == c_broadcast_ip)
    {
      const tx_entry copy = t;
      erase_tx_entry(i);
      write_udp_frame(itf, copy, c_broadcast_hw);
      return copy.id;
    }

    arp_table_entry* entry = find_arp_entry(t.remote.ip_addr);

    if (entry != nullptr && entry->is_complete())
    {
      touch(*entry);
      const tx_entry copy = t;
      erase_tx_entry(i);
      write_udp_frame(itf, copy, entry->hw_addr);
      return copy.id;
    }

    // Unknown host: an incomplete entry makes the loop below ask for it.
    // When the table is full of hosts being asked for, it waits its turn.
    if (entry == nullptr)
      insert_arp_entry(t.remote.ip_addr, ethernet::address{}, false);
  }

  // Ask for the hosts datagrams wait for, again after each interval
  for (std::size_t i = 0; i < g_arp_table.size(); ++i)
  {
    arp_table_entry& entry = g_arp_table[i];

    if (entry.is_complete() || !is_datagram_waiting_for(entry.ip_addr))
      continue;

    if (entry.requests > 0 && tick - entry.last_request < c_arp_retry_interval)
      continue;

    if (entry.requests >= c_arp_max_requests)
    {
      drop_datagrams_waiting_for(entry.ip_addr);
      erase_arp_entry(i);
      --i;
      continue;
    }

    auto p = g_packet_pool.acquire();

    if (!p)
      return std::nullopt;     // try again at the next step

    write_arp_request(itf, *p, entry.ip_addr);
    entry.last_request = tick;
    ++entry.requests;
    return p;
  }

  return std::nullopt;
}

void transmitted(packet_id p)
{
  ++g_stats.tx_frames;
  g_packet_pool.release(p);
}

std::optional<packet_id> waiting_frame()
{
  if (g_tx_waiting.empty())
    return std::nullopt;
  return g_tx_waiting.front();
}

void pop_waiting_frame()
{
  g_tx_waiting.pop();
}

void keep_waiting_frame(packet_id p)
{
  if (!g_tx_waiting.try_push(p))
  {
    ++g_stats.tx_reply_dropped;
    g_packet_pool.release(p);
  }
}

void handed_over(packet_id)
{
  ++g_stats.tx_frames;
}

void refused(packet_id)
{
  ++g_stats.tx_busy;
}

} // namespace detail

// ---- public functions -----------------------------------------------------------

void
initialize()
{
  g_packet_pool.reset();
  g_arp_table.clear();
  g_udp_ports.clear();
  g_tx_queue.clear();
  g_tx_waiting.clear();
  g_stats             = {};
  g_ip_identification = 0;
  g_lru_clock         = 0;
  g_step_counter      = 0;
}

bool
set
(
  const interface_designator  id,
  ethernet::address           hw_addr,
  ipv4::address               ip_addr
)
{
  if (id >= c_interface_table_size)
    return false;

  g_interfaces[id].hw_addr = hw_addr;
  g_interfaces[id].ip_addr = ip_addr;
  return true;
}

const statistics&
stats()
{
  return g_stats;
}

namespace dma
{

std::optional<packet_id> acquire()
{
  auto p = g_packet_pool.acquire(c_tx_reserved_blocks);
  if (!p)
    ++g_stats.rx_no_buffer;
  return p;
}

} // namespace dma

namespace udp
{

endpoint_designator
bind
(
  const interface_designator  id,
  const uint16_t              port
)
{
  TRACE("Binding " << port << " to " << id << "\n");

  if (id >= c_interface_table_size)
    return std::nullopt;

  const bool bound =
    std::any_of(g_udp_ports.begin(), g_udp_ports.end(),
                [&](const port_descriptor& d) { return d.intf == id && d.port == port; });

  if (bound || !haluj::bounded::push_back(g_udp_ports, port_descriptor{id, port, {}}))
    return std::nullopt;

  return g_udp_ports.size() - 1;
}

std::size_t
received_length
(
  const endpoint_designator&  ed
)
{
  const port_descriptor* d = port_of(ed);

  if (d == nullptr || d->rx.empty())
    return 0;

  return g_packet_pool.data(d->rx.front()).size();
}

std::optional<datagram>
receive
(
  const endpoint_designator&  ed
)
{
  port_descriptor* d = port_of(ed);

  if (d == nullptr || d->rx.empty())
    return std::nullopt;

  const packet_id p = d->rx.front();
  d->rx.pop();

  // The headers are still in front of the payload
  const std::uint8_t* h = ip_header_of(p);
  const std::uint8_t* u = g_packet_pool.data(p).data() - wire::udp::size;

  return datagram
  {
    packet(p),
    endpoint
    {
      wire::load<address>(h + wire::ip::source),
      wire::load16(u + wire::udp::source_port)
    }
  };
}

std::size_t
receive
(
  const endpoint_designator&  ed,
  uint8_t*                    data,
  const std::size_t           size,
  endpoint&                   remote
)
{
  auto d = receive(ed);

  if (!d)
    return 0;

  const std::size_t n = std::min(size, d->size());
  std::memcpy(data, d->data().data(), n);
  remote = d->remote;
  return n;               // the block is freed with d
}

std::optional<packet>
allocate
(
  const endpoint_designator&  ed,
  const std::size_t           size
)
{
  if (port_of(ed) == nullptr || size > c_max_udp_payload_size)
    return std::nullopt;

  auto p = g_packet_pool.acquire(c_rx_reserved_blocks);

  if (!p)
  {
    ++g_stats.tx_no_buffer;
    return std::nullopt;
  }

  // Room in front for the Ethernet, IP and UDP headers
  g_packet_pool.set(*p, c_packet_headroom + wire::eth::size + wire::ip::min_size + wire::udp::size, size);
  return packet(*p);
}

bool
send
(
  const endpoint_designator&  ed,
  packet&&                    p,
  const endpoint&             remote
)
{
  const port_descriptor* d = port_of(ed);

  if (d == nullptr || !p || p.size() > c_max_udp_payload_size)
    return false;

  const packet_id id = *p.id();

  if (front_room(id) < c_packet_headroom + wire::eth::size + wire::ip::min_size + wire::udp::size)
    return false;

  if (g_tx_queue.full())
  {
    ++g_stats.tx_queue_full;
    return false;
  }

  g_tx_queue.push_back(tx_entry{id, d->intf, d->port, remote});
  p.detach();
  return true;
}

std::size_t
send
(
  const endpoint_designator&  ed,
  const uint8_t               *data,
  const std::size_t           size,
  const endpoint&             remote
)
{
  auto p = allocate(ed, size);

  if (!p)
    return 0;

  std::memcpy(p->data().data(), data, size);
  return send(ed, std::move(*p), remote) ? size : 0;
}

} // namespace udp

} // namespace ipv4

} // namespace protocol
