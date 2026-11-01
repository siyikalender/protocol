/// \file frames.hpp
/// Builds and inspects Ethernet frames for the tests. Written independently
/// of the stack, so that a checksum or length bug in the stack is not hidden
/// by the same bug here.
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

#ifndef PROTOCOL_TESTS_FRAMES_HPP
#define PROTOCOL_TESTS_FRAMES_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "protocol/ethernet/address.hpp"
#include "protocol/ipv4/address.hpp"

namespace frames
{

using bytes = std::vector<std::uint8_t>;

inline const protocol::ethernet::address  stack_mac{0xdc, 0x0e, 0xa1, 0x1c, 0x8e, 0x19};
inline const protocol::ipv4::address      stack_ip{10, 0, 0, 2};

inline protocol::ethernet::address host_mac(std::uint8_t h) { return {0x02, 0, 0, 0, 0, h}; }
inline protocol::ipv4::address     host_ip(std::uint8_t h)  { return {10, 0, 0, h}; }

inline std::uint16_t get16(const bytes& b, std::size_t off)
{
  return std::uint16_t((b[off] << 8) | b[off + 1]);
}

inline void put16(bytes& b, std::size_t off, std::uint16_t v)
{
  b[off]     = std::uint8_t(v >> 8);
  b[off + 1] = std::uint8_t(v);
}

template<typename Array>
inline void put(bytes& b, std::size_t off, const Array& a)
{
  std::copy(a.begin(), a.end(), b.begin() + std::ptrdiff_t(off));
}

/// One's complement sum of big endian 16 bit words, not inverted
inline std::uint32_t sum16(const std::uint8_t* p, std::size_t n, std::uint32_t s = 0)
{
  for (std::size_t i = 0; i + 1 < n; i += 2)
    s += std::uint32_t((p[i] << 8) | p[i + 1]);
  if (n & 1U)
    s += std::uint32_t(p[n - 1] << 8);
  return s;
}

inline std::uint16_t fold(std::uint32_t s)
{
  while (s >> 16)
    s = (s & 0xFFFF) + (s >> 16);
  return std::uint16_t(~s);
}

// Offsets in an untagged Ethernet II frame
constexpr std::size_t eth = 0, ip = 14, l4 = 34;

/// ARP request from host h asking for target
inline bytes arp_request(std::uint8_t h, protocol::ipv4::address target = stack_ip)
{
  bytes f(60, 0);
  put(f, 0, protocol::ethernet::address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
  put(f, 6, host_mac(h));
  put16(f, 12, 0x0806);
  put16(f, 14, 1); put16(f, 16, 0x0800); f[18] = 6; f[19] = 4; put16(f, 20, 1);
  put(f, 22, host_mac(h)); put(f, 28, host_ip(h));
  put(f, 38, target);
  return f;
}

/// ARP reply from host h to the stack
inline bytes arp_reply(std::uint8_t h)
{
  bytes f(60, 0);
  put(f, 0, stack_mac);
  put(f, 6, host_mac(h));
  put16(f, 12, 0x0806);
  put16(f, 14, 1); put16(f, 16, 0x0800); f[18] = 6; f[19] = 4; put16(f, 20, 2);
  put(f, 22, host_mac(h)); put(f, 28, host_ip(h));
  put(f, 32, stack_mac);   put(f, 38, stack_ip);
  return f;
}

struct ip_options
{
  std::optional<std::uint16_t> total_length;   ///< override (a lie)
  bool                         bad_checksum = false;
  std::uint8_t                 tos          = 0;
  protocol::ipv4::address      dest         = stack_ip;
  std::uint8_t                 option_words = 0;   ///< IP options, 4 bytes each (NOPs)
};

/// IPv4 frame from host h with the given transport header + payload,
/// padded to the 60 byte Ethernet minimum
inline bytes ipv4_frame(std::uint8_t h, std::uint8_t proto, const bytes& l4data,
                        ip_options o = {})
{
  const std::size_t hl = 20 + 4U * o.option_words;
  bytes f(std::max<std::size_t>(60, 14 + hl + l4data.size()), 0);
  put(f, 0, stack_mac);
  put(f, 6, host_mac(h));
  put16(f, 12, 0x0800);
  f[14] = std::uint8_t(0x40 | (hl / 4)); f[15] = o.tos;
  put16(f, 16, o.total_length.value_or(std::uint16_t(hl + l4data.size())));
  put16(f, 18, 0x1234); put16(f, 20, 0x4000);  // DF
  f[22] = 64; f[23] = proto;
  put(f, 26, host_ip(h)); put(f, 30, o.dest);
  std::fill(f.begin() + 34, f.begin() + 14 + std::ptrdiff_t(hl), std::uint8_t(1));  // NOP
  std::uint16_t c = fold(sum16(&f[ip], hl));
  put16(f, 24, o.bad_checksum ? std::uint16_t(c ^ 0x5555) : c);
  std::copy(l4data.begin(), l4data.end(), f.begin() + 14 + std::ptrdiff_t(hl));
  return f;
}

inline std::uint32_t pseudo(protocol::ipv4::address s, protocol::ipv4::address d,
                            std::uint8_t proto, std::size_t len)
{
  std::uint32_t x = sum16(s.data(), 4);
  x = sum16(d.data(), 4, x);
  return x + proto + std::uint32_t(len);
}

inline bytes udp_frame(std::uint8_t h, std::uint16_t sport, std::uint16_t dport,
                       const bytes& data, ip_options o = {})
{
  bytes u(8 + data.size(), 0);
  put16(u, 0, sport); put16(u, 2, dport); put16(u, 4, std::uint16_t(u.size()));
  std::copy(data.begin(), data.end(), u.begin() + 8);
  std::uint16_t c = fold(sum16(u.data(), u.size(), pseudo(host_ip(h), o.dest, 17, u.size())));
  put16(u, 6, c == 0 ? 0xFFFF : c);
  return ipv4_frame(h, 17, u, o);
}

inline bytes icmp_echo(std::uint8_t h, std::uint16_t id, std::uint16_t seq, const bytes& data)
{
  bytes m(8 + data.size(), 0);
  m[0] = 8; put16(m, 4, id); put16(m, 6, seq);
  std::copy(data.begin(), data.end(), m.begin() + 8);
  put16(m, 2, fold(sum16(m.data(), m.size())));
  return ipv4_frame(h, 1, m);
}

inline bytes pattern(std::size_t n, std::uint8_t seed = 0)
{
  bytes b(n);
  for (std::size_t i = 0; i < n; ++i)
    b[i] = std::uint8_t(seed + i * 7);
  return b;
}

// ---- inspection of frames written by the stack ---------------------------

inline bool is_arp(const bytes& f, std::uint16_t opcode)
{
  return f.size() >= 42 && get16(f, 12) == 0x0806 && get16(f, 20) == opcode;
}

inline protocol::ipv4::address arp_target_ip(const bytes& f)
{
  return {f[38], f[39], f[40], f[41]};
}

inline bool is_ipv4(const bytes& f, std::uint8_t proto)
{
  return f.size() >= 34 && get16(f, 12) == 0x0800 && f[23] == proto;
}

/// Header checksum, version, IHL and total length agree with the frame
inline bool ipv4_valid(const bytes& f)
{
  return f.size() >= 34 &&
         f[14] == 0x45 &&
         fold(sum16(&f[ip], 20)) == 0 &&
         14u + get16(f, 16) <= f.size();
}

/// UDP length and checksum (pseudo header included) are valid
inline bool udp_valid(const bytes& f)
{
  if (!ipv4_valid(f) || !is_ipv4(f, 17)) return false;
  std::size_t len = get16(f, l4 + 4);
  if (len < 8 || len != get16(f, 16) - 20u) return false;
  protocol::ipv4::address s{f[26], f[27], f[28], f[29]}, d{f[30], f[31], f[32], f[33]};
  return get16(f, l4 + 6) == 0 ||
         fold(sum16(&f[l4], len, pseudo(s, d, 17, len))) == 0;
}

inline bytes udp_payload(const bytes& f)
{
  std::size_t len = get16(f, l4 + 4);
  return bytes(f.begin() + 42, f.begin() + 42 + std::ptrdiff_t(len - 8));
}

// ---- TCP --------------------------------------------------------------------

// TCP control bits
constexpr std::uint8_t FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

struct tcp_options
{
  std::uint16_t window = 8192;
  std::uint16_t mss    = 0;      ///< 0: no MSS option
};

/// A TCP segment from host h
inline bytes tcp_frame(std::uint8_t h, std::uint16_t sport, std::uint16_t dport,
                       std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                       const bytes& data = {}, tcp_options o = {})
{
  const std::size_t hl = o.mss ? 24 : 20;
  bytes t(hl + data.size(), 0);
  put16(t, 0, sport); put16(t, 2, dport);
  put16(t, 4, std::uint16_t(seq >> 16)); put16(t, 6, std::uint16_t(seq));
  put16(t, 8, std::uint16_t(ack >> 16)); put16(t, 10, std::uint16_t(ack));
  t[12] = std::uint8_t((hl / 4) << 4); t[13] = flags;
  put16(t, 14, o.window);
  if (o.mss) { t[20] = 2; t[21] = 4; put16(t, 22, o.mss); }
  std::copy(data.begin(), data.end(), t.begin() + std::ptrdiff_t(hl));
  put16(t, 16, fold(sum16(t.data(), t.size(), pseudo(host_ip(h), stack_ip, 6, t.size()))));
  return ipv4_frame(h, 6, t);
}

/// A TCP segment written by the stack (IP header without options)
struct tcp_seen
{
  std::uint16_t sport = 0, dport = 0, window = 0, mss = 0;
  std::uint32_t seq = 0, ack = 0;
  std::uint8_t  flags = 0;
  bytes         data;
  bool          checksum_ok = false;
};

inline std::optional<tcp_seen> parse_tcp(const bytes& f)
{
  if (!is_ipv4(f, 6) || !ipv4_valid(f))
    return std::nullopt;
  const std::size_t total = get16(f, 16), tl = total - 20;
  tcp_seen s;
  s.sport  = get16(f, 34);
  s.dport  = get16(f, 36);
  s.seq    = (std::uint32_t(get16(f, 38)) << 16) | get16(f, 40);
  s.ack    = (std::uint32_t(get16(f, 42)) << 16) | get16(f, 44);
  const std::size_t hl = (f[46] >> 4) * 4U;
  s.flags  = f[47];
  s.window = get16(f, 48);
  if (hl >= 24 && f[54] == 2 && f[55] == 4)
    s.mss = get16(f, 56);
  s.data.assign(f.begin() + std::ptrdiff_t(34 + hl), f.begin() + std::ptrdiff_t(14 + total));
  protocol::ipv4::address src{f[26], f[27], f[28], f[29]}, dst{f[30], f[31], f[32], f[33]};
  s.checksum_ok = fold(sum16(&f[34], tl, pseudo(src, dst, 6, tl))) == 0;
  return s;
}

} // namespace frames

// PROTOCOL_TESTS_FRAMES_HPP
#endif
