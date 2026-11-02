/// \file packet_pool.hpp
/// Fixed size packet buffer pool
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

#ifndef PROTOCOL_IPV4_PACKET_POOL_HPP
#define PROTOCOL_IPV4_PACKET_POOL_HPP

#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace protocol
{

namespace ipv4
{

/// Names one block of a packet_pool. It is a plain index: it does not own
/// the block, see ipv4::packet for an owning handle.
struct packet_id
{
  std::uint8_t index = 0;

  friend constexpr bool operator==(packet_id, packet_id) = default;
};

/// A pool of Count blocks of BlockSize bytes each. Allocation and release
/// take constant time and the pool cannot fragment: every block fits every
/// frame.
///
/// A block holds one frame. Its valid bytes are [offset, offset + length):
///   - receive: a frame is read at headroom(), and pull_header() steps over
///     the Ethernet, IP and UDP headers until only the payload is left,
///   - transmit: the payload is written at payload_offset, and
///     push_header() puts the UDP, IP and Ethernet headers in front of it.
/// So a frame is never copied from one buffer to another inside the stack.
///
/// Alignment: every block starts at an Alignment boundary. 32 matches the
/// Cortex-M7 data cache line (STM32F7), so a block can be cleaned or
/// invalidated for DMA without touching its neighbours. Headroom = 2 puts
/// the IP header on a 4 byte boundary after the 14 byte Ethernet header.
///
/// Concurrency: single context. Every function is called from the context
/// that calls step().
template
<
  std::size_t Count,
  std::size_t BlockSize,
  std::size_t Alignment,
  std::size_t Headroom
>
class packet_pool
{
  static_assert(Count >= 1 && Count <= 32, "the blocks in use are bits of a uint32_t");
  static_assert(std::has_single_bit(Alignment), "Alignment must be a power of two");
  static_assert(BlockSize % Alignment == 0, "blocks must stay aligned one after another");
  static_assert(BlockSize <= 0xFFFF, "offset and length are 16 bit");
  static_assert(Headroom < BlockSize);

public:
  /// Only the bytes: the blocks follow each other without gaps (their
  /// valid ranges are kept apart, see m_ranges)
  struct alignas(Alignment) block
  {
    std::array<std::uint8_t, BlockSize> data{};
  };
  static_assert(sizeof(block) == BlockSize);

  /// The valid bytes of a block
  struct range
  {
    std::uint16_t offset = 0;
    std::uint16_t length = 0;
  };

  static constexpr std::size_t capacity()   { return Count; }
  static constexpr std::size_t block_size() { return BlockSize; }
  static constexpr std::size_t headroom()   { return Headroom; }

  constexpr packet_pool() = default;

  /// Makes every block free. Ids handed out before are no longer valid.
  constexpr void reset()
  {
    m_used = 0;
  }

  /// Takes a free block, only when more than \p keep blocks are free: a
  /// caller of lower priority leaves \p keep blocks to the others.
  /// The block comes back empty, offset = headroom().
  constexpr std::optional<packet_id> acquire(const std::size_t keep = 0)
  {
    if (available() <= keep)
      return std::nullopt;

    const auto i = static_cast<std::uint8_t>(std::countr_one(m_used));
    m_used |= std::uint32_t(1) << i;
    m_ranges[i] = {Headroom, 0};
    return packet_id{i};
  }

  /// Gives the block back. Releasing a free block is a bug: it asserts.
  constexpr void release(const packet_id p)
  {
    assert(in_use(p) && "packet released twice");
    m_used &= ~(std::uint32_t(1) << p.index);
  }

  constexpr bool in_use(const packet_id p) const
  {
    return p.index < Count && (m_used & (std::uint32_t(1) << p.index)) != 0;
  }

  constexpr std::size_t available() const
  {
    return Count - static_cast<std::size_t>(std::popcount(m_used));
  }

  /// The valid bytes of the block
  constexpr std::span<std::uint8_t> data(const packet_id p)
  {
    const range& r = m_ranges[p.index];
    return {m_blocks[p.index].data.data() + r.offset, r.length};
  }

  /// All bytes from the headroom to the end of the block: where a received
  /// frame is read to
  constexpr std::span<std::uint8_t> frame_buffer(const packet_id p)
  {
    return {m_blocks[p.index].data.data() + Headroom, BlockSize - Headroom};
  }

  /// Sets the valid range. False, and nothing changes, when it does not fit.
  constexpr bool set(const packet_id p, const std::size_t offset, const std::size_t length)
  {
    if (offset > BlockSize || length > BlockSize - offset)
      return false;

    m_ranges[p.index] = {static_cast<std::uint16_t>(offset), static_cast<std::uint16_t>(length)};
    return true;
  }

  /// Shortens the valid range to \p length bytes (drops trailing padding)
  constexpr bool trim(const packet_id p, const std::size_t length)
  {
    range& b = m_ranges[p.index];
    if (length > b.length)
      return false;
    b.length = static_cast<std::uint16_t>(length);
    return true;
  }

  /// Transmit: opens \p size bytes in front of the valid range and returns
  /// them, nullptr when there is no room left in front.
  constexpr std::uint8_t* push_header(const packet_id p, const std::size_t size)
  {
    range& b = m_ranges[p.index];
    if (b.offset < size)
      return nullptr;
    b.offset = static_cast<std::uint16_t>(b.offset - size);
    b.length = static_cast<std::uint16_t>(b.length + size);
    return m_blocks[p.index].data.data() + b.offset;
  }

  /// Receive: returns the first \p size valid bytes and steps over them,
  /// nullptr when fewer than \p size bytes are valid.
  constexpr std::uint8_t* pull_header(const packet_id p, const std::size_t size)
  {
    range& b = m_ranges[p.index];
    if (b.length < size)
      return nullptr;
    std::uint8_t* header = m_blocks[p.index].data.data() + b.offset;
    b.offset = static_cast<std::uint16_t>(b.offset + size);
    b.length = static_cast<std::uint16_t>(b.length - size);
    return header;
  }

  /// Start of the block's storage, for headers at a known position
  constexpr std::uint8_t* base(const packet_id p)
  {
    return m_blocks[p.index].data.data();
  }

  /// The whole storage of the block, from its aligned start: what a DMA
  /// descriptor points to
  constexpr std::span<std::uint8_t> storage(const packet_id p)
  {
    return m_blocks[p.index].data;
  }

  /// The block that \p address points into, none when it points elsewhere.
  /// For drivers whose HAL hands back buffer addresses instead of ids.
  std::optional<packet_id> id_of(const void* address) const
  {
    // Integer arithmetic: comparing pointers into unrelated objects with <
    // is unspecified in C++
    const auto a     = reinterpret_cast<std::uintptr_t>(address);
    const auto first = reinterpret_cast<std::uintptr_t>(m_blocks.data());

    if (a < first)
      return std::nullopt;

    const std::size_t index  = (a - first) / sizeof(block);
    const std::size_t offset = (a - first) % sizeof(block);

    if (index >= Count || offset >= BlockSize)
      return std::nullopt;

    return packet_id{static_cast<std::uint8_t>(index)};
  }

private:
  // Bit i set: block i is in use. Every member starts as zero, so a global
  // pool goes to .bss: no flash copy and no start up code. The ranges come
  // first: near the start of the pool, Thumb loads reach them with a short
  // offset (behind the blocks they would need an extra add).
  std::array<range, Count> m_ranges{};
  std::uint32_t            m_used = 0;
  std::array<block, Count> m_blocks{};
};

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_PACKET_POOL_HPP
#endif
