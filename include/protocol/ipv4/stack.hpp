/// \file stack.hpp
/// Header for IPV4 stack implementation
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

#ifndef PROTOCOL_IPV4_HPP
#define PROTOCOL_IPV4_HPP

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

#include "types.hpp"
#include "defs.hpp"

namespace protocol
{

namespace ipv4
{

extern interface_container        g_interfaces;
extern arp_table_type             g_arp_table;
extern udp_ports_table_type       g_udp_ports;
extern packet_pool_type           g_packet_pool;

// ---- driver interface -----------------------------------------------------
//
// step() talks to the Ethernet driver (HAL) through three functions, usually
// lambdas, and optionally a fourth one, a clock.

/// True when a received frame is waiting in the driver
template<typename F>
concept rx_available_function =
  std::invocable<F&> && std::convertible_to<std::invoke_result_t<F&>, bool>;

/// Copies the waiting frame (without FCS) to buffer, at most capacity bytes,
/// and returns its size, 0 on error. buffer is a std::span<std::uint8_t>:
/// a lambda written as [](auto& buffer, std::size_t capacity) works with it.
template<typename F>
concept read_function =
  requires(F& f, std::span<std::uint8_t>& buffer, std::size_t capacity)
  {
    { f(buffer, capacity) } -> std::convertible_to<std::size_t>;
  };

/// Sends size bytes of frame. The frame buffer is reused when write returns,
/// so the driver copies it (to a DMA buffer) or sends it before returning.
template<typename F>
concept write_function =
  requires(F& f, std::span<std::uint8_t>& frame, std::size_t size)
  {
    f(frame, size);
  };

/// A free running counter, e.g. milliseconds since start. Wrapping around is
/// fine: only differences are used.
template<typename F>
concept clock_function =
  std::invocable<F&> && std::convertible_to<std::invoke_result_t<F&>, std::uint32_t>;

/// step() without a clock counts its own calls instead
struct no_clock
{
  constexpr std::uint32_t operator()() const { return 0; }
};

// ---- internals used by step() and the inline functions below ---------------

namespace detail
{
  std::uint32_t             count_step();
  std::optional<packet_id>  acquire_receive_block();
  std::span<std::uint8_t>   receive_buffer(packet_id p);
  /// Takes the block. Returns it again when it now holds a reply to send.
  std::optional<packet_id>  process_received_frame(interface_designator id, packet_id p,
                                                   std::size_t size);
  /// The next frame to send on the interface, or none
  std::optional<packet_id>  next_transmit_frame(interface_designator id, std::uint32_t tick);
  /// The block was written to the driver: counts and frees it
  void                      transmitted(packet_id p);

  inline void release(packet_id p)                     { g_packet_pool.release(p); }
  inline std::span<std::uint8_t> data(packet_id p)     { return g_packet_pool.data(p); }
} // namespace detail

/// Runs the stack once: reads at most one frame per interface and handles
/// it, then sends what is ready to be sent.
///
/// \code {.cpp}
/// ipv4::step
/// (
///   []                                   { return enet_frame_available(); },
///   [](auto& buffer, std::size_t capacity) { return enet_read(buffer.data(), capacity); },
///   [](auto& frame,  std::size_t size)     { enet_write(frame.data(), size); },
///   []                                   { return millis(); }   // optional
/// );
/// \endcode
template
<
  rx_available_function IsRxAvailableFunction,
  read_function         ReadFunction,
  write_function        WriteFunction,
  clock_function        ClockFunction = no_clock
>
inline void
step
(
  IsRxAvailableFunction   is_rx_available,
  ReadFunction            read,
  WriteFunction           write,
  ClockFunction           now = {}
)
{
  std::uint32_t tick;

  if constexpr (std::same_as<ClockFunction, no_clock>)
    tick = detail::count_step();
  else
    tick = static_cast<std::uint32_t>(now());

  auto transmit = [&write](packet_id p)
  {
    std::span<std::uint8_t> frame = detail::data(p);
    write(frame, frame.size());
    detail::transmitted(p);
  };

  for (interface_designator id = 0; id < c_interface_table_size; ++id)
  {
    if (is_rx_available())
    {
      // No free block: the frame stays in the driver until one is released
      if (auto block = detail::acquire_receive_block())
      {
        std::span<std::uint8_t> buffer = detail::receive_buffer(*block);
        const std::size_t       size   = read(buffer, buffer.size());

        if (auto reply = detail::process_received_frame(id, *block, size))
          transmit(*reply);
      }
    }

    while (auto frame = detail::next_transmit_frame(id, tick))
      transmit(*frame);
  }
}

/// Clears all tables and queues and frees every packet
extern void
initialize();

extern bool
set
(
  const interface_designator  id,
  ethernet::address           hw_addr,
  ipv4::address               ip_addr
);

extern const statistics&
stats();

/// Owns one block of the packet pool and frees it when destroyed, like a
/// std::unique_ptr for packets. It can be moved but not copied, so a block
/// always has exactly one owner and cannot be leaked or freed twice.
class packet
{
public:
  packet() = default;

  explicit packet(packet_id id) : m_id(id) {}

  packet(packet&& other) noexcept
  : m_id(std::exchange(other.m_id, std::nullopt))
  {}

  packet& operator=(packet&& other) noexcept
  {
    if (this != &other)
    {
      reset();
      m_id = std::exchange(other.m_id, std::nullopt);
    }
    return *this;
  }

  packet(const packet&)            = delete;
  packet& operator=(const packet&) = delete;

  ~packet() { reset(); }

  explicit operator bool() const { return m_id.has_value(); }

  /// The payload: received data, or the bytes to fill before sending
  std::span<std::uint8_t> data() const
  {
    return m_id ? detail::data(*m_id) : std::span<std::uint8_t>{};
  }

  std::size_t size() const { return data().size(); }

  std::optional<packet_id> id() const { return m_id; }

  /// Frees the block now
  void reset()
  {
    if (m_id)
    {
      detail::release(*m_id);
      m_id.reset();
    }
  }

  /// Gives up ownership without freeing: the caller frees the block
  std::optional<packet_id> detach() { return std::exchange(m_id, std::nullopt); }

private:
  std::optional<packet_id> m_id;
};

namespace udp
{

/// A received datagram. The block is freed when the datagram is destroyed,
/// or it can be moved into send() to answer without copying.
struct datagram
{
  packet    buffer;
  endpoint  remote;

  std::span<const std::uint8_t> data() const { return buffer.data(); }
  std::size_t                   size() const { return buffer.size(); }
};

/// Binds a port on an interface. Fails when the port is already bound or
/// the table is full.
extern endpoint_designator
bind
(
  const interface_designator  id,
  const uint16_t              port
);

/// Size of the oldest datagram waiting, 0 when none
extern std::size_t
received_length
(
  const endpoint_designator&  ed
);

/// Takes the oldest datagram waiting, without copying it
extern std::optional<datagram>
receive
(
  const endpoint_designator&  ed
);

/// Copies the oldest datagram waiting into data and frees it. A datagram
/// longer than size is cut to size bytes.
extern std::size_t
receive
(
  const endpoint_designator&  ed,
  uint8_t*                    data,
  const std::size_t           size,
  endpoint&                   remote
);

/// A packet with size bytes of payload to fill, for send() without copying
extern std::optional<packet>
allocate
(
  const endpoint_designator&  ed,
  const std::size_t           size
);

/// Queues the payload of p for sending. On success the stack owns the
/// packet; on failure p is left as it was.
extern bool
send
(
  const endpoint_designator&  ed,
  packet&&                    p,
  const endpoint&             remote
);

/// Copies data into a packet and queues it. Returns size, 0 on failure.
extern std::size_t
send
(
  const endpoint_designator&  ed,
  const uint8_t               *data,
  const std::size_t           size,
  const endpoint&             remote
);

} // namespace udp

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_HPP
#endif
