/// \file tcp.hpp
/// TCP (RFC 9293): listening and connecting, byte streams in both directions
///
/// \code {.cpp}
/// auto l = ipv4::tcp::listen(0, 502);
///
/// for (;;)
/// {
///   ipv4::step(...);
///
///   if (auto c = ipv4::tcp::accept(*l))
///     connection = *c;
///
///   std::uint8_t buffer[256];
///   if (auto n = ipv4::tcp::receive(connection, buffer, sizeof buffer))
///     ipv4::tcp::send(connection, buffer, n);           // echo
///
///   if (ipv4::tcp::state(connection) == ipv4::tcp::status::peer_closed)
///     ipv4::tcp::close(connection);
/// }
/// \endcode
///
/// TCP needs a clock: give step() / step_dma() one, or the timers count
/// calls of step() (see constants.hpp).
///
/// Data is kept in blocks of the packet pool. A connection holds at most
/// c_tcp_rx_segments blocks of received data and c_tcp_tx_segments blocks of
/// data to send; a sent block stays with the connection until the peer
/// acknowledges it and is sent again from there, without a copy, if needed.
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

#ifndef PROTOCOL_IPV4_TCP_HPP
#define PROTOCOL_IPV4_TCP_HPP

#include <cstddef>
#include <cstdint>
#include <optional>

#include "stack.hpp"

namespace protocol
{

namespace ipv4
{

namespace tcp
{

/// A port listened on
struct listener
{
  std::uint8_t index = 0;

  friend constexpr bool operator==(listener, listener) = default;
};

/// A connection. The generation tells a connection from a later one that
/// reuses its place, so an old handle cannot reach a new connection.
struct connection
{
  std::uint8_t index      = 0;
  std::uint8_t generation = 0;

  friend constexpr bool operator==(connection, connection) = default;
};

enum class status : std::uint8_t
{
  closed,         ///< no such connection (closed, or the handle is old)
  connecting,     ///< the handshake is going on
  established,    ///< data flows both ways
  peer_closed,    ///< the peer will send no more; data may still be sent
  closing,        ///< close() was called, the connection winds down
  reset,          ///< the peer reset the connection
  timed_out       ///< the peer stopped answering, or never did
};

/// Listens on a port. None when the port is listened on already or every
/// listener is in use.
std::optional<listener> listen(interface_designator id, std::uint16_t port);

/// Stops listening. Connections already accepted go on.
void stop(listener l);

/// A connection the listener has established, none when it has none yet
std::optional<connection> accept(listener l);

/// Opens a connection to remote. local_port 0 picks a free port. The
/// connection is connecting until the handshake ends.
std::optional<connection> connect(interface_designator id, const endpoint& remote,
                                  std::uint16_t local_port = 0);

status state(connection c);

/// The remote end of the connection
std::optional<endpoint> remote(connection c);

// ---- receiving --------------------------------------------------------------

/// Bytes received and not read yet
std::size_t received_length(connection c);

/// Copies up to size received bytes to data and returns how many
std::size_t receive(connection c, std::uint8_t* data, std::size_t size);

/// The next received bytes, as they came, without copying
std::optional<packet> receive(connection c);

// ---- sending ----------------------------------------------------------------

/// Bytes send() takes now
std::size_t send_space(connection c);

/// Queues up to size bytes of data and returns how many it took
std::size_t send(connection c, const std::uint8_t* data, std::size_t size);

/// A packet of size bytes (at most the connection's segment size) to fill
/// and send() without copying
std::optional<packet> allocate(connection c, std::size_t size);

/// Queues the packet's payload. On success the stack owns the packet; on
/// failure it is left as it was.
bool send(connection c, packet&& p);

// ---- ending -------------------------------------------------------------------

/// Sends what is queued, then closes; gives up the handle. Received data
/// not read yet is dropped.
void close(connection c);

/// Resets the connection at once; gives up the handle
void abort(connection c);

/// The key of the initial sequence numbers (RFC 6528). Seed it from a true
/// random source (RNG peripheral) at start up, so the sequence numbers of a
/// new connection cannot be guessed.
void set_secret(std::uint64_t secret);

} // namespace tcp

} // namespace ipv4

} // namespace protocol

// PROTOCOL_IPV4_TCP_HPP
#endif
