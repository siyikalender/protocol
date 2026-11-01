# protocol
Lightweight communication protocol stacks for embedded applications. 

## IPv4 stack (ARP, ICMP echo, UDP, TCP)

No heap. Every frame, received or sent, lives in one block of a fixed size
packet pool (`include/protocol/ipv4/packet_pool.hpp`); the sizes are set in
`include/protocol/ipv4/constants.hpp`. Headers are parsed and written in
place, so the stack itself copies no frame.

The Ethernet driver is plugged in with lambdas:

```cpp
#include "protocol/ipv4/stack.hpp"

using namespace protocol;

ipv4::initialize();
ipv4::set(0, ethernet::address{0x02, 0, 0, 0, 0, 1}, ipv4::address{10, 0, 0, 2});
auto ed = ipv4::udp::bind(0, 7);

for (;;)
{
  ipv4::step
  (
    []                                     { return enet_frame_available(); },
    [](auto& buffer, std::size_t capacity) { return enet_read(buffer.data(), capacity); },
    [](auto& frame,  std::size_t size)     { enet_write(frame.data(), size); },
    []                                     { return millis(); }   // optional clock
  );

  // Echo without copying: the reply is built in the received block
  if (auto d = ipv4::udp::receive(ed))
    ipv4::udp::send(ed, std::move(d->buffer), d->remote);
}
```

The copying `udp::send(ed, data, size, remote)` and
`udp::receive(ed, data, size, remote)` are available too.

### TCP

Listening and connecting, byte streams both ways (`include/protocol/ipv4/tcp.hpp`):

```cpp
auto l = ipv4::tcp::listen(0, 502);

for (;;)
{
  ipv4::step(...);                          // with a clock: TCP has timers

  if (auto c = ipv4::tcp::accept(*l))
    connection = *c;

  std::uint8_t buffer[256];
  if (auto n = ipv4::tcp::receive(connection, buffer, sizeof buffer))
    ipv4::tcp::send(connection, buffer, n);

  if (ipv4::tcp::state(connection) == ipv4::tcp::status::peer_closed)
    ipv4::tcp::close(connection);
}
```

`connect(0, {address, port})` opens a connection, `allocate()` /
`send(c, packet&&)` / `receive(c)` work without copying.

- RFC 9293 state machine, RFC 5961 protection against blind RST and SYN,
  RFC 6298 retransmission timer, RFC 6528 initial sequence numbers (seed
  them with `tcp::set_secret()` from an RNG), zero window probes, MSS
  option.
- Loss recovery: fast retransmit on duplicate ACKs (RFC 5681), fewer of
  them when only a few segments are out (early retransmit, RFC 5827), the
  next hole sent at once on a partial ACK (NewReno, RFC 6582).
- SACK (RFC 2018) when the peer offers it: the stack's ACKs tell which
  segments it keeps out of order; the peer's SACK blocks mark the sent
  segments it has, so only the holes are sent again, as soon as enough
  after them has arrived (RFC 6675), even when the peer's ACKs carry data.
- Segments received out of order are kept in their blocks until the gap is
  filled (they share the `PROTOCOL_IPV4_TCP_RX_SEGMENTS` blocks with data in
  order, and give them up to it); each is answered by a duplicate ACK
  without data.
- Sent segments stay in their pool blocks until acknowledged and are sent
  again from there: no send buffer, no copy.
- Tail loss probe (RFC 8985) with SACK: when ACKs stop, the last segment
  goes again after twice the smoothed RTT (at least
  `c_tcp_pto_min`), long before the timeout. In recovery the first hole
  goes instead, so a lost retransmission does not wait for the timeout
  either (RFC 8985 keeps probes out of recovery; with few segments out
  nothing else would bring an ACK).
- Sending leaves a block free for the next segment in order while a
  receive window is open, so data in order is not dropped for lack of a
  block.
- Not done: congestion control (RFC 5681), window scaling, timestamps.
  Data segments carry no SACK blocks, only ACKs without data do.

### DMA drivers

With a MAC whose DMA descriptors point to buffers, `step_dma()` lends the
pool blocks to the descriptors, so frames are not copied at all:

```cpp
ipv4::step_dma
(
  []                                { return enet.receive(); },   // std::optional<ipv4::rx_frame>
  [](ipv4::packet_id p, auto frame) { return enet.transmit(p, frame); },  // false: TX ring full
  []                                { return enet.reclaim(); },   // std::optional<ipv4::packet_id>
  []                                { return millis(); }          // optional clock
);
```

- Receive: each RX descriptor always holds a block. When a frame is in,
  the driver swaps the block for one from `ipv4::dma::acquire()` and returns
  `{id, size}`; when there is none it re-arms the same block and drops the
  frame, so the ring never runs empty.
- Transmit: the driver owns the block until the frame is sent, then
  `reclaim` hands it back. A refused frame is sent again at the next step.
- The frame starts `c_packet_headroom` bytes into `dma::storage(id)`;
  `dma::receive_buffer()` is that address. DMA drivers build with
  `PROTOCOL_IPV4_PACKET_HEADROOM=0`, so frames start on the block's aligned
  address (the stack reads headers byte by byte, alignment does not matter
  to it).
- `dma::id_of(address)` maps a buffer address from a HAL callback back to
  its block.
- Size the pool for the rings:
  `c_packet_pool_size >= RX descriptors + TX descriptors + datagrams waiting on ports + c_tx_reserved_blocks`.
- On a core with a data cache (STM32F7) put the pool in a non cacheable
  region, e.g. `-DPROTOCOL_IPV4_PACKET_POOL_ATTRIBUTES='__attribute__((section(".eth_ram")))'`
  with `.eth_ram` NOLOAD in the linker script, or clean / invalidate the
  blocks around DMA. `initialize()` resets the pool, the section needs no
  zeroing at start up.

Example drivers, built against the vendors' current releases:

| Folder | MCU | Vendor driver |
| --- | --- | --- |
| `examples/drivers/stm32f7` | STM32F7 | STM32Cube ETH HAL (`HAL_ETH_ReadData`, `HAL_ETH_RxAllocateCallback`), not the legacy one |
| `examples/drivers/kinetis` | Kinetis K60/K64/K66 | MCUXpresso SDK `fsl_enet` (`ENET_GetRxFrame`, `ENET_StartTxFrame`) |

Each header shows the start up order and the `step_dma()` call.

### Settings

`constants.hpp` holds the defaults. These can be changed per target with
compile definitions, seen by the library and the application alike
(e.g. `target_compile_definitions(protocol_ipv4 PUBLIC ...)`):

| Definition | Default |
| --- | --- |
| `PROTOCOL_IPV4_PACKET_POOL_SIZE` | 6 |
| `PROTOCOL_IPV4_PACKET_HEADROOM` | 2 (0 for DMA drivers) |
| `PROTOCOL_IPV4_PACKET_BLOCK_ALIGNMENT` | 32 |
| `PROTOCOL_IPV4_VERIFY_RX_CHECKSUMS` | 1 (0 with MAC checksum offload) |
| `PROTOCOL_IPV4_PACKET_POOL_ATTRIBUTES` | empty (e.g. a section attribute) |
| `PROTOCOL_IPV4_TCP_CONNECTIONS` | 4 (0 leaves TCP out) |
| `PROTOCOL_IPV4_TCP_LISTENERS` | 3 |
| `PROTOCOL_IPV4_TCP_RX_SEGMENTS` | 4 blocks per connection: its receive window |
| `PROTOCOL_IPV4_TCP_TX_SEGMENTS` | 4 blocks per connection: data sent or to send |

For streaming, give TCP room: e.g. `POOL_SIZE=24`, `TCP_RX_SEGMENTS=8`,
`TCP_TX_SEGMENTS=8`.

## Building and testing

Needs a C++20 compiler and the [haluj](https://github.com/siyikalender/haluj)
and [bit](https://github.com/siyikalender/bit) libraries, by default in
folders next to this one (`PROTOCOL_HALUJ_DIR`, `PROTOCOL_BIT_DIR`).

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

The `tcp_*` interop tests run TCP against the Linux stack through a TAP
interface. They need `/dev/net/tun` and CAP_NET_ADMIN (e.g. `sudo ctest`),
and are skipped without them.
