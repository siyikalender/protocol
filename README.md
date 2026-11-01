# protocol
Lightweight communication protocol stacks for embedded applications. 

## IPv4 stack (ARP, ICMP echo, UDP)

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

## Building and testing

Needs a C++20 compiler and the [haluj](https://github.com/siyikalender/haluj)
and [bit](https://github.com/siyikalender/bit) libraries, by default in
folders next to this one (`PROTOCOL_HALUJ_DIR`, `PROTOCOL_BIT_DIR`).

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```
