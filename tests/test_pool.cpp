/// \file test_pool.cpp
/// Tests of packet_pool on its own
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

#include <cstdint>
#include <optional>
#include <vector>

#include "protocol/ipv4/packet_pool.hpp"

#include "check.hpp"

using protocol::ipv4::packet_id;

using pool_type = protocol::ipv4::packet_pool<6, 1536, 32, 2>;

// A global pool is built at compile time: no start up code, in .bss
constinit pool_type g_pool{};

// The whole pool works in constant expressions too
static_assert([]
{
  protocol::ipv4::packet_pool<2, 64, 4, 2> p;
  auto a = p.acquire();
  auto b = p.acquire();
  bool ok = a && b && !p.acquire() && a->index != b->index;
  p.release(*a);
  ok = ok && p.available() == 1 && p.acquire()->index == a->index;
  return ok;
}());

int main()
{
  // Exhaustion and recovery, many times: the pool never shrinks
  for (int round = 0; round < 100; ++round)
  {
    std::vector<packet_id> taken;
    while (auto p = g_pool.acquire())
      taken.push_back(*p);
    PROTOCOL_CHECK(taken.size() == 6);
    PROTOCOL_CHECK(g_pool.available() == 0);
    // release in a different order every round
    for (std::size_t i = 0; i < taken.size(); ++i)
      g_pool.release(taken[(i + std::size_t(round)) % taken.size()]);
    PROTOCOL_CHECK(g_pool.available() == 6);
  }

  // keep: a low priority caller leaves blocks for the others
  {
    std::vector<packet_id> taken;
    while (auto p = g_pool.acquire(2))
      taken.push_back(*p);
    PROTOCOL_CHECK(taken.size() == 4);
    PROTOCOL_CHECK(g_pool.acquire().has_value());
    PROTOCOL_CHECK(g_pool.available() == 1);
    g_pool.reset();
  }

  // Alignment: blocks on 32 bytes, the IP header (headroom + 14) on 4
  {
    for (int i = 0; i < 6; ++i)
    {
      auto p = g_pool.acquire();
      auto addr = reinterpret_cast<std::uintptr_t>(g_pool.base(*p));
      PROTOCOL_CHECK(addr % 32 == 0);
      PROTOCOL_CHECK((addr + 2 + 14) % 4 == 0);
    }
    g_pool.reset();
  }

  // push_header / pull_header
  {
    auto p = *g_pool.acquire();
    PROTOCOL_CHECK(g_pool.data(p).empty());
    PROTOCOL_CHECK(g_pool.data(p).data() == g_pool.base(p) + 2);

    PROTOCOL_CHECK(g_pool.set(p, 44, 10));
    PROTOCOL_CHECK(g_pool.push_header(p, 8) == g_pool.base(p) + 36);
    PROTOCOL_CHECK(g_pool.push_header(p, 20) == g_pool.base(p) + 16);
    PROTOCOL_CHECK(g_pool.push_header(p, 14) == g_pool.base(p) + 2);
    PROTOCOL_CHECK(g_pool.data(p).size() == 52);
    PROTOCOL_CHECK(g_pool.push_header(p, 3) == nullptr);   // only 2 left
    PROTOCOL_CHECK(g_pool.data(p).size() == 52);           // unchanged

    PROTOCOL_CHECK(g_pool.pull_header(p, 14) == g_pool.base(p) + 2);
    PROTOCOL_CHECK(g_pool.pull_header(p, 100) == nullptr);
    PROTOCOL_CHECK(g_pool.trim(p, 5));
    PROTOCOL_CHECK(!g_pool.trim(p, 50));
    PROTOCOL_CHECK(g_pool.data(p).size() == 5);
    PROTOCOL_CHECK(!g_pool.set(p, 1536, 1));
    PROTOCOL_CHECK(g_pool.frame_buffer(p).size() == 1534);
    g_pool.release(p);
  }

  // storage and id_of: what DMA drivers use
  {
    auto p = *g_pool.acquire();
    auto q = *g_pool.acquire();
    auto s = g_pool.storage(q);
    PROTOCOL_CHECK(s.size() == 1536);
    PROTOCOL_CHECK(s.data() == g_pool.base(q));
    PROTOCOL_CHECK(g_pool.id_of(s.data()) == q);
    PROTOCOL_CHECK(g_pool.id_of(s.data() + 1535) == q);
    PROTOCOL_CHECK(g_pool.id_of(g_pool.base(p) + 2) == p);
    PROTOCOL_CHECK(!g_pool.id_of(s.data() + 1536).has_value());   // offset/length, not data
    int elsewhere = 0;
    PROTOCOL_CHECK(!g_pool.id_of(&elsewhere).has_value());
    g_pool.reset();
  }

  return protocol_test::report("test_pool");
}
