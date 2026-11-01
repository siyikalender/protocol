/// \file test_tcp_interop.cpp
/// TCP against the Linux TCP stack. The stack runs on a TAP interface:
/// frames go between it and the kernel, and kernel sockets are its peers.
///
/// Needs /dev/net/tun and CAP_NET_ADMIN (root in a container, sudo in CI);
/// without them every case is skipped (exit code 77). Each case runs in
/// its own process with its own interface and subnet, the case name is the
/// first command line argument.
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

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "protocol/ipv4/stack.hpp"
#include "protocol/ipv4/tcp.hpp"

#include "check.hpp"

using namespace protocol;
using bytes = std::vector<std::uint8_t>;

namespace
{

constexpr int c_skip = 77;

// ---- the TAP interface -----------------------------------------------------------

struct tap
{
  int         fd = -1;
  std::string name;
  std::string host_ip;     // the kernel's address
  std::string stack_ip;    // ours

  bool open(int subnet)
  {
    fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0)
      return false;

    name     = "ptcp" + std::to_string(::getpid() % 100000);
    host_ip  = "10.77." + std::to_string(subnet) + ".1";
    stack_ip = "10.77." + std::to_string(subnet) + ".2";

    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0)
      return false;

    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    auto set_address = [&](unsigned long request, const std::string& a)
    {
      ifreq r{};
      std::strncpy(r.ifr_name, name.c_str(), IFNAMSIZ - 1);
      auto* sin = reinterpret_cast<sockaddr_in*>(&r.ifr_addr);
      sin->sin_family = AF_INET;
      ::inet_pton(AF_INET, a.c_str(), &sin->sin_addr);
      return ::ioctl(s, request, &r) == 0;
    };

    bool ok = set_address(SIOCSIFADDR, host_ip) && set_address(SIOCSIFNETMASK, "255.255.255.0");

    ifreq r{};
    std::strncpy(r.ifr_name, name.c_str(), IFNAMSIZ - 1);
    ok = ok && ::ioctl(s, SIOCGIFFLAGS, &r) == 0;
    r.ifr_flags |= IFF_UP;
    ok = ok && ::ioctl(s, SIOCSIFFLAGS, &r) == 0;
    ::close(s);
    return ok;
  }

  ~tap()
  {
    if (fd >= 0)
      ::close(fd);
  }
};

ipv4::address to_address(const std::string& s)
{
  in_addr a{};
  ::inet_pton(AF_INET, s.c_str(), &a);
  ipv4::address r;
  std::memcpy(r.data(), &a, 4);
  return r;
}

// ---- the stack, in a thread of its own -------------------------------------------------
//
// The stack is not thread safe: every call to it is made by the stack
// thread. The test hands it work with run(), which waits for the result.

class stack_thread
{
public:
  explicit stack_thread(tap& t, double loss = 0.0)
  : m_tap(t), m_loss(loss)
  {
    ipv4::initialize();
    ipv4::set(0, ethernet::address{0x02, 0, 0, 0, 0, 0x02}, to_address(t.stack_ip));
    ipv4::tcp::set_secret(0x1234567890ABCDEFULL);
    m_thread = std::thread([this] { loop(); });
  }

  ~stack_thread()
  {
    m_stop = true;
    m_thread.join();
  }

  /// Runs f in the stack thread, once, and waits
  void run(std::function<void()> f)
  {
    std::atomic<bool> done{false};
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      m_once = [&] { f(); done = true; };
    }
    while (!done)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  /// f runs in the stack thread after every step, until replaced
  void every_step(std::function<void()> f)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_every = std::move(f);
  }

  std::size_t frames_dropped() const { return m_dropped; }

private:
  bool lose()
  {
    return m_loss > 0.0 && m_random(m_engine) < m_loss;
  }

  void loop()
  {
    using clock = std::chrono::steady_clock;
    const auto start = clock::now();
    std::uint8_t pending[2048];
    ssize_t      pending_size = -1;

    while (!m_stop)
    {
      if (pending_size < 0)
      {
        pollfd p{m_tap.fd, POLLIN, 0};
        if (::poll(&p, 1, 1) > 0)
        {
          pending_size = ::read(m_tap.fd, pending, sizeof pending);
          if (pending_size > 0 && lose())
          {
            ++m_dropped;
            pending_size = -1;
          }
        }
      }

      ipv4::step
      (
        [&] { return pending_size > 0; },
        [&](auto& buffer, std::size_t capacity) -> std::size_t
        {
          std::size_t n = pending_size > 0 ? std::size_t(pending_size) : 0;
          pending_size = -1;
          if (n > capacity) return 0;
          std::memcpy(buffer.data(), pending, n);
          return n;
        },
        [&](auto& frame, std::size_t size)
        {
          if (lose())
          {
            ++m_dropped;
            return;
          }
          [[maybe_unused]] auto r = ::write(m_tap.fd, frame.data(), size);
        },
        [&]
        {
          return std::uint32_t(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 clock::now() - start).count());
        }
      );

      std::function<void()> once;
      {
        std::lock_guard<std::mutex> lock(m_mutex);
        once.swap(m_once);
        if (m_every)
          m_every();
      }
      if (once)
        once();
    }
  }

  tap&                                    m_tap;
  double                                  m_loss;
  std::mt19937                            m_engine{42};
  std::uniform_real_distribution<double>  m_random{0.0, 1.0};
  std::atomic<std::size_t>                m_dropped{0};
  std::atomic<bool>                       m_stop{false};
  std::mutex                              m_mutex;
  std::function<void()>                   m_once;
  std::function<void()>                   m_every;
  std::thread                             m_thread;
};

// ---- kernel sockets --------------------------------------------------------------------

int kernel_socket()
{
  const int s = ::socket(AF_INET, SOCK_STREAM, 0);
  timeval tv{20, 0};
  ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  return s;
}

sockaddr_in socket_address(const std::string& ip, std::uint16_t port)
{
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port   = htons(port);
  ::inet_pton(AF_INET, ip.c_str(), &a.sin_addr);
  return a;
}

int kernel_connect(const std::string& ip, std::uint16_t port)
{
  const int s = kernel_socket();
  const sockaddr_in a = socket_address(ip, port);
  if (::connect(s, reinterpret_cast<const sockaddr*>(&a), sizeof a) != 0)
  {
    const int e = errno;
    ::close(s);
    errno = e;
    return -1;
  }
  return s;
}

bool send_all(int s, const bytes& data)
{
  std::size_t done = 0;
  while (done < data.size())
  {
    const ssize_t n = ::send(s, data.data() + done, data.size() - done, MSG_NOSIGNAL);
    if (n <= 0)
      return false;
    done += std::size_t(n);
  }
  return true;
}

/// Reads until size bytes or the end of the stream
bytes receive_all(int s, std::size_t size)
{
  bytes r;
  r.reserve(size);
  std::uint8_t buffer[65536];
  while (r.size() < size)
  {
    const ssize_t n = ::recv(s, buffer, sizeof buffer, 0);
    if (n <= 0)
      break;
    r.insert(r.end(), buffer, buffer + n);
  }
  return r;
}

bytes random_bytes(std::size_t n, unsigned seed)
{
  std::mt19937 g(seed);
  bytes b(n);
  for (auto& x : b)
    x = std::uint8_t(g());
  return b;
}

double seconds_since(std::chrono::steady_clock::time_point t)
{
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count();
}

// ---- an echo server on the stack ---------------------------------------------------------

/// Echoes every connection accepted on the listeners; closes when the peer
/// closes. Runs in the stack thread.
struct echo_server
{
  std::vector<ipv4::tcp::listener>   listeners;
  std::vector<ipv4::tcp::connection> connections;
  std::vector<bytes>                 pending;      // received, not sent back yet
  std::size_t                        closed = 0;

  void step()
  {
    for (auto l : listeners)
      while (auto c = ipv4::tcp::accept(l))
      {
        connections.push_back(*c);
        pending.emplace_back();
      }

    for (std::size_t i = 0; i < connections.size(); ++i)
    {
      auto c = connections[i];
      auto& p = pending[i];

      std::uint8_t buffer[4096];
      while (p.size() < 16384)
      {
        const std::size_t n = ipv4::tcp::receive(c, buffer, sizeof buffer);
        if (n == 0)
          break;
        p.insert(p.end(), buffer, buffer + n);
      }

      if (!p.empty())
      {
        const std::size_t n = ipv4::tcp::send(c, p.data(), p.size());
        p.erase(p.begin(), p.begin() + std::ptrdiff_t(n));
      }

      const auto s = ipv4::tcp::state(c);
      if (s == ipv4::tcp::status::peer_closed && p.empty() && ipv4::tcp::received_length(c) == 0)
      {
        ipv4::tcp::close(c);
        connections.erase(connections.begin() + std::ptrdiff_t(i));
        pending.erase(pending.begin() + std::ptrdiff_t(i));
        ++closed;
        --i;
      }
      else if (s == ipv4::tcp::status::reset || s == ipv4::tcp::status::timed_out)
      {
        ipv4::tcp::close(c);
        connections.erase(connections.begin() + std::ptrdiff_t(i));
        pending.erase(pending.begin() + std::ptrdiff_t(i));
        --i;
      }
    }
  }
};

/// The kernel sends data to the echo server and reads it back at the same
/// time, then closes
bool echo_round_trip(const std::string& ip, std::uint16_t port, std::size_t size, unsigned seed,
                     double* mbps = nullptr)
{
  const int s = kernel_connect(ip, port);
  if (s < 0)
  {
    std::fprintf(stderr, "connect: %s\n", std::strerror(errno));
    return false;
  }

  const bytes data = random_bytes(size, seed);
  const auto  t0   = std::chrono::steady_clock::now();
  bytes       back;

  std::thread reader([&] { back = receive_all(s, size); });
  const bool sent = send_all(s, data);
  reader.join();
  ::shutdown(s, SHUT_WR);

  // The server closes after our FIN: the stream ends
  std::uint8_t b;
  const ssize_t end = ::recv(s, &b, 1, 0);
  ::close(s);

  if (mbps != nullptr)
    *mbps = double(size) * 8 / 1e6 / seconds_since(t0);

  if (!sent || back != data || end != 0)
  {
    std::fprintf(stderr, "sent %d, back %zu of %zu, %s, end %zd\n", int(sent), back.size(),
                 size, back == data ? "equal" : "differs", end);
    return false;
  }
  return true;
}

bool wait_until(const std::function<bool()>& condition, int seconds = 10)
{
  const auto t0 = std::chrono::steady_clock::now();
  while (!condition())
  {
    if (seconds_since(t0) > seconds)
      return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return true;
}

/// After everything closed, every block is back in the pool
bool no_leak(stack_thread& st)
{
  return wait_until([&]
  {
    std::size_t available = 0;
    st.run([&] { available = ipv4::g_packet_pool.available(); });
    return available == ipv4::c_packet_pool_size;
  }, int(ipv4::c_tcp_time_wait / 1000) + 5);
}

// ---- cases ------------------------------------------------------------------------------

void server_echo_stream(tap& t)
{
  stack_thread st(t);
  echo_server  server;
  st.run([&] { server.listeners.push_back(*ipv4::tcp::listen(0, 7000)); });
  st.every_step([&] { server.step(); });

  double mbps = 0;
  PROTOCOL_CHECK(echo_round_trip(t.stack_ip, 7000, 2 * 1024 * 1024, 1, &mbps));
  ipv4::statistics s{};
  st.run([&] { s = ipv4::stats(); });
  std::printf("echo of 2 MB: %.1f Mbit/s each way; retransmitted %u, data refused %u, "
              "rx without a block %u\n", mbps, s.tcp_retransmits, s.tcp_rx_refused, s.rx_no_buffer);

  st.every_step(nullptr);
  PROTOCOL_CHECK(no_leak(st));
}

void server_echo_lossy(tap& t)
{
  stack_thread st(t, 0.03);   // 3 % of the frames lost, both ways
  echo_server  server;
  st.run([&] { server.listeners.push_back(*ipv4::tcp::listen(0, 7000)); });
  st.every_step([&] { server.step(); });

  PROTOCOL_CHECK(echo_round_trip(t.stack_ip, 7000, 512 * 1024, 2));
  std::printf("frames dropped: %zu\n", st.frames_dropped());

  ipv4::statistics s{};
  st.run([&] { s = ipv4::stats(); });
  std::printf("retransmitted: %u, data refused: %u\n", s.tcp_retransmits, s.tcp_rx_refused);
  PROTOCOL_CHECK(s.tcp_retransmits > 0);

  st.every_step(nullptr);
  PROTOCOL_CHECK(no_leak(st));
}

void three_listeners(tap& t)
{
  stack_thread st(t);
  echo_server  server;
  st.run([&]
  {
    for (std::uint16_t port : {7001, 7002, 7003})
      server.listeners.push_back(*ipv4::tcp::listen(0, port));
    PROTOCOL_CHECK(!ipv4::tcp::listen(0, 7001).has_value());     // already
    PROTOCOL_CHECK(!ipv4::tcp::listen(0, 7004).has_value());     // all in use
  });
  st.every_step([&] { server.step(); });

  std::vector<std::thread> clients;
  std::atomic<int>         good{0};
  for (std::uint16_t port : {7001, 7002, 7003})
    clients.emplace_back([&, port] { if (echo_round_trip(t.stack_ip, port, 256 * 1024, port)) ++good; });
  for (auto& c : clients)
    c.join();
  PROTOCOL_CHECK(good == 3);

  st.every_step(nullptr);
  PROTOCOL_CHECK(no_leak(st));
}

void client_stream(tap& t)
{
  stack_thread st(t);

  // The kernel listens
  const int l = kernel_socket();
  const int one = 1;
  ::setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  const sockaddr_in a = socket_address(t.host_ip, 7100);
  PROTOCOL_CHECK(::bind(l, reinterpret_cast<const sockaddr*>(&a), sizeof a) == 0);
  ::listen(l, 1);

  const bytes up   = random_bytes(1024 * 1024, 3);   // stack -> kernel
  const bytes down = random_bytes(512 * 1024, 4);    // kernel -> stack

  std::optional<ipv4::tcp::connection> c;
  st.run([&] { c = ipv4::tcp::connect(0, {to_address(t.host_ip), 7100}); });
  PROTOCOL_CHECK(c.has_value());
  if (!c) return;

  // The stack sends `up` and collects what comes, then closes
  std::size_t        sent = 0;
  bytes              got;
  std::atomic<bool>  closed{false};
  st.every_step([&]
  {
    if (ipv4::tcp::state(*c) == ipv4::tcp::status::connecting)
      return;
    if (sent < up.size())
      sent += ipv4::tcp::send(*c, up.data() + sent, up.size() - sent);
    std::uint8_t buffer[4096];
    while (std::size_t n = ipv4::tcp::receive(*c, buffer, sizeof buffer))
      got.insert(got.end(), buffer, buffer + n);
    if (!closed && sent == up.size() && got.size() == down.size())
    {
      ipv4::tcp::close(*c);
      closed = true;
    }
  });

  const int s = ::accept(l, nullptr, nullptr);
  PROTOCOL_CHECK(s >= 0);
  timeval tv{20, 0};
  ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

  std::thread writer([&] { send_all(s, down); });
  const bytes received = receive_all(s, up.size() + 1);   // up to the end of the stream
  writer.join();

  if (received != up)
  {
    std::size_t sent_now = 0, got_now = 0; ipv4::tcp::status state{}; ipv4::statistics st_now{};
    st.run([&] { sent_now = sent; got_now = got.size(); state = ipv4::tcp::state(*c); st_now = ipv4::stats(); });
    std::fprintf(stderr, "kernel got %zu of %zu; stack sent %zu, got %zu of %zu, state %d, retx %u refused %u no_buffer %u rx_no_buffer %u\n",
                 received.size(), up.size(), sent_now, got_now, down.size(), int(state),
                 st_now.tcp_retransmits, st_now.tcp_rx_refused, st_now.tx_no_buffer, st_now.rx_no_buffer);
  }
  PROTOCOL_CHECK(received == up);
  PROTOCOL_CHECK(wait_until([&] { return closed.load(); }));
  bytes down_copy;
  st.run([&] { down_copy = got; });
  PROTOCOL_CHECK(down_copy == down);

  ::close(s);
  ::close(l);
  st.every_step(nullptr);
  PROTOCOL_CHECK(no_leak(st));
}

void refused_and_reset(tap& t)
{
  stack_thread st(t);

  // Nobody listens: the kernel's connect is refused with a RST
  PROTOCOL_CHECK(kernel_connect(t.stack_ip, 7200) < 0 && errno == ECONNREFUSED);

  // abort() resets an established connection
  std::optional<ipv4::tcp::listener> l;
  st.run([&] { l = ipv4::tcp::listen(0, 7201); });
  const int s = kernel_connect(t.stack_ip, 7201);
  PROTOCOL_CHECK(s >= 0);

  std::optional<ipv4::tcp::connection> c;
  PROTOCOL_CHECK(wait_until([&]
  {
    st.run([&] { if (!c) c = ipv4::tcp::accept(*l); });
    return c.has_value();
  }));
  st.run([&] { ipv4::tcp::abort(*c); });

  std::uint8_t b;
  const ssize_t n = ::recv(s, &b, 1, 0);
  PROTOCOL_CHECK(n < 0 && errno == ECONNRESET);
  ::close(s);

  // A kernel reset is seen by the stack
  const int s2 = kernel_connect(t.stack_ip, 7201);
  std::optional<ipv4::tcp::connection> c2;
  PROTOCOL_CHECK(wait_until([&]
  {
    st.run([&] { if (!c2) c2 = ipv4::tcp::accept(*l); });
    return c2.has_value();
  }));
  linger lg{1, 0};
  ::setsockopt(s2, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
  ::close(s2);   // RST
  PROTOCOL_CHECK(wait_until([&]
  {
    ipv4::tcp::status state{};
    st.run([&] { state = ipv4::tcp::state(*c2); });
    return state == ipv4::tcp::status::reset;
  }));
  st.run([&] { ipv4::tcp::close(*c2); ipv4::tcp::stop(*l); });
  PROTOCOL_CHECK(no_leak(st));
}

struct test_case { std::string_view name; void (*run)(tap&); };

const test_case g_cases[] =
{
  {"tcp_server_echo_stream", server_echo_stream},
  {"tcp_server_echo_lossy",  server_echo_lossy},
  {"tcp_three_listeners",    three_listeners},
  {"tcp_client_stream",      client_stream},
  {"tcp_refused_and_reset",  refused_and_reset},
};

} // namespace

int main(int argc, char** argv)
{
  if (argc < 2)
  {
    for (auto& c : g_cases) std::printf("%.*s\n", int(c.name.size()), c.name.data());
    return 0;
  }

  for (std::size_t i = 0; i < std::size(g_cases); ++i)
  {
    if (g_cases[i].name == argv[1])
    {
      tap t;
      if (!t.open(int(i) + 1))
      {
        std::printf("%s: skipped, no TAP interface (needs CAP_NET_ADMIN)\n", argv[1]);
        return c_skip;
      }
      g_cases[i].run(t);
      return protocol_test::report(argv[1]);
    }
  }

  std::fprintf(stderr, "unknown test case %s\n", argv[1]);
  return 2;
}
