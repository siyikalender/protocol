// Example compile statement
// g++ -Wall -g -I../../../haluj/include -I../../../bit/include -I../../include  -I../../../include/cpp -DDEBUG -std=c++17 -o ipstack main.cpp ../../src/protocol/ipv4/stack.cpp

#include <iostream>
#include <cstring>
#include <optional>

#include "protocol/ipv4/stack.hpp"

using namespace protocol;

struct packet
{
  std::size_t   size;
  const char    *data;
};

packet g_packets[] =
{
  { // ARP
    60,
    "\xff\xff\xff\xff\xff\xff\xfe\xed\x0b\xad\xbe\xef\x08\x06\x00\x01" \
    "\x08\x00\x06\x04\x00\x01\xc4\x01\x32\x58\x00\x00\x0a\x00\x00\x01" \
    "\xc4\x02\x32\x6b\x00\x00\x0a\x00\x00\x02\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  },
  { // ICMP
    74,
    "\xde\xad\xbe\xef\xfe\xed\xfe\xed\x0b\xad\xbe\xef\x08\x00\x45\x00" \
    "\x00\x3c\xc6\x3e\x00\x00\x80\x01\xf2\xd7\x0a\x00\x00\x01\x0a\x00" \
    "\x00\x02\x08\x00\x42\x5c\x02\x00\x09\x00\x61\x62\x63\x64\x65\x66" \
    "\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76" \
    "\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69"
  },
  { // UDP 55898 -> 8000 "TEST 1\n"
    60,
    "\xdc\x0e\xa1\x1c\x8e\x19\x1c\x6f\x65\x4a\xe2\x0f\x08\x00\x45\x00" \
    "\x00\x23\x92\x92\x40\x00\x40\x11\x94\x35\x0a\x00\x00\x01\x0a\x00" \
    "\x00\x02\xa2\x26\x1f\x40\x00\x0f\x14\x23\x54\x45\x53\x54\x20\x31" \
    "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  },
  { // UDP 55898 -> 8000 "TEST 2\n"
    60,
    "\xdc\x0e\xa1\x1c\x8e\x19\x1c\x6f\x65\x4a\xe2\x0f\x08\x00\x45\x00" \
    "\x00\x23\x83\x34\x40\x00\x40\x11\xa3\x93\x0a\x00\x00\x01\x0a\x00" \
    "\x00\x02\xda\x5a\x1f\x40\x00\x0f\x14\x23\x54\x45\x53\x54\x20\x32"
    "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  },
  { // UDP 55898 -> 8000 "TEST 3\n"
    60,
    "\xdc\x0e\xa1\x1c\x8e\x19\x1c\x6f\x65\x4a\xe2\x0f\x08\x00\x45\x00" \
    "\x00\x23\x83\x35\x40\x00\x40\x11\xa3\x92\x0a\x00\x00\x01\x0a\x00" \
    "\x00\x02\xda\x5a\x1f\x40\x00\x0f\x14\x23\x54\x45\x53\x54\x20\x33"
    "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  },
  { // UDP 55898 -> 8000 "TEST 4\n"
    60,
    "\xdc\x0e\xa1\x1c\x8e\x19\x1c\x6f\x65\x4a\xe2\x0f\x08\x00\x45\x00" \
    "\x00\x23\x83\x36\x40\x00\x40\x11\xa3\x91\x0a\x00\x00\x01\x0a\x00" \
    "\x00\x02\xda\x5a\x1f\x40\x00\x0f\x14\x23\x54\x45\x53\x54\x20\x34"
    "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  }  
};

void step(std::optional<std::size_t> packet_index = std::nullopt)
{
  protocol::ipv4::step
  (
    // Receive Frame Available
    [packet_index]() -> bool 
    {
      return packet_index.has_value();
    },
    // Read
    [packet_index](auto &b, const std::size_t max_size) -> std::size_t 
    {
      std::size_t result = 0;
      if (g_packets[*packet_index].size <= max_size)
      {
        result = g_packets[*packet_index].size;
        std::memcpy(&b[0], g_packets[*packet_index].data, result);
        std::cout << "Read :" << result << " byte(s)\n";
      }
      return result;
    },
    // Write
    [packet_index](auto &b, const std::size_t size) -> std::size_t 
    {
      std::cout << "Write :" << size << " byte(s)\n";
      return size;
    }
  );
}

void test_ip()
{
  ipv4::initialize();
  
  if
  (
    ipv4::set
    (
      0,
      ethernet::address{0xdc, 0x0e, 0xa1, 0x1c, 0x8e, 0x19},
      ipv4::address{10, 0, 0, 2}
    )
  )
  {
    auto &in = protocol::ipv4::g_interfaces[0];
    
    std::cout << "Interface:" << 0 << "\n";
    std::cout << "HW ADDR:" << in.hw_addr << "\n";
    std::cout << "IP ADDR:" << in.ip_addr << "\n";
  }

  uint8_t   paket[2048];
  
  auto &intf = protocol::ipv4::g_interfaces[0];
  std::cout << "============= ARP\n";
  
  step(0);

  // assert

  std::cout << "=============  ICMP\n";

  step(1);

  // assert

  // UDP

  std::cout << "=============  UDP Receive: 1\n";

  auto ed = ipv4::udp::bind(0, 8000);
  
  step(2);

  std::size_t   l;
  uint8_t       buffer[2048];
  ipv4::endpoint remote;
  
  l = ipv4::udp::received_length(ed);

  std:: cout << "=> rx length:" << l << "\n";

  ipv4::udp::receive(ed, buffer, l, remote);

  std:: cout << "-------> send echo\n";
  
  ipv4::udp::send(ed, buffer, l, remote);

  step();
  // assert
  std::cout << "=============  UDP Receive: 2\n";

  step(3);

  l = ipv4::udp::received_length(ed);

  std:: cout << "=> rx length:" << l << "\n";

  ipv4::udp::receive(ed, buffer, l, remote);

  std:: cout << "-------> send echo\n";
  
  ipv4::udp::send(ed, buffer, l, remote);

  step();

  std::cout << "=============  UDP Receive: 3\n";

  step(4);

  l = ipv4::udp::received_length(ed);

  std:: cout << "=> rx length:" << l << "\n";

  ipv4::udp::receive(ed, buffer, l, remote);

  std:: cout << "-------> send echo\n";
  
  ipv4::udp::send(ed, buffer, l, remote);

  step();

  std::cout << "=============  UDP Receive: 4\n";

  step(5);

  l = ipv4::udp::received_length(ed);

  std:: cout << "=> rx length:" << l << "\n";

  ipv4::udp::receive(ed, buffer, l, remote);

  std:: cout << "-------> send echo\n";
  
  ipv4::udp::send(ed, buffer, l, remote);

  step();
}

int main()
{
  test_ip();
  
  return 0;  
}



