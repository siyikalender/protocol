/// \file constants.hpp
/// Constant declarations for IPV4 stack implementation
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
#ifndef PROTOCOL_IPV4_CONSTANTS_HPP
#define PROTOCOL_IPV4_CONSTANTS_HPP

#include <cstdint>

namespace protocol
{

namespace ipv4
{

constexpr uint8_t   ICMP = 0x01;
constexpr uint8_t   TCP  = 0x06;
constexpr uint8_t   UDP  = 0x11;

constexpr std::size_t c_min_eth_frame_size      = 60;   // without crc
constexpr std::size_t c_max_eth_frame_size      = 1518; // without crc
constexpr std::size_t c_interface_table_size    = 1;
constexpr std::size_t c_arp_table_size          = 4;
constexpr std::size_t c_udp_ports_table_size    = 8;
constexpr std::size_t c_rx_buffer_size          = 2048U;
constexpr std::size_t c_tx_buffer_size          = 2048U;
constexpr std::size_t c_buffer_descriptor_size  = 4U;

} // namespace ipv4

} // namespace protocol

//  PROTOCOL_IPV4_CONSTANTS_HPP
#endif 
