/// \file address.hpp
/// Type definition for ethernet address with stream support for debugging purposes
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

#ifndef PROTOCOL_ETHERNET_HPP
#define PROTOCOL_ETHERNET_HPP

#include <cstdint>
#include <array>

namespace protocol
{

namespace ethernet
{

typedef std::array<uint8_t, 6>    address;

} // namespace ethernet

} // namespace protocol

#ifdef DEBUG

#include <ostream>

inline std::ostream& operator<< (std::ostream& os, const protocol::ethernet::address& a)
{
  os << std::hex << uint32_t(a[0]) 
          << ":" << uint32_t(a[1]) 
          << ":" << uint32_t(a[2]) 
          << ":" << uint32_t(a[3]) 
          << ":" << uint32_t(a[4]) 
          << ":" << uint32_t(a[5]) 
          << std::dec;
  
  return os;
}

#endif

// PROTOCOL_ETHERNET_HPP
#endif 
