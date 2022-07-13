/// \file bd.cpp
/// Source for buffer descriptors
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

#include "protocol/ipv4/types.hpp"
#include "protocol/ipv4/defs.hpp"

namespace protocol
{

namespace ipv4
{
  
void invalidate_descriptors
(
  buffer_descriptor_container   &descriptors
)
{
  for (auto &d : descriptors)
  {
    d.flags.clear<valid>();
  }
}

void reset_descriptor_ranges
(
  payload_buffer_container      &payload_buffer,
  buffer_descriptor_container   &descriptors
)
{
  auto first = std::begin(payload_buffer);
  auto last  = std::end(payload_buffer);

  for (auto &d : descriptors)
  {
    d.first = first;
    d.last  = last;
    first   = last;
  }
}


buffer_descriptor_ref
find_available_bd
(
  buffer_descriptor_container   &descriptors, 
  const std::size_t             size
)
{
  buffer_descriptor_ref   result;
  
  auto it = 
    std::find_if
    (
      std::begin(descriptors), 
      std::end(descriptors), 
      [&] (buffer_descriptor &e) 
      {
        return
          !e.flags.test<valid>() && 
          (size <= std::distance(e.first, e.last)); 
      }
    );
  
  if (it != std::end(descriptors))
  {
    result = std::ref(*it);
  }
  
  return result;
}

buffer_descriptor_ref
find_prev_neighbour_bd
(
  payload_buffer_container    &payload_buffer,
  buffer_descriptor_container &descriptors,
  buffer_descriptor           &c
)
{
  TRACE( __FUNCTION__ << "\n");

  int     min_dist  = -int(payload_buffer.size());
  
  buffer_descriptor_ref  result;

  for (auto &other : descriptors)
  {
    if (&other != &c)
    {
      auto l = std::distance(c.first, other.last);
      
      TRACE(" -> " << l << "\n");
      
      if (l <= 0 && l > min_dist)
      {
        result    = std::ref(other);
        min_dist  = l;
      }
    }
  }

  TRACE("closest neighbour:" << min_dist << "\n");
  
  return result;
}

buffer_descriptor_ref
find_next_neighbour_bd
(
  payload_buffer_container    &payload_buffer,
  buffer_descriptor_container &descriptors,
  buffer_descriptor           &c
)
{
  TRACE( __FUNCTION__ << "\n");

  int     min_dist  = int(payload_buffer.size());
  
  buffer_descriptor_ref  result;

  for (auto &other : descriptors)
  {
    if (&other != &c)
    {
      auto l = std::distance(c.last, other.first);
      
      TRACE(" -> " << l << "\n");
      
      if (l >= 0 && l <= min_dist)
      {
        result    = std::ref(other);
        min_dist  = l;
      }
    }
  }

  TRACE("closest neighbour:" << min_dist << "\n");
  
  return result;
}

void
adjust_range_next_bd
(
  payload_buffer_container    &payload_buffer,
  buffer_descriptor_container &descriptors,
  buffer_descriptor           &c
)
{
  auto nbd_ref = 
    find_next_neighbour_bd
    (
      payload_buffer,
      descriptors,
      c
    );
    
  if (nbd_ref)
  {
    buffer_descriptor &nbd = *nbd_ref;
    
    TRACE("A\n");
    
    if (!nbd.flags.test<valid>())
    {
      // Only descriptors not valid are modified
      nbd.first = c.last;
      TRACE("B:" << std::distance(nbd.first, nbd.last) << "\n");
    }
  }
  else
  {
    TRACE( "No next neighbour\n" );
  }
}


/// Allocates buffer a buffer descriptor
buffer_descriptor_ref
allocate_bd
(
  payload_buffer_container    &payload_buffer,
  buffer_descriptor_container &descriptors,
  const std::size_t           size
)
{
  buffer_descriptor_ref result;
  
  auto bd_ref = 
    find_available_bd
    (
      descriptors, 
      size
    );

  if (bd_ref)
  {
    buffer_descriptor &bd = *bd_ref;
    
    bd.flags.set<valid>();
    bd.size = size;
    bd.last = bd.first + bd.size; 
    
    TRACE("BD:" 
          << std::hex
          << uintptr_t(bd.first) << " , " 
          << uintptr_t(bd.last) << " , " 
          << std::dec 
          << bd.size << "\n");
  
    adjust_range_next_bd
    (
      payload_buffer, 
      descriptors, 
      bd
    );
    
    result = bd_ref;
  }
  else
  {
    TRACE( "No available Buffer Descriptor\n" );
  }
  return result;
}

} // namespace ipv4

} // namespace protocol

