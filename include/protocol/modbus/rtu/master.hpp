/// \file master.cpp
/// Modbus RTU Master interface based on "MODBUS over serial line 
/// specification and implementation guide V1.02" Section 2.4.1

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
/// \date   2018

#ifndef PROTOCOL_MODBUS_MASTER_HPP
#define PROTOCOL_MODBUS_MASTER_HPP

#include <cstdint>

#include <bit/field.hpp>
#include <bit/pack.hpp>
#include <bit/storage.hpp>

namespace protocol
{
 
namespace modbus
{
  
namespace rtu
{  

template
<
  typename      Controller
>
struct master
{
private: // Types

  enum class states : uint8_t
  {
    null,
    idle,
    waiting_turnaround_delay,
    waiting_for_reply,
    processing
  };

public: // Types

  typedef Controller                    controller;
  typedef typename controller::timer    timer;
  typedef typename controller::buffer   buffer;
  typedef typename timer::duration      duration;

private: // Constants

  struct broadcast_bit      : bit::field<0> {};
  struct unicast_bit        : bit::field<1> {};
  struct received_reply_bit : bit::field<2> {};
  struct error_bit          : bit::field<3> {};
  
  using flags = 
    bit::storage
    <
      bit::pack
      <
        uint8_t,
        broadcast_bit,
        unicast_bit,
        received_reply_bit,
        error_bit
      >
    >;

public:  // Constants
  
  static constexpr int32_t c_default_wait_turnaround = 100000;  // in ticks
  static constexpr int32_t c_default_wait_reply      = 2000000; // in ticks

public: // Constructors and Destructor
  
  master()
  : current_(states::null),
    active_address_(0),
    duration_wait_reply_(c_default_wait_reply),
    duration_wait_turnaround_(c_default_wait_turnaround)
  {}
  
  master(const master&) = delete;

  master(master&& ) = delete;
  
  ~master() {}
  
public: // Operator overloads
  
  template<typename Process, typename Timeout>
  void operator()(Process  process, Timeout timeout)
  {
    using namespace haluj;    
    
    auto &b           = controller_.rx_buffer_;      
    
    controller_(
      [&]() {
        if (active_address_ == 0)
        {
          set_broadcast();
          timer_.set(duration_wait_turnaround_);
        } 
        else
        {
          set_unicast();
          timer_.set(duration_wait_reply_);
        }
      },  // emission completed
      [&](bool frame_ok) {
        set_received_reply();
      }
    );      
    
    auto g_end_of_processing = [&]() -> bool
    {
      return process(!controller_.is_frame_ok() || test_error(), b); // frame_ok
    };
    
    switch(current_)
    {
    default:
      current_ = states::idle;
      b.clear();
      break;
    case states::idle:
      clear_error();
      if (test_broadcast())
      {
        clear_broadcast();
        current_ = states::waiting_turnaround_delay;
      }
      else if (test_unicast())
      {
        clear_unicast();
        current_ = states::waiting_for_reply;
      }
      break;
    case states::waiting_turnaround_delay:
      if(timer_(1, one_shot()))
      {
        timeout();
        current_ = states::null;
      }
      break;
    case states::waiting_for_reply:
      if (timer_())
      {
        set_error();
        current_ = states::processing; 
      }
      else if (test_received_reply())
      {
        clear_received_reply();
        current_ = states::processing;
      }
      
      break;
    case states::processing:
      if (g_end_of_processing())
      {
        current_ = states::null;
      }
      break;
    }
  }

public: // Methods

  bool is_busy() const
  {
    return controller_.is_busy() && current() != states::idle;
  }

  states current() const
  {
    return current_;
  }
  
  bool send(const uint8_t      p_slave_address,
            const uint8_t      p_function,
            const uint8_t*     p_data, 
            const std::size_t  p_size)
  {
    active_address_ = p_slave_address;
    return controller_.send(p_slave_address, p_function, p_data, p_size);
  }    

  void clear_counters()
  {
    controller_.clear_counters();
  }
  
  void reset()
  {
    current_                  = states::null;
    active_address_           = 0;
    flags_                    = 0;
    duration_wait_reply_      = c_default_wait_reply;
    duration_wait_turnaround_ = c_default_wait_turnaround;
    controller_.reset();
  }

  void set_delays(const int32_t p_wait_reply,
                  const int32_t p_wait_turnaround,
                  const int32_t p_duration_0c5)
  {
    duration_wait_reply_      = p_wait_reply;
    duration_wait_turnaround_ = p_wait_turnaround;
    controller_.set_delays(p_duration_0c5);
  }

private: // Methods

  void set_broadcast() 
  {
    flags_.template set<broadcast_bit>();
  }
  
  void clear_broadcast() 
  {
    flags_.template clear<broadcast_bit>();
  }

  bool test_broadcast() const
  {
    return flags_.template test<broadcast_bit>();
  }
  
  void set_unicast() 
  {
    flags_.template set<unicast_bit>();
  }
  
  void clear_unicast() 
  {
    flags_.template clear<unicast_bit>();
  }
  
  bool test_unicast() const
  {
    return flags_.template test<unicast_bit>();
  }

  void set_received_reply() 
  {
    flags_.template set<received_reply_bit>();
  }
  
  void clear_received_reply() 
  {
    flags_.template clear<received_reply_bit>();
  }
  
  bool test_received_reply() const
  {
    return flags_.template test<received_reply_bit>();
  }

  void set_error() 
  {
    flags_.template set<error_bit>();
  }
  
  void clear_error() 
  {
    flags_.template clear<error_bit>();
  }
  
  bool test_error() const
  {
    return flags_.template test<error_bit>();
  }

private: // Members

  states        current_;
  uint8_t       active_address_;
  flags         flags_;
  duration      duration_wait_reply_;
  duration      duration_wait_turnaround_;
  controller    controller_;
  timer         timer_;

};

} // namespace rtu

} // namespace modbus

} // namespace protocol

// PROTOCOL_MODBUS_MASTER_HPP
#endif 
