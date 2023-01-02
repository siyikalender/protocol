/// \file slave.cpp
/// Modbus RTU Slave interface based on "MODBUS over serial line 
/// specification and implementation guide V1.02" Section 2.4.2

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

#ifndef PROTOCOL_MODBUS_SLAVE_HPP
#define PROTOCOL_MODBUS_SLAVE_HPP

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
struct slave
{
private: // Types

  enum class states : uint8_t
  {
    null,
    idle,
    checking_request,
    processing_required_action,
    formatting_reply
  };

public: // Types 

  typedef Controller                    controller;
  typedef typename controller::timer    timer;
  typedef typename controller::buffer   buffer;
  typedef typename timer::duration      duration;

private: // Contants

  struct reception_of_request_bit : bit::field<0> {};
  struct reply_sent_bit           : bit::field<1> {};
  struct is_broadcast_bit         : bit::field<2> {};

  using flags = 
    bit::storage
    <
      bit::pack
      <
        uint8_t,
        reception_of_request_bit,
        reply_sent_bit,
        is_broadcast_bit
      >
    >;

public: // Constructors and Destructor

  slave()
  : current_(states::null),
    address_(1)
  {}
  
  slave(const slave&) = delete;

  slave(slave&& ) = delete;
  
  ~slave() {}

public: // Operator overloads

  template<typename Check, typename Process>
  void operator()(Check p_check, Process p_process)
  {
    auto &b           = controller_.rx_buffer_;
    
    controller_(
      [&]() 
      {
        set_reply_sent();
      },  // emission completed
      [&](bool frame_ok) 
      {
        set_reception_of_request();
        flags_.template assign<is_broadcast_bit>((b.size() > 0) && (b[0] == 0));
      }   // reception completed
    );

    auto g_frame_nok_not_my_msg = [&]() -> bool
    {
      bool p  = (b.size() == 0) || !((b[0] == address_) || test_is_broadcast());
      return !controller_.is_frame_ok() || p;
    };

    switch(current_)
    {
    default:
      current_ = states::idle;
      b.clear();
      break;
    case states::idle:
      if (test_reception_of_request())
      {
        clear_reception_of_request();
        current_ = states::checking_request;
      }
      break;
    case states::checking_request:
      {
        if (g_frame_nok_not_my_msg())
        {
          current_ = states::null;
        }
        else 
        {
          if (!p_check(b)) 
          {
            current_ = (test_is_broadcast()) ? states::null : states::formatting_reply;
          }
          else
          {
            current_ = states::processing_required_action;
          }
        }
      }
      break;
    case states::processing_required_action:
      if (p_process(test_is_broadcast(), b)) 
      {
        current_ = (test_is_broadcast()) ? states::null : states::formatting_reply;
      }
      break;
    case states::formatting_reply:
      if (test_reply_sent())
      {
        clear_reply_sent();
        current_ = states::null;
      }      
      break;
    }
  }

public: // Methods  

  bool send(const uint8_t      p_function,
            const uint8_t*     p_data, 
            const std::size_t  p_size)
  {
    return controller_.send(address_, p_function, p_data, p_size);
  }
  
  void set_address(const uint8_t p_address)
  {
    address_ = p_address;
  }
  
  void clear_counters()
  {
    controller_.clear_counters();
  }
  
  bool is_busy() const
  {
    return (current_ != states::idle);
  }

  states current() const
  {
    return current_;
  }
  
  void reset()
  {
    current_ = states::null;
    address_ = 1;
    flags_   = 0;
    controller_.reset();
  }

  void set_delays(const int32_t p_duration_0c5)
  {
    controller_.set_delays(p_duration_0c5);
  }

private: // Methods

  void set_reception_of_request() 
  {
    flags_.template set<reception_of_request_bit>();
  }
  
  void clear_reception_of_request() 
  {
    flags_.template clear<reception_of_request_bit>();
  }

  bool test_reception_of_request() const
  {
    flags_.template test<reception_of_request_bit>();
  }
  
  void set_reply_sent() 
  {
    flags_.template set<reply_sent_bit>();
  }
  
  void clear_reply_sent() 
  {
    flags_.template clear<reply_sent_bit>();
  }
  
  bool test_reply_sent() const
  {
    return flags_.template test<reply_sent_bit>();
  }
  
  void set_is_broadcast() 
  {
    flags_.template set<is_broadcast_bit>();
  }
  
  void clear_is_broadcast() 
  {
    flags_.template clear<is_broadcast_bit>();
  }
  
  bool test_is_broadcast() const
  {
    return flags_.template test<is_broadcast_bit>();
  }

private: // Members

  states      current_;
  uint8_t     address_;
  flags       flags_;
  controller  controller_;

};

} // namespace rtu

} // namespace modbus

} // namespace protocol

// PROTOCOL_MODBUS_SLAVE_HPP
#endif 
