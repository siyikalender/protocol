/// \file controller.cpp
/// Modbus RTU Controller based on "MODBUS over serial line 
/// specification and implementation guide V1.02" - Figure 14

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

#ifndef PROTOCOL_MODBUS_CONTROLLER_HPP
#define PROTOCOL_MODBUS_CONTROLLER_HPP

#include <cstdint>
#include <algorithm>

#include "crc_ccitt.hpp"

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
  typename     HalfDuplexSerialDevice,
  typename     Timer,
  typename     Buffer
>
struct controller
{
private: // Types

  enum class states : uint8_t
  {
    null,
    initial_state,
    idle,
    reception,
    control_and_wait,
    emission
  };

public: // Types  

  typedef Timer                       timer;    
  typedef typename Timer::duration    duration;
  typedef HalfDuplexSerialDevice      serial_device;
  typedef Buffer                      buffer;

  enum diagnostic_counters
  {
    cpt_1,
    cpt_2,
    cpt_3,
    cpt_4,
    cpt_5,
    cpt_6,
    cpt_7,
    cpt_8,
    number_of_counters
  };

private: // Constants
  
  struct frame_ok_bit           : bit::field<0> {};
  struct demand_of_emission_bit : bit::field<1> {};
  struct emission_timer_bit     : bit::field<2> {};
  
  using flags = 
    bit::storage
    <
      bit::pack
      <
        uint8_t,
        frame_ok_bit,
        demand_of_emission_bit,
        emission_timer_bit
      >
    >;  

public: // Constructors and Destructor

  controller()
  : current_(states::null)
  {}
  
  controller(const controller&) = delete;

  controller(controller&& )     = delete;      
  
public: // Operator overloads
  
  template
  <
    typename EmissionCompleted,
    typename ReceptionCompleted
  >
  void operator()
  (
    EmissionCompleted   ec, 
    ReceptionCompleted  rc
  )
  {
    using namespace haluj;
    
    auto bounded_push_back = [](buffer &b, const uint8_t c) -> bool
    {
      bool result = false;
      
      if (b.size() < b.capacity())
      {
        b.push_back(c);
        result = true;
      }
      
      return result;
    };
    
    auto append_rx = [&](const uint8_t c)
    {
      if (!bounded_push_back(rx_buffer_, c))
      {
        counters[cpt_8]++;
      }
      else
      {
        auto sz = rx_buffer_.size();
        if (sz >= 3)
        {
          crc.process_byte(rx_buffer_[sz - 3]);
        }
      }
    };
    
    auto e_initial_state = [&]()
    {
      timer_.set(duration_3c5_);
      flags_ = 0;
      serial_device_.enable_rx();
    };
    
    auto a_initial_state = [&]()
    {
      if (serial_device_.is_rx_available())
      {
        (void) serial_device_.read(); // dummy read
        timer_.set(duration_3c5_);
      }
    };

    auto e_emission =  [&]()
    {
      crc.reset();
      clear_demand_of_emission();
      tx_index_ = 0;
      serial_device_.enable_tx();
    };
    
    auto a_emission =  [&]()
    {
      if (serial_device_.is_tx_ready())
      {
        auto sz = tx_buffer_.size();
        if (tx_index_ < sz && tx_index_ < tx_buffer_.capacity())
        {
          uint8_t c = tx_buffer_[tx_index_];
          serial_device_.write(c);
          if (tx_index_ < (sz - 2))
          {
            crc.process_byte(c);
          }
          tx_index_++;
          if (tx_index_ == (sz - 2))
          {
            tx_buffer_[tx_index_] = crc.crc_lo;
          }
          else if (tx_index_ == (sz - 1))
          {
            tx_buffer_[tx_index_] = crc.crc_hi;
          }
        }
        else
        {
          if (!test_emission_timer())
          {
            set_emission_timer();
            timer_.set(duration_3c5_);
          }
        }
      }
      else
      {}
    };

    auto l_emission =  [&]()
    {
      clear_emission_timer();
      serial_device_.enable_rx();
    };
    
    auto e_reception = [&]()
    {
      crc.reset();
      rx_buffer_.clear();
      bounded_push_back(rx_buffer_, serial_device_.read());
      timer_.set(duration_1c5_);
      clear_frame_ok();      
    };
    
    auto a_reception = [&]()
    {
      if (serial_device_.is_error())
      {
        serial_device_.clear_errors();
        counters[cpt_2]++;
      }
      else if (serial_device_.is_rx_available())
      {
        append_rx(uint8_t(serial_device_.read()));
        timer_.set(duration_1c5_);
      }
    };
    
    auto e_control_and_wait = [&]()
    {
      auto sz = rx_buffer_.size();
      
      if (sz >= 2)
      {
        auto crc_l  = rx_buffer_[sz - 2];
        auto crc_h  = rx_buffer_[sz - 1];

        auto rcv_crc = 
          crc_ccitt::value_type(crc_l) | 
          ( crc_ccitt::value_type(crc_h) << 8 );
        
        if (crc() == rcv_crc)
        {
          set_frame_ok();
          counters[cpt_1]++;
        }
        else
        {
          counters[cpt_2]++;
        }
      }
      else
      {
        counters[cpt_2]++;
      }
      
      timer_.set(duration_3c5_ - duration_1c5_);
    };
    
    auto a_control_and_wait = [&]()
    {
      if (serial_device_.is_rx_available())
      {
        clear_frame_ok();
      }
    };
    
    // Guards
    
    switch(current_)
    {
    default:
      current_ = states::initial_state;
      e_initial_state();
      break;
    case states::initial_state:
      a_initial_state();
      if ( timer_() ) 
      { 
        current_ = states::idle; 
      }
      break;
    case states::idle:
      if (test_demand_of_emission())
      {
        current_ = states::emission;
        e_emission();
      }
      else if (serial_device_.is_error())
      {
        serial_device_.clear_errors();
        counters[cpt_2]++;
      }
      else if ( serial_device_.is_rx_available() )
      {
        current_ = states::reception;
        e_reception();
      }
      break;
    case states::reception:
      a_reception();
      if ( timer_() ) 
      { 
        current_ = states::control_and_wait; 
        e_control_and_wait();
      }
      break;
    case states::control_and_wait:
      a_control_and_wait();
      if ( timer_() ) 
      { 
        rc(test_frame_ok());
        current_ = states::idle; 
      }
      break;
    case states::emission:
      a_emission();
      if ( timer_() ) 
      { 
        l_emission();
        ec();
        current_ = states::idle; 
      }
      break;
    }
  }

public: // Methods

  states current() const
  {
    return current_;
  }

  bool send(const uint8_t      p_slave_address,
            const uint8_t      p_function,
            const uint8_t*     p_data, 
            const std::size_t  p_size)
  {
    using namespace haluj;    
    
    bool result = false;
    
    if (p_size <= (tx_buffer_.capacity() - 4U))
    {
      tx_buffer_.clear();
      
      tx_buffer_.push_back(p_slave_address);
      tx_buffer_.push_back(p_function);
      
      for (std::size_t i = 0; i < p_size; i++)
      {
       tx_buffer_.push_back(*(p_data + i));
      }
      
      tx_buffer_.push_back(uint8_t(0));
      tx_buffer_.push_back(uint8_t(0));

      set_demand_of_emission();
      
      result = true;
    }
    
    return result;
  }    
  
  void set_delays(const int32_t p_duration_0c5)
  {
    duration_1c5_ = p_duration_0c5 * 3;
    duration_3c5_ = p_duration_0c5 * 7;
  } 

  bool is_busy() const
  {
    return current_ != states::idle;
  }
  
  bool is_frame_ok() const
  {
    return test_frame_ok();
  }
  
  void clear_counters()
  {
    std::fill_n(&counters[0], number_of_counters, 0);
  }
  
  void reset()
  {
    current_ = states::null;
  }
  
private: // Methods  
  
  void set_demand_of_emission()
  {
    flags_.template set<demand_of_emission_bit>();
  }

  void clear_demand_of_emission()
  {
    flags_.template clear<demand_of_emission_bit>();    
  }
  
  bool test_demand_of_emission() const
  {
    flags_.template test<demand_of_emission_bit>();    
  }
  
  void set_frame_ok()
  {
    flags_.template set<frame_ok_bit>();
  }

  void clear_frame_ok()
  {
    flags_.template clear<frame_ok_bit>();
  }
  
  bool test_frame_ok() const
  {
    return flags_.template test<frame_ok_bit>();
  }

  void set_emission_timer()
  {
    flags_.template set<emission_timer_bit>();
  }

  void clear_emission_timer()
  {
    flags_.template clear<emission_timer_bit>();
  }
  
  bool test_emission_timer() const
  {
    return flags_.template test<emission_timer_bit>();
  }

public: // Members

  serial_device                   serial_device_;
  flags                           flags_;
  states                          current_;
  crc_ccitt                       crc;
  uint32_t                        tx_index_;
  buffer                          rx_buffer_;
  buffer                          tx_buffer_;
  timer                           timer_;
  duration                        duration_1c5_;
  duration                        duration_3c5_;
  uint16_t                        counters[number_of_counters];

};

} // namespace rtu

} // namespace modbus

} // namespace protocol

// PROTOCOL_MODBUS_CONTROLLER_HPP
#endif 
