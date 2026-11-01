/// \file eth_dma.hpp
/// Zero copy Ethernet driver for STM32F7 with the STM32Cube ETH HAL (the
/// HAL_ETH_ReadData / HAL_ETH_RxAllocateCallback driver, not the legacy
/// one), for ipv4::step_dma().
///
/// \code {.cpp}
/// // CubeMX: ETH with heth.Init.RxBuffLen = 1536, descriptors in a non
/// // cacheable region (the usual MPU setup of the Cube examples).
/// // Build with PROTOCOL_IPV4_PACKET_HEADROOM=0 and a pool large enough
/// // for the rings (see below).
///
/// ipv4::initialize();                 // before the descriptors get blocks
/// ipv4::set(0, mac, ip);
/// MX_ETH_Init();                      // HAL_ETH_Init(&heth)
/// stm32f7_eth::attach(heth);
/// HAL_ETH_Start(&heth);               // arms the RX ring from the pool
///
/// for (;;)
/// {
///   ipv4::step_dma
///   (
///     []                                { return stm32f7_eth::receive(); },
///     [](ipv4::packet_id p, auto frame) { return stm32f7_eth::transmit(p, frame); },
///     []                                { return stm32f7_eth::reclaim(); },
///     []                                { return HAL_GetTick(); }
///   );
/// }
/// \endcode
///
/// Everything runs in the context that calls step_dma(): HAL_ETH_Start(),
/// not HAL_ETH_Start_IT(), is enough. If HAL_ETH_ReleaseTxPacket() is also
/// called from an interrupt (HAL_ETH_TxCpltCallback), the queue between the
/// two is single producer / single consumer and stays safe.
///
/// The pool may be cacheable: the driver cleans a block before the DMA
/// reads it and invalidates it before and after the DMA writes it. A non
/// cacheable pool (PROTOCOL_IPV4_PACKET_POOL_ATTRIBUTES) works the same.
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

#ifndef PROTOCOL_EXAMPLES_STM32F7_ETH_DMA_HPP
#define PROTOCOL_EXAMPLES_STM32F7_ETH_DMA_HPP

#include <cstdint>
#include <optional>
#include <span>

#include "stm32f7xx_hal.h"

#include "protocol/ipv4/stack.hpp"

namespace stm32f7_eth
{

namespace ipv4 = protocol::ipv4;

/// Frames start on the aligned block start: the DMA gets aligned buffers
static_assert(ipv4::c_packet_headroom == 0,
              "build with PROTOCOL_IPV4_PACKET_HEADROOM=0 for the STM32F7 DMA");

/// Each RX descriptor always holds a block, each TX descriptor may; one more
/// for the datagram being handled plus the transmit reserve
static_assert(ipv4::c_packet_pool_size >=
                ETH_RX_DESC_CNT + ETH_TX_DESC_CNT + ipv4::c_tx_reserved_blocks + 1,
              "PROTOCOL_IPV4_PACKET_POOL_SIZE too small for the ETH descriptor rings");

/// Hooks the driver to the handle. Call after ipv4::initialize() and
/// HAL_ETH_Init(), before HAL_ETH_Start(). False when heth.Init.RxBuffLen
/// does not fit a block or is too short for a whole frame.
bool attach(ETH_HandleTypeDef& heth);

/// For step_dma()
std::optional<ipv4::rx_frame>   receive();
bool                            transmit(ipv4::packet_id p, std::span<const std::uint8_t> frame);
std::optional<ipv4::packet_id>  reclaim();

} // namespace stm32f7_eth

// PROTOCOL_EXAMPLES_STM32F7_ETH_DMA_HPP
#endif
