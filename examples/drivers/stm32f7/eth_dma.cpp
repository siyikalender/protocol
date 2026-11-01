/// \file eth_dma.cpp
/// Zero copy Ethernet driver for STM32F7 with the STM32Cube ETH HAL
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

#include "eth_dma.hpp"

#include <array>

#include "haluj/ring_buffer.hpp"

namespace stm32f7_eth
{

namespace
{

ETH_HandleTypeDef* g_heth = nullptr;

// Set by the link callback during HAL_ETH_ReadData()
std::uint16_t      g_rx_length  = 0;
bool               g_rx_spanned = false;

// Blocks whose frame was sent, from the TX free callback to reclaim()
haluj::ring_buffer<std::array<ipv4::packet_id, ETH_TX_DESC_CNT>, haluj::spsc> g_tx_done;

// ---- data cache ------------------------------------------------------------
//
// Blocks start on a 32 byte cache line and the DMA part of a block is a
// whole number of lines, so maintaining one block never touches another.

void invalidate(std::span<std::uint8_t> block)
{
#if defined(__DCACHE_PRESENT) && (__DCACHE_PRESENT == 1U)
  SCB_InvalidateDCache_by_Addr(block.data(), static_cast<std::int32_t>(block.size()));
#else
  static_cast<void>(block);
#endif
}

void clean(std::span<const std::uint8_t> frame)
{
#if defined(__DCACHE_PRESENT) && (__DCACHE_PRESENT == 1U)
  SCB_CleanDCache_by_Addr(const_cast<std::uint8_t*>(frame.data()),
                          static_cast<std::int32_t>(frame.size()));
#else
  static_cast<void>(frame);
#endif
}

// ---- HAL callbacks ---------------------------------------------------------

/// The HAL arms an RX descriptor. With no block left (only the transmit
/// reserve) the descriptor stays unarmed and the HAL asks again at the next
/// HAL_ETH_ReadData(); the MAC drops frames meanwhile.
void rx_allocate(std::uint8_t** buffer)
{
  *buffer = nullptr;

  if (auto p = ipv4::dma::acquire())
  {
    auto b = ipv4::dma::receive_buffer(*p);
    invalidate(b);          // no dirty line may be written over the DMA's data
    *buffer = b.data();
  }
}

/// A received buffer. RxBuffLen holds a whole frame, so a frame is one
/// buffer; a frame in several (attach() prevents it) is dropped.
void rx_link(void** start, void** end, std::uint8_t* buffer, std::uint16_t length)
{
  if (*start == nullptr)
  {
    *start       = buffer;
    *end         = buffer;
    g_rx_length  = length;
  }
  else
  {
    if (auto p = ipv4::dma::id_of(buffer))
      ipv4::dma::release(*p);
    g_rx_spanned = true;
  }
}

/// A sent frame: pData of the packet was the frame's address
void tx_free(std::uint32_t* buffer)
{
  if (auto p = ipv4::dma::id_of(buffer))
    g_tx_done.try_push(*p);   // capacity = TX descriptors: never full
}

} // namespace

bool attach(ETH_HandleTypeDef& heth)
{
  const std::size_t room = ipv4::dma::receive_buffer(ipv4::packet_id{}).size();

  // A whole frame with its FCS in one buffer
  if (heth.Init.RxBuffLen > room || heth.Init.RxBuffLen < ipv4::c_max_eth_frame_size + 4)
    return false;

  g_heth = &heth;
  g_tx_done.clear();

#if (USE_HAL_ETH_REGISTER_CALLBACKS == 1)
  HAL_ETH_RegisterRxAllocateCallback(&heth, rx_allocate);
  HAL_ETH_RegisterRxLinkCallback(&heth, rx_link);
  HAL_ETH_RegisterTxFreeCallback(&heth, tx_free);
#endif

  return true;
}

std::optional<ipv4::rx_frame> receive()
{
  // Frames the driver must drop are skipped, so one call still returns
  // the next good frame
  for (std::uint32_t n = 0; n < ETH_RX_DESC_CNT; ++n)
  {
    void* buffer = nullptr;
    g_rx_spanned = false;

    if (HAL_ETH_ReadData(g_heth, &buffer) != HAL_OK)
      return std::nullopt;            // nothing received

    auto p = ipv4::dma::id_of(buffer);

    if (!p)
      continue;                       // not a pool block: cannot happen

    if (g_rx_spanned)
    {
      ipv4::dma::release(*p);
      continue;
    }

    invalidate(ipv4::dma::receive_buffer(*p));   // drop lines the core read ahead
    return ipv4::rx_frame{*p, g_rx_length};
  }

  return std::nullopt;
}

bool transmit(ipv4::packet_id p, std::span<const std::uint8_t> frame)
{
  static_cast<void>(p);
  clean(frame);

  ETH_BufferTypeDef buffer{};
  buffer.buffer = const_cast<std::uint8_t*>(frame.data());
  buffer.len    = static_cast<std::uint32_t>(frame.size());
  buffer.next   = nullptr;

  ETH_TxPacketConfigTypeDef config{};
  config.Attributes   = ETH_TX_PACKETS_FEATURES_CRCPAD;
  config.CRCPadCtrl   = ETH_CRC_PAD_INSERT;
  config.Length       = buffer.len;
  config.TxBuffer     = &buffer;
  config.pData        = buffer.buffer;     // handed back to tx_free()

  // HAL_ERROR with HAL_ETH_ERROR_BUSY: no free descriptor, try again later
  return HAL_ETH_Transmit_IT(g_heth, &config) == HAL_OK;
}

std::optional<ipv4::packet_id> reclaim()
{
  if (g_tx_done.empty())
    HAL_ETH_ReleaseTxPacket(g_heth);

  ipv4::packet_id p;
  if (!g_tx_done.try_pop(p))
    return std::nullopt;
  return p;
}

} // namespace stm32f7_eth

#if (USE_HAL_ETH_REGISTER_CALLBACKS != 1)

// The HAL's weak callbacks, replaced

extern "C" void HAL_ETH_RxAllocateCallback(uint8_t** buff)
{
  stm32f7_eth::rx_allocate(buff);
}

extern "C" void HAL_ETH_RxLinkCallback(void** pStart, void** pEnd, uint8_t* buff, uint16_t Length)
{
  stm32f7_eth::rx_link(pStart, pEnd, buff, Length);
}

extern "C" void HAL_ETH_TxFreeCallback(uint32_t* buff)
{
  stm32f7_eth::tx_free(buff);
}

#endif
