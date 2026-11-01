/// \file enet_dma.cpp
/// Zero copy Ethernet driver for Kinetis ENET with the MCUXpresso SDK
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

#include "enet_dma.hpp"

#include <array>

#include "haluj/ring_buffer.hpp"

namespace kinetis_enet
{

namespace
{

// Descriptor rings. The Kinetis K cores have no data cache, so ordinary
// RAM works; with a cache they must be in a non cacheable region.
alignas(ENET_BUFF_ALIGNMENT) enet_rx_bd_struct_t g_rx_bd[c_rx_descriptors];
alignas(ENET_BUFF_ALIGNMENT) enet_tx_bd_struct_t g_tx_bd[c_tx_descriptors];
enet_frame_info_t                                g_tx_info[c_tx_descriptors];

enet_handle_t g_handle;
ENET_Type*    g_base = nullptr;

// Blocks whose frame was sent, from the event callback to reclaim()
haluj::ring_buffer<std::array<ipv4::packet_id, c_tx_descriptors>, haluj::spsc> g_tx_done;

// ---- SDK callbacks ---------------------------------------------------------

/// A buffer for an RX descriptor; NULL makes the SDK drop the frame and keep
/// the descriptor's old buffer
void* rx_allocate(ENET_Type*, void*, std::uint8_t)
{
  if (auto p = ipv4::dma::acquire())
    return ipv4::dma::receive_buffer(*p).data();
  return nullptr;
}

/// The SDK gives back a buffer it no longer needs (deinit, broken frame)
void rx_free(ENET_Type*, void* buffer, void*, std::uint8_t)
{
  if (auto p = ipv4::dma::id_of(buffer))
    ipv4::dma::release(*p);
}

/// kENET_TxEvent from ENET_ReclaimTxDescriptor(): context was the frame
#if FSL_FEATURE_ENET_QUEUE > 1
void event(ENET_Type*, enet_handle_t*, std::uint32_t, enet_event_t e,
           enet_frame_info_t* info, void*)
#else
void event(ENET_Type*, enet_handle_t*, enet_event_t e,
           enet_frame_info_t* info, void*)
#endif
{
  if (e == kENET_TxEvent && info != nullptr)
  {
    if (auto p = ipv4::dma::id_of(info->context))
      g_tx_done.try_push(*p);   // capacity = TX descriptors: never full
  }
}

} // namespace

status_t init(ENET_Type* base, enet_config_t config, std::uint8_t* mac, std::uint32_t clock_hz)
{
  g_base = base;
  g_tx_done.clear();

  enet_buffer_config_t buffers{};
  buffers.rxBdNumber          = c_rx_descriptors;
  buffers.txBdNumber          = c_tx_descriptors;
  buffers.rxBuffSizeAlign     = static_cast<std::uint16_t>(ipv4::c_packet_block_size);
  buffers.txBuffSizeAlign     = static_cast<std::uint16_t>(ipv4::c_packet_block_size);
  buffers.rxBdStartAddrAlign  = g_rx_bd;
  buffers.txBdStartAddrAlign  = g_tx_bd;
  buffers.rxBufferAlign       = nullptr;     // from rx_allocate()
  buffers.txBufferAlign       = nullptr;     // the stack's frames
  buffers.rxMaintainEnable    = false;
  buffers.txMaintainEnable    = false;
  buffers.txFrameInfo         = g_tx_info;   // context of the frames being sent

  config.rxBuffAlloc = rx_allocate;
  config.rxBuffFree  = rx_free;
  config.callback    = event;
  config.userData    = nullptr;

  status_t status = ENET_Init(base, &g_handle, &config, &buffers, mac, clock_hz);

  if (status == kStatus_Success)
    status = ENET_SetTxReclaim(&g_handle, true, 0);

  if (status == kStatus_Success)
    ENET_ActiveRead(base);

  return status;
}

std::optional<ipv4::rx_frame> receive()
{
  // Frames the SDK drops (errors, no fresh block) are skipped, so one call
  // still returns the next good frame
  for (std::size_t n = 0; n < c_rx_descriptors; ++n)
  {
    enet_buffer_struct_t   buffer{};
    enet_rx_frame_struct_t frame{};
    frame.rxBuffArray = &buffer;   // a whole frame fits one buffer

    const status_t status = ENET_GetRxFrame(g_base, &g_handle, &frame, 0);

    if (status == kStatus_ENET_RxFrameEmpty)
      return std::nullopt;

    if (status != kStatus_Success)
      continue;                    // kStatus_ENET_RxFrameError / RxFrameDrop

    if (auto p = ipv4::dma::id_of(buffer.buffer))
      return ipv4::rx_frame{*p, frame.totLen};   // the SDK strips the FCS (RCR CRCFWD)
  }

  return std::nullopt;
}

bool transmit(ipv4::packet_id p, std::span<const std::uint8_t> frame)
{
  static_cast<void>(p);

  enet_buffer_struct_t buffer{};
  buffer.buffer = const_cast<std::uint8_t*>(frame.data());
  buffer.length = static_cast<std::uint16_t>(frame.size());

  enet_tx_frame_struct_t tx{};
  tx.txBuffArray = &buffer;
  tx.txBuffNum   = 1;
  tx.context     = buffer.buffer;  // handed back to event()

  // kStatus_ENET_TxFrameBusy: no free descriptor, try again later
  return ENET_StartTxFrame(g_base, &g_handle, &tx, 0) == kStatus_Success;
}

std::optional<ipv4::packet_id> reclaim()
{
  if (g_tx_done.empty())
    ENET_ReclaimTxDescriptor(g_base, &g_handle, 0);

  ipv4::packet_id p;
  if (!g_tx_done.try_pop(p))
    return std::nullopt;
  return p;
}

} // namespace kinetis_enet
