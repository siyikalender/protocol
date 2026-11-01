/// \file enet_dma.hpp
/// Zero copy Ethernet driver for Kinetis K60/K64/K66 (ENET) with the
/// MCUXpresso SDK fsl_enet driver (ENET_GetRxFrame / ENET_StartTxFrame),
/// for ipv4::step_dma().
///
/// \code {.cpp}
/// // Build with PROTOCOL_IPV4_PACKET_HEADROOM=0 and a pool large enough for
/// // the rings (see below).
///
/// ipv4::initialize();                   // before ENET_Init arms the RX ring
/// ipv4::set(0, mac, ip);
///
/// enet_config_t config;
/// ENET_GetDefaultConfig(&config);
/// config.miiSpeed  = ...;               // from the PHY, as usual
/// config.miiDuplex = ...;
/// kinetis_enet::init(ENET, config, mac.data(), CLOCK_GetFreq(kCLOCK_CoreSysClk));
///
/// for (;;)
/// {
///   ipv4::step_dma
///   (
///     []                                { return kinetis_enet::receive(); },
///     [](ipv4::packet_id p, auto frame) { return kinetis_enet::transmit(p, frame); },
///     []                                { return kinetis_enet::reclaim(); },
///     []                                { return millis(); }
///   );
/// }
/// \endcode
///
/// Everything runs in the context that calls step_dma(): leave the ENET
/// transmit interrupt off (config.interrupt), so ENET_ReclaimTxDescriptor()
/// is called only from reclaim().
///
/// The receive buffers are the pool's blocks: the SDK takes one from
/// dma::acquire() for every frame it hands over, and drops the frame when
/// there is none (kStatus_ENET_RxFrameDrop), so its ring never runs empty.
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

#ifndef PROTOCOL_EXAMPLES_KINETIS_ENET_DMA_HPP
#define PROTOCOL_EXAMPLES_KINETIS_ENET_DMA_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "fsl_enet.h"

#include "protocol/ipv4/stack.hpp"

#ifndef KINETIS_ENET_RX_DESCRIPTORS
#define KINETIS_ENET_RX_DESCRIPTORS 4
#endif

#ifndef KINETIS_ENET_TX_DESCRIPTORS
#define KINETIS_ENET_TX_DESCRIPTORS 2
#endif

namespace kinetis_enet
{

namespace ipv4 = protocol::ipv4;

constexpr std::size_t c_rx_descriptors = KINETIS_ENET_RX_DESCRIPTORS;
constexpr std::size_t c_tx_descriptors = KINETIS_ENET_TX_DESCRIPTORS;

/// The ENET DMA needs ENET_BUFF_ALIGNMENT aligned buffers whose size is a
/// multiple of it: frames start on the aligned block start
static_assert(ipv4::c_packet_headroom == 0,
              "build with PROTOCOL_IPV4_PACKET_HEADROOM=0 for the ENET DMA");
static_assert(ipv4::c_packet_block_alignment % ENET_BUFF_ALIGNMENT == 0);
static_assert(ipv4::c_packet_block_size % ENET_BUFF_ALIGNMENT == 0);
static_assert(ipv4::c_packet_block_size >= ENET_FRAME_MAX_FRAMELEN,
              "a whole frame must fit one receive buffer");

/// Each RX descriptor always holds a block, each TX descriptor may; one more
/// for the frame being handled plus the transmit reserve
static_assert(ipv4::c_packet_pool_size >=
                c_rx_descriptors + c_tx_descriptors + ipv4::c_tx_reserved_blocks + 1,
              "PROTOCOL_IPV4_PACKET_POOL_SIZE too small for the ENET descriptor rings");

/// Initializes the ENET with the descriptor rings on the packet pool.
/// config: ENET_GetDefaultConfig() with the PHY's speed and duplex; its
/// buffer callbacks and event callback are set here. Call after
/// ipv4::initialize().
status_t init(ENET_Type* base, enet_config_t config, std::uint8_t* mac, std::uint32_t clock_hz);

/// For step_dma()
std::optional<ipv4::rx_frame>   receive();
bool                            transmit(ipv4::packet_id p, std::span<const std::uint8_t> frame);
std::optional<ipv4::packet_id>  reclaim();

} // namespace kinetis_enet

// PROTOCOL_EXAMPLES_KINETIS_ENET_DMA_HPP
#endif
