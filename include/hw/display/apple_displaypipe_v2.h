/*
 * Apple Display Pipe V2 Controller.
 *
 * Copyright (c) 2023-2025 Visual Ehrmanntraut.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_DISPLAY_ADBE_V2_H
#define HW_DISPLAY_ADBE_V2_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/boot.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/sysbus.h"

#define TYPE_APPLE_DISPLAY_PIPE_V2 "apple-display-pipe-v2"
OBJECT_DECLARE_SIMPLE_TYPE(AppleDisplayPipeV2State, APPLE_DISPLAY_PIPE_V2);

SysBusDevice *adp_v2_create(DTBNode *node, MemoryRegion *dma_mr,
                            AppleVideoArgs *video_args, uint64_t vram_size);
void adp_v2_update_vram_mapping(AppleDisplayPipeV2State *s, MemoryRegion *mr,
                                hwaddr base);

#endif /* HW_DISPLAY_ADBE_V2_H */
