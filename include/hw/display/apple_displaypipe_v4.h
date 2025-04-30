/*
 * Apple Display Pipe V4 Controller.
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
#ifndef APPLE_DISPLAYPIPE_V4_H
#define APPLE_DISPLAYPIPE_V4_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/boot.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_DISPLAY_PIPE_V4 "apple-display-pipe-v4"
OBJECT_DECLARE_SIMPLE_TYPE(AppleDisplayPipeV4State, APPLE_DISPLAY_PIPE_V4);

SysBusDevice *adp_v4_create(DTBNode *node, MemoryRegion *dma_mr,
                            AppleVideoArgs *video_args, hwaddr vram_size);

void adp_v4_update_vram_mapping(AppleDisplayPipeV4State *s, MemoryRegion *mr,
                                hwaddr base);

#endif /* APPLE_DISPLAYPIPE_V4_H */
