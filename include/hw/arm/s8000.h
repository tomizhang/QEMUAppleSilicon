/*
 * Apple s8000 SoC.
 *
 * Copyright (c) 2023 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2023 Christian Inci (chris-pcguy).
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

#ifndef HW_ARM_S8000_H
#define HW_ARM_S8000_H

#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "exec/memory.h"
#include "hw/arm/apple_a9.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu.h"
#include "hw/boards.h"
#include "hw/cpu/cluster.h"
#include "hw/sysbus.h"
#include "sysemu/kvm.h"
#include "cpu.h"

#define TYPE_S8000 "s8000"

#define TYPE_S8000_MACHINE MACHINE_TYPE_NAME(TYPE_S8000)

#define S8000_MACHINE(obj) \
    OBJECT_CHECK(S8000MachineState, (obj), TYPE_S8000_MACHINE)

typedef struct {
    MachineClass parent;
} S8000MachineClass;

typedef struct {
    MachineState parent;
    hwaddr soc_base_pa;
    hwaddr soc_size;

    unsigned long dram_size;
    AppleA9State *cpus[A9_MAX_CPU];
    CPUClusterState cluster;
    SysBusDevice *aic;
    SysBusDevice *sep;
    MemoryRegion *sysmem;
    MachoHeader64 *kernel, *secure_monitor;
    uint8_t *trustcache;
    DTBNode *device_tree;
    AppleBootInfo bootinfo;
    AppleVideoArgs video;
    char *trustcache_filename;
    char *ticket_filename;
    char *seprom_filename;
    uint32_t build_version;
    uint64_t ecid;
    Notifier init_done_notifier;
    hwaddr panic_base;
    hwaddr panic_size;
    char pmgr_reg[0x100000];
    bool force_dfu;
} S8000MachineState;
#endif
