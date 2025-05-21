/*
 * Copyright (c) 2017, Impinj, Inc.
 * Copyright (c) 2025 Christian Inci (chris-pcguy).
 *
 * Apple PCIe IP block emulation
 * Frankenstein's monster built from gutted designware/xiling
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
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef APCIE_H
#define APCIE_H

#include "hw/arm/apple-silicon/dtb.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pcie_host.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_PCIE_ROOT_BUS "apple-pcie-root-BUS"
OBJECT_DECLARE_SIMPLE_TYPE(ApplePCIERootBus, APPLE_PCIE_ROOT_BUS)

#define TYPE_APPLE_PCIE_HOST "apple-pcie-host"
OBJECT_DECLARE_SIMPLE_TYPE(ApplePCIEHost, APPLE_PCIE_HOST)

#define TYPE_APPLE_PCIE_ROOT "apple-pcie-root"
OBJECT_DECLARE_SIMPLE_TYPE(ApplePCIERoot, APPLE_PCIE_ROOT)

#define TYPE_APPLE_PCIE "apple-pcie"
OBJECT_DECLARE_SIMPLE_TYPE(ApplePCIEState, APPLE_PCIE)

// sizes: s8000 == 0x8000 ; t8030 == 0x4000
#define APCIE_COMMON_REGS_LENGTH 0x8000

struct ApplePCIERootBus {
    PCIBus parent;
};

#if 0
typedef struct ApplePCIEMSIBank {
    uint32_t enable;
    uint32_t mask;
    uint32_t status;
} ApplePCIEMSIBank;

typedef struct ApplePCIEMSI {
    uint64_t     base;
    MemoryRegion iomem;

#define APPLE_PCIE_NUM_MSI_BANKS 1

    ApplePCIEMSIBank intr[APPLE_PCIE_NUM_MSI_BANKS];
} ApplePCIEMSI;
#endif

struct ApplePCIERoot {
    PCIBridge parent_obj;

    MemoryRegion cfg;
    MemoryRegion common;
    MemoryRegion phy;
#if 0
    ApplePCIEMSI msi;
#endif
    uint32_t phy_enabled;
    uint32_t common_regs[APCIE_COMMON_REGS_LENGTH / sizeof(uint32_t)];
};

struct ApplePCIEHost {
    PCIExpressHost parent_obj;

    ApplePCIERoot root;
#if 0
    PCIExpLinkSpeed speed;
    PCIExpLinkWidth width;
#endif
    MemoryRegion mmio, io;
    qemu_irq irq;
    char bus_path[8];
    char name[16];

    uint32_t bus_nr;
    uint32_t clkreq_gpio_id;
    uint32_t clkreq_gpio_value;
    uint32_t device_id;
};

struct ApplePCIEState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    DTBNode *node;

    qemu_irq irqs[4];
    qemu_irq msi;

    ApplePCIEHost *pcie[4];
};

SysBusDevice *apple_pcie_create(DTBNode *node);

#endif /* APCIE_H */
