/*
 * Copyright (c) 2018, Impinj, Inc.
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

#include "qemu/osdep.h"
#include "hw/pci/msi.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "hw/irq.h"
#include "hw/pci-host/apcie.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/pcie_port.h"
#include "hw/qdev-properties.h"

// #define DEBUG_APCIE

#ifdef DEBUG_APCIE
#define DPRINTF(fmt, ...)                             \
    do {                                              \
        qemu_log_mask(LOG_UNIMP, fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define DPRINTF(fmt, ...) \
    do {                  \
    } while (0)
#endif

#if 0
#define APPLE_PCIE_PORT_LINK_CONTROL 0x710
#define APPLE_PCIE_PHY_DEBUG_R1 0x72C
#define APPLE_PCIE_PHY_DEBUG_R1_XMLH_LINK_UP BIT(4)
#define APPLE_PCIE_LINK_WIDTH_SPEED_CONTROL 0x80C
#define APPLE_PCIE_PORT_LOGIC_SPEED_CHANGE BIT(17)
#define APPLE_PCIE_MSI_ADDR_LO 0x820
#define APPLE_PCIE_MSI_ADDR_HI 0x824
#define APPLE_PCIE_MSI_INTR0_ENABLE 0x828
#define APPLE_PCIE_MSI_INTR0_MASK 0x82C
#define APPLE_PCIE_MSI_INTR0_STATUS 0x830
#endif

static ApplePCIEHost *apple_pcie_root_to_host(ApplePCIERoot *root)
{
    BusState *bus = qdev_get_parent_bus(DEVICE(root));
    return APPLE_PCIE_HOST(bus->parent);
}

#if 0
static uint64_t apple_pcie_root_msi_read(void *opaque, hwaddr addr,
                                              unsigned size)
{
    /*
     * Attempts to read from the MSI address are undefined in
     * the PCI specifications. For this hardware, the datasheet
     * specifies that a read from the magic address is simply not
     * intercepted by the MSI controller, and will go out to the
     * AHB/AXI bus like any other PCI-device-initiated DMA read.
     * This is not trivial to implement in QEMU, so since
     * well-behaved guests won't ever ask a PCI device to DMA from
     * this address we just log the missing functionality.
     */
    DPRINTF("%s not implemented\n", __func__);
    return 0;
}

static void apple_pcie_root_msi_write(void *opaque, hwaddr addr,
                                           uint64_t data, unsigned size)
{
    ApplePCIERoot *root = APPLE_PCIE_ROOT(opaque);
    ApplePCIEHost *host = apple_pcie_root_to_host(root);

    root->msi.intr[0].status |= BIT(data) & root->msi.intr[0].enable;

    if (root->msi.intr[0].status & ~root->msi.intr[0].mask) {
        qemu_set_irq(host->pci.msi, 1);
    }
}

static const MemoryRegionOps apple_pcie_host_msi_ops = {
    .read = apple_pcie_root_msi_read,
    .write = apple_pcie_root_msi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void apple_pcie_root_update_msi_mapping(ApplePCIERoot *root)

{
    MemoryRegion *mem   = &root->msi.iomem;
    const uint64_t base = root->msi.base;
    const bool enable   = root->msi.intr[0].enable;

    memory_region_set_address(mem, base);
    memory_region_set_enabled(mem, enable);
}
#endif

static uint32_t apple_pcie_root_config_read(PCIDevice *d, uint32_t addr,
                                            int size)
{
    ApplePCIERoot *root = APPLE_PCIE_ROOT(d);
    // ApplePCIEViewport *viewport = apple_pcie_root_get_current_viewport(root);
    ApplePCIEHost *host = apple_pcie_root_to_host(root);

    uint32_t val = 0;

// #ifdef ENABLE_CPU_DUMP_STATE
#if 1
    // cpu_dump_state(CPU(s->cpu), stderr, CPU_DUMP_CODE);
#endif

    switch (addr) {
#if 0
    case APPLE_PCIE_PORT_LINK_CONTROL:
        /*
         * Linux guest uses this register only to configure number of
         * PCIE lane (which in our case is irrelevant) and doesn't
         * really care about the value it reads from this register
         */
        val = 0xDEADBEEF;
        break;

    case APPLE_PCIE_LINK_WIDTH_SPEED_CONTROL:
        /*
         * To make sure that any code in guest waiting for speed
         * change does not time out we always report
         * PORT_LOGIC_SPEED_CHANGE as set
         */
        val = APPLE_PCIE_PORT_LOGIC_SPEED_CHANGE;
        break;

    case APPLE_PCIE_MSI_ADDR_LO:
        val = root->msi.base;
        break;

    case APPLE_PCIE_MSI_ADDR_HI:
        val = root->msi.base >> 32;
        break;

    case APPLE_PCIE_MSI_INTR0_ENABLE:
        val = root->msi.intr[0].enable;
        break;

    case APPLE_PCIE_MSI_INTR0_MASK:
        val = root->msi.intr[0].mask;
        break;

    case APPLE_PCIE_MSI_INTR0_STATUS:
        val = root->msi.intr[0].status;
        break;

    case APPLE_PCIE_PHY_DEBUG_R1:
        val = APPLE_PCIE_PHY_DEBUG_R1_XMLH_LINK_UP;
        break;
#endif
#if 0
    case 0x2c:
        // TODO: maybe return offset 0x4 value, or is it just coincidentally the same?
        val = 0x11;
        break;
#endif

#if 0
    case 0x12c:
        val = 0x1;
        break;
#endif

    default:
        val = pci_default_read_config(d, addr, size);
        break;
    }

    DPRINTF("%s: READ @ 0x%x value: 0x%x"
            "\n",
            __func__, addr, val);
    return val;
}

static void machine_set_gpio(int interrupt_num, int level)
{
    DeviceState *gpio;
    gpio = DEVICE(object_property_get_link(OBJECT(qdev_get_machine()), "gpio",
                                           &error_fatal));

    DPRINTF("%s: called with interrupt_num 0x%x/%u level %u\n", __func__,
            interrupt_num, interrupt_num, level);
    qemu_set_irq(qdev_get_gpio_in(gpio, interrupt_num), level);
}

static void apple_pcie_root_config_write(PCIDevice *d, uint32_t addr,
                                         uint32_t data, int size)
{
    ApplePCIERoot *root = APPLE_PCIE_ROOT(d);
    ApplePCIEHost *host = apple_pcie_root_to_host(root);

    DPRINTF("%s: WRITE @ 0x%x value: 0x%x"
            "\n",
            __func__, addr, data);
    switch (addr) {
#if 0
    case APPLE_PCIE_PORT_LINK_CONTROL:
    case APPLE_PCIE_LINK_WIDTH_SPEED_CONTROL:
    case APPLE_PCIE_PHY_DEBUG_R1:
        /* No-op */
        break;

    case APPLE_PCIE_MSI_ADDR_LO:
        root->msi.base &= 0xFFFFFFFF00000000ULL;
        root->msi.base |= data;
        apple_pcie_root_update_msi_mapping(root);
        break;

    case APPLE_PCIE_MSI_ADDR_HI:
        root->msi.base &= 0x00000000FFFFFFFFULL;
        root->msi.base |= (uint64_t)data << 32;
        apple_pcie_root_update_msi_mapping(root);
        break;

    case APPLE_PCIE_MSI_INTR0_ENABLE:
        root->msi.intr[0].enable = data;
        apple_pcie_root_update_msi_mapping(root);
        break;

    case APPLE_PCIE_MSI_INTR0_MASK:
        root->msi.intr[0].mask = data;
        break;

    case APPLE_PCIE_MSI_INTR0_STATUS:
        root->msi.intr[0].status ^= data;
        if (!root->msi.intr[0].status) {
            qemu_set_irq(host->pci.msi, 0);
        }
        break;
#endif
#if 1
    case 0xa0:
        if (data == 0x2) {
#if 1
            if (host->clkreq_gpio_id != 0) {
                machine_set_gpio(host->clkreq_gpio_id, host->clkreq_gpio_value);
            }
#endif
        }
        break;
#endif

    default:
        // pci_bridge_write_config(d, addr, data, size);
        break;
    }
    pci_bridge_write_config(d, addr, data, size);
}

static uint64_t apple_pcie_root_data_access(void *opaque, hwaddr addr,
                                            uint64_t *data, unsigned size)
{
    ApplePCIERoot *root = opaque;
    hwaddr orig_addr = addr;

    uint8_t busnum = 0;
    uint8_t devfn = 0;
    devfn = addr / 0x8000;
    busnum = devfn / PCI_SLOT_MAX;
    devfn %= PCI_SLOT_MAX;
    PCIBus *pcibus = pci_get_bus(PCI_DEVICE(root));
    PCIDevice *pcidev = pci_find_device(pcibus, busnum, devfn);

    if (pcidev) {
        addr &= pci_config_size(pcidev) - 1;

        if (data) {
            pci_host_config_write_common(pcidev, addr, pci_config_size(pcidev),
                                         *data, size);
            DPRINTF("%s: test0 orig_addr == 0x" HWADDR_FMT_plx
                    " ; size %u ; write 0x" HWADDR_FMT_plx "\n",
                    __func__, orig_addr, size, *data);
        } else {
            uint64_t ret = pci_host_config_read_common(
                pcidev, addr, pci_config_size(pcidev), size);
            DPRINTF("%s: test0 orig_addr == 0x" HWADDR_FMT_plx
                    " ; size %u ; read 0x" HWADDR_FMT_plx "\n",
                    __func__, orig_addr, size, ret);
            return ret;
        }
    }

    return UINT64_MAX;
}

static uint64_t apple_pcie_root_data_read(void *opaque, hwaddr addr,
                                          unsigned size)
{
    return apple_pcie_root_data_access(opaque, addr, NULL, size);
}

static void apple_pcie_root_data_write(void *opaque, hwaddr addr, uint64_t data,
                                       unsigned size)
{
    apple_pcie_root_data_access(opaque, addr, &data, size);
}

static const MemoryRegionOps apple_pcie_host_conf_ops = {
    .read = apple_pcie_root_data_read,
    .write = apple_pcie_root_data_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};


static uint64_t apple_pcie_host_common_read(void *opaque, hwaddr addr,
                                            unsigned int size)
{
#if 0
    PCIHostState *pci = PCI_HOST_BRIDGE(opaque);
    PCIDevice *device = pci_find_device(pci->bus, 0, 0);
    DPRINTF("%s: test0 addr == 0x" HWADDR_FMT_plx "\n", __func__, addr);

    return pci_host_config_read_common(device, addr, pci_config_size(device), size);
#endif
    ApplePCIERoot *root = opaque;
    ApplePCIEHost *host = apple_pcie_root_to_host(root);
    uint32_t val = 0;

    switch (addr) {
    // case 0x0:
    //     break;
    case 0x28:
        val = 0x10; // refclk good ; for T8030
        break;
    default:
        // val = 0;
        val = root->common_regs[addr >> 2];
        break;
    }

    DPRINTF("%s: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, addr, val);
    return val;
}

static void apple_pcie_host_common_write(void *opaque, hwaddr addr,
                                         uint64_t data, unsigned int size)
{
#if 0
    PCIHostState *pci = PCI_HOST_BRIDGE(opaque);
    PCIDevice *device = pci_find_device(pci->bus, 0, 0);

    return pci_host_config_write_common(device, addr, pci_config_size(device), data, size);
#endif
    ApplePCIERoot *root = opaque;
    ApplePCIEHost *host = apple_pcie_root_to_host(root);

    DPRINTF("%s: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx "\n",
            __func__, addr, data);
    switch (addr) {
    // case 0x0:
    //     break;
    case 0x4:
        if (data == 0x11) {
            root->common_regs[0x114 >> 2] = 0x100;
            root->common_regs[0x2c >> 2] = 0x11; // for S8000/N66AP
            root->common_regs[0x12c >> 2] =
                0x1; // for S8000/N66AP, mayber lower for S8003, dunno.
#if 0
            if (host->clkreq_gpio_id != 0) {
                machine_set_gpio(host->clkreq_gpio_id, host->clkreq_gpio_value);
            }
#endif
        }
        break;
    case 0x114:
        if (data == 0x101) {
            ////root->common_regs[0x2c >> 2] = 0x11; // for S8003/N66mAP
        }
        break;
    default:
        break;
    }
    root->common_regs[addr >> 2] = data;
}

static const MemoryRegionOps apple_pcie_host_common_ops = {
    .read       = apple_pcie_host_common_read,
    .write      = apple_pcie_host_common_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
        .unaligned = false,
    },
};

static uint64_t apple_pcie_root_host_phy_read(void *opaque, hwaddr addr,
                                              unsigned size)
{
    ApplePCIERoot *root = opaque;
    ApplePCIEHost *host = apple_pcie_root_to_host(root);
    uint32_t val = 0;

// #ifdef ENABLE_CPU_DUMP_STATE
#if 0
    cpu_dump_state(CPU(first_cpu), stderr, CPU_DUMP_CODE);
#endif

    switch (addr) {
    case 0x0:
        val = root->phy_enabled;
        break;
    case 0x10000:
        val = root->refclk_buffer_enabled;
        break;
    default:
        val = 0;
        break;
    }

    DPRINTF("%s: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, addr, val);
    return val;
}

static void apple_pcie_root_host_phy_write(void *opaque, hwaddr addr,
                                           uint64_t data, unsigned size)
{
    ApplePCIERoot *root = opaque;
    ApplePCIEHost *host = apple_pcie_root_to_host(root);

    DPRINTF("%s: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx "\n",
            __func__, addr, data);
    switch (addr) {
    case 0x0:
        DPRINTF("phy_enabled before == 0x%x\n", root->phy_enabled);
        ////data = 0xdeadbeef;
        if ((data & (1 << 0)) != 0) {
            data |= (1 << 2);
        }
        if ((data & (1 << 1)) != 0) {
            data |= (1 << 3);
        }
        root->phy_enabled = data;
        DPRINTF("phy_enabled after == 0x%x\n", root->phy_enabled);
        break;
    case 0x10000: // for refclk buffer
        DPRINTF("refclk_buffer_enabled before == 0x%x\n", root->refclk_buffer_enabled);
        if ((data & (1 << 0)) != 0) {
            data |= (1 << 2);
        }
        if ((data & (1 << 1)) != 0) {
            data |= (1 << 1); // yes, REALLY bit1
        }
        root->refclk_buffer_enabled = data;
        DPRINTF("refclk_buffer_enabled after == 0x%x\n", root->refclk_buffer_enabled);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps apple_pcie_host_phy_ops = {
    .read = apple_pcie_root_host_phy_read,
    .write = apple_pcie_root_host_phy_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};


static void apple_pcie_root_realize(PCIDevice *pci_dev, Error **errp)
{
#if 0
    BusState *bus = qdev_get_parent_bus(DEVICE(pci_dev));
    ApplePCIEHost *s = APPLE_PCIE_HOST(bus->parent);
    pci_bridge_initfn(pci_dev, TYPE_PCI_BUS);
    pcie_cap_init(pci_dev, 0x70, PCI_EXP_TYPE_ROOT_PORT, 0, &error_fatal);
#endif

#if 0
    if (pcie_endpoint_cap_v1_init(pci_dev, 0x80) < 0) {
        error_setg(errp, "Failed to initialize PCIe capability");
    }
#endif
    // return;

    ApplePCIERoot *root = APPLE_PCIE_ROOT(pci_dev);
    ApplePCIEHost *host = apple_pcie_root_to_host(root);
    MemoryRegion *host_mem = get_system_memory();
    // MemoryRegion *address_space = &host->pci.memory;
    PCIBridge *br = PCI_BRIDGE(pci_dev);
    // br->bus_name  = "apple-pcie";

    pci_config_set_device_id(pci_dev->config, host->device_id);

    pci_set_word(pci_dev->config + PCI_COMMAND,
                 PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

#if 1
    pci_config_set_interrupt_pin(pci_dev->config, 1);
    pci_set_byte(pci_dev->config + PCI_INTERRUPT_LINE, 0xff);
    pci_dev->config[PCI_INTERRUPT_LINE] = 0xff;
    pci_dev->wmask[PCI_INTERRUPT_LINE] = 0x0;
    pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
#endif
    // pci_bridge_initfn(pci_dev, TYPE_PCIE_BUS);
    pci_bridge_initfn(pci_dev, TYPE_PCI_BUS); // this avoids a qemu windows hack

    pcie_port_init_reg(pci_dev);

    // v2, offset 0x70, root_port
    pcie_cap_init(pci_dev, 0x70, PCI_EXP_TYPE_ROOT_PORT, 0, &error_fatal);
#if 0
    pci_bridge_initfn(pci_dev, TYPE_PCI_BUS);

    if (pcie_endpoint_cap_v1_init(pci_dev, 0x80) < 0) {
        error_setg(errp, "Failed to initialize PCIe capability");
    }
#endif

    // deverr enabled
    pcie_cap_deverr_init(pci_dev);

    msi_nonbroken = true;
    // offset 0x50, only 1 vector for the first bridge, 64-bit enabled,
    // per-vector-mask disabled
    msi_init(pci_dev, 0x50, 1, true, false, &error_fatal);

    pci_pm_init(pci_dev, 0x40, &error_fatal);

    bool is_bridge = IS_PCI_BRIDGE(pci_dev);
    DPRINTF("%s: is_bridge == %u\n", __func__, is_bridge);

#if 1
    // sizes: 0x50 for the bridges and qualcomm baseband, 0x3c for broadcom
    // wifi, 0x48 for nvme versions: 1 for broadcom wifi, 2 for the rest
    ////pcie_aer_init(pci_dev, 1, 0x100, PCI_ERR_SIZEOF, &error_fatal);
    pcie_aer_init(pci_dev, PCI_ERR_VER, 0x100, 0x50, &error_fatal);
#endif
#if 0
    pci_dev->wmask[PCI_INTERRUPT_LINE] = 0x0;
    pci_set_byte(pci_dev->config + PCI_INTERRUPT_LINE, 0xff);
    //pci_dev->config[PCI_INTERRUPT_LINE] = 0xff;
    pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
#endif

#if 0
    pci_dev->wmask[PCI_PRIMARY_BUS] = 0x0;
    pci_dev->wmask[PCI_SECONDARY_BUS] = 0x0;
    pci_dev->wmask[PCI_SUBORDINATE_BUS] = 0x0;
    pci_set_byte(pci_dev->config + PCI_PRIMARY_BUS, pci_dev_bus_num(pci_dev));
    pci_set_byte(pci_dev->config + PCI_SECONDARY_BUS, 3);
    pci_set_byte(pci_dev->config + PCI_SUBORDINATE_BUS, 3);
    pci_default_write_config(pci_dev, PCI_PRIMARY_BUS, pci_dev_bus_num(pci_dev), 1);
    pci_default_write_config(pci_dev, PCI_SECONDARY_BUS, 3, 1);
    pci_default_write_config(pci_dev, PCI_SUBORDINATE_BUS, 3, 1);
#endif
#if 0
    msix_init_exclusive_bar(pci_dev, 1, 0, &error_fatal);
    msix_vector_use(pci_dev, 0);
#endif

#if 0
    memory_region_init_io(&root->msi.iomem, OBJECT(root),
                          &apple_pcie_host_msi_ops,
                          root, "pcie-msi", 0x4);
    /*
     * We initially place MSI interrupt I/O region at address 0 and
     * disable it. It'll be later moved to correct offset and enabled
     * in apple_pcie_root_update_msi_mapping() as a part of
     * initialization done by guest OS
     */
    memory_region_add_subregion(address_space, dummy_offset, &root->msi.iomem);
    memory_region_set_enabled(&root->msi.iomem, false);
#endif
}

static void apple_pcie_set_irq(void *opaque, int irq_num, int level)
{
    ApplePCIEHost *host = APPLE_PCIE_HOST(opaque);
    // qemu_set_irq(host->pci.irqs[irq_num], level);
    ////qemu_set_irq(s->irq, level);
    qemu_set_irq(host->irq, level);
}

static const char *apple_pcie_host_root_bus_path(PCIHostState *host_bridge,
                                                 PCIBus *rootbus)
{
    return "0000:00";
}

static void apple_pcie_root_reset(DeviceState *dev)
{
    ApplePCIERoot *root = APPLE_PCIE_ROOT(dev);
    PCIDevice *pci_dev = PCI_DEVICE(dev);
    uint8_t *pci_conf = pci_dev->config;
    uint32_t config;

    // pci_set_byte(pci_conf + PCI_INTERRUPT_LINE, 0xff);
    // pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
    // pci_conf[PCI_INTERRUPT_LINE] = 0xff;
    pci_bridge_reset(dev);
    pcie_cap_deverr_reset(pci_dev);
    // pcie_cap_fill_link_ep_usp(pci_dev, QEMU_PCI_EXP_LNK_X2,
    // QEMU_PCI_EXP_LNK_5GT);
    pcie_cap_fill_link_ep_usp(pci_dev, QEMU_PCI_EXP_LNK_X2,
                              QEMU_PCI_EXP_LNK_8GT);
    // tested, will not reset on its own(==by other reset methods).
    root->phy_enabled = 0x0;
    root->refclk_buffer_enabled = 0x0;
    memset(root->common_regs, 0, sizeof(root->common_regs));

    // pci_set_long(pci_conf + PCI_PREF_LIMIT_UPPER32, 0x11);
    // pci_set_long(pci_conf + 0x12c, 0x11);
    // pci_set_byte(pci_conf + PCI_INTERRUPT_LINE, 0xff);
    // pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
    // pci_conf[PCI_INTERRUPT_LINE] = 0xff;
#if 0
    config = pci_default_read_config(pci_dev, PCI_COMMAND, 4);
    config |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER; //0x0002 | 0x0004; /* memory | bus */
    pci_default_write_config(pci_dev, PCI_COMMAND, config, 4);
    assert(pci_dev->bus_master_enable_region.enabled);
#endif
}

#if 0
static const Property apple_pcie_root_props[] = {
    DEFINE_PROP_PCIE_LINK_SPEED("x-speed", ApplePCIERoot,
                                speed, PCIE_LINK_SPEED_5),
    DEFINE_PROP_PCIE_LINK_WIDTH("x-width", ApplePCIERoot,
                                width, PCIE_LINK_WIDTH_2),
};
#endif

static void apple_pcie_root_class_init(ObjectClass *klass, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);

    k->vendor_id = PCI_VENDOR_ID_APPLE;
    k->device_id =
        0; // 0x1003 for the bridge ; + 1 if manual-enable property exists
    // k->device_id = 0x1003;
    k->revision = 0x1;
    // k->class_id = PCI_CLASS_BRIDGE_PCI; // already done inside
    // pci_bridge_initfn?
    k->exit = pci_bridge_exitfn;
    k->realize = apple_pcie_root_realize;
    k->config_read = apple_pcie_root_config_read;
    k->config_write = apple_pcie_root_config_write;

    // device_class_set_props(dc, apple_pcie_root_props);
    device_class_set_legacy_reset(dc, apple_pcie_root_reset);
    /*
     * PCI-facing part of the host bridge, not usable without the
     * host-facing part, which can't be device_add'ed, yet.
     */
    dc->user_creatable = false;
}

#if 1
static ApplePCIEHost *apple_pcie_create_bridge(DTBNode *node, uint32_t bus_nr,
                                               qemu_irq irq, bool use_t8030)
{
    DeviceState *dev;
    DTBNode *child;
    DTBProp *prop;
    // ApplePCIEHost *s;
    // ApplePCIERoot *root;
    char link_name[16];
    char bridge_node_name[16];
    // uint32_t *armfunc;
    int clkreq_gpio_id = 0, clkreq_gpio_value = 0;
    int device_id = 0;
    snprintf(link_name, sizeof(link_name), "pcie.bridge%u", bus_nr);
    // char link_secbus_name[32];
    // snprintf(link_secbus_name, sizeof(link_secbus_name),
    // "pcie.bridge%u.secbus", bus_nr);
    snprintf(bridge_node_name, sizeof(bridge_node_name), "pci-bridge%u",
             bus_nr);
    child = dtb_get_node(node, bridge_node_name);
#if 0
    if (child != NULL) {
        // only on S8000
        g_assert_nonnull(child);

        prop = dtb_find_prop(child, "function-clkreq");
        g_assert_nonnull(prop);
        if (prop->length == 16) {
            armfunc = (uint32_t *)prop->data;
            clkreq_gpio_id = armfunc[2];
            clkreq_gpio_value = armfunc[3] != 2; // == 0
            ////clkreq_gpio_value = armfunc[3] == 2; // != 0
        }
    }
#endif
#if 1
    if (use_t8030) {
        device_id = 0x1002;
    } else if (child != NULL) {
        g_assert_nonnull(child);
        prop = dtb_find_prop(child, "manual-enable");
        device_id = (prop == NULL) ? 0x1003 : 0x1004;
    }
#endif

    dev = qdev_new(TYPE_APPLE_PCIE_HOST);
    // s = APPLE_PCIE_HOST(dev);
    object_property_add_child(qdev_get_machine(), link_name, OBJECT(dev));
    // root = &s->root;
    // PCIBus *sec_bus = &PCI_BRIDGE(root)->sec_bus;
    // object_property_add_child(qdev_get_machine(), link_secbus_name,
    // OBJECT(sec_bus));
    qdev_prop_set_uint32(dev, "bus_nr", bus_nr);
    qdev_prop_set_uint32(dev, "clkreq_gpio_id", clkreq_gpio_id);
    qdev_prop_set_uint32(dev, "clkreq_gpio_value", clkreq_gpio_value);
    qdev_prop_set_uint32(dev, "device_id", device_id);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    return APPLE_PCIE_HOST(dev);
}
#endif

#if 1
SysBusDevice *apple_pcie_create(DTBNode *node)
{
    DeviceState *dev;
    ApplePCIEState *s;
    SysBusDevice *sbd;
    size_t i;
    DTBProp *prop;
    uint64_t *reg;

    dev = qdev_new(TYPE_APPLE_PCIE);
    s = APPLE_PCIE(dev);
    sbd = SYS_BUS_DEVICE(dev);

    s->node = node;
    prop = dtb_find_prop(s->node, "reg");
    g_assert_nonnull(prop);
    reg = (uint64_t *)prop->data;

    const char *s800x_compatible_substring = "apcie,s800";

    prop = dtb_find_prop(s->node, "compatible");
    g_assert_nonnull(prop);

#if 1
    for (i = 0; i < ARRAY_SIZE(s->irqs); i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }
    sysbus_init_irq(sbd, &s->msi);
#endif

    uint64_t common_index, bridge_count;
    bool use_t8030;

    if (strncmp((char *)prop->data, s800x_compatible_substring,
                strlen(s800x_compatible_substring)) == 0) {
        DPRINTF("%s: compatible check: use S8000(/S8003) mode\n", __func__);

        common_index = 9;
        bridge_count = 3;
        use_t8030 = false;

        s->pcie[3] = NULL;

    } else {
        DPRINTF("%s: compatible check: use T8030(/T8020) mode\n", __func__);

        common_index = 1;
        bridge_count = 4;
        use_t8030 = true;
    }

    for (i = 0; i < bridge_count; i++) {
        s->pcie[i] = apple_pcie_create_bridge(node, i, s->irqs[i], use_t8030);
    }

    g_assert_cmpuint(reg[common_index * 2 + 1], <=, APCIE_COMMON_REGS_LENGTH);

    ApplePCIERoot *root = &s->pcie[0]->root;
    memory_region_init_io(&root->cfg, OBJECT(root), &apple_pcie_host_conf_ops,
                          root, "root_cfg", reg[0 * 2 + 1]);
    sysbus_init_mmio(sbd, &root->cfg);
    memory_region_init_io(&root->common, OBJECT(root),
                          &apple_pcie_host_common_ops, root, "root_common",
                          reg[common_index * 2 + 1]);
    sysbus_init_mmio(sbd, &root->common);
    if (use_t8030) {
        memory_region_init_io(&root->phy, OBJECT(root),
                              &apple_pcie_host_phy_ops, root, "root_phy",
                              reg[2 * 2 + 1]);
        sysbus_init_mmio(sbd, &root->phy);
    }

    DPRINTF("%s: reg[1] == 0x" HWADDR_FMT_plx "\n", __func__, reg[1]);

    return sbd;
}
#endif

static void apple_pcie_host_realize(DeviceState *dev, Error **errp)
{
    PCIHostState *pci = PCI_HOST_BRIDGE(dev);
    ApplePCIEHost *s = APPLE_PCIE_HOST(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    snprintf(s->name, sizeof(s->name), "pcie%u", s->bus_nr);

    /* MMIO region */
    memory_region_init(&s->mmio, OBJECT(s), "mmio", UINT64_MAX);
    /* dummy PCI I/O region (not visible to the CPU) */
    memory_region_init(&s->io, OBJECT(s), "io", 16);

    /* interrupt out */
    qdev_init_gpio_out_named(dev, &s->irq, "interrupt_pci", 1);

    pci->bus = pci_register_root_bus(dev, s->name, apple_pcie_set_irq,
                                     pci_swizzle_map_irq_fn, s, &s->mmio,
                                     &s->io, 0, 4, TYPE_PCIE_BUS);

    qdev_realize(DEVICE(&s->root), BUS(pci->bus), &error_fatal);
}

#if 1
static const Property apple_pcie_host_props[] = {
    DEFINE_PROP_UINT32("bus_nr", ApplePCIEHost, bus_nr, 0),
    DEFINE_PROP_UINT32("clkreq_gpio_id", ApplePCIEHost, clkreq_gpio_id, 0),
    DEFINE_PROP_UINT32("clkreq_gpio_value", ApplePCIEHost, clkreq_gpio_value,
                       0),
    DEFINE_PROP_UINT32("device_id", ApplePCIEHost, device_id, 0),
};
#endif

static void apple_pcie_host_class_init(ObjectClass *klass, void *data)
{
    PCIHostBridgeClass *hc = PCI_HOST_BRIDGE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);

    hc->root_bus_path = apple_pcie_host_root_bus_path;
    dc->realize = apple_pcie_host_realize;

    dc->fw_name = "pci";
    dc->user_creatable = false;
    device_class_set_props(dc, apple_pcie_host_props);
}

static void apple_pcie_host_init(Object *obj)
{
    ApplePCIEHost *s = APPLE_PCIE_HOST(obj);
    ApplePCIERoot *root = &s->root;
    object_initialize_child(obj, "root", root, TYPE_APPLE_PCIE_ROOT);
    qdev_prop_set_int32(DEVICE(root), "addr", PCI_DEVFN(0, 0));
    qdev_prop_set_bit(DEVICE(root), "multifunction", false);
}

static void apple_pcie_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "Apple PCI Express (APCIE)";
    dc->user_creatable = false;
}

// ApplePCIEHost is the parent of ApplePCIERoot

static const TypeInfo apple_pcie_types[] = {
    {
        .name = TYPE_APPLE_PCIE_HOST,
        .parent = TYPE_PCIE_HOST_BRIDGE,
        .instance_size = sizeof(ApplePCIEHost),
        .instance_init = apple_pcie_host_init,
        .class_init = apple_pcie_host_class_init,
    },
    {
        .name = TYPE_APPLE_PCIE_ROOT,
        .parent = TYPE_PCI_BRIDGE,
        .instance_size = sizeof(ApplePCIERoot),
        .class_init = apple_pcie_root_class_init,
        .interfaces = (InterfaceInfo[]){ { INTERFACE_PCIE_DEVICE }, {} },
    },
    {
        .name = TYPE_APPLE_PCIE,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(ApplePCIEState),
        .class_init = apple_pcie_class_init,
    },
};

DEFINE_TYPES(apple_pcie_types)
