/*
 * Copyright (c) 2018, Impinj, Inc.
 * Copyright (c) 2025 Christian Inci (chris-pcguy).
 *
 * Apple PCIe IP block emulation
 * Frankenstein's monster built from gutted designware/xiling/pnv_phb and others
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
#include "hw/irq.h"
#include "hw/misc/unimp.h"
#include "hw/pci-host/apcie.h"
#include "hw/pci/msi.h"
#include "qapi/error.h"
#include "qemu/log.h"
// #include "hw/pci/msix.h"
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

// #define ENABLE_CPU_DUMP_STATE

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

static void apple_pcie_root_bus_class_init(ObjectClass *klass, void *data)
{
    BusClass *k = BUS_CLASS(klass);

    /*
     * Designware has only a single root complex. Enforce the limit on the
     * parent bus
     * And so does Apple, apparently.
     */
    k->max_dev = 1;
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
    ApplePCIEHost *host = APPLE_PCIE_HOST(opaque);

    host->msi.intr[0].status |= BIT(data) & host->msi.intr[0].enable;

    if (host->msi.intr[0].status & ~host->msi.intr[0].mask) {
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

static void apple_pcie_root_update_msi_mapping(ApplePCIEHost *host)

{
    MemoryRegion *mem   = &host->msi.iomem;
    const uint64_t base = host->msi.base;
    const bool enable   = host->msi.intr[0].enable;

    memory_region_set_address(mem, base);
    memory_region_set_enabled(mem, enable);
}
#endif

static void machine_set_gpio(int interrupt_num, int level)
{
    DeviceState *gpio;
    gpio = DEVICE(object_property_get_link(OBJECT(qdev_get_machine()), "gpio",
                                           &error_fatal));

    DPRINTF("%s: called with interrupt_num 0x%x/%u level %u\n", __func__,
            interrupt_num, interrupt_num, level);
    qemu_set_irq(qdev_get_gpio_in(gpio, interrupt_num), level);
}

static uint64_t apple_pcie_root_data_access(void *opaque, hwaddr addr,
                                            uint64_t *data, unsigned size)
{
    ApplePCIEHost *host = opaque;
    hwaddr orig_addr = addr;

    uint8_t busnum, device, function, devfn;
    function = addr % 0x8000;
    function /= 0x1000;
    device = addr / 0x8000;
    busnum = device / PCI_SLOT_MAX;
    device %= PCI_SLOT_MAX;
    devfn = PCI_DEVFN(device, function);
    PCIHostState *pci = PCI_HOST_BRIDGE(host);
    PCIDevice *pcidev = pci_find_device(pci->bus, busnum, devfn);

    if (pcidev) {
        addr &= pci_config_size(pcidev) - 1;

        if (data) {
            pci_host_config_write_common(pcidev, addr, pci_config_size(pcidev),
                                         *data, size);
            DPRINTF("%s: test0: %02u:%02u.%01u: orig_addr == 0x" HWADDR_FMT_plx
                    " ; size %u ; write 0x" HWADDR_FMT_plx "\n",
                    __func__, busnum, device, function, orig_addr, size, *data);
        } else {
            uint64_t ret = pci_host_config_read_common(
                pcidev, addr, pci_config_size(pcidev), size);
            DPRINTF("%s: test0: %02u:%02u.%01u: orig_addr == 0x" HWADDR_FMT_plx
                    " ; size %u ; read 0x" HWADDR_FMT_plx "\n",
                    __func__, busnum, device, function, orig_addr, size, ret);
            return ret;
        }
    } else {
        if (data) {
            DPRINTF("%s: test0: %02u:%02u.%01u: orig_addr == 0x" HWADDR_FMT_plx
                    " ; size %u ; write UNKNOWN DEVICE\n",
                    __func__, busnum, device, function, orig_addr, size);
        } else {
            DPRINTF("%s: test0: %02u:%02u.%01u: orig_addr == 0x" HWADDR_FMT_plx
                    " ; size %u ; read UNKNOWN DEVICE\n",
                    __func__, busnum, device, function, orig_addr, size);
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

static const MemoryRegionOps apple_pcie_root_conf_ops = {
    .read = apple_pcie_root_data_read,
    .write = apple_pcie_root_data_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};


static uint64_t apple_pcie_root_common_read(void *opaque, hwaddr addr,
                                            unsigned int size)
{
#if 0
    PCIHostState *pci = PCI_HOST_BRIDGE(opaque);
    PCIDevice *device = pci_find_device(pci->bus, 0, 0);
    DPRINTF("%s: test0 addr == 0x" HWADDR_FMT_plx "\n", __func__, addr);

    return pci_host_config_read_common(device, addr, pci_config_size(device), size);
#endif
    ApplePCIEHost *host = APPLE_PCIE_HOST(opaque);
    uint32_t val = 0;

    switch (addr) {
    // case 0x0:
    //     break;
    case 0x28:
        val = 0x10; // refclk good ; for T8030
        break;
    case 0x1ac: // for S8000
        val = 0x1;
        break;
    default:
        // val = 0;
        val = host->root_common_regs[addr >> 2];
        break;
    }

    DPRINTF("%s: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, addr, val);
    return val;
}

static void apple_pcie_root_common_write(void *opaque, hwaddr addr,
                                         uint64_t data, unsigned int size)
{
#if 0
    PCIHostState *pci = PCI_HOST_BRIDGE(opaque);
    PCIDevice *device = pci_find_device(pci->bus, 0, 0);

    return pci_host_config_write_common(device, addr, pci_config_size(device), data, size);
#endif
    ApplePCIEHost *host = APPLE_PCIE_HOST(opaque);

    DPRINTF("%s: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx "\n",
            __func__, addr, data);
    switch (addr) {
    // case 0x0:
    //     break;
    case 0x4:
        if (data == 0x11) {
            host->root_common_regs[0x114 >> 2] = 0x100;
            host->root_common_regs[0x2c >> 2] = 0x11; // for S8000/N66AP
            host->root_common_regs[0x12c >> 2] =
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
            ////host->root_common_regs[0x2c >> 2] = 0x11; // for S8003/N66mAP
        }
        break;
    default:
        break;
    }
    host->root_common_regs[addr >> 2] = data;
}

static const MemoryRegionOps apple_pcie_root_common_ops = {
    .read       = apple_pcie_root_common_read,
    .write      = apple_pcie_root_common_write,
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
    ApplePCIEHost *host = APPLE_PCIE_HOST(opaque);
    uint32_t val = 0;

#ifdef ENABLE_CPU_DUMP_STATE
    // #if 1
    cpu_dump_state(CPU(first_cpu), stderr, CPU_DUMP_CODE);
#endif

    switch (addr) {
    case 0x0:
        val = host->root_phy_enabled;
        break;
    case 0x10000:
        val = host->root_refclk_buffer_enabled;
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
    ApplePCIEHost *host = APPLE_PCIE_HOST(opaque);

    DPRINTF("%s: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx "\n",
            __func__, addr, data);
    switch (addr) {
    case 0x0:
        DPRINTF("phy_enabled before == 0x%x\n", host->root_phy_enabled);
        ////data = 0xdeadbeef;
        if ((data & (1 << 0)) != 0) {
            data |= (1 << 2);
        }
        if ((data & (1 << 1)) != 0) {
            data |= (1 << 3);
        }
        host->root_phy_enabled = data;
        DPRINTF("phy_enabled after == 0x%x\n", host->root_phy_enabled);
        break;
    case 0x10000: // for refclk buffer
        DPRINTF("refclk_buffer_enabled before == 0x%x\n",
                host->root_refclk_buffer_enabled);
        if ((data & (1 << 0)) != 0) {
            data |= (1 << 2);
        }
        if ((data & (1 << 1)) != 0) {
            data |= (1 << 1); // yes, REALLY bit1
        }
        host->root_refclk_buffer_enabled = data;
        DPRINTF("refclk_buffer_enabled after == 0x%x\n",
                host->root_refclk_buffer_enabled);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps apple_pcie_root_host_phy_ops = {
    .read = apple_pcie_root_host_phy_read,
    .write = apple_pcie_root_host_phy_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static uint64_t apple_pcie_port_config_read(void *opaque, hwaddr addr,
                                            unsigned size)
{
    ApplePCIEPort *port = opaque;
    uint32_t is_port_enabled;
    uint32_t val = 0;

// #ifdef ENABLE_CPU_DUMP_STATE
#if 0
    cpu_dump_state(CPU(first_cpu), stderr, CPU_DUMP_CODE);
#endif

    is_port_enabled = (port->port_cfg_port_config & 1) != 0;

    switch (addr) {
    case 0x100: // pcielint
        //val = 0xdeadbeef;
        //val |= 0x1000; // link-up interrupt
        //val |= 0x4000; // link-down interrupt
        //val |= 0x8000; // AF timeout interrupt
        //val |= 0x20000; // bad-request-interrupt: malformed mmu request
        //val |= 0x40000; // bad-request-interrupt: msi error
        //val |= 0x80000; // bad-request-interrupt: msi data miscompare
        //val |= 0x200000; // bad-request-interrupt: read response error
        //val |= 0x800000; // completion-timeout interrupt
        //val |= 0x2000000; // completer-abort interrupt
        //val |= 0x4000000; // bad-request-interrupt: requester-to-sid mapping error
        val = port->port_last_interrupt;
        // Don't reset/clear the value here, iOS will do that!
        ////port->port_last_interrupt = 0;
        break;
    case 0x208: // linksts ; for getLinkUp/isLinkInL2. I've no idea what I
                // should return for bit6
        ////val = (1 << 0); // getLinkUp
        val = (is_port_enabled << 0); // getLinkUp
        val |= (0 << 6); // isLinkInL2
        // val |= (1 << 6); // isLinkInL2
        break;
    case 0x210: // linkcdmsts
        break;
    case 0x800: // for setPortEnable/initializeRootComplex/expressCapOffset?
                // bit0 seems to be "enable port"
        val = port->port_cfg_port_config;
        break;
    case 0x804: // for enable port hardware
        val = is_port_enabled;
        break;
    case 0x810:
        val = port->port_cfg_refclk_config;
        break;
    case 0x814:
        val = port->port_cfg_rootport_perst;
        break;
    default:
        val = 0;
        break;
    }

    DPRINTF("%s: Port %u: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, port->bus_nr, addr, val);
    return val;
}

static void apple_pcie_port_config_write(void *opaque, hwaddr addr,
                                         uint64_t data, unsigned size)
{
    ApplePCIEPort *port = opaque;

    DPRINTF("%s: Port %u: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx
            "\n",
            __func__, port->bus_nr, addr, data);
    switch (addr) {
    case 0x100: // pcielint? ; and enableInterrupts?
        if (data == 0x0) {
            port->port_last_interrupt = data;
        }
        break;
    case 0x13c:
        if ((data & 0x100) != 0) {
            // return 0x4000 at offset 0x100
            port->port_last_interrupt |= 0x4000; // link-down interrupt
        }
        break;
    case 0x800: // for setPortEnable/initializeRootComplex/expressCapOffset?
                // bit0 seems to be "enable port"
        port->port_cfg_port_config = data;
        break;
    case 0x810:
        port->port_cfg_refclk_config = data;
        break;
    case 0x814:
        port->port_cfg_rootport_perst = data;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps apple_pcie_port_config_ops = {
    .read = apple_pcie_port_config_read,
    .write = apple_pcie_port_config_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static uint64_t apple_pcie_port_config_ltssm_debug_read(void *opaque, hwaddr addr,
                                            unsigned size)
{
    ApplePCIEPort *port = opaque;
    uint32_t val = 0;

// #ifdef ENABLE_CPU_DUMP_STATE
#if 0
    cpu_dump_state(CPU(first_cpu), stderr, CPU_DUMP_CODE);
#endif

    switch (addr) {
    case 0x30:
        val = 0xffffffff;
        break;
    default:
        val = 0;
        break;
    }

    DPRINTF("%s: Port %u: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, port->bus_nr, addr, val);
    return val;
}

static void apple_pcie_port_config_ltssm_debug_write(void *opaque, hwaddr addr,
                                         uint64_t data, unsigned size)
{
    ApplePCIEPort *port = opaque;

    DPRINTF("%s: Port %u: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx
            "\n",
            __func__, port->bus_nr, addr, data);
    switch (addr) {
    default:
        break;
    }
}

static const MemoryRegionOps apple_pcie_port_config_ltssm_debug_ops = {
    .read = apple_pcie_port_config_ltssm_debug_read,
    .write = apple_pcie_port_config_ltssm_debug_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static uint64_t apple_pcie_port_phy_glue_read(void *opaque, hwaddr addr,
                                              unsigned size)
{
    ApplePCIEPort *port = opaque;
    uint32_t val = 0;

// #ifdef ENABLE_CPU_DUMP_STATE
#if 0
    cpu_dump_state(CPU(first_cpu), stderr, CPU_DUMP_CODE);
#endif

    switch (addr) {
    case 0x0: // for port refclk buffer ; copied from
              // apple_pcie_root_host_phy_read
        val = port->port_refclk_buffer_enabled;
        break;
    default:
        val = 0;
        break;
    }

    DPRINTF("%s: Port %u: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, port->bus_nr, addr, val);
    return val;
}

static void apple_pcie_port_phy_glue_write(void *opaque, hwaddr addr,
                                           uint64_t data, unsigned size)
{
    ApplePCIEPort *port = opaque;

    DPRINTF("%s: Port %u: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx
            "\n",
            __func__, port->bus_nr, addr, data);
    switch (addr) {
    case 0x0: // for port refclk buffer ; copied from
              // apple_pcie_root_host_phy_write
        DPRINTF("refclk_buffer_enabled before == 0x%x\n",
                port->port_refclk_buffer_enabled);
        if ((data & (1 << 0)) != 0) {
            data |= (1 << 2);
        }
        if ((data & (1 << 1)) != 0) {
            data |= (1 << 1); // yes, REALLY bit1
        }
        port->port_refclk_buffer_enabled = data;
        DPRINTF("refclk_buffer_enabled after == 0x%x\n",
                port->port_refclk_buffer_enabled);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps apple_pcie_port_phy_glue_ops = {
    .read = apple_pcie_port_phy_glue_read,
    .write = apple_pcie_port_phy_glue_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static uint64_t apple_pcie_port_phy_ip_read(void *opaque, hwaddr addr,
                                            unsigned size)
{
    ApplePCIEPort *port = opaque;
    uint32_t val = 0;

// #ifdef ENABLE_CPU_DUMP_STATE
#if 0
    cpu_dump_state(CPU(first_cpu), stderr, CPU_DUMP_CODE);
#endif

    switch (addr) {
    default:
        val = 0;
        break;
    }

    DPRINTF("%s: Port %u: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, port->bus_nr, addr, val);
    return val;
}

static void apple_pcie_port_phy_ip_write(void *opaque, hwaddr addr,
                                         uint64_t data, unsigned size)
{
    ApplePCIEPort *port = opaque;

    DPRINTF("%s: Port %u: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx
            "\n",
            __func__, port->bus_nr, addr, data);
    switch (addr) {
    default:
        break;
    }
}

static const MemoryRegionOps apple_pcie_port_phy_ip_ops = {
    .read = apple_pcie_port_phy_ip_read,
    .write = apple_pcie_port_phy_ip_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};


static void apple_pcie_set_irq(void *opaque, int irq_num, int level)
{
    ApplePCIEHost *host = APPLE_PCIE_HOST(opaque);
    // qemu_set_irq(host->pci.irqs[irq_num], level);
    ////qemu_set_irq(s->irq, level);
    // qemu_set_irq(host->irq, level);
    qemu_set_irq(host->irqs[irq_num], level);
}

static const char *apple_pcie_host_root_bus_path(PCIHostState *host_bridge,
                                                 PCIBus *rootbus)
{
    return "0000:00";
}

static void apple_pcie_host_reset(DeviceState *dev)
{
    ApplePCIEHost *host = APPLE_PCIE_HOST(dev);
    // PCIDevice *pci_dev = PCI_DEVICE(dev);
    // uint8_t *pci_conf = pci_dev->config;
    // uint32_t config;

    // pci_set_byte(pci_conf + PCI_INTERRUPT_LINE, 0xff);
    // pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
    // pci_conf[PCI_INTERRUPT_LINE] = 0xff;
    // pci_bridge_reset(dev);
    // pcie_cap_deverr_reset(pci_dev);
    // pcie_cap_fill_link_ep_usp(pci_dev, QEMU_PCI_EXP_LNK_X2,
    // QEMU_PCI_EXP_LNK_5GT);
    // pcie_cap_fill_link_ep_usp(pci_dev, QEMU_PCI_EXP_LNK_X2,
    // QEMU_PCI_EXP_LNK_8GT);

    host->root_phy_enabled = 0x0;
    host->root_refclk_buffer_enabled = 0x0;
    memset(host->root_common_regs, 0, sizeof(host->root_common_regs));

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

#if 1
static ApplePCIEPort *apple_pcie_create_port(DTBNode *node, uint32_t bus_nr,
                                             qemu_irq irq, bool use_t8030,
                                             PCIBus *bus)
{
    // DeviceState *dev;
    PCIDevice *pci_dev;
    DTBNode *child;
    DTBProp *prop;
    // ApplePCIEHost *s;
    char link_name[16];
    char bridge_node_name[16];
    // uint32_t *armfunc;
    // int clkreq_gpio_id = 0, clkreq_gpio_value = 0;
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
        // device_id = 0x1003;
    } else if (child != NULL) {
        g_assert_nonnull(child);
        prop = dtb_find_prop(child, "manual-enable");
        device_id = (prop == NULL) ? 0x1003 : 0x1004;
    }
#endif

    // dev = qdev_new(TYPE_APPLE_PCIE_PORT);
    // object_property_add_child(qdev_get_machine(), link_name, OBJECT(dev));
    //pci_dev = pci_new(-1, TYPE_APPLE_PCIE_PORT);
    pci_dev = pci_new(PCI_DEVFN(bus_nr, 0), TYPE_APPLE_PCIE_PORT);
    object_property_add_child(qdev_get_machine(), link_name, OBJECT(pci_dev));

    qdev_prop_set_uint32(DEVICE(pci_dev), "bus_nr", bus_nr);
    // qdev_prop_set_uint32(dev, "clkreq_gpio_id", clkreq_gpio_id);
    // qdev_prop_set_uint32(dev, "clkreq_gpio_value", clkreq_gpio_value);
    qdev_prop_set_uint32(DEVICE(pci_dev), "device_id", device_id);

    // qdev_realize(DEVICE(dev), NULL, &error_abort);
    // sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    pci_realize_and_unref(pci_dev, bus, &error_fatal);

    return APPLE_PCIE_PORT(pci_dev);
}
#endif

#if 1
SysBusDevice *apple_pcie_create(DTBNode *node)
{
    DeviceState *dev;
    ApplePCIEState *s;
    SysBusDevice *sbd;
    DeviceState *host_dev;
    ApplePCIEHost *host;
    ApplePCIEPort *port;
    PCIHostState *pci;
    // size_t i;
    int i;
    DTBProp *prop;
    uint64_t *reg;
    char temp_name[32];

    dev = qdev_new(TYPE_APPLE_PCIE);
    s = APPLE_PCIE(dev);
    sbd = SYS_BUS_DEVICE(dev);

    host_dev = qdev_new(TYPE_APPLE_PCIE_HOST);
    object_property_add_child(qdev_get_machine(), "pcie.host",
                              OBJECT(host_dev));
    host = APPLE_PCIE_HOST(host_dev);
    s->host = host;

    s->node = node;
    prop = dtb_find_prop(s->node, "reg");
    g_assert_nonnull(prop);
    reg = (uint64_t *)prop->data;

    const char *s800x_compatible_substring = "apcie,s800";

    prop = dtb_find_prop(s->node, "compatible");
    g_assert_nonnull(prop);

    for (i = 0; i < ARRAY_SIZE(host->irqs); i++) {
        sysbus_init_irq(sbd, &host->irqs[i]);
    }
    sysbus_init_irq(sbd, &host->msi);

    uint64_t common_index, port_index, port_count, port_entries, root_mappings,
        port_mappings;
    bool use_t8030;

    if (strncmp((char *)prop->data, s800x_compatible_substring,
                strlen(s800x_compatible_substring)) == 0) {
        DPRINTF("%s: compatible check: use S8000(/S8003) mode\n", __func__);

        common_index = 9;
        port_index = 1;
        port_count = 4;
        port_entries = 2;
        root_mappings = 2;
        port_mappings = 1;
        use_t8030 = false;
    } else {
        DPRINTF("%s: compatible check: use T8030(/T8020) mode\n", __func__);

        common_index = 1;
        port_index = 6;
        port_count = 4;
        port_entries = 4;
        root_mappings = 3;
        port_mappings = 4;
        use_t8030 = true;
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(host_dev), &error_fatal);
    pci = PCI_HOST_BRIDGE(host_dev);
    for (i = 0; i < port_count; i++) {
        s->ports[i] = apple_pcie_create_port(node, i, host->irqs[i], use_t8030, pci->bus);
    }
    g_assert_cmpuint(reg[common_index * 2 + 1], <=, APCIE_COMMON_REGS_LENGTH);

    memory_region_init_io(&host->root_cfg, OBJECT(host),
                          &apple_pcie_root_conf_ops, host, "root_cfg",
                          reg[0 * 2 + 1]);
    sysbus_init_mmio(sbd, &host->root_cfg);
    sysbus_mmio_map(sbd, 0, reg[0 * 2]);
    memory_region_init_io(&host->root_common, OBJECT(host),
                          &apple_pcie_root_common_ops, host, "root_common",
                          reg[common_index * 2 + 1]);
    sysbus_init_mmio(sbd, &host->root_common);
    sysbus_mmio_map(sbd, 1, reg[common_index * 2]);
    if (use_t8030) {
        memory_region_init_io(&host->root_phy, OBJECT(host),
                              &apple_pcie_root_host_phy_ops, host, "root_phy",
                              reg[2 * 2 + 1]);
        sysbus_init_mmio(sbd, &host->root_phy);
        sysbus_mmio_map(sbd, 2, reg[2 * 2]);
    }

    // the ports have to come later, as root and port phy's will overlap
    // otherwise (ports need to take preference)
    for (i = 0; i < port_count; i++) {
        port = s->ports[i];
        if (port == NULL)
            continue;
        snprintf(temp_name, sizeof(temp_name), "port%u_config", i);
        memory_region_init_io(
            &port->port_cfg, OBJECT(port), &apple_pcie_port_config_ops, port,
            temp_name, reg[(port_index + (i * port_entries) + 0) * 2 + 1]);
        sysbus_init_mmio(sbd, &port->port_cfg);
        sysbus_mmio_map(sbd, root_mappings + 0 + (i * port_mappings),
                        reg[(port_index + (i * port_entries) + 0) * 2 + 0]);
        if (use_t8030) {
            snprintf(temp_name, sizeof(temp_name), "port%u_config_ltssm_debug",
                     i);
            memory_region_init_io(
                &port->port_config_ltssm_debug, OBJECT(port),
                &apple_pcie_port_config_ltssm_debug_ops, port, temp_name,
                reg[(port_index + (i * port_entries) + 1) * 2 + 1]);
            sysbus_init_mmio(sbd, &port->port_config_ltssm_debug);
            sysbus_mmio_map(sbd, root_mappings + 1 + (i * port_mappings),
                            reg[(port_index + (i * port_entries) + 1) * 2 + 0]);

            snprintf(temp_name, sizeof(temp_name), "port%u_phy_glue", i);
            memory_region_init_io(
                &port->port_phy_glue, OBJECT(port),
                &apple_pcie_port_phy_glue_ops, port, temp_name,
                reg[(port_index + (i * port_entries) + 2) * 2 + 1]);
            sysbus_init_mmio(sbd, &port->port_phy_glue);
            sysbus_mmio_map(sbd, root_mappings + 2 + (i * port_mappings),
                            reg[(port_index + (i * port_entries) + 2) * 2 + 0]);

            snprintf(temp_name, sizeof(temp_name), "port%u_phy_ip", i);
            memory_region_init_io(
                &port->port_phy_ip, OBJECT(port), &apple_pcie_port_phy_ip_ops,
                port, temp_name,
                reg[(port_index + (i * port_entries) + 3) * 2 + 1]);
            sysbus_init_mmio(sbd, &port->port_phy_ip);
            sysbus_mmio_map(sbd, root_mappings + 3 + (i * port_mappings),
                            reg[(port_index + (i * port_entries) + 3) * 2 + 0]);
        } else {
            snprintf(temp_name, sizeof(temp_name), "port%u_phy", i);
            create_unimplemented_device(
                temp_name, reg[(port_index + (i * port_entries) + 1) * 2 + 0],
                reg[(port_index + (i * port_entries) + 1) * 2 + 1]);
        }
    }

    if (use_t8030) {
        pci_set_power(PCI_DEVICE(s->ports[0]), false);
        pci_set_power(PCI_DEVICE(s->ports[1]), false);
    } else {
        pci_set_power(PCI_DEVICE(s->ports[3]), false);
    }

    DPRINTF("%s: reg[1] == 0x" HWADDR_FMT_plx "\n", __func__, reg[1]);

    return sbd;
}
#endif

static void apple_pcie_port_reset_hold(Object *obj, ResetType type)
{
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(obj);
    ApplePCIEPort *port = APPLE_PCIE_PORT(obj);
    PCIDevice *pci_dev = PCI_DEVICE(obj);
    uint8_t *pci_conf = pci_dev->config;
    uint32_t config;

    if (rpc->parent_phases.hold) {
        rpc->parent_phases.hold(obj, type);
    }

    // pci_set_byte(pci_conf + PCI_INTERRUPT_LINE, 0xff);
    // pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
    // pci_conf[PCI_INTERRUPT_LINE] = 0xff;
    // pci_bridge_reset(dev);
    // pcie_cap_deverr_reset(pci_dev);
    // pcie_cap_fill_link_ep_usp(pci_dev, QEMU_PCI_EXP_LNK_X2,
    // QEMU_PCI_EXP_LNK_5GT);
    pcie_cap_fill_link_ep_usp(pci_dev, QEMU_PCI_EXP_LNK_X2,
                              QEMU_PCI_EXP_LNK_8GT);

    port->port_last_interrupt = 0x0;
    port->port_cfg_port_config = 0x0;
    port->port_cfg_refclk_config = 0x0;
    port->port_cfg_rootport_perst = 0x0;
    port->port_refclk_buffer_enabled = 0x0;

    // pci_set_long(pci_conf + PCI_PREF_LIMIT_UPPER32, 0x11);
    // pci_set_long(pci_conf + 0x12c, 0x11);
    // pci_set_byte(pci_conf + PCI_INTERRUPT_LINE, 0xff);
    // pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
    // pci_conf[PCI_INTERRUPT_LINE] = 0xff;
#if 1
    config = pci_default_read_config(pci_dev, PCI_COMMAND, 4);
    config |= PCI_COMMAND_MEMORY |
              PCI_COMMAND_MASTER; // 0x0002 | 0x0004; /* memory | bus */
    pci_default_write_config(pci_dev, PCI_COMMAND, config, 4);
    pci_set_word(pci_dev->config + PCI_COMMAND, config);
    // assert(pci_dev->bus_master_enable_region.enabled);
#endif
#if 0
    pci_byte_test_and_set_mask(pci_conf + PCI_IO_BASE,
                               PCI_IO_RANGE_MASK & 0xff);
    pci_byte_test_and_clear_mask(pci_conf + PCI_IO_LIMIT,
                                 PCI_IO_RANGE_MASK & 0xff);
    pci_set_word(pci_conf + PCI_MEMORY_BASE, 0);
    pci_set_word(pci_conf + PCI_MEMORY_LIMIT, 0xfff0);
    pci_set_word(pci_conf + PCI_PREF_MEMORY_BASE, 0x1);
    pci_set_word(pci_conf + PCI_PREF_MEMORY_LIMIT, 0xfff1);
    pci_set_long(pci_conf + PCI_PREF_BASE_UPPER32, 0x1); /* Hack */
    pci_set_long(pci_conf + PCI_PREF_LIMIT_UPPER32, 0xffffffff);
#endif
    // pci_config_set_interrupt_pin(pci_conf, 0);
    // pci_config_set_interrupt_pin(pci_conf, 1);
}

static void apple_pcie_port_realize(DeviceState *dev, Error **errp)
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

    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(dev);
    ApplePCIEPort *port = APPLE_PCIE_PORT(dev);
    PCIBus *bus = PCI_BUS(qdev_get_parent_bus(dev));
    PCIDevice *pci = PCI_DEVICE(dev);

    // PCIHostState *pci = PCI_HOST_BRIDGE(dev);
    // ApplePCIEHost *s = APPLE_PCIE_HOST(dev);
    // PCIExpressHost *pex = PCIE_HOST_BRIDGE(dev);
    // pcie_host_mmcfg_init(pex, 32 * 1024 * 1024);
    // pcie_host_mmcfg_init(pex, PCIE_MMCFG_SIZE_MAX);

    // MemoryRegion *host_mem = get_system_memory();
    //  MemoryRegion *address_space = &host->pci.memory;
    // PCIBridge *br = PCI_BRIDGE(pci_dev);
    //  br->bus_name  = "apple-pcie";

    /* Set unique chassis/slot values for the root port */
    qdev_prop_set_uint8(dev, "chassis", 0);
    qdev_prop_set_uint16(dev, "slot", port->bus_nr);

    rpc->parent_realize(dev, &error_fatal);

    pci_config_set_device_id(pci->config, port->device_id);
    // pci_config_set_interrupt_pin(pci->config, 0);

    pci_set_word(pci->config + PCI_COMMAND,
                 PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

#if 1
    pci_config_set_interrupt_pin(pci->config, 1);
    pci_set_byte(pci->config + PCI_INTERRUPT_LINE, 0xff);
    // pci->config[PCI_INTERRUPT_LINE] = 0xff;
    pci->wmask[PCI_INTERRUPT_LINE] = 0x0;
    // pci_default_write_config(pci, PCI_INTERRUPT_LINE, 0xff, 1);
#endif
#if 0
    pci_config_set_interrupt_pin(pci_dev->config, 1);
    pci_set_byte(pci_dev->config + PCI_INTERRUPT_LINE, 0xff);
    pci_dev->config[PCI_INTERRUPT_LINE] = 0xff;
    pci_dev->wmask[PCI_INTERRUPT_LINE] = 0x0;
    pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE, 0xff, 1);
#endif
    // pci_bridge_initfn(pci, TYPE_PCIE_BUS);
    // pci_bridge_initfn(pci, TYPE_PCI_BUS); // this avoids a qemu windows hack
    // pci_dev->config[PCI_INTERRUPT_PIN] = 0x1;
    // pci_dev->config[PCI_INTERRUPT_PIN] = port->bus_nr + 0x1;

    // pcie_port_init_reg(pci);

    // v2, offset 0x70, root_port
    // pcie_cap_init(pci, 0x70, PCI_EXP_TYPE_ROOT_PORT, 0, &error_fatal);
    // pcie_cap_init(pci, 0, PCI_EXP_TYPE_ROOT_PORT, 0, &error_fatal);
#if 0
    pci_bridge_initfn(pci_dev, TYPE_PCI_BUS);

    if (pcie_endpoint_cap_v1_init(pci_dev, 0x80) < 0) {
        error_setg(errp, "Failed to initialize PCIe capability");
    }
#endif

    // deverr enabled
    pcie_cap_deverr_init(pci);

    // msi_nonbroken = true;
    //  offset 0x50, only 1 vector for the first bridge, 64-bit enabled,
    //  per-vector-mask disabled
    // msi_init(pci, 0x50, 1, true, false, &error_fatal);
    // msi_init(pci, 0, 1, true, false, &error_fatal);

    // pci_pm_init(pci, 0x40, &error_fatal);
    pci_pm_init(pci, 0, &error_fatal);

    bool is_bridge = IS_PCI_BRIDGE(pci);
    DPRINTF("%s: is_bridge == %u\n", __func__, is_bridge);

#if 1
    // sizes: 0x50 for the bridges and qualcomm baseband,
    // 0x3c for broadcom wifi, 0x48 for nvme
    // versions: 1 for broadcom wifi, 2 for the rest
    ////pcie_aer_init(pci_dev, 1, 0x100, PCI_ERR_SIZEOF, &error_fatal);
    // pcie_aer_init(pci_dev, PCI_ERR_VER, 0x100, 0x50, &error_fatal);
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
    msix_init_exclusive_bar(pci, 1, 0, &error_fatal);
    msix_vector_use(pci, 0);
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
    // qdev_init_gpio_out_named(DEVICE(port), &port->irq, "interrupt_pci", 1);
}

static int apple_pcie_port_interrupts_init(PCIDevice *d, Error **errp)
{
    int rc;

    ////rc = msi_init(d, IOH_EP_MSI_OFFSET, IOH_EP_MSI_NR_VECTOR,
    ///IOH_EP_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_64BIT,
    ///IOH_EP_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_MASKBIT, errp);
    // rc = msi_init(d, 0, 1, true, false, errp);
    msi_nonbroken = true;
    // offset 0x50, only 1 vector for the first bridge, 64-bit enabled,
    // per-vector-mask disabled
    rc = msi_init(d, 0x50, 1, true, false, errp);
    if (rc < 0) {
        assert(rc == -ENOTSUP);
    }

    return rc;
}

static void apple_pcie_port_interrupts_uninit(PCIDevice *d)
{
    msi_uninit(d);
}

/*
 * If two MSI vector are allocated, Advanced Error Interrupt Message Number
 * is 1. otherwise 0.
 * 17.12.5.10 RPERRSTS,  32:27 bit Advanced Error Interrupt Message Number.
 */
static uint8_t apple_pcie_aer_vector(const PCIDevice *d)
{
    switch (msi_nr_vectors_allocated(d)) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
    case 8:
    case 16:
    case 32:
    default:
        break;
    }
    abort();
    return 0;
}

static const Property apple_pcie_port_props[] = {
    DEFINE_PROP_UINT32("bus_nr", ApplePCIEPort, bus_nr, 0),
    // DEFINE_PROP_UINT32("clkreq_gpio_id", ApplePCIEPort, clkreq_gpio_id, 0),
    // DEFINE_PROP_UINT32("clkreq_gpio_value", ApplePCIEPort, clkreq_gpio_value,
    // 0),
    DEFINE_PROP_UINT32("device_id", ApplePCIEPort, device_id, 0),
};

static void apple_pcie_port_class_init(ObjectClass *klass, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_CLASS(klass);

    dc->desc = "Apple PCIE Root Port";
    k->vendor_id = PCI_VENDOR_ID_APPLE;
    // s8000: 0x1003 for the bridge ; + 1 if manual-enable property exists?
    // t8030: 0x1002?
    k->device_id = 0;
    k->revision = 0x1;

    device_class_set_props(dc, apple_pcie_port_props);
    device_class_set_parent_realize(dc, apple_pcie_port_realize,
                                    &rpc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, apple_pcie_port_reset_hold,
                                       NULL, &rpc->parent_phases);
    /*
     * PCI-facing part of the host bridge, not usable without the
     * host-facing part, which can't be device_add'ed, yet.
     */
    dc->user_creatable = false;

    rpc->exp_offset = 0x70;
    rpc->aer_offset = 0x100;
    rpc->aer_vector = apple_pcie_aer_vector;
    ////rpc->acs_offset = ;

    rpc->interrupts_init = apple_pcie_port_interrupts_init;
    rpc->interrupts_uninit = apple_pcie_port_interrupts_uninit;

    dc->hotpluggable = false;
}

static void apple_pcie_host_realize(DeviceState *dev, Error **errp)
{
    PCIHostState *pci = PCI_HOST_BRIDGE(dev);
    ApplePCIEHost *s = APPLE_PCIE_HOST(dev);
    // PCIExpressHost *pex = PCIE_HOST_BRIDGE(dev);
    // pcie_host_mmcfg_init(pex, 32 * 1024 * 1024);
    // pcie_host_mmcfg_init(pex, PCIE_MMCFG_SIZE_MAX);

    /* MMIO region */
    memory_region_init(&s->mmio, OBJECT(s), "mmio", UINT64_MAX);
    /* dummy PCI I/O region (not visible to the CPU) */
    memory_region_init(&s->io, OBJECT(s), "io", 16);

    /* interrupt out */
    // qdev_init_gpio_out_named(dev, &s->irq, "interrupt_pci", 1);
    qdev_init_gpio_out_named(dev, s->irqs, "interrupt_pci", 4);

    pci->bus = pci_register_root_bus(dev, "apcie", apple_pcie_set_irq,
                                     pci_swizzle_map_irq_fn, s, &s->mmio,
                                     &s->io, 0, 4, TYPE_APPLE_PCIE_ROOT_BUS);
    // pci->bus->flags |= PCI_BUS_EXTENDED_CONFIG_SPACE;
}

#if 0
static const Property apple_pcie_root_props[] = {
    DEFINE_PROP_PCIE_LINK_SPEED("x-speed", ApplePCIERoot,
                                speed, PCIE_LINK_SPEED_5),
    DEFINE_PROP_PCIE_LINK_WIDTH("x-width", ApplePCIERoot,
                                width, PCIE_LINK_WIDTH_2),
};
#endif

static void apple_pcie_host_class_init(ObjectClass *klass, void *data)
{
    PCIHostBridgeClass *hc = PCI_HOST_BRIDGE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);

    hc->root_bus_path = apple_pcie_host_root_bus_path;
    dc->realize = apple_pcie_host_realize;
    device_class_set_legacy_reset(dc, apple_pcie_host_reset);
    // dc->fw_name = "pci";

    dc->user_creatable = false;
}

static void apple_pcie_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "Apple PCI Express (APCIE)";
    dc->user_creatable = false;
}

static const TypeInfo apple_pcie_types[] = {
    {
        .name = TYPE_APPLE_PCIE_ROOT_BUS,
        .parent = TYPE_PCIE_BUS,
        .instance_size = sizeof(ApplePCIERootBus),
        .class_init = apple_pcie_root_bus_class_init,
    },
    {
        .name = TYPE_APPLE_PCIE_HOST,
        .parent = TYPE_PCIE_HOST_BRIDGE,
        .instance_size = sizeof(ApplePCIEHost),
        .class_init = apple_pcie_host_class_init,
    },
    {
        .name = TYPE_APPLE_PCIE_PORT,
        .parent = TYPE_PCIE_ROOT_PORT,
        .instance_size = sizeof(ApplePCIEPort),
        .class_init = apple_pcie_port_class_init,
    },
    {
        .name = TYPE_APPLE_PCIE,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(ApplePCIEState),
        .class_init = apple_pcie_class_init,
    },
};

DEFINE_TYPES(apple_pcie_types)
