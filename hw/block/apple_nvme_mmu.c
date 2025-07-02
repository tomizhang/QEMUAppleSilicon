/*
 * Apple NVMe MMU Controller.
 *
 * Copyright (c) 2023-2025 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2025 Christian Inci (chris-pcguy).
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

#include "qemu/osdep.h"
#include "hw/block/apple_nvme_mmu.h"
#include "hw/irq.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci_device.h"
#include "hw/sysbus.h"
#include "qapi/error.h"
#include "qemu/log.h"

#define DEBUG_NVME_MMU
#ifdef DEBUG_NVME_MMU
#define DPRINTF(fmt, ...)                             \
    do {                                              \
        qemu_log_mask(LOG_UNIMP, fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define DPRINTF(fmt, ...) \
    do {                  \
    } while (0)
#endif

static void apple_nvme_mmu_common_reg_write(void *opaque, hwaddr addr,
                                            uint64_t data, unsigned size)
{
    AppleNVMeMMUState *s = APPLE_NVME_MMU(opaque);
    uint32_t *mmio = &s->common_reg[addr >> 2];
    DPRINTF("apple_nvme_mmu: common reg WRITE @ 0x" HWADDR_FMT_plx
            " value: 0x" HWADDR_FMT_plx "\n",
            addr, data);
    switch (addr) {
#if 0
    case NVME_APPLE_MAX_PEND_CMDS:
        val = NVME_APPLE_MAX_PEND_CMDS_VAL;
        break;
    case NVME_APPLE_BOOT_STATUS:
        val = NVME_APPLE_BOOT_STATUS_OK;
        break;
    case NVME_APPLE_BASE_CMD_ID:
        val = 0x6000;
        break;
#endif
    case 0x4:
        if ((data & (1 << 16)) != 0) {
            data &= ~(1 << 16);
        }
        break;
    default:
        break;
    }
    *mmio = data;
}

static uint64_t apple_nvme_mmu_common_reg_read(void *opaque, hwaddr addr,
                                               unsigned size)
{
    AppleNVMeMMUState *s = APPLE_NVME_MMU(opaque);
    uint32_t *mmio = &s->common_reg[addr >> 2];
    uint32_t val = *mmio;

    switch (addr) {
#if 0
    case NVME_APPLE_MAX_PEND_CMDS:
        val = NVME_APPLE_MAX_PEND_CMDS_VAL;
        break;
    case NVME_APPLE_BOOT_STATUS:
        val = NVME_APPLE_BOOT_STATUS_OK;
        break;
    case NVME_APPLE_BASE_CMD_ID:
        val = 0x6000;
        break;
#endif
    default:
        break;
    }
    DPRINTF("apple_nvme_mmu: common reg READ @ 0x" HWADDR_FMT_plx
            " value: 0x%x\n",
            addr, val);
    return val;
}

static const MemoryRegionOps apple_nvme_mmu_common_reg_ops = {
    .write = apple_nvme_mmu_common_reg_write,
    .read = apple_nvme_mmu_common_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static void apple_nvme_mmu_config_reg_write(void *opaque, hwaddr addr,
                                            uint64_t data, unsigned size)
{
    AppleNVMeMMUState *s = APPLE_NVME_MMU(opaque);
    uint32_t *mmio = &s->config_reg[addr >> 2];
    DPRINTF("apple_nvme_mmu: config reg WRITE @ 0x" HWADDR_FMT_plx
            " value: 0x" HWADDR_FMT_plx "\n",
            addr, data);
    switch (addr) {
#if 0
    case NVME_APPLE_MAX_PEND_CMDS:
        val = NVME_APPLE_MAX_PEND_CMDS_VAL;
        break;
    case NVME_APPLE_BOOT_STATUS:
        val = NVME_APPLE_BOOT_STATUS_OK;
        break;
    case NVME_APPLE_BASE_CMD_ID:
        val = 0x6000;
        break;
#endif
    default:
        break;
    }
    *mmio = data;
}

static uint64_t apple_nvme_mmu_config_reg_read(void *opaque, hwaddr addr,
                                               unsigned size)
{
    AppleNVMeMMUState *s = APPLE_NVME_MMU(opaque);
    uint32_t *mmio = &s->config_reg[addr >> 2];
    uint32_t val = *mmio;

    switch (addr) {
#if 0
    case NVME_APPLE_MAX_PEND_CMDS:
        val = NVME_APPLE_MAX_PEND_CMDS_VAL;
        break;
    case NVME_APPLE_BOOT_STATUS:
        val = NVME_APPLE_BOOT_STATUS_OK;
        break;
    case NVME_APPLE_BASE_CMD_ID:
        val = 0x6000;
        break;
#endif
    default:
        break;
    }
    DPRINTF("apple_nvme_mmu: config reg READ @ 0x" HWADDR_FMT_plx
            " value: 0x%x\n",
            addr, val);
    return val;
}

static const MemoryRegionOps apple_nvme_mmu_config_reg_ops = {
    .write = apple_nvme_mmu_config_reg_write,
    .read = apple_nvme_mmu_config_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static void apple_nvme_mmu_set_irq(void *opaque, int irq_num, int level)
{
    AppleNVMeMMUState *s = APPLE_NVME_MMU(opaque);
    qemu_set_irq(s->irq, level);
}

static void apple_nvme_mmu_start(AppleNVMeMMUState *s)
{
    PCIDevice *pci_dev = PCI_DEVICE(s->nvme);
    uint32_t config;

    config = pci_default_read_config(pci_dev, PCI_COMMAND, 4);
    config |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
    pci_default_write_config(pci_dev, PCI_COMMAND, config, 4);

    g_assert_true(pci_dev->bus_master_enable_region.enabled);
}

SysBusDevice *apple_nvme_mmu_create(DTBNode *node, PCIBus *pci_bus)
{
    DeviceState *dev;
    AppleNVMeMMUState *s;
    SysBusDevice *sbd;
    DTBProp *prop;
    uint64_t *reg;
    PCIDevice *pci_dev;

    dev = qdev_new(TYPE_APPLE_NVME_MMU);
    s = APPLE_NVME_MMU(dev);
    sbd = SYS_BUS_DEVICE(dev);

    s->pci_bus = pci_bus;
    pci_dev = pci_new(-1, TYPE_NVME);
    s->nvme = NVME(pci_dev);

    object_property_set_str(OBJECT(s->nvme), "serial", "ChefKiss-NVMeMMU",
                            &error_fatal);
    object_property_set_uint(OBJECT(s->nvme), "max_ioqpairs", 7, &error_fatal);
    object_property_set_uint(OBJECT(s->nvme), "mdts", 8, &error_fatal);
    object_property_set_uint(OBJECT(s->nvme), "logical_block_size", 4096,
                             &error_fatal);
    object_property_set_uint(OBJECT(s->nvme), "physical_block_size", 4096,
                             &error_fatal);
    object_property_add_child(OBJECT(dev), "nvme", OBJECT(s->nvme));

    prop = dtb_find_prop(node, "reg");
    g_assert_nonnull(prop);

    reg = (uint64_t *)prop->data;

    sysbus_init_irq(sbd, &s->irq);
    qdev_init_gpio_in_named(dev, apple_nvme_mmu_set_irq, "interrupt_pci", 1);
    memory_region_init_io(&s->common, OBJECT(dev),
                          &apple_nvme_mmu_common_reg_ops, s,
                          TYPE_APPLE_NVME_MMU ".common-reg", reg[1]);
    sysbus_init_mmio(sbd, &s->common);
    memory_region_init_io(&s->config, OBJECT(dev),
                          &apple_nvme_mmu_config_reg_ops, s,
                          TYPE_APPLE_NVME_MMU ".config-reg", reg[3]);
    sysbus_init_mmio(sbd, &s->config);

    return sbd;
}

static void apple_nvme_mmu_realize(DeviceState *dev, Error **errp)
{
    AppleNVMeMMUState *s = APPLE_NVME_MMU(dev);

    PCIDevice *pci_dev = PCI_DEVICE(s->nvme);
    //pci_bus_irqs(s->pci_bus, apple_nvme_mmu_set_irq, s, 4);
    qdev_realize(DEVICE(s->nvme), BUS(s->pci_bus), &error_fatal);
    g_assert_true(pci_is_express(pci_dev));
    pcie_endpoint_cap_init(pci_dev, 0);
    pcie_cap_deverr_init(pci_dev);

    msi_nonbroken = true;
    // for root bridge: offset 0x50, only 1 vector for the first bridge, 64-bit
    // enabled, per-vector-mask disabled
    msi_init(pci_dev, 0, 1, true, false, &error_fatal);
    //msi_init(pci_dev, 0, 8, true, false, &error_fatal);

    pci_pm_init(pci_dev, 0, &error_fatal);
    // pcie_cap_fill_link_ep_usp(pci_dev, QEMU_PCI_EXP_LNK_X2,
    //                           QEMU_PCI_EXP_LNK_8GT);
    pcie_aer_init(pci_dev, PCI_ERR_VER, 0x100, PCI_ERR_SIZEOF, &error_fatal);
    pci_config_set_class(pci_dev->config, PCI_CLASS_STORAGE_OTHER);
    apple_nvme_mmu_start(s);
}

static void apple_nvme_mmu_reset(DeviceState *qdev)
{
    AppleNVMeMMUState *s = APPLE_NVME_MMU(qdev);
    PCIDevice *d = PCI_DEVICE(s->nvme);

    pcie_cap_deverr_reset(d);
}

static void apple_nvme_mmu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_nvme_mmu_realize;
    device_class_set_legacy_reset(dc, apple_nvme_mmu_reset);
    dc->desc = "Apple NVMe MMU";
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    dc->fw_name = "pci";
}

static const TypeInfo apple_nvme_mmu_info = {
    .name = TYPE_APPLE_NVME_MMU,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleNVMeMMUState),
    .class_init = apple_nvme_mmu_class_init,
};

static void apple_nvme_mmu_register_types(void)
{
    type_register_static(&apple_nvme_mmu_info);
}

type_init(apple_nvme_mmu_register_types);
