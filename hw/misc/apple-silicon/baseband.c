/*
 * Apple iPhone 11 Baseband
 *
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
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/irq.h"
#include "hw/misc/apple-silicon/baseband.h"
#include "hw/misc/apple-silicon/smc.h"
#include "hw/misc/apple-silicon/spmi-baseband.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/units.h"

// #define DEBUG_BASEBAND
#ifdef DEBUG_BASEBAND
#define DPRINTF(fmt, ...)                             \
    do {                                              \
        qemu_log_mask(LOG_UNIMP, fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define DPRINTF(fmt, ...) \
    do {                  \
    } while (0)
#endif

#define TYPE_APPLE_BASEBAND_DEVICE "apple.baseband_device"
OBJECT_DECLARE_SIMPLE_TYPE(AppleBasebandDeviceState, APPLE_BASEBAND_DEVICE)

#define TYPE_APPLE_BASEBAND "apple.baseband"
OBJECT_DECLARE_SIMPLE_TYPE(AppleBasebandState, APPLE_BASEBAND)

// #define APPLE_BASEBAND_DEVICE_BAR0_SIZE (4 * KiB)
// #define APPLE_BASEBAND_DEVICE_BAR1_SIZE (4 * KiB)
#define APPLE_BASEBAND_DEVICE_BAR0_SIZE (16 * MiB)
#define APPLE_BASEBAND_DEVICE_BAR1_SIZE (16 * MiB)

typedef struct custom_hmap_t {
    uint32_t cap_header;
    uint16_t vsec_id;
    char _6[6];
    uint32_t field_c_0x300f6;
    char _10[0x30];
    uint64_t field_40_msi_address_4KiB_aligned_BITWISE_OR_0x3;
    char _48[4];
    uint32_t field_4c_msi_address_BITWISE_AND_0xffc;
    char _50[0x10];
    uint64_t field_60_arg2_4KiB_aligned_BITWISE_OR_0x3;
    uint64_t field_68_arg3_4KiB_aligned;
} custom_hmap_t;

typedef struct custom_l1ss_t {
    uint32_t cap_header;
    uint32_t value_cap;
    uint32_t value_ctl1;
    uint32_t value_ctl2;
} custom_l1ss_t;

struct AppleBasebandDeviceState {
    PCIDevice parent_obj;
    AppleBasebandState *root;

    MemoryRegion container;
    MemoryRegion bar0;
    MemoryRegion bar1;
    MemoryRegion bar0_alias;
    MemoryRegion bar1_alias;
    // MemoryRegion msix; // no msix for now

    ApplePCIEPort *port;
    MemoryRegion *dma_mr;
    AddressSpace *dma_as;

    uint32_t hmap_hardcoded_offset;
    custom_hmap_t hmap;
    custom_l1ss_t l1ss;

    qemu_irq gpio_reset_det_irq;
    bool gpio_coredump_val;
    bool gpio_reset_det_val;
    uint32_t boot_stage;
};

struct AppleBasebandState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    AppleBasebandDeviceState *device;
#if 1
    qemu_irq irq;
#endif

    PCIBus *pci_bus;
};

#if 1
static void apple_baseband_set_irq(void *opaque, int irq_num, int level)
{
    AppleBasebandState *s = APPLE_BASEBAND(opaque);
    DPRINTF("%s: before first qemu_set_irq: host->irqs[irq_num]: %p ; irq_num: "
            "%d/0x%x ; level: %d\n",
            __func__, s->irq, irq_num, irq_num, level);
    qemu_set_irq(s->irq, level);
    DPRINTF("%s: after first qemu_set_irq: host->irqs[irq_num]: %p ; irq_num: "
            "%d/0x%x ; level: %d\n",
            __func__, s->irq, irq_num, irq_num, level);
}
#endif

static void baseband_gpio_coredump(void *opaque, int n, int level)
{
    AppleBasebandState *s = APPLE_BASEBAND(opaque);
    AppleBasebandDeviceState *s_device = s->device;
    bool coredump = !!level;
    assert(n == 0);
    DPRINTF("%s: iOS set_val: old: %d ; new %d\n", __func__,
            s_device->gpio_coredump_val, coredump);
    if (s_device->gpio_coredump_val != coredump) {
        //
    }
    s_device->gpio_coredump_val = coredump;
}

static void baseband_gpio_reset_det(void *opaque, int n, int level)
{
    AppleBasebandState *s = APPLE_BASEBAND(opaque);
    AppleBasebandDeviceState *s_device = s->device;
    bool coredump = !!level;
    assert(n == 0);
    DPRINTF("%s: iOS set_val: old: %d ; new %d\n", __func__,
            s_device->gpio_reset_det_val, coredump);
    if (s_device->gpio_reset_det_val != coredump) {
        //
    }
    s_device->gpio_reset_det_val = coredump;
}

static void baseband_gpio_set_reset_det(DeviceState *dev, int level)
{
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(dev);
    DPRINTF("%s: device set_irq: old: %d ; new %d\n", __func__,
            s->gpio_reset_det_val, level);
    s->gpio_reset_det_val = level;
    qemu_set_irq(s->gpio_reset_det_irq, level);
}

static void apple_baseband_add_pcie_cap_hmap(AppleBasebandDeviceState *s,
                                             PCIDevice *dev)
{
    DPRINTF("%s: pci_is_express: %d\n", __func__, pci_is_express(dev));
    g_assert_cmpuint(sizeof(s->hmap), ==, 0x70);
    memset(&s->hmap, 0x0, sizeof(s->hmap));
    s->hmap.vsec_id = 0x24;
    pcie_add_capability(dev, PCI_EXT_CAP_ID_VNDR, 0x0, s->hmap_hardcoded_offset,
                        sizeof(s->hmap));
    // TODO: this might/will not work on big-endian
    // don't override the type, skip the first four bytes.
    memcpy(dev->config + s->hmap_hardcoded_offset + 4, &s->hmap.vsec_id,
           sizeof(s->hmap) - 4);
    // make it read-write, because iOS needs to write to it
    memset(dev->wmask + s->hmap_hardcoded_offset, 0xff, sizeof(s->hmap));
}

static uint8_t *apple_baseband_dma_read(AppleBasebandDeviceState *s,
                                        uint64_t offset, uint64_t size)
{
    uint8_t *buf;

    DPRINTF("%s: READ @ 0x" HWADDR_FMT_plx " size: 0x" HWADDR_FMT_plx "\n",
            __func__, offset, size);

    buf = g_malloc(size);
    if (dma_memory_read(s->dma_as, offset, buf, size, MEMTXATTRS_UNSPECIFIED) !=
        MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: Failed to read from DMA.",
                      __func__);
        g_free(buf);
        return NULL;
    }
    return buf;
}

static void apple_baseband_dma_write(AppleBasebandDeviceState *s,
                                     uint64_t offset, uint64_t size,
                                     uint8_t *buf)
{
    DPRINTF("%s: WRITE @ 0x" HWADDR_FMT_plx " size: 0x" HWADDR_FMT_plx "\n",
            __func__, offset, size);

    if (dma_memory_write(s->dma_as, offset, buf, size,
                         MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: Failed to write to DMA.", __func__);
    }
}

static void apple_baseband_device_bar0_write(void *opaque, hwaddr addr,
                                             uint64_t data, unsigned size)
{
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(opaque);

    DPRINTF("%s: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx "\n",
            __func__, addr, data);
    switch (addr) {
    default:
        break;
    }
}

typedef struct QEMU_PACKED custom_baseband0_t {
    uint16_t unkn0; // 0x0
    uint8_t chip_id; // 0x2 ; ChipID
    uint8_t unkn1; // 0x3
    uint8_t pad0[6]; // 0x4
    uint8_t serial_number[12]; // 0xa ; ChipSerialNo/SNUM
    uint32_t cert_id; // 0x16 ; CertID/CERTID
    uint8_t public_key_hash[28]; // 0x1a ; PKHASH/CertHash
    uint8_t pad1[6]; // 0x36
} custom_baseband0_t;

static uint64_t apple_baseband_device_bar0_read(void *opaque, hwaddr addr,
                                                unsigned size)
{
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(opaque);
    // uint32_t *mmio = &s->vendor_reg[addr >> 2];
    // uint32_t val = *mmio;
    uint32_t val = 0x0;
    uint32_t vals[0x3c / 4] = { 0 };
    custom_baseband0_t custom_baseband0 = { 0 };
    g_assert_cmpuint(sizeof(custom_baseband0), ==, 60);
    memset(&custom_baseband0, 0x0, sizeof(custom_baseband0));

    switch (addr) {
    case 0x0: // boot stage
        val = s->boot_stage;
        // baseband_gpio_set_reset_det(DEVICE(s), 0);
        baseband_gpio_set_reset_det(DEVICE(s), 1);
        break;
    case 0x4 ... 0x3c:
        custom_baseband0.unkn0 = 0xdead;
        custom_baseband0.chip_id = 0x60; // chip-id
        custom_baseband0.unkn1 = 0xfe;
        memcpy(custom_baseband0.pad0, "FOBART",
               sizeof(custom_baseband0.pad0)); // non-null-terminated
        memcpy(custom_baseband0.serial_number, "SNUMSNUMSNUM",
               sizeof(custom_baseband0.serial_number)); // non-null-terminated
        // iPhone 11 value from wiki. random iPhone 7 log value is found in a
        // wiki page, so the values should be good.
        custom_baseband0.cert_id = 524245983;
        memcpy(custom_baseband0.public_key_hash, "HASHHASHHASHHASHHASHHASHHASH",
               sizeof(custom_baseband0.public_key_hash)); // non-null-terminated
        memcpy(custom_baseband0.pad1, "67890A",
               sizeof(custom_baseband0.pad1)); // non-null-terminated
        uint8_t *custom_baseband0_ptr = (uint8_t *)&custom_baseband0;
        val = ldl_le_p(custom_baseband0_ptr + addr - 0x4);
    default:
        break;
    }

    DPRINTF("%s: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            " size %d\n",
            __func__, addr, val, size);
    return val;
}

static const MemoryRegionOps bar0_ops = {
    .read = apple_baseband_device_bar0_read,
    .write = apple_baseband_device_bar0_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl =
        {
            .min_access_size = 4,
            .max_access_size = 4,
        },
};

static void apple_baseband_device_bar1_write(void *opaque, hwaddr addr,
                                             uint64_t data, unsigned size)
{
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(opaque);
    ApplePCIEPort *port = APPLE_PCIE_PORT(object_property_get_link(
        OBJECT(qdev_get_machine()), "pcie.bridge3", &error_fatal));
    ApplePCIEHost *host = port->host;
    ApplePCIEState *pcie = host->pcie;
    AppleSPMIBasebandState *spmi = APPLE_SPMI_BASEBAND(object_property_get_link(
        OBJECT(qdev_get_machine()), "baseband-spmi", &error_fatal));
    int i, j;

    DPRINTF("%s: WRITE @ 0x" HWADDR_FMT_plx " value: 0x" HWADDR_FMT_plx "\n",
            __func__, addr, data);
    switch (addr) {
    case 0x90:
        // bit0
#if 0
        if ((data & 1) != 0) {
        }
#endif
        break;
    default:
        break;
    }
}

static uint64_t apple_baseband_device_bar1_read(void *opaque, hwaddr addr,
                                                unsigned size)
{
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(opaque);
    uint32_t val = 0x0;

    switch (addr) {
    default:
        break;
    }

    DPRINTF("%s: READ @ 0x" HWADDR_FMT_plx " value: 0x%x"
            "\n",
            __func__, addr, val);
    return val;
}

static const MemoryRegionOps bar1_ops = {
    .read = apple_baseband_device_bar1_read,
    .write = apple_baseband_device_bar1_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl =
        {
            .min_access_size = 4,
            .max_access_size = 4,
        },
};

static uint8_t smc_key_gP07_read(AppleSMCState *s, SMCKey *key,
                                 SMCKeyData *data, void *payload,
                                 uint8_t length)
{
    uint32_t value;
    uint32_t tmpval0;

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    value = ldl_le_p(payload);

    if (data->data == NULL) {
        data->data = g_malloc(key->info.size);
    } else {
        uint32_t *data0 = data->data;
        DPRINTF("%s: data->data: %p ; data0[0]: 0x%08x\n", __func__,
                data->data, data0[0]);
    }

    DPRINTF("%s: key->info.size: 0x%08x ; length: 0x%08x\n", __func__,
            key->info.size, length);
    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value,
            length);

    switch (value) {
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_gP07_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    AppleRTKit *rtk;
    uint32_t value;
    KeyResponse r;

    AppleBasebandState *baseband = APPLE_BASEBAND(object_property_get_link(
        OBJECT(qdev_get_machine()), "baseband", &error_fatal));
    ApplePCIEPort *port = APPLE_PCIE_PORT(object_property_get_link(
        OBJECT(qdev_get_machine()), "pcie.bridge3", &error_fatal));
    ApplePCIEHost *host = port->host;
    ApplePCIEState *pcie = host->pcie;
    PCIDevice *port_pci_dev = PCI_DEVICE(port);

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    rtk = APPLE_RTKIT(s);
    value = ldl_le_p(payload);

    // Do not use data->data here, as it only contains the data last written to
    // by the read function (smc_key_gP09_read)

    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value,
            length);

    switch (value) {
    // function-bb_on: 0x00800000 write?
    // AppleBasebandPlatform::setPowerOnBBPMUPinGated: bit0 == enable
    case 0x00800000:
    case 0x00800001: {
        int enable_baseband_power = (value & 1) != 0;
        DPRINTF("%s: setPowerOnBBPMUPinGated/bb_on enable: %d\n",
                __func__, enable_baseband_power);
        return kSMCSuccess;
    }
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_gP09_read(AppleSMCState *s, SMCKey *key,
                                 SMCKeyData *data, void *payload,
                                 uint8_t length)
{
    uint32_t value;
    uint32_t tmpval0;

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    value = ldl_le_p(payload);

    if (data->data == NULL) {
        data->data = g_malloc(key->info.size);
    } else {
        uint32_t *data0 = data->data;
        DPRINTF("%s: data->data: %p ; data0[0]: 0x%08x\n", __func__,
                data->data, data0[0]);
    }

    DPRINTF("%s: key->info.size: 0x%08x ; length: 0x%08x\n", __func__,
            key->info.size, length);
    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value,
            length);

    switch (value) {
    // function-pmu_exton: 0x02000000 read?
    case 0x02000000: {
        DPRINTF("%s: pmu_exton\n", __func__);
        return kSMCSuccess;
    }
    case 0x06000000: {
        DPRINTF("%s: getVectorType\n", __func__);
        // AppleSMCPMU::getVectorType
        // value 0x0/0x1 means vector type "Level", else "Edge"
        // tmpval0 = 0x0;
        tmpval0 = 0x1;
        // tmpval0 = 0x2;
        memcpy(data->data, &tmpval0, sizeof(tmpval0));
        return kSMCSuccess;
    }
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_gP09_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    AppleRTKit *rtk;
    uint32_t value;
    KeyResponse r;

    AppleBasebandState *baseband = APPLE_BASEBAND(object_property_get_link(
        OBJECT(qdev_get_machine()), "baseband", &error_fatal));
    ApplePCIEPort *port = APPLE_PCIE_PORT(object_property_get_link(
        OBJECT(qdev_get_machine()), "pcie.bridge3", &error_fatal));
    ApplePCIEHost *host = port->host;
    ApplePCIEState *pcie = host->pcie;
    PCIDevice *port_pci_dev = PCI_DEVICE(port);

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    rtk = APPLE_RTKIT(s);
    value = ldl_le_p(payload);

    // Do not use data->data here, as it only contains the data last written to
    // by the read function (smc_key_gP09_read)

    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value,
            length);

    switch (value) {
    case 0x04000000: {
        // disableVectorHard/IENA
        DPRINTF("%s: disableVectorHard\n", __func__);
        return kSMCSuccess;
    }
    case 0x04000001: {
        // enableVector/IENA
        DPRINTF("%s: enableVector\n", __func__);
        return kSMCSuccess;
    }
    // function-pmu_exton_config: 0x07000000/0x07000001 write?
    case 0x07000000:
    // case 0x0700dead:
    case 0x07000001: {
        // AppleBasebandPlatform::pmuExtOnConfigGated
        // bit0 == use_pmuExtOnConfigOverride_enabled == maybe enable baseband
        // bit0 == pull-down enabled
        int use_pmuExtOnConfigOverride_enabled = (value & 1) != 0;
        DPRINTF("%s: pmuExtOnConfigGated/pmu_exton_config enable: %d\n",
                __func__, use_pmuExtOnConfigOverride_enabled);
#if 0
    AppleSPMIBasebandState *baseband_spmi = APPLE_SPMI_BASEBAND(object_property_get_link(OBJECT(qdev_get_machine()), "baseband-spmi", &error_fatal));
    g_assert_nonnull(baseband_spmi);
#endif
        return kSMCSuccess;
    }
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_gP11_read(AppleSMCState *s, SMCKey *key,
                                 SMCKeyData *data, void *payload,
                                 uint8_t length)
{
    uint32_t value;
    uint32_t tmpval0;

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    value = ldl_le_p(payload);

    if (data->data == NULL) {
        data->data = g_malloc(key->info.size);
    } else {
        uint32_t *data0 = data->data;
        DPRINTF("%s: data->data: %p ; data0[0]: 0x%08x\n", __func__,
                data->data, data0[0]);
    }

    DPRINTF("%s: key->info.size: 0x%08x ; length: 0x%08x\n", __func__,
            key->info.size, length);
    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value,
            length);

    switch (value) {
    // gP11 is actually for amfm (wifi/bluetooth-pcie bridge)
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_gP11_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    AppleRTKit *rtk;
    uint32_t value;
    KeyResponse r;

    AppleBasebandState *baseband = APPLE_BASEBAND(object_property_get_link(
        OBJECT(qdev_get_machine()), "baseband", &error_fatal));
    ApplePCIEPort *port = APPLE_PCIE_PORT(object_property_get_link(
        OBJECT(qdev_get_machine()), "pcie.bridge3", &error_fatal));
    ApplePCIEHost *host = port->host;
    ApplePCIEState *pcie = host->pcie;
    PCIDevice *port_pci_dev = PCI_DEVICE(port);

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    rtk = APPLE_RTKIT(s);
    value = ldl_le_p(payload);

    // Do not use data->data here, as it only contains the data last written to
    // by the read function (smc_key_gP09_read)

    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value,
            length);

    switch (value) {
    // gP11 is actually for amfm (wifi/bluetooth-pcie bridge)
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

SysBusDevice *apple_baseband_create(DTBNode *node, PCIBus *pci_bus,
                                    ApplePCIEPort *port)
{
    DeviceState *dev;
    AppleBasebandState *s;
    SysBusDevice *sbd;
    DTBNode *child;
    DTBProp *prop;
    uint64_t *reg;
    MemoryRegion *alias;
    PCIDevice *pci_dev;

    dev = qdev_new(TYPE_APPLE_BASEBAND);
    s = APPLE_BASEBAND(dev);
    sbd = SYS_BUS_DEVICE(dev);

#if 0
    prop = dtb_find_prop(node, "reg");
    g_assert_nonnull(prop);

    reg = (uint64_t *)prop->data;
#endif

#if 1
    sysbus_init_irq(sbd, &s->irq);
    // qdev_init_gpio_in_named(dev, apple_baseband_set_irq, "interrupt_pci", 1);
#endif

    s->pci_bus = pci_bus;
    pci_dev = pci_new(-1, TYPE_APPLE_BASEBAND_DEVICE);
    s->device = APPLE_BASEBAND_DEVICE(pci_dev);
    s->device->root = s;
    s->device->port = port;
    s->device->dma_mr = port->dma_mr;
    s->device->dma_as = &port->dma_as;

    object_property_add_child(OBJECT(s), "device", OBJECT(s->device));

    // smc-pmu
    AppleSMCState *smc = APPLE_SMC_IOP(object_property_get_link(
        OBJECT(qdev_get_machine()), "smc", &error_fatal));
    apple_smc_create_key_func(smc, 'gP07', 4, SMCKeyTypeUInt32,
                        SMC_ATTR_FUNCTION | SMC_ATTR_WRITEABLE |
                            SMC_ATTR_READABLE | 0x20,
                        &smc_key_gP07_read, &smc_key_gP07_write);
    apple_smc_create_key_func(smc, 'gP09', 4, SMCKeyTypeUInt32,
                        SMC_ATTR_FUNCTION | SMC_ATTR_WRITEABLE |
                            SMC_ATTR_READABLE | 0x20,
                        &smc_key_gP09_read, &smc_key_gP09_write);
    apple_smc_create_key_func(smc, 'gP11', 4, SMCKeyTypeUInt32,
                        SMC_ATTR_FUNCTION | SMC_ATTR_WRITEABLE |
                            SMC_ATTR_READABLE | 0x20,
                        &smc_key_gP11_read, &smc_key_gP11_write);
    // TODO: gP09/gP11 are 0xf0, so gP07 should be as well.
    // TODO: missing, according to t8015, gP01/gp05/gp0e/gp0f/gp12/gp13/gp15

    return sbd;
}

static void apple_baseband_device_pci_realize(PCIDevice *dev, Error **errp)
{
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(dev);
    uint8_t *pci_conf = dev->config;
    int ret, i;

    pci_set_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID, 0);
    pci_set_word(pci_conf + PCI_SUBSYSTEM_ID, 0);

    memory_region_init_io(&s->bar0, OBJECT(dev), &bar0_ops, s,
                          "apple-baseband-device-bar0",
                          APPLE_BASEBAND_DEVICE_BAR0_SIZE);
    memory_region_init_io(&s->bar1, OBJECT(dev), &bar1_ops, s,
                          "apple-baseband-device-bar1",
                          APPLE_BASEBAND_DEVICE_BAR1_SIZE);

    g_assert_true(pci_is_express(dev));
    pcie_endpoint_cap_init(dev, 0x70);

    pcie_cap_deverr_init(dev);
    msi_nonbroken = true;
    msi_init(dev, 0x50, 1, true, false, &error_fatal);
    pci_pm_init(dev, 0x40, &error_fatal);
    // warning: this will override the settings of the ports as well.
    // for S8000
    if (s->port->maximum_link_speed == 2) {
        pcie_cap_fill_link_ep_usp(dev, QEMU_PCI_EXP_LNK_X2,
                                  QEMU_PCI_EXP_LNK_8GT);
    }
    // for T8030
    if (s->port->maximum_link_speed == 1) {
        pcie_cap_fill_link_ep_usp(dev, QEMU_PCI_EXP_LNK_X2,
                                  QEMU_PCI_EXP_LNK_5GT);
    }
    // sizes: 0x50 for the bridges and qualcomm baseband,
    // 0x3c for broadcom wifi, 0x48 for nvme
    // versions: 1 for broadcom wifi, 2 for the rest
    // // pcie_aer_init(pci_dev, 1, 0x100, PCI_ERR_SIZEOF, &error_fatal);
    // pcie_aer_init(dev, PCI_ERR_VER, 0x100, 0x50, &error_fatal);
    pcie_aer_init(dev, PCI_ERR_VER, 0x100, PCI_ERR_SIZEOF, &error_fatal);

    // TODO: under S8000, bar0/bar2 have the same address/size and are 64-bit
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar0);
    pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar1);
#define BASEBAND_BAR_SUB_ADDR 0x40000000ULL
    memory_region_init(&s->container, OBJECT(s), "baseband-bar-container", APPLE_BASEBAND_DEVICE_BAR0_SIZE + APPLE_BASEBAND_DEVICE_BAR1_SIZE);
    // these aliases are needed, because iOS will mess with the pci subregions
    memory_region_init_alias(&s->bar0_alias, OBJECT(s), "baseband-bar0-alias",
                             &s->bar0, 0x0, APPLE_BASEBAND_DEVICE_BAR0_SIZE);
    memory_region_init_alias(&s->bar1_alias, OBJECT(s), "baseband-bar1-alias",
                             &s->bar1, 0x0, APPLE_BASEBAND_DEVICE_BAR1_SIZE);
    memory_region_add_subregion(&s->container, 0x0000, &s->bar0_alias);
    memory_region_add_subregion(&s->container, APPLE_BASEBAND_DEVICE_BAR0_SIZE, &s->bar1_alias);
    memory_region_add_subregion(get_system_memory(), APCIE_ROOT_COMMON_ADDRESS + BASEBAND_BAR_SUB_ADDR + 0x0000, &s->container);
}

static void apple_baseband_device_qdev_reset_hold(Object *obj, ResetType type)
{
    PCIDevice *dev = PCI_DEVICE(obj);
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(dev);

    pci_set_word(dev->config + PCI_COMMAND,
                 PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

    // Don't risk any overlap here. e.g. with AER
    s->hmap_hardcoded_offset = 0x180;
    apple_baseband_add_pcie_cap_hmap(s, dev);
    //apple_baseband_add_pcie_cap_l1ss(s, dev);
    s->gpio_coredump_val = 0;
    s->gpio_reset_det_val = 0;
    baseband_gpio_set_reset_det(DEVICE(s), 0);

    // s->boot_stage = 0xfeedb007; // rom stage is legacy
    // s->boot_stage = 0xffffffff; // failed to read execution environment
    s->boot_stage = 0x0;
    // s->boot_stage = 0x2; // this stage will skip HMAP

    // TODO: pcie_cap_slot_reset can and will silently revert
    // set_power/set_enable when it's being done here
    DPRINTF("%s: port_manual_enable: %d ; dev->enabled: %d\n", __func__,
            s->port->manual_enable, dev->enabled);
}

static void apple_baseband_device_pci_uninit(PCIDevice *dev)
{
    AppleBasebandDeviceState *s = APPLE_BASEBAND_DEVICE(dev);

    pcie_aer_exit(dev);
    pcie_cap_exit(dev);
    msi_uninit(dev);
}

static void apple_baseband_device_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *c = PCI_DEVICE_CLASS(class);
    ResettableClass *rc = RESETTABLE_CLASS(class);

    c->realize = apple_baseband_device_pci_realize;
    c->exit = apple_baseband_device_pci_uninit;
    c->vendor_id = 0x17cb;
    c->device_id = 0x0300;
    c->revision = 0x00;
    c->class_id = PCI_CLASS_OTHERS;

    rc->phases.hold = apple_baseband_device_qdev_reset_hold;

    dc->desc = "Apple Baseband Device";
    dc->user_creatable = false;

    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);

    dc->hotpluggable = false;
}

static void apple_baseband_realize(DeviceState *dev, Error **errp)
{
    AppleBasebandState *s = APPLE_BASEBAND(dev);
    AppleBasebandDeviceState *s_device = s->device;
    PCIDevice *pci_dev = PCI_DEVICE(s->device);
    qdev_realize(DEVICE(s->device), BUS(s->pci_bus), &error_fatal);

    qdev_init_gpio_in_named(DEVICE(s), apple_baseband_set_irq, "interrupt_pci",
                            1);
    qdev_init_gpio_in_named(DEVICE(s), baseband_gpio_coredump,
                            BASEBAND_GPIO_COREDUMP, 1);
    qdev_init_gpio_in_named(DEVICE(s), baseband_gpio_reset_det,
                            BASEBAND_GPIO_RESET_DET_IN, 1);
    qdev_init_gpio_out_named(DEVICE(s), &s_device->gpio_reset_det_irq,
                             BASEBAND_GPIO_RESET_DET_OUT, 1);
}

static void apple_baseband_unrealize(DeviceState *dev)
{
    AppleBasebandState *s = APPLE_BASEBAND(dev);
}

static const VMStateDescription vmstate_apple_baseband = {
    .name = "apple_baseband",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_END_OF_LIST(),
        }
};

static void apple_baseband_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_baseband_realize;
    dc->unrealize = apple_baseband_unrealize;
    dc->desc = "Apple Baseband";
    dc->vmsd = &vmstate_apple_baseband;
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
}

static const TypeInfo apple_baseband_types[] = {
    {
        .name = TYPE_APPLE_BASEBAND_DEVICE,
        .parent = TYPE_PCI_DEVICE,
        .instance_size = sizeof(AppleBasebandDeviceState),
        .class_init = apple_baseband_device_class_init,
        .interfaces = (InterfaceInfo[]) {
            { INTERFACE_PCIE_DEVICE },
            { }
        },
    },
    {
        .name = TYPE_APPLE_BASEBAND,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(AppleBasebandState),
        .class_init = apple_baseband_class_init,
    },
};

DEFINE_TYPES(apple_baseband_types)
