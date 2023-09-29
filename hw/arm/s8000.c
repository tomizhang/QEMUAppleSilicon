/*
 * iPhone 6s - S8000
 *
 * Copyright (c) 2019 Johnathan Afek <jonyafek@me.com>
 * Copyright (c) 2021 Nguyen Hoang Trung (TrungNguyen1909)
 * Copyright (c) 2023 Visual Ehrmanntraut.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "hw/arm/apple_a9.h"
#include "hw/arm/apple_dart.h"
#include "hw/arm/apple_sep.h"
#include "hw/arm/boot.h"
#include "hw/arm/exynos4210.h"
#include "hw/arm/s8000.h"
#include "hw/arm/xnu_pf.h"
#include "hw/gpio/apple_gpio.h"
#include "hw/i2c/apple_i2c.h"
#include "hw/intc/apple_aic.h"
#include "hw/irq.h"
#include "hw/misc/apple_aes.h"
#include "hw/misc/unimp.h"
#include "hw/nvram/apple_nvram.h"
#include "hw/or-irq.h"
#include "hw/platform-bus.h"
#include "hw/ssi/apple_spi.h"
#include "hw/usb/apple_otg.h"
#include "hw/watchdog/apple_wdt.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "sysemu/block-backend.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"

#define S8000_SROM_BASE (0x100000000ULL)
#define S8000_SROM_SIZE (0x80000ULL)
#define S8000_SRAM_BASE (0x180000000ULL)
#define S8000_SRAM_SIZE (0x400000ULL)
#define S8000_DRAM_BASE (0x800000000ULL)
#define S8000_DRAM_SIZE (2 * GiB)
#define S8000_SPI0_BASE (0x00A080000ULL)
#define S8000_SPI0_IRQ (188)

#define S8000_SEPROM_BASE (0x20D000000ULL)
#define S8000_SEPROM_SIZE (0x001000000ULL)

#define S8000_GPIO_HOLD_KEY (97)
#define S8000_GPIO_MENU_KEY (96)
#define S8000_GPIO_SPI0_CS (106)
#define S8000_GPIO_FORCE_DFU (123)
#define S8000_GPIO_DFU_STATUS (136)

// static void s8000_wake_up_cpus(MachineState *machine, uint64_t cpu_mask)
// {
//     S8000MachineState *tms = S8000_MACHINE(machine);
//     int i;

//     for (i = 0; i < machine->smp.cpus - 1; i++) {
//         if (test_bit(i, (unsigned long *)&cpu_mask) &&
//             apple_a9_is_sleep(tms->cpus[i])) {
//             apple_a9_wakeup(tms->cpus[i]);
//         }
//     }
// }

static void s8000_create_s3c_uart(const S8000MachineState *tms, Chardev *chr)
{
    DeviceState *dev;
    hwaddr base;
    // first fetch the uart mmio address
    int vector;
    DTBProp *prop;
    hwaddr *uart_offset;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    g_assert(child);

    child = find_dtb_node(child, "uart0");
    g_assert(child);

    // make sure this node has the boot-console prop
    prop = find_dtb_prop(child, "boot-console");
    g_assert(prop);

    prop = find_dtb_prop(child, "reg");
    g_assert(prop);

    uart_offset = (hwaddr *)prop->value;
    base = tms->soc_base_pa + uart_offset[0];

    prop = find_dtb_prop(child, "interrupts");
    g_assert(prop);

    vector = *(uint32_t *)prop->value;
    dev = exynos4210_uart_create(base, 256, 0, chr,
                                 qdev_get_gpio_in(DEVICE(tms->aic), vector));
    g_assert(dev);
}

// static void s8000_patch_kernel(struct mach_header_64 *hdr)
// {
// }

static bool s8000_check_panic(MachineState *machine)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    if (!tms->panic_size) {
        return false;
    }
    g_autofree struct xnu_embedded_panic_header *panic_info =
        g_malloc0(tms->panic_size);
    g_autofree void *buffer = g_malloc0(tms->panic_size);

    address_space_rw(&address_space_memory, tms->panic_base,
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)panic_info,
                     tms->panic_size, 0);
    address_space_rw(&address_space_memory, tms->panic_base,
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)buffer, tms->panic_size,
                     1);

    return panic_info->eph_magic == EMBEDDED_PANIC_MAGIC;
}

static void s8000_memory_setup(MachineState *machine)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    AddressSpace *nsas = &address_space_memory;
    g_autofree char *securerom = NULL;
    g_autofree char *seprom = NULL;
    unsigned long fsize = 0;

    // setup the memory layout:
    if (s8000_check_panic(machine)) {
        qemu_system_guest_panicked(NULL);
        return;
    }

    if (machine->firmware == NULL) {
        error_report("Please set firmware to SecureROM's path");
        exit(EXIT_FAILURE);
    }

    if (!g_file_get_contents(machine->firmware, &securerom, &fsize, NULL)) {
        error_report("Could not load data from file '%s'", machine->firmware);
        exit(EXIT_FAILURE);
    }
    address_space_rw(nsas, S8000_SROM_BASE, MEMTXATTRS_UNSPECIFIED,
                     (uint8_t *)securerom, fsize, true);

    if (tms->seprom_filename == NULL) {
        error_report("Please set path to SEPROM");
        exit(EXIT_FAILURE);
    }

    if (!g_file_get_contents(tms->seprom_filename, &seprom, &fsize, NULL)) {
        error_report("Could not load data from file '%s'",
                     tms->seprom_filename);
        exit(EXIT_FAILURE);
    }
    address_space_rw(nsas, S8000_SEPROM_BASE, MEMTXATTRS_UNSPECIFIED,
                     (uint8_t *)seprom, fsize, true);
}

static void pmgr_unk_reg_write(void *opaque, hwaddr addr, uint64_t data,
                               unsigned size)
{
    hwaddr base = (hwaddr)opaque;
    qemu_log_mask(LOG_UNIMP,
                  "PMGR reg WRITE unk @ 0x" TARGET_FMT_lx
                  " base: 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n",
                  base + addr, base, data);
}

static uint64_t pmgr_unk_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    hwaddr base = (hwaddr)opaque;

    switch (base + addr) {
    case 0x102BC000: //! CFG_FUSE0
        return (1 << 2);
    case 0x102BC200: //! CFG_FUSE0_RAW
        return 0x0;
    case 0x102BC080: //! ECID_LO
        return 0x13371337;
    case 0x102BC084: //! ECID_HI
        return 0xDEADBEEF;
    case 0x102E8000: // ????
        return 0x4;
    case 0x102BC104: // ???? bit 24 => is fresh boot?
        return (1 << 24) | (1 << 25);
    default:
        qemu_log_mask(LOG_UNIMP,
                      "PMGR reg READ unk @ 0x" TARGET_FMT_lx
                      " base: 0x" TARGET_FMT_lx "\n",
                      base + addr, base);
        break;
    }
    return 0;
}

static const MemoryRegionOps pmgr_unk_reg_ops = {
    .write = pmgr_unk_reg_write,
    .read = pmgr_unk_reg_read,
};

static void pmgr_reg_write(void *opaque, hwaddr addr, uint64_t data,
                           unsigned size)
{
    S8000MachineState *tms = S8000_MACHINE(opaque);
    uint32_t value = data;

    qemu_log_mask(LOG_UNIMP,
                  "PMGR reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx
                  "\n",
                  addr, data);

    if (addr >= 0x80000 && addr <= 0x88010) {
        value = (value & 0xf) << 4 | (value & 0xf);
    }

    switch (addr) {
    case 0x80400: //! SEP Power State, Manual & Actual: Run Max
        value = 0xFF;
        break;
    default:
        break;
    }
    memcpy(tms->pmgr_reg + addr, &value, size);
}

static uint64_t pmgr_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    S8000MachineState *tms = S8000_MACHINE(opaque);
    uint64_t result = 0;
    qemu_log_mask(LOG_UNIMP, "PMGR reg READ @ 0x" TARGET_FMT_lx "\n", addr);

    memcpy(&result, tms->pmgr_reg + addr, size);
    return result;
}

static const MemoryRegionOps pmgr_reg_ops = {
    .write = pmgr_reg_write,
    .read = pmgr_reg_read,
};

static void s8000_cpu_setup(MachineState *machine)
{
    unsigned int i;
    DTBNode *root;
    S8000MachineState *tms = S8000_MACHINE(machine);
    GList *iter;
    GList *next = NULL;

    root = find_dtb_node(tms->device_tree, "cpus");
    g_assert(root);
    object_initialize_child(OBJECT(machine), "cluster", &tms->cluster,
                            TYPE_CPU_CLUSTER);
    qdev_prop_set_uint32(DEVICE(&tms->cluster), "cluster-id", 0);

    for (iter = root->child_nodes, i = 0; iter; iter = next, i++) {
        DTBNode *node;

        next = iter->next;
        node = (DTBNode *)iter->data;
        if (i >= machine->smp.cpus - 1) {
            remove_dtb_node(root, node);
            continue;
        }

        tms->cpus[i] = apple_a9_create(node, NULL, 0, 0);

        object_property_add_child(OBJECT(&tms->cluster),
                                  DEVICE(tms->cpus[i])->id,
                                  OBJECT(tms->cpus[i]));

        qdev_realize(DEVICE(tms->cpus[i]), NULL, &error_fatal);
    }
    qdev_realize(DEVICE(&tms->cluster), NULL, &error_fatal);
}

static void s8000_create_aic(MachineState *machine)
{
    unsigned int i;
    hwaddr *reg;
    DTBProp *prop;
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *soc = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *child;
    DTBNode *timebase;

    g_assert(soc);
    child = find_dtb_node(soc, "aic");
    g_assert(child);
    timebase = find_dtb_node(soc, "aic-timebase");
    g_assert(timebase);

    tms->aic = apple_aic_create(machine->smp.cpus - 1, child, timebase);
    object_property_add_child(OBJECT(machine), "aic", OBJECT(tms->aic));
    g_assert(tms->aic);
    sysbus_realize(tms->aic, &error_fatal);

    prop = find_dtb_prop(child, "reg");
    g_assert(prop);

    reg = (hwaddr *)prop->value;

    for (i = 0; i < machine->smp.cpus - 1; i++) {
        memory_region_add_subregion_overlap(
            &tms->cpus[i]->memory, tms->soc_base_pa + reg[0],
            sysbus_mmio_get_region(tms->aic, i), 0);
        sysbus_connect_irq(tms->aic, i,
                           qdev_get_gpio_in(DEVICE(tms->cpus[i]), ARM_CPU_IRQ));
    }
}

static void s8000_pmgr_setup(MachineState *machine)
{
    uint64_t *reg;
    int i;
    char name[32];
    DTBProp *prop;
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    g_assert(child);
    child = find_dtb_node(child, "pmgr");
    g_assert(child);

    prop = find_dtb_prop(child, "reg");
    g_assert(prop);

    reg = (uint64_t *)prop->value;

    for (i = 0; i < prop->length / 8; i += 2) {
        MemoryRegion *mem = g_new(MemoryRegion, 1);
        if (i > 0) {
            snprintf(name, 32, "pmgr-unk-reg-%d", i);
            memory_region_init_io(mem, OBJECT(machine), &pmgr_unk_reg_ops,
                                  (void *)reg[i], name, reg[i + 1]);
        } else {
            memory_region_init_io(mem, OBJECT(machine), &pmgr_reg_ops, tms,
                                  "pmgr-reg", reg[i + 1]);
        }
        memory_region_add_subregion_overlap(
            tms->sysmem,
            reg[i] + reg[i + 1] < tms->soc_size ? tms->soc_base_pa + reg[i] :
                                                  reg[i],
            mem, -1);
    }
}

// static void s8000_create_dart(MachineState *machine, const char *name)
// {
//     AppleDARTState *dart = NULL;
//     DTBProp *prop;
//     uint64_t *reg;
//     uint32_t *ints;
//     int i;
//     S8000MachineState *tms = S8000_MACHINE(machine);
//     DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

//     g_assert(child);
//     child = find_dtb_node(child, name);
//     if (!child)
//         return;

//     dart = apple_dart_create(child);
//     g_assert(dart);
//     object_property_add_child(OBJECT(machine), name, OBJECT(dart));

//     prop = find_dtb_prop(child, "reg");
//     g_assert(prop);

//     reg = (uint64_t *)prop->value;

//     for (int i = 0; i < prop->length / 16; i++) {
//         sysbus_mmio_map(SYS_BUS_DEVICE(dart), i, tms->soc_base_pa + reg[i *
//         2]);
//     }

//     prop = find_dtb_prop(child, "interrupts");
//     g_assert(prop);
//     ints = (uint32_t *)prop->value;

//     for (i = 0; i < prop->length / sizeof(uint32_t); i++) {
//         sysbus_connect_irq(SYS_BUS_DEVICE(dart), i,
//                            qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
//     }

//     sysbus_realize_and_unref(SYS_BUS_DEVICE(dart), &error_fatal);
// }

static void s8000_create_gpio(MachineState *machine, const char *name)
{
    DeviceState *gpio = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    int i;
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    child = find_dtb_node(child, name);
    g_assert(child);
    gpio = apple_gpio_create(child);
    g_assert(gpio);
    object_property_add_child(OBJECT(machine), name, OBJECT(gpio));

    prop = find_dtb_prop(child, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;
    sysbus_mmio_map(SYS_BUS_DEVICE(gpio), 0, tms->soc_base_pa + reg[0]);
    prop = find_dtb_prop(child, "interrupts");
    g_assert(prop);

    ints = (uint32_t *)prop->value;

    for (i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(gpio), i,
                           qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(gpio), &error_fatal);
}

static void s8000_create_i2c(MachineState *machine, const char *name)
{
    SysBusDevice *i2c;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    int i;
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    child = find_dtb_node(child, name);
    g_assert(child);
    i2c = apple_i2c_create(name);
    g_assert(i2c);
    object_property_add_child(OBJECT(machine), name, OBJECT(i2c));

    prop = find_dtb_prop(child, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;
    sysbus_mmio_map(i2c, 0, tms->soc_base_pa + reg[0]);
    prop = find_dtb_prop(child, "interrupts");
    g_assert(prop);

    ints = (uint32_t *)prop->value;

    for (i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(i2c, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(i2c, &error_fatal);
}

static void s8000_create_spi0(MachineState *machine)
{
    DeviceState *spi = NULL;
    DeviceState *gpio = NULL;
    S8000MachineState *tms = S8000_MACHINE(machine);
    const char *name = "spi0";

    spi = qdev_new(TYPE_APPLE_SPI);
    g_assert(spi);
    DEVICE(spi)->id = g_strdup(name);

    object_property_add_child(OBJECT(machine), name, OBJECT(spi));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(spi), &error_fatal);

    sysbus_mmio_map(SYS_BUS_DEVICE(spi), 0, tms->soc_base_pa + S8000_SPI0_BASE);

    sysbus_connect_irq(SYS_BUS_DEVICE(spi), 0,
                       qdev_get_gpio_in(DEVICE(tms->aic), S8000_SPI0_IRQ));
    // The second sysbus IRQ is the cs line
    gpio =
        DEVICE(object_property_get_link(OBJECT(machine), "gpio", &error_fatal));
    qdev_connect_gpio_out(gpio, S8000_GPIO_SPI0_CS,
                          qdev_get_gpio_in_named(spi, SSI_GPIO_CS, 0));
}

static void s8000_create_spi(MachineState *machine, const char *name)
{
    SysBusDevice *spi = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    child = find_dtb_node(child, name);
    g_assert(child);
    spi = apple_spi_create(child);
    g_assert(spi);
    object_property_add_child(OBJECT(machine), name, OBJECT(spi));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(spi), &error_fatal);

    prop = find_dtb_prop(child, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;
    sysbus_mmio_map(SYS_BUS_DEVICE(spi), 0, tms->soc_base_pa + reg[0]);
    prop = find_dtb_prop(child, "interrupts");
    g_assert(prop);

    // The second sysbus IRQ is the cs line
    // TODO: Connect this to gpio over spi_cs0?
    ints = (uint32_t *)prop->value;
    sysbus_connect_irq(SYS_BUS_DEVICE(spi), 0,
                       qdev_get_gpio_in(DEVICE(tms->aic), ints[0]));
}

static void s8000_create_usb(MachineState *machine)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *phy, *complex, *device;
    DTBProp *prop;
    DeviceState *otg;

    phy = get_dtb_node(child, "otgphyctrl");
    g_assert(phy);

    complex = get_dtb_node(child, "usb-complex");
    g_assert(complex);

    device = get_dtb_node(complex, "usb-device");
    g_assert(device);

    otg = apple_otg_create(complex);
    object_property_add_child(OBJECT(machine), "otg", OBJECT(otg));
    prop = find_dtb_prop(phy, "reg");
    g_assert(prop);
    sysbus_mmio_map(SYS_BUS_DEVICE(otg), 0,
                    tms->soc_base_pa + ((uint64_t *)prop->value)[0]);
    sysbus_mmio_map(SYS_BUS_DEVICE(otg), 1,
                    tms->soc_base_pa + ((uint64_t *)prop->value)[2]);
    sysbus_mmio_map(
        SYS_BUS_DEVICE(otg), 2,
        tms->soc_base_pa +
            ((uint64_t *)find_dtb_prop(complex, "ranges")->value)[1] +
            ((uint64_t *)find_dtb_prop(device, "reg")->value)[0]);

    prop = find_dtb_prop(complex, "reg");
    if (prop) {
        sysbus_mmio_map(SYS_BUS_DEVICE(otg), 3,
                        tms->soc_base_pa + ((uint64_t *)prop->value)[0]);
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(otg), &error_fatal);

    prop = find_dtb_prop(device, "interrupts");
    g_assert(prop);
    sysbus_connect_irq(
        SYS_BUS_DEVICE(otg), 0,
        qdev_get_gpio_in(DEVICE(tms->aic), ((uint32_t *)prop->value)[0]));
}

static void s8000_create_wdt(MachineState *machine)
{
    int i;
    uint32_t *ints;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t value;
    S8000MachineState *tms = S8000_MACHINE(machine);
    SysBusDevice *wdt;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    g_assert(child);
    child = find_dtb_node(child, "wdt");
    g_assert(child);

    wdt = apple_wdt_create(child);
    g_assert(wdt);

    object_property_add_child(OBJECT(machine), "wdt", OBJECT(wdt));
    prop = find_dtb_prop(child, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;

    sysbus_mmio_map(wdt, 0, tms->soc_base_pa + reg[0]);
    sysbus_mmio_map(wdt, 1, tms->soc_base_pa + reg[2]);

    prop = find_dtb_prop(child, "interrupts");
    g_assert(prop);
    ints = (uint32_t *)prop->value;

    for (i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(wdt, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    // TODO: MCC
    prop = find_dtb_prop(child, "function-panic_flush_helper");
    if (prop) {
        remove_dtb_prop(child, prop);
    }

    prop = find_dtb_prop(child, "function-panic_halt_helper");
    if (prop) {
        remove_dtb_prop(child, prop);
    }

    value = 1;
    set_dtb_prop(child, "no-pmu", sizeof(value), &value);

    sysbus_realize_and_unref(wdt, &error_fatal);
}

static void s8000_create_aes(MachineState *machine)
{
    S8000MachineState *tms;
    DTBNode *child;
    SysBusDevice *aes;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;

    tms = S8000_MACHINE(machine);
    child = find_dtb_node(tms->device_tree, "arm-io");
    g_assert(child);
    child = find_dtb_node(child, "aes");
    g_assert(child);

    aes = apple_aes_create(child);
    g_assert(aes);

    object_property_add_child(OBJECT(machine), "aes", OBJECT(aes));
    prop = find_dtb_prop(child, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;

    sysbus_mmio_map(aes, 0, tms->soc_base_pa + reg[0]);
    sysbus_mmio_map(aes, 1, tms->soc_base_pa + reg[2]);

    prop = find_dtb_prop(child, "interrupts");
    g_assert(prop);
    g_assert(prop->length == 4);
    ints = (uint32_t *)prop->value;

    sysbus_connect_irq(aes, 0, qdev_get_gpio_in(DEVICE(tms->aic), *ints));

    g_assert(object_property_add_const_link(OBJECT(aes), "dma-mr",
                                            OBJECT(tms->sysmem)));

    sysbus_realize_and_unref(aes, &error_fatal);
}

static void s8000_create_sep(MachineState *machine)
{
    S8000MachineState *tms;
    DTBNode *child;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    int i;

    tms = S8000_MACHINE(machine);
    child = find_dtb_node(tms->device_tree, "arm-io");
    g_assert(child);
    child = find_dtb_node(child, "sep");
    g_assert(child);

    tms->sep = SYS_BUS_DEVICE(
        apple_sep_create(child, 0, A9_MAX_CPU + 1, tms->build_version, false));
    g_assert(tms->sep);

    object_property_add_child(OBJECT(machine), "sep", OBJECT(tms->sep));
    prop = find_dtb_prop(child, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;

    sysbus_mmio_map_overlap(SYS_BUS_DEVICE(tms->sep), 0,
                            tms->soc_base_pa + reg[0], 2);
    sysbus_mmio_map_overlap(SYS_BUS_DEVICE(tms->sep), 1,
                            tms->soc_base_pa + 0xD500000, 2);

    prop = find_dtb_prop(child, "interrupts");
    g_assert(prop);
    ints = (uint32_t *)prop->value;

    for (i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(tms->sep), i,
                           qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    g_assert(object_property_add_const_link(OBJECT(tms->sep), "dma-mr",
                                            OBJECT(tms->sysmem)));

    sysbus_realize_and_unref(SYS_BUS_DEVICE(tms->sep), &error_fatal);
}

static void apple_a9_reset(void *opaque)
{
    MachineState *machine = MACHINE(opaque);
    S8000MachineState *tms = S8000_MACHINE(machine);
    CPUState *cpu;

    CPU_FOREACH (cpu) {
        AppleA9State *tcpu = APPLE_A9(cpu);
        if (tcpu == NULL || tcpu->cpu_id == A9_MAX_CPU + 1) {
            continue;
        }
        object_property_set_int(OBJECT(cpu), "rvbar",
                                tms->bootinfo.entry & ~0xFFF, &error_abort);
        cpu_reset(cpu);
        if (tcpu->cpu_id == 0) {
            cpu_set_pc(cpu, S8000_SROM_BASE);
        }
    }
}

static void s8000_machine_reset(MachineState *machine, ShutdownCause reason)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    DeviceState *gpio = NULL;

    qemu_devices_reset(reason);
    if (!runstate_check(RUN_STATE_RESTORE_VM) &&
        !runstate_check(RUN_STATE_PRELAUNCH)) {
        if (!runstate_check(RUN_STATE_PAUSED) ||
            reason != SHUTDOWN_CAUSE_NONE) {
            s8000_memory_setup(MACHINE(tms));
        }
    }
    apple_a9_reset(tms);

    gpio =
        DEVICE(object_property_get_link(OBJECT(machine), "gpio", &error_fatal));

    qemu_set_irq(qdev_get_gpio_in(gpio, S8000_GPIO_FORCE_DFU), tms->force_dfu);
}

static void s8000_machine_init_done(Notifier *notifier, void *data)
{
    S8000MachineState *tms =
        container_of(notifier, S8000MachineState, init_done_notifier);
    s8000_memory_setup(MACHINE(tms));
    apple_a9_reset(tms);
}

static void s8000_machine_init(MachineState *machine)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *child;
    DTBProp *prop;
    hwaddr *ranges;

    tms->sysmem = get_system_memory();
    allocate_ram(tms->sysmem, "SROM", S8000_SROM_BASE, S8000_SROM_SIZE, 0);
    allocate_ram(tms->sysmem, "SRAM", S8000_SRAM_BASE, S8000_SRAM_SIZE, 0);
    allocate_ram(tms->sysmem, "DRAM", S8000_DRAM_BASE, machine->ram_size, 0);
    allocate_ram(tms->sysmem, "SEPROM", S8000_SEPROM_BASE, S8000_SEPROM_SIZE,
                 0);
    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    memory_region_init_alias(mr, OBJECT(tms), "s8000.seprom.alias", tms->sysmem,
                             S8000_SEPROM_BASE, S8000_SEPROM_SIZE);
    memory_region_add_subregion_overlap(tms->sysmem, 0, mr, 1);

    tms->device_tree = load_dtb_from_file(machine->dtb);
    child = find_dtb_node(tms->device_tree, "arm-io");
    g_assert(child);

    prop = find_dtb_prop(child, "ranges");
    g_assert(prop);

    ranges = (hwaddr *)prop->value;
    tms->soc_base_pa = ranges[1];
    tms->soc_size = ranges[2];

    s8000_cpu_setup(machine);

    s8000_create_aic(machine);

    s8000_create_s3c_uart(tms, serial_hd(0));

    s8000_pmgr_setup(machine);

    s8000_create_gpio(machine, "gpio");
    s8000_create_gpio(machine, "aop-gpio");

    s8000_create_i2c(machine, "i2c0");
    s8000_create_i2c(machine, "i2c1");
    s8000_create_i2c(machine, "i2c2");

    s8000_create_usb(machine);

    s8000_create_wdt(machine);

    s8000_create_aes(machine);

    s8000_create_spi0(machine);
    s8000_create_spi(machine, "spi1");
    s8000_create_spi(machine, "spi2");
    s8000_create_spi(machine, "spi3");

    s8000_create_sep(machine);

    tms->init_done_notifier.notify = s8000_machine_init_done;
    qemu_add_machine_init_done_notifier(&tms->init_done_notifier);
}

static ram_addr_t s8000_machine_fixup_ram_size(ram_addr_t size)
{
    g_assert(size == S8000_DRAM_SIZE);
    return size;
}

static void s8000_set_seprom_filename(Object *obj, const char *value,
                                      Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    g_free(tms->seprom_filename);
    tms->seprom_filename = g_strdup(value);
}

static char *s8000_get_seprom_filename(Object *obj, Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    return g_strdup(tms->seprom_filename);
}

static void s8000_set_force_dfu(Object *obj, bool value, Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    tms->force_dfu = value;
}

static bool s8000_get_force_dfu(Object *obj, Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    return tms->force_dfu;
}

static void s8000_machine_class_init(ObjectClass *klass, void *data)
{
    MachineClass *mc;

    mc = MACHINE_CLASS(klass);
    mc->desc = "S8000";
    mc->init = s8000_machine_init;
    mc->reset = s8000_machine_reset;
    mc->max_cpus = A9_MAX_CPU + 1;
    mc->no_sdcard = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_parallel = 1;
    mc->default_cpu_type = TYPE_APPLE_A9;
    mc->minimum_page_bits = 14;
    mc->default_ram_size = S8000_DRAM_SIZE;
    mc->fixup_ram_size = s8000_machine_fixup_ram_size;

    object_class_property_add_str(klass, "seprom", s8000_get_seprom_filename,
                                  s8000_set_seprom_filename);
    object_class_property_set_description(klass, "seprom",
                                          "SEPROM to be loaded");
    object_class_property_add_bool(klass, "force-dfu", s8000_get_force_dfu,
                                   s8000_set_force_dfu);
    object_class_property_set_description(klass, "force-dfu", "Force DFU");
}

static const TypeInfo s8000_machine_info = {
    .name = TYPE_S8000_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(S8000MachineState),
    .class_size = sizeof(S8000MachineClass),
    .class_init = s8000_machine_class_init,
};

static void s8000_machine_types(void)
{
    type_register_static(&s8000_machine_info);
}

type_init(s8000_machine_types)
