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
#include "qapi/visitor.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "sysemu/block-backend.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"

#define S8000_SPI0_IRQ (188)

#define S8000_GPIO_HOLD_KEY (97)
#define S8000_GPIO_MENU_KEY (96)
#define S8000_GPIO_SPI0_CS (106)
#define S8000_GPIO_FORCE_DFU (123)
#define S8000_GPIO_DFU_STATUS (136)

#define S8000_SRAM_BASE (0x180000000ull)
#define S8000_SRAM_SIZE (0x400000ull)

#define S8000_DRAM_BASE (0x800000000ull)
#define S8000_DRAM_SIZE (2 * GiB)

#define S8000_SPI0_BASE (0xA080000ull)

#define S8000_SEPROM_BASE (0x20D000000ull)
#define S8000_SEPROM_SIZE (0x1000000ull)

#define S8000_TZ1_BASE (S8000_DRAM_BASE + 0x7E780000ull)
#define S8000_TZ1_SIZE (0x80000ull)

#define S8000_PANIC_BASE (S8000_DRAM_BASE + 0x7E6F8000ull)
#define S8000_PANIC_SIZE (0x80000ull)

#define S8000_DISPLAY_SIZE (0x1100000ull)
#define S8000_DISPLAY_BASE (S8000_PANIC_BASE - S8000_DISPLAY_SIZE)

#define S8000_KERNEL_REGION_BASE (S8000_DRAM_BASE)
#define S8000_KERNEL_REGION_SIZE (S8000_DISPLAY_BASE - S8000_KERNEL_REGION_BASE)

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
    int vector;
    DTBProp *prop;
    hwaddr *uart_offset;
    DTBNode *child;

    child = find_dtb_node(tms->device_tree, "arm-io/uart0");
    g_assert(child);

    g_assert(find_dtb_prop(child, "boot-console"));

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

static void s8000_patch_kernel(MachoHeader64 *hdr)
{
    kpf();
}

static bool s8000_check_panic(MachineState *machine)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    if (!tms->panic_size) {
        return false;
    }
    g_autofree AppleEmbeddedPanicHeader *panic_info =
        g_malloc0(tms->panic_size);
    g_autofree void *buffer = g_malloc0(tms->panic_size);

    address_space_rw(&address_space_memory, tms->panic_base,
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)panic_info,
                     tms->panic_size, 0);
    address_space_rw(&address_space_memory, tms->panic_base,
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)buffer, tms->panic_size,
                     1);

    return panic_info->magic == EMBEDDED_PANIC_MAGIC;
}

static size_t get_kaslr_random(void)
{
    size_t value = 0;
    qemu_guest_getrandom(&value, sizeof(value), NULL);
    return value;
}

#define L2_GRANULE ((16384) * (16384 / 8))
#define L2_GRANULE_MASK (L2_GRANULE - 1)

static void get_kaslr_slides(S8000MachineState *tms, hwaddr *phys_slide_out,
                             hwaddr *virt_slide_out)
{
    hwaddr slide_phys = 0, slide_virt = 0;
    const size_t slide_granular = (1 << 14);
    const size_t slide_granular_mask = slide_granular - 1;
    const size_t slide_virt_max = 0x100 * (2 * 1024 * 1024);
    size_t random_value = get_kaslr_random();

    // if (tms->kaslr_off) {
    *phys_slide_out = 0;
    *virt_slide_out = 0;
    //     return;
    // }

    // slide_virt = (random_value & ~slide_granular_mask) % slide_virt_max;
    // if (slide_virt == 0) {
    //     slide_virt = slide_virt_max;
    // }
    // slide_phys = slide_virt & L2_GRANULE_MASK;

    // *phys_slide_out = slide_phys;
    // *virt_slide_out = slide_virt;
}

static void s8000_load_classic_kc(S8000MachineState *tms, const char *cmdline)
{
    MachineState *machine = MACHINE(tms);
    MachoHeader64 *hdr = tms->kernel;
    MemoryRegion *sysmem = tms->sysmem;
    AddressSpace *nsas = &address_space_memory;
    hwaddr virt_low;
    hwaddr virt_end;
    hwaddr dtb_va;
    hwaddr top_of_kernel_data_pa;
    hwaddr mem_size;
    hwaddr phys_ptr;
    // hwaddr amcc_lower;
    // hwaddr amcc_upper;
    hwaddr slide_phys = 0;
    hwaddr slide_virt = 0;
    AppleBootInfo *info = &tms->bootinfo;
    g_autofree ApplePfRange *last_range = NULL;
    g_autofree ApplePfRange *text_range = NULL;
    DTBNode *memory_map = get_dtb_node(tms->device_tree, "/chosen/memory-map");

    /*
     * Setup the memory layout:
     * The trustcache is right in front of the __TEXT section, aligned to 16k
     * Then we have all the kernel sections.
     * After that we have ramdisk
     * After that we have the kernel boot args
     * After that we have the device tree
     * After that we have the rest of the RAM
     */

    g_phys_base = (hwaddr)macho_get_buffer(hdr);
    macho_highest_lowest(hdr, &virt_low, &virt_end);
    last_range = xnu_pf_segment(hdr, "__LAST");
    text_range = xnu_pf_segment(hdr, "__TEXT");

    get_kaslr_slides(tms, &slide_phys, &slide_virt);

    g_phys_base = phys_ptr = align_up(S8000_KERNEL_REGION_BASE, 16 * MiB);
    phys_ptr += slide_phys;
    g_virt_base += slide_virt - slide_phys;

    //! TrustCache
    info->trustcache_pa =
        vtop_static(text_range->va + slide_virt) - info->trustcache_size;

    macho_load_trustcache(tms->trustcache, info->trustcache_size, nsas, sysmem,
                          info->trustcache_pa);
    phys_ptr += align_16k_high(info->trustcache_size);

    info->kern_entry = arm_load_macho(hdr, nsas, sysmem, memory_map,
                                      g_phys_base + slide_phys, slide_virt);
    fprintf(stderr,
            "g_virt_base: 0x" TARGET_FMT_lx "\n"
            "g_phys_base: 0x" TARGET_FMT_lx "\n",
            g_virt_base, g_phys_base);
    fprintf(stderr,
            "slide_virt: 0x" TARGET_FMT_lx "\n"
            "slide_phys: 0x" TARGET_FMT_lx "\n",
            slide_virt, slide_phys);
    fprintf(stderr, "entry: 0x" TARGET_FMT_lx "\n", info->kern_entry);

    virt_end += slide_virt;
    phys_ptr = vtop_static(align_16k_high(virt_end));

    // amcc_lower = info->trustcache_pa;
    // amcc_upper =
    //     vtop_static(last_range->va + slide_virt) + last_range->size - 1;
    // for (int i = 0; i < 4; i++) {
    //     AMCC_REG(tms, AMCC_LOWER(i)) = (amcc_lower - S8000_DRAM_BASE) >> 14;
    //     AMCC_REG(tms, AMCC_UPPER(i)) = (amcc_upper - S8000_DRAM_BASE) >> 14;
    // }

    //! ramdisk
    if (machine->initrd_filename) {
        info->ramdisk_pa = phys_ptr;
        macho_load_ramdisk(machine->initrd_filename, nsas, sysmem,
                           info->ramdisk_pa, &info->ramdisk_size);
        info->ramdisk_size = align_16k_high(info->ramdisk_size);
        phys_ptr += info->ramdisk_size;
    }

    //! Kernel boot args
    info->kern_boot_args_pa = phys_ptr;
    phys_ptr += align_16k_high(0x4000);

    //! device tree
    info->device_tree_pa = phys_ptr;
    dtb_va = ptov_static(info->device_tree_pa);
    phys_ptr += align_16k_high(info->device_tree_size);

    // if (tms->sepfw_filename) {
    //     info->sepfw_pa = phys_ptr;
    //     macho_load_raw_file(tms->sepfw_filename, nsas, sysmem, "sepfw",
    //                         info->sepfw_pa, &info->sepfw_size);
    //     info->sepfw_size = align_16k_high(8 * MiB);
    //     phys_ptr += info->sepfw_size;
    // }

    mem_size =
        machine->maxram_size -
        (S8000_KERNEL_REGION_SIZE - (g_phys_base - S8000_KERNEL_REGION_BASE));

    macho_load_dtb(tms->device_tree, nsas, sysmem, "DeviceTree", info);

    top_of_kernel_data_pa = (align_16k_high(phys_ptr) + 0x3000ull) & ~0x3fffull;

    fprintf(stderr, "cmdline: [%s]\n", cmdline);
    macho_setup_bootargs("BootArgs", nsas, sysmem, info->kern_boot_args_pa,
                         g_virt_base, g_phys_base, mem_size,
                         top_of_kernel_data_pa, dtb_va, info->device_tree_size,
                         tms->video, cmdline);
    g_virt_base = virt_low;
}

static void s8000_load_fileset_kc(S8000MachineState *tms, const char *cmdline)
{
    MachineState *machine = MACHINE(tms);
    MachoHeader64 *hdr = tms->kernel;
    MemoryRegion *sysmem = tms->sysmem;
    AddressSpace *nsas = &address_space_memory;
    hwaddr virt_low;
    hwaddr virt_end;
    hwaddr dtb_va;
    hwaddr top_of_kernel_data_pa;
    hwaddr mem_size;
    hwaddr phys_ptr;
    // hwaddr amcc_lower;
    // hwaddr amcc_upper;
    hwaddr slide_phys = 0;
    hwaddr slide_virt = 0;
    uint64_t l2_remaining = 0;
    uint64_t extradata_size = 0;
    AppleBootInfo *info = &tms->bootinfo;
    g_autofree ApplePfRange *last_range = NULL;
    DTBNode *memory_map = get_dtb_node(tms->device_tree, "/chosen/memory-map");

    /*
     * Setup the memory layout:
     * First we have the device tree
     * The trustcache is right after the device tree
     * Then we have all the kernel sections.
     * After that we have ramdisk
     * After that we have the kernel boot args
     * After that we have the rest of the RAM
     */

    g_phys_base = (hwaddr)macho_get_buffer(hdr);
    macho_highest_lowest(hdr, &virt_low, &virt_end);
    g_virt_base = virt_low;
    last_range = xnu_pf_segment(hdr, "__PRELINK_INFO");

    extradata_size =
        align_16k_high(info->device_tree_size + info->trustcache_size);
    g_assert(extradata_size < L2_GRANULE);

    get_kaslr_slides(tms, &slide_phys, &slide_virt);

    l2_remaining = (virt_low + slide_virt) & L2_GRANULE_MASK;

    if (extradata_size >= l2_remaining) {
        uint64_t grown_slide = align_16k_high(extradata_size - l2_remaining);
        slide_phys += grown_slide;
        slide_virt += grown_slide;
    }

    phys_ptr = align_up(S8000_KERNEL_REGION_BASE, 32 * MiB) |
               (virt_low & L2_GRANULE_MASK);
    g_phys_base = phys_ptr & ~L2_GRANULE_MASK;
    phys_ptr += slide_phys;
    phys_ptr -= extradata_size;

    //! device tree
    info->device_tree_pa = phys_ptr;
    phys_ptr += info->device_tree_size;

    //! TrustCache
    info->trustcache_pa = phys_ptr;
    macho_load_trustcache(tms->trustcache, info->trustcache_size, nsas, sysmem,
                          info->trustcache_pa);
    phys_ptr += align_16k_high(info->trustcache_size);

    g_virt_base += slide_virt;
    g_virt_base -= phys_ptr - g_phys_base;
    info->kern_entry =
        arm_load_macho(hdr, nsas, sysmem, memory_map, phys_ptr, slide_virt);
    fprintf(stderr,
            "g_virt_base: 0x" TARGET_FMT_lx "\n"
            "g_phys_base: 0x" TARGET_FMT_lx "\n",
            g_virt_base, g_phys_base);
    fprintf(stderr,
            "slide_virt: 0x" TARGET_FMT_lx "\n"
            "slide_phys: 0x" TARGET_FMT_lx "\n",
            slide_virt, slide_phys);
    fprintf(stderr, "entry: 0x" TARGET_FMT_lx "\n", info->kern_entry);

    virt_end += slide_virt;
    phys_ptr = vtop_static(align_16k_high(virt_end));

    // amcc_lower = info->dtb_pa;
    // amcc_upper =
    //     vtop_static(last_range->va + slide_virt) + last_range->size - 1;
    // for (int i = 0; i < 4; i++) {
    //     AMCC_REG(tms, AMCC_LOWER(i)) = (amcc_lower - S8000_DRAM_BASE) >> 14;
    //     AMCC_REG(tms, AMCC_UPPER(i)) = (amcc_upper - S8000_DRAM_BASE) >> 14;
    // }

    dtb_va = ptov_static(info->device_tree_pa);

    //! ramdisk
    if (machine->initrd_filename) {
        info->ramdisk_pa = phys_ptr;
        macho_load_ramdisk(machine->initrd_filename, nsas, sysmem,
                           info->ramdisk_pa, &info->ramdisk_size);
        info->ramdisk_size = align_16k_high(info->ramdisk_size);
        phys_ptr += info->ramdisk_size;
    }

    //! Kernel boot args
    info->kern_boot_args_pa = phys_ptr;
    phys_ptr += align_16k_high(0x4000);

    mem_size =
        S8000_KERNEL_REGION_SIZE - (g_phys_base - S8000_KERNEL_REGION_BASE);

    macho_load_dtb(tms->device_tree, nsas, sysmem, "DeviceTree", info);

    top_of_kernel_data_pa = (align_16k_high(phys_ptr) + 0x3000ull) & ~0x3fffull;

    fprintf(stderr, "cmdline: [%s]\n", cmdline);
    macho_setup_bootargs("BootArgs", nsas, sysmem, info->kern_boot_args_pa,
                         g_virt_base, g_phys_base, mem_size,
                         top_of_kernel_data_pa, dtb_va, info->device_tree_size,
                         tms->video, cmdline);
    g_virt_base = virt_low;
}

static void s8000_memory_setup(MachineState *machine)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    AppleBootInfo *info = &tms->bootinfo;
    AddressSpace *nsas = &address_space_memory;
    g_autofree char *seprom;
    unsigned long fsize = 0;
    // AppleNvramState *nvram;
    g_autofree char *cmdline;
    MachoHeader64 *hdr;
    DTBNode *memory_map;
    hwaddr tz1_virt_low;
    hwaddr tz1_virt_high;

    memory_map = get_dtb_node(tms->device_tree, "/chosen/memory-map");

    if (s8000_check_panic(machine)) {
        qemu_system_guest_panicked(NULL);
        return;
    }

    info->dram_base = S8000_DRAM_BASE;
    info->dram_size = S8000_DRAM_SIZE;

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

    // nvram = APPLE_NVRAM(qdev_find_recursive(sysbus_get_default(), "nvram"));
    // if (!nvram) {
    //     error_setg(&error_abort, "%s: Failed to find nvram device",
    //     __func__); return;
    // };
    // apple_nvram_load(nvram);

    // fprintf(stderr, "boot_mode: %u\n", tms->boot_mode);
    // switch (tms->boot_mode) {
    // case kBootModeEnterRecovery:
    //     env_set(nvram, "auto-boot", "false", 0);
    //     tms->boot_mode = kBootModeAuto;
    //     break;
    // case kBootModeExitRecovery:
    //     env_set(nvram, "auto-boot", "true", 0);
    //     tms->boot_mode = kBootModeAuto;
    //     break;
    // default:
    //     break;
    // }

    // fprintf(stderr, "auto-boot=%s\n",
    //         env_get_bool(nvram, "auto-boot", false) ? "true" : "false");

    // switch (tms->boot_mode) {
    // case kBootModeAuto:
    // if (!env_get_bool(nvram, "auto-boot", false)) {
    asprintf(&cmdline, "-restore rd=md0 nand-enable-reformat=1 -progress %s",
             machine->kernel_cmdline);
    // break;
    // }
    //     QEMU_FALLTHROUGH;
    // default:
    //     asprintf(&cmdline, "%s", machine->kernel_cmdline);
    // }

    // apple_nvram_save(nvram);

    // info->nvram_size = nvram->len;

    // if (info->nvram_size > XNU_MAX_NVRAM_SIZE) {
    //     info->nvram_size = XNU_MAX_NVRAM_SIZE;
    // }
    // if (apple_nvram_serialize(nvram, info->nvram_data,
    //                           sizeof(info->nvram_data)) < 0) {
    //     error_report("%s: Failed to read NVRAM", __func__);
    // }

    if (tms->ticket_filename) {
        if (!g_file_get_contents(tms->ticket_filename, &info->ticket_data,
                                 (gsize *)&info->ticket_length, NULL)) {
            error_report("%s: Failed to read ticket from file %s", __func__,
                         tms->ticket_filename);
        }
    }

    if (xnu_contains_boot_arg(cmdline, "-restore", false)) {
        //! HACK: Use DEV Hardware model to restore without FDR errors
        set_dtb_prop(tms->device_tree, "compatible", 28,
                     "N66DEV\0iPhone12,1\0AppleARM\0$");
    } else {
        set_dtb_prop(tms->device_tree, "compatible", 27,
                     "N66AP\0iPhone12,1\0AppleARM\0$");
    }

    if (!xnu_contains_boot_arg(cmdline, "rd=", true)) {
        DTBNode *chosen = find_dtb_node(tms->device_tree, "chosen");
        DTBProp *prop = find_dtb_prop(chosen, "root-matching");

        if (prop) {
            snprintf((char *)prop->value, prop->length,
                     "<dict><key>IOProviderClass</key><string>IOMedia</"
                     "string><key>IOPropertyMatch</key><dict><key>Partition "
                     "ID</key><integer>1</integer></dict></dict>");
        }
    }

    DTBNode *pram = find_dtb_node(tms->device_tree, "pram");
    if (pram) {
        uint64_t panic_reg[2] = { 0 };
        uint64_t panic_base = S8000_PANIC_BASE;
        uint64_t panic_size = S8000_PANIC_SIZE;

        panic_reg[0] = panic_base;
        panic_reg[1] = panic_size;

        set_dtb_prop(pram, "reg", sizeof(panic_reg), &panic_reg);
        DTBNode *chosen = find_dtb_node(tms->device_tree, "chosen");
        set_dtb_prop(chosen, "embedded-panic-log-size", 8, &panic_size);
        tms->panic_base = panic_base;
        tms->panic_size = panic_size;
    }

    // DTBNode *vram = find_dtb_node(tms->device_tree, "vram");
    // if (vram) {
    //     uint64_t vram_reg[2] = { 0 };
    //     uint64_t vram_base = S8000_DISPLAY_BASE;
    //     uint64_t vram_size = S8000_DISPLAY_SIZE;
    //     vram_reg[0] = vram_base;
    //     vram_reg[1] = vram_size;
    //     set_dtb_prop(vram, "reg", sizeof(vram_reg), &vram_reg);
    // }

    hdr = tms->kernel;
    g_assert(hdr);

    macho_allocate_segment_records(memory_map, hdr);

    macho_populate_dtb(tms->device_tree, info);

    switch (hdr->file_type) {
    case MH_EXECUTE:
        s8000_load_classic_kc(tms, cmdline);
        break;
    case MH_FILESET:
        s8000_load_fileset_kc(tms, cmdline);
        break;
    default:
        error_setg(&error_abort, "%s: Unsupported kernelcache type: 0x%x\n",
                   __func__, hdr->file_type);
        break;
    }

    macho_highest_lowest(tms->secure_monitor, &tz1_virt_low, &tz1_virt_high);
    info_report("TrustZone 1 virtual address low: " TARGET_FMT_lx,
                tz1_virt_low);
    info_report("TrustZone 1 virtual address high: " TARGET_FMT_lx,
                tz1_virt_high);
    AddressSpace *sas = cpu_get_address_space(CPU(tms->cpus[0]), ARMASIdx_S);
    g_assert(sas);
    hwaddr tz1_entry = arm_load_macho(tms->secure_monitor, sas, tms->sysmem,
                                      NULL, S8000_TZ1_BASE, 0);
    info_report("TrustZone 1 entry: " TARGET_FMT_lx, tz1_entry);
    hwaddr tz1_boot_args_pa =
        S8000_TZ1_BASE + S8000_TZ1_SIZE - sizeof(AppleMonitorBootArgs);
    info_report("TrustZone 1 boot args address: " TARGET_FMT_lx,
                tz1_boot_args_pa);
    apple_monitor_setup_boot_args(
        "TZ1_BOOTARGS", sas, tms->sysmem, tz1_boot_args_pa, tz1_virt_low,
        S8000_TZ1_BASE, 0x80000, tms->bootinfo.kern_boot_args_pa,
        tms->bootinfo.kern_entry, S8000_KERNEL_REGION_BASE);
    tms->bootinfo.tz1_entry = tz1_entry;
    tms->bootinfo.tz1_boot_args_pa = tz1_boot_args_pa;
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

static void s8000_cpu_reset_work(CPUState *cpu, run_on_cpu_data data)
{
    S8000MachineState *tms = data.host_ptr;
    CPUARMState *env;
    AppleA13State *tcpu = APPLE_A13(cpu);
    if (!tcpu) {
        return;
    }
    cpu_reset(cpu);
    env = &ARM_CPU(cpu)->env;
    //! Disable MMU, caches, etc.
    env->cp15.sctlr_el[3] &=
        ~(SCTLR_D | SCTLR_SA | SCTLR_I | SCTLR_M | SCTLR_WXN);
    env->xregs[0] = tms->bootinfo.tz1_boot_args_pa;
    qemu_log_mask(LOG_GUEST_ERROR, "Jumping to secure monitor....\n");
    cpu_set_pc(cpu, tms->bootinfo.tz1_entry);
}

static void apple_a9_reset(void *opaque)
{
    MachineState *machine = MACHINE(opaque);
    S8000MachineState *tms = S8000_MACHINE(machine);
    CPUState *cpu;
    uint64_t m_lo = 0;
    uint64_t m_hi = 0;
    qemu_guest_getrandom(&m_lo, sizeof(m_lo), NULL);
    qemu_guest_getrandom(&m_hi, sizeof(m_hi), NULL);

    CPU_FOREACH (cpu) {
        AppleA9State *tcpu = APPLE_A9(cpu);
        if (tcpu == NULL || tcpu->cpu_id == A9_MAX_CPU + 1) {
            continue;
        }
        object_property_set_int(OBJECT(cpu), "rvbar", S8000_TZ1_BASE,
                                &error_abort);
        object_property_set_uint(OBJECT(cpu), "pauth-mlo", m_lo, &error_abort);
        object_property_set_uint(OBJECT(cpu), "pauth-mhi", m_hi, &error_abort);
        if (tcpu->cpu_id == 0) {
            run_on_cpu(cpu, s8000_cpu_reset_work, RUN_ON_CPU_HOST_PTR(tms));
            continue;
        }
        run_on_cpu(cpu, (run_on_cpu_func)cpu_reset, RUN_ON_CPU_NULL);
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
}

static void s8000_machine_init(MachineState *machine)
{
    S8000MachineState *tms = S8000_MACHINE(machine);
    DTBNode *child;
    DTBProp *prop;
    hwaddr *ranges;
    MachoHeader64 *hdr, *secure_monitor = 0;
    uint32_t build_version;
    uint64_t kernel_low = 0, kernel_high = 0;
    uint32_t data;
    uint64_t data64;
    uint8_t buffer[0x40];

    tms->sysmem = get_system_memory();
    allocate_ram(tms->sysmem, "SRAM", S8000_SRAM_BASE, S8000_SRAM_SIZE, 0);
    allocate_ram(tms->sysmem, "DRAM", S8000_DRAM_BASE, machine->ram_size, 0);
    allocate_ram(tms->sysmem, "SEPROM", S8000_SEPROM_BASE, S8000_SEPROM_SIZE,
                 0);
    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    memory_region_init_alias(mr, OBJECT(tms), "s8000.seprom.alias", tms->sysmem,
                             S8000_SEPROM_BASE, S8000_SEPROM_SIZE);
    memory_region_add_subregion_overlap(tms->sysmem, 0, mr, 1);

    hdr = macho_load_file(machine->kernel_filename, &secure_monitor);
    g_assert(hdr);
    g_assert(secure_monitor);
    tms->kernel = hdr;
    tms->secure_monitor = secure_monitor;
    xnu_header = hdr;
    build_version = macho_build_version(hdr);
    fprintf(stderr, "Loading %s %u.%u...\n", macho_platform_string(hdr),
            BUILD_VERSION_MAJOR(build_version),
            BUILD_VERSION_MINOR(build_version));
    tms->build_version = build_version;

    // if (tms->rtbuddyv2_protocol_version == 0) {
    //     switch (BUILD_VERSION_MAJOR(build_version)) {
    //     case 13:
    //         tms->rtbuddyv2_protocol_version = 10;
    //         break;
    //     case 14:
    //         tms->rtbuddyv2_protocol_version = 11;
    //         break;
    //     case 15:
    //         QEMU_FALLTHROUGH;
    //     case 16:
    //         tms->rtbuddyv2_protocol_version = 12;
    //         break;
    //     default:
    //         break;
    //     }
    // }

    macho_highest_lowest(hdr, &kernel_low, &kernel_high);
    fprintf(stderr,
            "kernel_low: 0x" TARGET_FMT_lx "\n"
            "kernel_high: 0x" TARGET_FMT_lx "\n",
            kernel_low, kernel_high);

    g_virt_base = kernel_low;
    g_phys_base = (hwaddr)macho_get_buffer(hdr);

    s8000_patch_kernel(hdr);

    tms->device_tree = load_dtb_from_file(machine->dtb);
    tms->trustcache = load_trustcache_from_file(tms->trustcache_filename,
                                                &tms->bootinfo.trustcache_size);
    data = 24000000;
    set_dtb_prop(tms->device_tree, "clock-frequency", sizeof(data), &data);
    child = find_dtb_node(tms->device_tree, "arm-io");
    g_assert(child);

    data = 0x20;
    set_dtb_prop(child, "chip-revision", sizeof(data), &data);

    // set_dtb_prop(child, "clock-frequencies", sizeof(clock_freq), clock_freq);

    prop = find_dtb_prop(child, "ranges");
    g_assert(prop);

    ranges = (hwaddr *)prop->value;
    tms->soc_base_pa = ranges[1];
    tms->soc_size = ranges[2];

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "s8000", 5);
    set_dtb_prop(tms->device_tree, "platform-name", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "MWL72", 5);
    set_dtb_prop(tms->device_tree, "model-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "LL/A", 4);
    set_dtb_prop(tms->device_tree, "region-info", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    set_dtb_prop(tms->device_tree, "config-number", 0x40, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "C39ZRMDEN72J", 12);
    set_dtb_prop(tms->device_tree, "serial-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "C39948108J9N72J1F", 17);
    set_dtb_prop(tms->device_tree, "mlb-serial-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "A2111", 5);
    set_dtb_prop(tms->device_tree, "regulatory-model-number", 32, buffer);

    child = get_dtb_node(tms->device_tree, "chosen");
    data = 0x6000;
    set_dtb_prop(child, "chip-id", 4, &data);
    data = 0x1; //! board-id ; match with apple_aes.c
    set_dtb_prop(child, "board-id", 4, &data);

    if (tms->ecid == 0) {
        tms->ecid = 0x1122334455667788;
    }
    set_dtb_prop(child, "unique-chip-id", 8, &tms->ecid);

    //! Update the display parameters
    data = 0;
    set_dtb_prop(child, "display-rotation", sizeof(data), &data);
    data = 2;
    set_dtb_prop(child, "display-scale", sizeof(data), &data);

    child = get_dtb_node(tms->device_tree, "product");

    data64 = 0x100000027;
    g_assert(
        set_dtb_prop(child, "display-corner-radius", sizeof(data64), &data64));
    data = 0x1;
    g_assert(set_dtb_prop(child, "oled-display", sizeof(data), &data));
    g_assert(set_dtb_prop(child, "graphics-featureset-class", 7, "MTL1,2"));
    g_assert(set_dtb_prop(child, "graphics-featureset-fallbacks", 15,
                          "MTL1,2:GLES2,0"));
    // TODO: PMP
    g_assert(set_dtb_prop(tms->device_tree, "target-type", 4, "sim"));
    data = 0;
    g_assert(set_dtb_prop(child, "device-color-policy", sizeof(data), &data));

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

static void s8000_set_trustcache_filename(Object *obj, const char *value,
                                          Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    g_free(tms->trustcache_filename);
    tms->trustcache_filename = g_strdup(value);
}

static char *s8000_get_trustcache_filename(Object *obj, Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    return g_strdup(tms->trustcache_filename);
}

static void s8000_set_ticket_filename(Object *obj, const char *value,
                                      Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    g_free(tms->ticket_filename);
    tms->ticket_filename = g_strdup(value);
}

static char *s8000_get_ticket_filename(Object *obj, Error **errp)
{
    S8000MachineState *tms;

    tms = S8000_MACHINE(obj);
    return g_strdup(tms->ticket_filename);
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

static void s8000_get_ecid(Object *obj, Visitor *v, const char *name,
                           void *opaque, Error **errp)
{
    S8000MachineState *tms;
    int64_t value;

    tms = S8000_MACHINE(obj);
    value = tms->ecid;
    visit_type_int(v, name, &value, errp);
}

static void s8000_set_ecid(Object *obj, Visitor *v, const char *name,
                           void *opaque, Error **errp)
{
    S8000MachineState *tms;
    int64_t value;

    tms = S8000_MACHINE(obj);

    if (!visit_type_int(v, name, &value, errp)) {
        return;
    }

    tms->ecid = value;
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
    mc->minimum_page_bits = 12;
    mc->default_ram_size = S8000_DRAM_SIZE;
    mc->fixup_ram_size = s8000_machine_fixup_ram_size;

    object_class_property_add_str(klass, "trustcache",
                                  s8000_get_trustcache_filename,
                                  s8000_set_trustcache_filename);
    object_class_property_set_description(klass, "trustcache",
                                          "Trustcache to be loaded");
    object_class_property_add_str(klass, "ticket", s8000_get_ticket_filename,
                                  s8000_set_ticket_filename);
    object_class_property_set_description(klass, "ticket",
                                          "APTicket to be loaded");
    object_class_property_add_str(klass, "seprom", s8000_get_seprom_filename,
                                  s8000_set_seprom_filename);
    object_class_property_set_description(klass, "seprom",
                                          "SEPROM to be loaded");
    object_class_property_add(klass, "ecid", "uint64", s8000_get_ecid,
                              s8000_set_ecid, NULL, NULL);
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
