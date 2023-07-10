/*
 * AppleMobileDispH12P
 *
 * Copyright (c) 2023 ChefKiss Inc. Licensed under the Thou Shalt Not Profit License version 1.0. See LICENSE.TSNPL
 * for details.
 *
 */

#include "qemu/osdep.h"
#include "hw/display/apple_h12p.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"
#include "ui/pixel_ops.h"
#include "ui/console.h"
#include "qapi/error.h"
#include "framebuffer.h"
#include "hw/arm/t8030.h"
#include "hw/arm/apple_dart.h"

static void h12p_up_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    AppleH12PState *s = APPLE_H12P(opaque);
    if (addr >= 0x200000) { addr -= 0x200000; }
    info_report("[H12P] 0x" TARGET_FMT_plx " <- 0x" TARGET_FMT_plx, addr, data);
    switch (addr) {
        case REG_GENPIPE0_PLANE_START:
            s->genpipe0_plane_start = (uint32_t)data;
            info_report("[H12P] plane0 start: 0x" TARGET_FMT_plx, data);
            break;
        case REG_GENPIPE0_PLANE_END:
            s->genpipe0_plane_end = (uint32_t)data;
            info_report("[H12P] plane0 end: 0x" TARGET_FMT_plx, data);
            break;
        case REG_GENPIPE0_PLANE_STRIDE:
            s->genpipe0_plane_stride = (uint32_t)data;
            info_report("[H12P] plane0 stride: 0x" TARGET_FMT_plx, data);
            break;
        case REG_GENPIPE1_PLANE_START:
            s->genpipe1_plane_start = (uint32_t)data;
            info_report("[H12P] plane1 start: 0x" TARGET_FMT_plx, data);
            break;
        case REG_GENPIPE1_PLANE_END:
            s->genpipe1_plane_end = (uint32_t)data;
            info_report("[H12P] plane1 end: 0x" TARGET_FMT_plx, data);
            break;
        case REG_GENPIPE1_PLANE_STRIDE:
            s->genpipe1_plane_stride = (uint32_t)data;
            info_report("[H12P] plane1 stride: 0x" TARGET_FMT_plx, data);
            break;
        case REG_UPPIPE_INT_FILTER:
            s->uppipe_int_filter &= ~(uint32_t)data;
            break;
        case REG_PCC_SOFT_RESET:
            info_report("[H12P] PCC SOFT RESET!");
            break;
        default:
            *(uint32_t *)&s->regs[addr] = (uint32_t)data;
            break;
    }
}

static uint64_t h12p_up_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleH12PState *s = APPLE_H12P(opaque);
    uint64_t ret = 0;
    if (addr >= 0x200000) { addr -= 0x200000; }
    switch (addr) {
        case REG_UPPIPE_VER:
            ret = 0x70045;
            break;
        case REG_GENPIPE0_PIXEL_FORMAT:
        case REG_GENPIPE1_PIXEL_FORMAT:
            ret = GENPIPE_DFB_PIXEL_FORMAT_BGRA;
            break;
        case REG_GENPIPE0_PLANE_START:
            ret = s->genpipe0_plane_start;
            break;
        case REG_GENPIPE0_PLANE_END:
            ret = s->genpipe0_plane_end;
            break;
        case REG_GENPIPE0_PLANE_STRIDE:
            ret = s->genpipe0_plane_stride;
            break;
        case REG_GENPIPE1_PLANE_START:
            ret = s->genpipe1_plane_start;
            break;
        case REG_GENPIPE1_PLANE_END:
            ret = s->genpipe1_plane_end;
            break;
        case REG_GENPIPE1_PLANE_STRIDE:
            ret = s->genpipe1_plane_stride;
            break;
        case REG_GENPIPE0_FRAME_SIZE:
            QEMU_FALLTHROUGH;
        case REG_GENPIPE1_FRAME_SIZE:
            QEMU_FALLTHROUGH;
        case REG_UPPIPE_FRAME_SIZE:
            ret = (s->width << 16) | s->height;
            break;
        case REG_UPPIPE_INT_FILTER:
            ret = s->uppipe_int_filter;
            s->frame_processed = false;
            qemu_irq_lower(s->irqs[0]);
            break;
        default:
            ret = *(uint32_t *)&s->regs[addr];
            break;
    }
    info_report("[H12P] 0x" TARGET_FMT_plx " -> 0x" TARGET_FMT_plx, addr, ret);
    return ret;
}

static const MemoryRegionOps h12p_up_ops = {
    .write = h12p_up_write,
    .read = h12p_up_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

void apple_h12p_create(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    DeviceState *dev = qdev_new(TYPE_APPLE_H12P);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AppleH12PState *s = APPLE_H12P(sbd);
    tms->video.v_baseAddr = T8030_DISPLAY_BASE;
    tms->video.v_rowBytes = s->width * 4;
    tms->video.v_width = s->width;
    tms->video.v_height = s->height;
    tms->video.v_depth = 32 | ((2 - 1) << 16);
    tms->video.v_display = 1;

    if (xnu_contains_boot_arg(machine->kernel_cmdline, "-s", false)
        || xnu_contains_boot_arg(machine->kernel_cmdline, "-v", false)) {
        tms->video.v_display = 0;
    }

    *(uint32_t *)&s->regs[REG_GENPIPE0_BLACK_FRAME] = -1;
    *(uint32_t *)&s->regs[REG_GENPIPE1_BLACK_FRAME] = -1;

    DTBNode *armio = find_dtb_node(tms->device_tree, "arm-io");
    assert(armio);
    DTBNode *child = find_dtb_node(armio, "disp0");
    assert(child);
    assert(set_dtb_prop(child, "display-target", 15, "DisplayTarget5"));
    uint32_t dispTimingInfo[] = {0x33C, 0x90, 0x1, 0x1, 0x700, 0x1, 0x1, 0x1};
    assert(set_dtb_prop(child, "display-timing-info", sizeof(dispTimingInfo), &dispTimingInfo));
    uint32_t data = 0xD;
    assert(set_dtb_prop(child, "bics-param-set", sizeof(data), &data));
    uint32_t dot_pitch = 326;
    assert(set_dtb_prop(child, "dot-pitch", sizeof(dot_pitch), &dot_pitch));
    assert(set_dtb_prop(child, "function-brightness_update", 0, ""));

    DTBProp *prop = find_dtb_prop(child, "reg");
    assert(prop);
    uint64_t *reg = (uint64_t *)prop->value;
    memory_region_init_io(&s->up_regs, OBJECT(sbd), &h12p_up_ops, sbd, "up.regs", reg[1]);
    sysbus_init_mmio(sbd, &s->up_regs);
    sysbus_mmio_map(sbd, 0, tms->soc_base_pa + reg[0]);
    object_property_add_const_link(OBJECT(sbd), "up.regs", OBJECT(&s->up_regs));

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    uint32_t *ints = (uint32_t *)prop->value;

    for (size_t i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
        sysbus_connect_irq(sbd, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    AppleDARTState *dart = APPLE_DART(object_property_get_link(OBJECT(machine), "dart-disp0", &error_fatal));
    assert(dart);
    child = find_dtb_node(armio, "dart-disp0");
    assert(child);
    child = find_dtb_node(child, "mapper-disp0");
    assert(child);
    prop = find_dtb_prop(child, "reg");
    assert(prop);
    s->dma_mr = MEMORY_REGION(apple_dart_iommu_mr(dart, *(uint32_t *)prop->value));
    assert(s->dma_mr);
    assert(object_property_add_const_link(OBJECT(sbd), "dma_mr", OBJECT(s->dma_mr)));
    address_space_init(&s->dma_as, s->dma_mr, "disp0.dma");

    memory_region_init_ram(&s->vram, OBJECT(sbd), "vram", T8030_DISPLAY_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(tms->sysmem, tms->video.v_baseAddr, &s->vram, 1);
    object_property_add_const_link(OBJECT(sbd), "vram", OBJECT(&s->vram));
    object_property_add_child(OBJECT(machine), "disp0", OBJECT(sbd));

    sysbus_realize_and_unref(sbd, &error_fatal);
}

static void h12p_draw_row(void *opaque, uint8_t *dest, const uint8_t *src, int width, int dest_pitch)
{
    while (width--) {
        /* Load using endian-safe loads */
        uint32_t colour = ldl_le_p(src);
        /* Increment source pointer */
        src += sizeof(colour);

        /* Blit it to the display output now that it's converted */
        /* FIXME this might not be endian-safe but the rest should be */
        memcpy(dest, &colour, sizeof(colour));
        dest += sizeof(colour);
    }
}

static void h12p_gfx_update(void *opaque)
{
    AppleH12PState *s = APPLE_H12P(opaque);
    DisplaySurface *surface = qemu_console_surface(s->console);

    int stride = s->width * sizeof(uint32_t);

    if (!s->genpipe0_plane_start || !s->genpipe0_plane_end) {
        int first = 0, last = 0;

        if (!s->vram_section.mr) {
            framebuffer_update_memory_section(&s->vram_section, &s->vram, 0, s->height, stride);
        }
        framebuffer_update_display(surface, &s->vram_section, s->width, s->height, stride, stride, 0, 0, h12p_draw_row, s, &first, &last);
        if (first >= 0) { dpy_gfx_update(s->console, 0, first, s->width, last - first + 1); }

        return;
    }

    if (!s->frame_processed) {
        size_t size0 = 0;
        g_autofree uint8_t *buf0 = NULL;
        if (s->genpipe0_plane_start && s->genpipe0_plane_end && s->genpipe0_plane_stride) {
            size0 = s->genpipe0_plane_end - s->genpipe0_plane_start;
            buf0 = g_malloc(size0);
            if (dma_memory_read(&s->dma_as, s->genpipe0_plane_start, buf0, size0, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
                error_report("Failed to read framebuffer");
                return;
            }
        }
        size_t size1 = 0;
        g_autofree uint8_t *buf1 = NULL;
        if (s->genpipe1_plane_start && s->genpipe1_plane_end && s->genpipe1_plane_stride && s->genpipe0_plane_stride) {
            size1 = s->genpipe1_plane_end - s->genpipe1_plane_start;
            buf1 = g_malloc(size1);
            if (dma_memory_read(&s->dma_as, s->genpipe1_plane_start, buf1, size1, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
                error_report("Failed to read framebuffer2");
                return;
            }
        }

        uint8_t *dest = surface_data(surface);
        for (size_t i = 0; i < s->height; i++) {
            if (size0 && buf0 != NULL)
                h12p_draw_row(s, dest + i * stride, buf0 + i * stride, s->width, 0);
            if (size1 && buf1 != NULL)
                h12p_draw_row(s, dest + i * stride, buf1 + i * stride, s->width, 0);
        }

        dpy_gfx_update_full(s->console);
        s->uppipe_int_filter |= (1UL << 10) | (1UL << 19) | (1UL << 20);
        qemu_irq_raise(s->irqs[0]);
        s->frame_processed = true;
    }
}

static const GraphicHwOps apple_h12p_ops = {
    .gfx_update = h12p_gfx_update,
};

static void apple_h12p_realize(DeviceState *dev, Error **errp)
{
    AppleH12PState *s = APPLE_H12P(dev);

    s->uppipe_int_filter = s->genpipe0_plane_start = s->genpipe0_plane_end = s->genpipe0_plane_stride = s->genpipe1_plane_start = s->genpipe1_plane_end = s->genpipe1_plane_stride = s->frame_processed = 0;
    s->console = graphic_console_init(dev, 0, &apple_h12p_ops, s);
    qemu_console_resize(s->console, s->width, s->height);
}

static const VMStateDescription vmstate_apple_h12p = {
    .name = TYPE_APPLE_H12P,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(width, AppleH12PState),
        VMSTATE_UINT32(height, AppleH12PState),
        VMSTATE_END_OF_LIST()
    },
};

static Property apple_h12p_props[] = {
    // iPhone 4/4S
    DEFINE_PROP_UINT32("width", AppleH12PState, width, 640),
    DEFINE_PROP_UINT32("height", AppleH12PState, height, 960),
    // iPhone 11
    //DEFINE_PROP_UINT32("width", AppleH12PState, width, 828),
    //DEFINE_PROP_UINT32("height", AppleH12PState, height, 1792),
    DEFINE_PROP_END_OF_LIST()
};

static void apple_h12p_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    device_class_set_props(dc, apple_h12p_props);
    dc->realize = apple_h12p_realize;
    dc->vmsd = &vmstate_apple_h12p;
}

static const TypeInfo apple_h12p_type_info = {
    .name = TYPE_APPLE_H12P,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleH12PState),
    .class_init = apple_h12p_class_init,
};

static void apple_h12p_register_types(void)
{
    type_register_static(&apple_h12p_type_info);
}

type_init(apple_h12p_register_types);
