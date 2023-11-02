/*
 * Apple Display Pipe V2 Controller.
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
#include "hw/arm/apple_dart.h"
#include "hw/arm/t8030.h"
#include "hw/display/apple_displaypipe_v2.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qom/object.h"
#include "ui/console.h"
#include "ui/pixel_ops.h"
#include "framebuffer.h"

// #define DEBUG_DISPLAYPIPE_V2

static void apple_genpipev2_write(GenPipeState *s, hwaddr addr, uint64_t data)
{
    switch (addr - GENPIPEV2_BASE_FOR(s->index)) {
    case GENPIPEV2_GP_CONFIG_CONTROL:
        s->config_control = (uint32_t)data;
        break;

    case GENPIPEV2_PLANE_START:
        s->plane_start = (uint32_t)data;
#ifdef DEBUG_DISPLAYPIPE_V2
        info_report("GenPipe %zu: Plane Start <- 0x" HWADDR_FMT_plx, s->index,
                    data);
#endif
        break;

    case GENPIPEV2_PLANE_END:
        s->plane_end = (uint32_t)data;
#ifdef DEBUG_DISPLAYPIPE_V2
        info_report("GenPipe %zu: Plane End <- 0x" HWADDR_FMT_plx, s->index,
                    data);
#endif
        break;

    case GENPIPEV2_PLANE_STRIDE:
        s->plane_stride = (uint32_t)data;
#ifdef DEBUG_DISPLAYPIPE_V2
        info_report("GenPipe %zu: Plane Stride <- 0x" HWADDR_FMT_plx, s->index,
                    data);
#endif
        break;

    default:
        break;
    }
}

static uint32_t apple_genpipev2_read(GenPipeState *s, hwaddr addr)
{
    switch (addr - GENPIPEV2_BASE_FOR(s->index)) {
    case GENPIPEV2_GP_CONFIG_CONTROL:
        return s->config_control;

    case GENPIPEV2_PLANE_START:
        return s->plane_start;

    case GENPIPEV2_PLANE_END:
        return s->plane_end;

    case GENPIPEV2_PLANE_STRIDE:
        return s->plane_stride;

    case GENPIPEV2_PIXEL_FORMAT:
        return GENPIPEV2_DFB_PIXEL_FORMAT_BGRA;

    case GENPIPEV2_FRAME_SIZE:
        return (s->width << 16) | s->height;

    default:
        return 0;
    }
}

static uint8_t *apple_genpipev2_read_fb(GenPipeState *s, AddressSpace *dma_as,
                                        uint32_t plane_stride, size_t *size_out)
{
    if (s->plane_start && s->plane_end && s->plane_stride && plane_stride) {
        size_t size = s->plane_end - s->plane_start;
        uint8_t *buf = g_malloc(size);
        if (dma_memory_read(dma_as, s->plane_start, buf, size,
                            MEMTXATTRS_UNSPECIFIED) == MEMTX_OK) {
            *size_out = size;
            return buf;
        }
    }
    *size_out = 0;
    return NULL;
}

static bool apple_genpipev2_init(GenPipeState *s, size_t index, uint32_t width,
                                 uint32_t height)
{
    memset(s, 0, sizeof(*s));
    s->index = index;
    s->width = width;
    s->height = height;
    s->config_control = GENPIPEV2_GP_CONFIG_CONTROL_ENABLED;
    return true;
}


static void apple_displaypipe_v2_write(void *opaque, hwaddr addr, uint64_t data,
                                       unsigned size)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(opaque);
    if (addr >= 0x200000) {
        addr -= 0x200000;
    }
    switch (addr) {
    case GENPIPEV2_BASE_FOR(0)... GENPIPEV2_END_FOR(0):
        apple_genpipev2_write(&s->genpipe0, addr, data);
        break;

    case GENPIPEV2_BASE_FOR(1)... GENPIPEV2_END_FOR(1):
        apple_genpipev2_write(&s->genpipe1, addr, data);
        break;

    case UPPIPEV2_INT_FILTER:
        s->uppipe_int_filter &= ~(uint32_t)data;
        s->frame_processed = false;
        qemu_irq_lower(s->irqs[0]);
        break;

    default:
#ifdef DEBUG_DISPLAYPIPE_V2
        qemu_log_mask(LOG_UNIMP,
                      "%s: unknown write @ 0x" HWADDR_FMT_plx
                      " value: 0x" HWADDR_FMT_plx "\n",
                      s->id, addr, data);
#endif
        break;
    }
}

static uint64_t apple_displaypipe_v2_read(void *opaque, hwaddr addr,
                                          unsigned size)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(opaque);
    if (addr >= 0x200000) {
        addr -= 0x200000;
    }
    switch (addr) {
    case GENPIPEV2_BASE_FOR(0)... GENPIPEV2_END_FOR(0):
        return apple_genpipev2_read(&s->genpipe0, addr);

    case GENPIPEV2_BASE_FOR(1)... GENPIPEV2_END_FOR(1):
        return apple_genpipev2_read(&s->genpipe1, addr);

    case UPPIPEV2_VER:
        return UPPIPEV2_VER_A1;

    case UPPIPEV2_FRAME_SIZE:
        return (s->width << 16) | s->height;

    case UPPIPEV2_INT_FILTER:
        return s->uppipe_int_filter;

    default:
#ifdef DEBUG_DISPLAYPIPE_V2
        qemu_log_mask(LOG_UNIMP, "%s: unknown read @ 0x" HWADDR_FMT_plx "\n",
                      s->id, addr);
#endif
        return 0;
    }
}

static const MemoryRegionOps apple_displaypipe_v2_reg_ops = {
    .write = apple_displaypipe_v2_write,
    .read = apple_displaypipe_v2_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

void apple_displaypipe_v2_create(MachineState *machine, const char *name)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    DeviceState *dev = qdev_new(TYPE_APPLE_DISPLAYPIPE_V2);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(sbd);
    tms->video_args.base_addr = T8030_DISPLAY_BASE;
    tms->video_args.row_bytes = s->width * 4;
    tms->video_args.width = s->width;
    tms->video_args.height = s->height;
    tms->video_args.depth = 32 | ((2 - 1) << 16);
    tms->video_args.display = 1;
    s->id = name;

    if (xnu_contains_boot_arg(machine->kernel_cmdline, "-s", false) ||
        xnu_contains_boot_arg(machine->kernel_cmdline, "-v", false)) {
        tms->video_args.display = 0;
    }

    DTBNode *armio = find_dtb_node(tms->device_tree, "arm-io");
    assert(armio);
    DTBNode *child = find_dtb_node(armio, name);
    assert(child);
    assert(set_dtb_prop(child, "display-target", 15, "DisplayTarget5"));
    uint32_t dispTimingInfo[] = { 0x33C, 0x90, 0x1, 0x1, 0x700, 0x1, 0x1, 0x1 };
    assert(set_dtb_prop(child, "display-timing-info", sizeof(dispTimingInfo),
                        &dispTimingInfo));
    uint32_t data = 0xD;
    assert(set_dtb_prop(child, "bics-param-set", sizeof(data), &data));
    uint32_t dot_pitch = 326;
    assert(set_dtb_prop(child, "dot-pitch", sizeof(dot_pitch), &dot_pitch));
    assert(set_dtb_prop(child, "function-brightness_update", 0, ""));

    DTBProp *prop = find_dtb_prop(child, "reg");
    assert(prop);
    uint64_t *reg = (uint64_t *)prop->value;
    memory_region_init_io(&s->up_regs, OBJECT(sbd),
                          &apple_displaypipe_v2_reg_ops, sbd, "up.regs",
                          reg[1]);
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

    g_autofree char *dart_name = g_strdup_printf("dart-%s", name);
    AppleDARTState *dart = APPLE_DART(
        object_property_get_link(OBJECT(machine), dart_name, &error_fatal));
    assert(dart);
    child = find_dtb_node(armio, dart_name);
    assert(child);
    g_autofree char *mapper_name = g_strdup_printf("mapper-%s", name);
    child = find_dtb_node(child, mapper_name);
    assert(child);
    prop = find_dtb_prop(child, "reg");
    assert(prop);
    s->dma_mr =
        MEMORY_REGION(apple_dart_iommu_mr(dart, *(uint32_t *)prop->value));
    assert(s->dma_mr);
    assert(object_property_add_const_link(OBJECT(sbd), "dma_mr",
                                          OBJECT(s->dma_mr)));
    g_autofree char *dma_name = g_strdup_printf("%s.dma", name);
    address_space_init(&s->dma_as, s->dma_mr, dma_name);

    memory_region_init_ram(&s->vram, OBJECT(sbd), "vram", T8030_DISPLAY_SIZE,
                           &error_fatal);
    memory_region_add_subregion_overlap(tms->sysmem, tms->video_args.base_addr,
                                        &s->vram, 1);
    object_property_add_const_link(OBJECT(sbd), "vram", OBJECT(&s->vram));
    object_property_add_child(OBJECT(machine), name, OBJECT(sbd));

    sysbus_realize_and_unref(sbd, &error_fatal);
}

static void apple_displaypipe_v2_draw_row(void *opaque, uint8_t *dest,
                                          const uint8_t *src, int width,
                                          int dest_pitch)
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

static void apple_displaypipe_v2_gfx_update(void *opaque)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(opaque);
    DisplaySurface *surface = qemu_console_surface(s->console);

    int stride = s->width * sizeof(uint32_t);

    if (!s->genpipe0.plane_start || !s->genpipe0.plane_end) {
        int first = 0, last = 0;

        if (!s->vram_section.mr) {
            framebuffer_update_memory_section(&s->vram_section, &s->vram, 0,
                                              s->height, stride);
        }
        framebuffer_update_display(
            surface, &s->vram_section, s->width, s->height, stride, stride, 0,
            0, apple_displaypipe_v2_draw_row, s, &first, &last);
        if (first >= 0) {
            dpy_gfx_update(s->console, 0, first, s->width, last - first + 1);
        }

        return;
    }

    if (!s->frame_processed) {
        size_t size0 = 0;
        g_autofree uint8_t *buf0 = apple_genpipev2_read_fb(
            &s->genpipe0, &s->dma_as, s->genpipe0.plane_stride, &size0);
        size_t size1 = 0;
        g_autofree uint8_t *buf1 = apple_genpipev2_read_fb(
            &s->genpipe1, &s->dma_as, s->genpipe0.plane_stride, &size1);

        uint8_t *dest = surface_data(surface);
        for (size_t i = 0; i < s->height; i++) {
            if (size0 && buf0 != NULL)
                apple_displaypipe_v2_draw_row(s, dest + i * stride,
                                              buf0 + i * stride, s->width, 0);
            if (size1 && buf1 != NULL)
                apple_displaypipe_v2_draw_row(s, dest + i * stride,
                                              buf1 + i * stride, s->width, 0);
        }

        dpy_gfx_update_full(s->console);
        s->uppipe_int_filter |= (1UL << 10) | (1UL << 19) | (1UL << 20);
        qemu_irq_raise(s->irqs[0]);
        s->frame_processed = true;
    }
}

static const GraphicHwOps apple_displaypipe_v2_ops = {
    .gfx_update = apple_displaypipe_v2_gfx_update,
};

static void apple_displaypipe_v2_realize(DeviceState *dev, Error **errp)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(dev);

    s->uppipe_int_filter = 0;
    s->frame_processed = false;
    apple_genpipev2_init(&s->genpipe0, 0, s->width, s->height);
    apple_genpipev2_init(&s->genpipe1, 1, s->width, s->height);
    s->console = graphic_console_init(dev, 0, &apple_displaypipe_v2_ops, s);
    qemu_console_resize(s->console, s->width, s->height);
}

static const VMStateDescription vmstate_apple_displaypipe_v2 = {
    .name = TYPE_APPLE_DISPLAYPIPE_V2,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (VMStateField[]){
            VMSTATE_UINT32(width, AppleDisplayPipeV2State),
            VMSTATE_UINT32(height, AppleDisplayPipeV2State),
            VMSTATE_END_OF_LIST(),
        },
};

static Property apple_displaypipe_v2_props[] = {
    // iPhone 4/4S
    DEFINE_PROP_UINT32("width", AppleDisplayPipeV2State, width, 640),
    DEFINE_PROP_UINT32("height", AppleDisplayPipeV2State, height, 960),
    // iPhone 11
    // DEFINE_PROP_UINT32("width", AppleDisplayPipeV2State, width, 828),
    // DEFINE_PROP_UINT32("height", AppleDisplayPipeV2State, height, 1792),
    DEFINE_PROP_END_OF_LIST()
};

static void apple_displaypipe_v2_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    device_class_set_props(dc, apple_displaypipe_v2_props);
    dc->realize = apple_displaypipe_v2_realize;
    dc->vmsd = &vmstate_apple_displaypipe_v2;
}

static const TypeInfo apple_displaypipe_v2_type_info = {
    .name = TYPE_APPLE_DISPLAYPIPE_V2,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleDisplayPipeV2State),
    .class_init = apple_displaypipe_v2_class_init,
};

static void apple_displaypipe_v2_register_types(void)
{
    type_register_static(&apple_displaypipe_v2_type_info);
}

type_init(apple_displaypipe_v2_register_types);
