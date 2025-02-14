/*
 * Apple Display Pipe V2 Controller.
 *
 * Copyright (c) 2023-2025 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2023-2025 Christian Inci (chris-pcguy).
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
#include "block/aio.h"
#include "exec/memory.h"
#include "hw/display/apple_displaypipe_v2.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "qemu/error-report.h"
#include "qom/object.h"
#include "sysemu/dma.h"
#include "ui/console.h"
#include "ui/pixel_ops.h"
#include "framebuffer.h"

// #define DEBUG_DISP

#ifdef DEBUG_DISP
#define DISP_DBGLOG(fmt, ...) info_report(fmt, __VA_ARGS__)
#else
#define DISP_DBGLOG(fmt, ...) \
    do {                      \
    } while (0);
#endif

/**
 * Block Bases (DisplayTarget5)
 * 0x08000  |  M3 Control Mailbox
 * 0x0A000  |  M3 Video Mode Mailbox
 * 0x40000  |  Control
 * 0x48000  |  Vertical Frame Timing Generator
 * 0x50000  |  Generic Pipe 0
 * 0x58000  |  Generic Pipe 1
 * 0x60000  |  Blend
 * 0x70000  |  White Point Correction
 * 0x7C000  |  Panel Response Correction
 * 0x80000  |  Dither
 * 0x82000  |  Dither: Enchanced ST Dither 0
 * 0x83000  |  Dither: Enchanced ST Dither 1
 * 0x84000  |  Content Dependent Frame Duration
 * 0x88000  |  SPLR (Sub-Pixel Layout R?)
 * 0x90000  |  Burn-In Compensation Sampler
 * 0x98000  |  SPUC
 * 0xA0000  |  PDC (Panel D? Correction?)
 * 0xB0000  |  PCC (Pixel Color Correction?)
 * 0xD0000  |  PCC Mailbox
 * 0xF0000  |  DBM (Dynamic Backlight Modulation?)
 */

#define REG_CONTROL_INT_STATUS (0x45818)
#define CONTROL_INT_STATUS_MODE_CHANGED BIT(1)
#define CONTROL_INT_STATUS_DISP_UNDERRUN BIT(3)
#define CONTROL_INT_STATUS_VBLANK BIT(10) // "Swap Done"
#define CONTROL_INT_STATUS_SUB_FRAME_OVERFLOW BIT(11)
#define CONTROL_INT_STATUS_M3 BIT(13)
#define CONTROL_INT_STATUS_PCC BIT(17)
// #define CONTROL_INT_STATUS_?? BIT(19) // "Start accumulating"
// #define CONTROL_INT_STATUS_?? BIT(20) // "Frame Processed"
#define CONTROL_INT_STATUS_AXI_READ_ERR BIT(30)
#define CONTROL_INT_STATUS_AXI_WRITE_ERR BIT(31)
#define REG_CONTROL_VERSION (0x46020)
#define CONTROL_VERSION_A0 (0x70044)
#define CONTROL_VERSION_A1 (0x70045)
#define REG_CONTROL_FRAME_SIZE (0x4603C)
#define REG_CONTROL_CONFIG (0x46040)
#define REG_CONTROL_OUT_FIFO_CLK_GATE (0x46074)
#define REG_CONTROL_OUT_FIFO_DEPTH (0x46084)
#define REG_CONTROL_COMPRESSION_CFG (0x460E0)
#define REG_CONTROL_BACKPRESSURE (0x46120)
#define REG_CONTROL_POWER_GATE_CTRL (0x46158)
#define REG_CONTROL_BIS_UPDATE_INTERVAL (0x46198)
#define REG_CONTROL_MIN_BANDWIDTH_RATE (0x461C0)
#define REG_CONTROL_BANDWIDTH_RATE_SCALE_FACTOR (0x461C4)
#define REG_CONTROL_PIO_DMA_BANDWIDTH_RATE (0x461C8)
#define REG_CONTROL_REPLAY_DMA_BANDWIDTH_RATE (0x461CC)
#define REG_CONTROL_GATE_CONTROL (0x461D0)
#define REG_CONTROL_READ_LINK_GATE_METRIC (0x461D4)
#define REG_CONTROL_READ_LTR_CONFIG (0x461D8)
#define REG_CONTROL_LTR_TIMER (0x461DC)
#define REG_CONTROL_WRITE_LTR_CONFIG (0x461E0)

#define GP_BLOCK_BASE (0x50000)
#define REG_GP_REG_SIZE (0x8000)
#define REG_GP_CONFIG_CONTROL (0x4)
#define GP_CONFIG_CONTROL_RUN BIT(0)
#define GP_CONFIG_CONTROL_USE_DMA BIT(18)
#define GP_CONFIG_CONTROL_HDR BIT(24)
#define GP_CONFIG_CONTROL_ENABLED BIT(31)
#define REG_GP_PIXEL_FORMAT (0x0001C)
#define GP_PIXEL_FORMAT_BGRA ((BIT(4) << 22) | BIT(24) | (3 << 13))
#define GP_PIXEL_FORMAT_ARGB ((BIT(4) << 22) | BIT(24))
#define GP_PIXEL_FORMAT_COMPRESSED BIT(30)
#define REG_GP_BASE (0x30)
#define REG_GP_END (0x40)
#define REG_GP_STRIDE (0x60)
#define REG_GP_SIZE (0x70)
#define REG_GP_FRAME_SIZE (0x80)
#define REG_GP_CRC_DATA (0x160)
#define REG_GP_BANDWIDTH_RATE (0x170)
#define REG_GP_STATUS (0x184)
#define GP_STATUS_DECOMPRESSION_FAIL BIT(0)

#define GP_BLOCK_BASE_FOR(i) (GP_BLOCK_BASE + i * REG_GP_REG_SIZE)
#define GP_BLOCK_END_FOR(i) (GP_BLOCK_BASE_FOR(i) + (REG_GP_REG_SIZE - 1))

static void apple_disp_update_irqs(AppleDisplayPipeV2State *s)
{
    qemu_set_irq(s->irqs[0], (s->int_status & CONTROL_INT_STATUS_VBLANK) != 0);
}

static void apple_disp_gp_reg_write(GenPipeState *s, hwaddr addr, uint64_t data)
{
    switch (addr - GP_BLOCK_BASE_FOR(s->index)) {
    case REG_GP_CONFIG_CONTROL: {
        DISP_DBGLOG("[GP%zu] Control <- 0x" HWADDR_FMT_plx, s->index, data);
        s->config_control = (uint32_t)data;
        if (data & GP_CONFIG_CONTROL_RUN) {
            qemu_bh_schedule(s->bh);
        }
        break;
    }
    case REG_GP_PIXEL_FORMAT: {
        DISP_DBGLOG("[GP%zu] Pixel format <- 0x" HWADDR_FMT_plx, s->index,
                    data);
        s->pixel_format = (uint32_t)data;
        break;
    }
    case REG_GP_BASE: {
        DISP_DBGLOG("[GP%zu] Base <- 0x" HWADDR_FMT_plx, s->index, data);
        s->base = (uint32_t)data;
        break;
    }
    case REG_GP_END: {
        DISP_DBGLOG("[GP%zu] End <- 0x" HWADDR_FMT_plx, s->index, data);
        s->end = (uint32_t)data;
        break;
    }
    case REG_GP_STRIDE: {
        DISP_DBGLOG("[GP%zu] Stride <- 0x" HWADDR_FMT_plx, s->index, data);
        s->stride = (uint32_t)data;
        break;
    }
    case REG_GP_SIZE: {
        DISP_DBGLOG("[GP%zu] Size <- 0x" HWADDR_FMT_plx, s->index, data);
        s->size = (uint32_t)data;
        break;
    }
    case REG_GP_FRAME_SIZE: {
        DISP_DBGLOG("[GP%zu] Frame Size <- 0x" HWADDR_FMT_plx, s->index, data);
        s->height = data & 0xFFFF;
        s->width = (data >> 16) & 0xFFFF;
        break;
    }
    default: {
        DISP_DBGLOG("[GP%zu] Unknown @ 0x" HWADDR_FMT_plx
                    " <- 0x" HWADDR_FMT_plx,
                    s->index, addr, data);
        break;
    }
    }
}

static uint32_t apple_disp_gp_reg_read(GenPipeState *s, hwaddr addr)
{
    switch (addr - GP_BLOCK_BASE_FOR(s->index)) {
    case REG_GP_CONFIG_CONTROL: {
        DISP_DBGLOG("[GP%zu] Control -> 0x%x", s->index, s->config_control);
        return s->config_control;
    }
    case REG_GP_PIXEL_FORMAT: {
        DISP_DBGLOG("[GP%zu] Pixel format -> 0x%x", s->index, s->pixel_format);
        return s->pixel_format;
    }
    case REG_GP_BASE: {
        DISP_DBGLOG("[GP%zu] Base -> 0x%x", s->index, s->base);
        return s->base;
    }
    case REG_GP_END: {
        DISP_DBGLOG("[GP%zu] End -> 0x%x", s->index, s->end);
        return s->end;
    }
    case REG_GP_STRIDE: {
        DISP_DBGLOG("[GP%zu] Stride -> 0x%x", s->index, s->stride);
        return s->stride;
    }
    case REG_GP_SIZE: {
        DISP_DBGLOG("[GP%zu] Size -> 0x%x", s->index, s->size);
        return s->size;
    }
    case REG_GP_FRAME_SIZE: {
        DISP_DBGLOG("[GP%zu] Frame Size -> 0x%x (width: %d height: %d)",
                    s->index, (s->width << 16) | s->height, s->width,
                    s->height);
        return (s->width << 16) | s->height;
    }
    default: {
        DISP_DBGLOG("[GP%zu] Unknown @ 0x" HWADDR_FMT_plx
                    " -> 0x" HWADDR_FMT_plx,
                    s->index, addr, (hwaddr)0);
        return 0;
    }
    }
}

static void apple_gp_draw_bh(void *opaque)
{
    GenPipeState *s;
    uint16_t height;
    uint16_t width;
    pixman_format_code_t src_fmt;
    uint8_t *buf;

    s = (GenPipeState *)opaque;

    // TODO: Decompress the data and display it properly.
    if (s->pixel_format & GP_PIXEL_FORMAT_COMPRESSED) {
        error_report("[GP%zu] Dropping frame as it's compressed.", s->index);
        return;
    }

    height = s->size & 0xFFFF;
    width = (s->size >> 16) & 0xFFFF;

    DISP_DBGLOG("[GP%zu] Width and height is %dx%d.", s->index, width, height);
    DISP_DBGLOG("[GP%zu] Stride is %d.", s->index, s->stride);

    if (height == 0 || width == 0 || s->stride == 0) {
        error_report(
            "[GP%zu] Dropping frame as width, height or stride is zero.",
            s->index);
        return;
    }

    if (width > s->disp_width || height > s->disp_height) {
        error_report("[GP%zu] Dropping frame as it's larger than the screen.",
                     s->index);
        return;
    }

    if ((s->pixel_format & GP_PIXEL_FORMAT_BGRA) == GP_PIXEL_FORMAT_BGRA) {
        DISP_DBGLOG("[GP%zu] Pixel Format is BGRA (0x%X).", s->index,
                    s->pixel_format);
        src_fmt = PIXMAN_b8g8r8a8;
    } else if ((s->pixel_format & GP_PIXEL_FORMAT_ARGB) ==
               GP_PIXEL_FORMAT_ARGB) {
        DISP_DBGLOG("[GP%zu] Pixel Format is ARGB (0x%X).", s->index,
                    s->pixel_format);
        src_fmt = PIXMAN_a8r8g8b8;
    } else {
        error_report("[GP%zu] Pixel Format is unknown (0x%X).", s->index,
                     s->pixel_format);
        return;
    }

    buf = g_malloc(height * width * s->stride);
    if (dma_memory_read(s->dma_as, s->base, buf, s->end - s->base,
                        MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        error_report("[GP%zu] Failed to read from DMA.", s->index);
        g_free(buf);
        return;
    }

    // TODO: Where is the destination X and Y?
    pixman_image_t *image = pixman_image_create_bits(
        src_fmt, width, height, (uint32_t *)buf, s->stride);
    pixman_image_composite32(PIXMAN_OP_OVER, image, NULL, s->disp_image, 0, 0,
                             0, 0, 0, 0, width, height);
    pixman_image_unref(image);
    g_free(buf);
    memory_region_set_dirty(s->vram, 0, height * s->width * sizeof(uint32_t));
}

static void apple_genpipev2_init(GenPipeState *s, size_t index,
                                 MemoryRegion *vram, AddressSpace *dma_as,
                                 pixman_image_t *disp_image,
                                 uint16_t disp_width, uint16_t disp_height)
{
    if (s->bh != NULL) {
        qemu_bh_delete(s->bh);
    }

    memset(s, 0, sizeof(*s));
    s->index = index;
    s->vram = vram;
    s->dma_as = dma_as;
    s->bh = qemu_bh_new(apple_gp_draw_bh, s);
    s->disp_image = disp_image;
    s->disp_width = disp_width;
    s->disp_height = disp_height;
}

static void apple_disp_reg_write(void *opaque, hwaddr addr, uint64_t data,
                                 unsigned size)
{
    AppleDisplayPipeV2State *s;

    s = APPLE_DISPLAYPIPE_V2(opaque);

    if (addr >= 0x200000) {
        addr -= 0x200000;
    }

    switch (addr) {
    case GP_BLOCK_BASE_FOR(0)... GP_BLOCK_END_FOR(0): {
        apple_disp_gp_reg_write(&s->genpipes[0], addr, data);
        break;
    }
    case GP_BLOCK_BASE_FOR(1)... GP_BLOCK_END_FOR(1): {
        apple_disp_gp_reg_write(&s->genpipes[1], addr, data);
        break;
    }
    case REG_CONTROL_INT_STATUS: {
        s->int_status &= ~(uint32_t)data;
        apple_disp_update_irqs(s);
        break;
    }
    default: {
        DISP_DBGLOG("[disp] Unknown @ 0x" HWADDR_FMT_plx
                    " <- 0x" HWADDR_FMT_plx,
                    addr, data);
        break;
    }
    }
}

static uint64_t apple_disp_reg_read(void *opaque, hwaddr addr,
                                    const unsigned size)
{
    AppleDisplayPipeV2State *s;

    s = APPLE_DISPLAYPIPE_V2(opaque);

    if (addr >= 0x200000) {
        addr -= 0x200000;
    }

    switch (addr) {
    case GP_BLOCK_BASE_FOR(0)... GP_BLOCK_END_FOR(0): {
        return apple_disp_gp_reg_read(&s->genpipes[0], addr);
    }
    case GP_BLOCK_BASE_FOR(1)... GP_BLOCK_END_FOR(1): {
        return apple_disp_gp_reg_read(&s->genpipes[1], addr);
    }
    case REG_CONTROL_VERSION: {
        DISP_DBGLOG("[disp] Version -> 0x%x", CONTROL_VERSION_A0);
        return CONTROL_VERSION_A0;
    }
    case REG_CONTROL_FRAME_SIZE: {
        DISP_DBGLOG("[disp] Frame Size -> 0x%x", (s->width << 16) | s->height);
        return (s->width << 16) | s->height;
    }
    case REG_CONTROL_INT_STATUS: {
        DISP_DBGLOG("[disp] Int Status -> 0x%x", s->int_status);
        return s->int_status;
    }
    default: {
        DISP_DBGLOG("[disp] Unknown @ 0x" HWADDR_FMT_plx
                    " -> 0x" HWADDR_FMT_plx,
                    addr, (hwaddr)0);
        return 0;
    }
    }
}

static const MemoryRegionOps apple_disp_v2_reg_ops = {
    .write = apple_disp_reg_write,
    .read = apple_disp_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static uint32_t disp_timing_info[] = { 0x33C, 0x90, 0x1, 0x1,
                                       0x700, 0x1,  0x1, 0x1 };

AppleDisplayPipeV2State *apple_displaypipe_v2_create(DTBNode *node)
{
    DeviceState *dev;
    SysBusDevice *sbd;
    AppleDisplayPipeV2State *s;
    DTBProp *prop;
    uint64_t *reg;
    int i;

    dev = qdev_new(TYPE_APPLE_DISPLAYPIPE_V2);
    sbd = SYS_BUS_DEVICE(dev);
    s = APPLE_DISPLAYPIPE_V2(sbd);

    dtb_set_prop(node, "display-target", 15, "DisplayTarget5");
    dtb_set_prop(node, "display-timing-info", sizeof(disp_timing_info),
                 disp_timing_info);
    dtb_set_prop_u32(node, "bics-param-set", 0xD);
    dtb_set_prop_u32(node, "dot-pitch", 326);
    dtb_set_prop_null(node, "function-brightness_update");

    prop = dtb_find_prop(node, "reg");
    g_assert_nonnull(prop);
    reg = (uint64_t *)prop->data;
    memory_region_init_io(&s->up_regs, OBJECT(sbd), &apple_disp_v2_reg_ops, sbd,
                          "up.regs", reg[1]);
    sysbus_init_mmio(sbd, &s->up_regs);
    object_property_add_const_link(OBJECT(sbd), "up.regs", OBJECT(&s->up_regs));

    for (i = 0; i < 9; i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }

    return s;
}

static void apple_displaypipe_v2_draw_row(void *opaque, uint8_t *dest,
                                          const uint8_t *src, int width,
                                          int dest_pitch)
{
    while (width--) {
        uint32_t colour = ldl_le_p(src);
        memcpy(dest, &colour, sizeof(colour));
        src += sizeof(colour);
        dest += sizeof(colour);
    }
}

static void apple_displaypipe_v2_invalidate(void *opaque)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(opaque);
    s->invalidated = true;
}

static void apple_displaypipe_v2_gfx_update(void *opaque)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(opaque);
    DisplaySurface *surface = qemu_console_surface(s->console);

    int stride = s->width * sizeof(uint32_t);
    int first = 0, last = 0;

    if (s->invalidated) {
        framebuffer_update_memory_section(&s->vram_section, &s->vram, 0,
                                          s->height, stride);
        s->invalidated = false;
    }

    framebuffer_update_display(surface, &s->vram_section, s->width, s->height,
                               stride, stride, 0, 0,
                               apple_displaypipe_v2_draw_row, s, &first, &last);
    if (first >= 0) {
        dpy_gfx_update(s->console, 0, first, s->width, last - first + 1);
    }

    s->int_status |= CONTROL_INT_STATUS_VBLANK;
    apple_disp_update_irqs(s);
}

static const GraphicHwOps apple_displaypipe_v2_ops = {
    .invalidate = apple_displaypipe_v2_invalidate,
    .gfx_update = apple_displaypipe_v2_gfx_update,
};

static void apple_displaypipe_v2_reset_hold(Object *obj, ResetType type)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(obj);

    s->invalidated = true;

    s->int_status = 0;
    apple_disp_update_irqs(s);

    qemu_pixman_image_unref(s->disp_image);
    s->disp_image = pixman_image_create_bits(
        PIXMAN_a8r8g8b8, s->width, s->height,
        (uint32_t *)memory_region_get_ram_ptr(&s->vram),
        s->width * sizeof(uint32_t));

    apple_genpipev2_init(&s->genpipes[0], 0, &s->vram, &s->dma_as,
                         s->disp_image, s->width, s->height);
    apple_genpipev2_init(&s->genpipes[1], 1, &s->vram, &s->dma_as,
                         s->disp_image, s->width, s->height);

    memset(memory_region_get_ram_ptr(&s->vram), 0,
           memory_region_size(&s->vram));
    memory_region_set_dirty(&s->vram, 0, memory_region_size(&s->vram));
}

static void apple_displaypipe_v2_realize(DeviceState *dev, Error **errp)
{
    AppleDisplayPipeV2State *s = APPLE_DISPLAYPIPE_V2(dev);

    s->console = graphic_console_init(dev, 0, &apple_displaypipe_v2_ops, s);
    qemu_console_resize(s->console, s->width, s->height);
}

static Property apple_displaypipe_v2_props[] = {
    DEFINE_PROP_UINT32("width", AppleDisplayPipeV2State, width, 828),
    DEFINE_PROP_UINT32("height", AppleDisplayPipeV2State, height, 1792),
    DEFINE_PROP_END_OF_LIST(),
};

static void apple_displaypipe_v2_class_init(ObjectClass *klass, void *data)
{
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    rc->phases.hold = apple_displaypipe_v2_reset_hold;

    device_class_set_props(dc, apple_displaypipe_v2_props);
    dc->realize = apple_displaypipe_v2_realize;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
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
