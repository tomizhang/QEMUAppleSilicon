/*
 * Apple SEP.
 *
 * Copyright (c) 2023-2024 Visual Ehrmanntraut.
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
#include "crypto/random.h"
#include "hw/arm/apple-silicon/a13.h"
#include "hw/arm/apple-silicon/a9.h"
#include "hw/arm/apple-silicon/sep.h"
#include "hw/core/cpu.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "qemu/log.h"

#define REG_TRNG_FIFO_OUTPUT_BASE (0x00)
#define REG_TRNG_FIFO_OUTPUT_END (0x0C)
#define REG_TRNG_STATUS (0x10)
#define TRNG_STATUS_FILLED BIT(0)
#define REG_TRNG_CONFIG (0x14)
#define TRNG_CONFIG_ENABLED BIT(19)
#define TRNG_CONFIG_PERSONALISED BIT(20)
#define REG_TRNG_AES_KEY_BASE (0x40)
#define REG_TRNG_AES_KEY_END (0x5C)
#define REG_TRNG_ECID_LOW (0x60)
#define REG_TRNG_ECID_HI (0x64)

static void trng_reg_write(void *opaque, hwaddr addr, uint64_t data,
                           unsigned size)
{
    AppleTRNGState *s;

    s = (AppleTRNGState *)opaque;

    switch (addr) {
    case REG_TRNG_CONFIG:
        s->config = (uint32_t)data;
        break;
    case REG_TRNG_AES_KEY_BASE ... REG_TRNG_AES_KEY_END:
        memcpy(s->key + (addr - REG_TRNG_AES_KEY_BASE), &data, size);
        break;
    case REG_TRNG_ECID_LOW:
        s->ecid &= 0xFFFFFFFF00000000;
        s->ecid |= data & 0xFFFFFFFF;
        break;
    case REG_TRNG_ECID_HI:
        s->ecid &= 0x00000000FFFFFFFF;
        s->ecid |= (data & 0xFFFFFFFF) << 32;
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "TRNG: Unknown write at 0x" HWADDR_FMT_plx
                      " of value 0x" HWADDR_FMT_plx "\n",
                      addr, data);
        break;
    }
}

static uint64_t trng_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleTRNGState *s;
    uint64_t ret;

    s = (AppleTRNGState *)opaque;

    switch (addr) {
    case REG_TRNG_FIFO_OUTPUT_BASE ... REG_TRNG_FIFO_OUTPUT_END: {
        uint64_t ret = 0;
        qcrypto_random_bytes(&ret, size, NULL);
        return ret;
    }
    case REG_TRNG_STATUS:
        return TRNG_STATUS_FILLED;
    case REG_TRNG_CONFIG:
        return s->config;
    case REG_TRNG_AES_KEY_BASE ... REG_TRNG_AES_KEY_END:
        memcpy(&ret, s->key + (addr - REG_TRNG_AES_KEY_BASE), size);
        return ret;
    case REG_TRNG_ECID_LOW:
        return s->ecid & 0xFFFFFFFF;
    case REG_TRNG_ECID_HI:
        return (s->ecid & 0xFFFFFFFF00000000) >> 32;
    default:
        qemu_log_mask(LOG_UNIMP, "TRNG: Unknown read at 0x" HWADDR_FMT_plx "\n",
                      addr);
        return 0;
    }
}

static const MemoryRegionOps trng_reg_ops = {
    .write = trng_reg_write,
    .read = trng_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.unaligned = false,
};

static void misc0_reg_write(void *opaque, hwaddr addr, uint64_t data,
                            unsigned size)
{
    AppleSEPState *s = APPLE_SEP(opaque);

    switch (addr) {
    default:
        memcpy(&s->misc0_regs[addr], &data, size);
        qemu_log_mask(LOG_UNIMP,
                      "SEP MISC0: Unknown write at 0x" HWADDR_FMT_plx
                      " with value 0x" HWADDR_FMT_plx "\n",
                      addr, data);
        break;
    }
}

static uint64_t misc0_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleSEPState *s = APPLE_SEP(opaque);
    uint64_t ret = 0;

    switch (addr) {
    case 0xc: // ???? bit1 clear, bit0 set
        return (0 << 1) | (1 << 0);
    case 0xf4: // ????
        return 0x0;
    default:
        memcpy(&ret, &s->misc0_regs[addr], size);
        qemu_log_mask(LOG_UNIMP,
                      "SEP MISC0: Unknown read at 0x" HWADDR_FMT_plx "\n",
                      addr);
        break;
    }

    return ret;
}

static const MemoryRegionOps misc0_reg_ops = {
    .write = misc0_reg_write,
    .read = misc0_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.unaligned = false,
};

static void misc1_reg_write(void *opaque, hwaddr addr, uint64_t data,
                            unsigned size)
{
    AppleSEPState *s = APPLE_SEP(opaque);
    switch (addr) {
    // case 0x20:
    //     break;
    default:
        memcpy(&s->misc1_regs[addr], &data, size);
        qemu_log_mask(LOG_UNIMP,
                      "SEP MISC1: Unknown write at 0x" HWADDR_FMT_plx
                      " with value 0x" HWADDR_FMT_plx "\n",
                      addr, data);
        break;
    }
}

static uint64_t misc1_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleSEPState *s = APPLE_SEP(opaque);
    uint64_t ret = 0;

    switch (addr) {
    case 0xc: // ???? bit1 clear, bit0 set
        return (0 << 1) | (1 << 0);
    // case 0x20:
    // return 0x1;
    case 0xe4: // ????
        return 0x0;
    case 0x280: // ????
        return 0x1;
    default:
        memcpy(&ret, &s->misc1_regs[addr], size);
        qemu_log_mask(LOG_UNIMP,
                      "SEP MISC1: Unknown read at 0x" HWADDR_FMT_plx "\n",
                      addr);
        break;
    }

    return ret;
}

static const MemoryRegionOps misc1_reg_ops = {
    .write = misc1_reg_write,
    .read = misc1_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.unaligned = false,
};

static void misc2_reg_write(void *opaque, hwaddr addr, uint64_t data,
                            unsigned size)
{
    AppleSEPState *s = APPLE_SEP(opaque);
    switch (addr) {
    default:
        memcpy(&s->misc2_regs[addr], &data, size);
        qemu_log_mask(LOG_UNIMP,
                      "SEP MISC2: Unknown write at 0x" HWADDR_FMT_plx
                      " with value 0x" HWADDR_FMT_plx "\n",
                      addr, data);
        break;
    }
}

static uint64_t misc2_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleSEPState *s = APPLE_SEP(opaque);
    uint64_t ret = 0;

    switch (addr) {
    case 0x24: // ????
        return 0x0;
    default:
        memcpy(&ret, &s->misc2_regs[addr], size);
        qemu_log_mask(LOG_UNIMP,
                      "SEP MISC2: Unknown read at 0x" HWADDR_FMT_plx "\n",
                      addr);
        break;
    }

    return ret;
}

static const MemoryRegionOps misc2_reg_ops = {
    .write = misc2_reg_write,
    .read = misc2_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.unaligned = false,
};


AppleSEPState *apple_sep_create(DTBNode *node, vaddr base, uint32_t cpu_id,
                                uint32_t build_version, bool modern)
{
    DeviceState *dev;
    AppleA7IOP *a7iop;
    AppleSEPState *s;
    SysBusDevice *sbd;
    DTBProp *prop;
    uint64_t *reg;

    dev = qdev_new(TYPE_APPLE_SEP);
    a7iop = APPLE_A7IOP(dev);
    s = APPLE_SEP(dev);
    sbd = SYS_BUS_DEVICE(dev);

    prop = find_dtb_prop(node, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;

    apple_a7iop_init(a7iop, "SEP", reg[1],
                     modern ? APPLE_A7IOP_V4 : APPLE_A7IOP_V2, NULL, NULL);
    s->base = base;
    s->modern = modern;

    if (modern) {
        s->cpu = ARM_CPU(apple_a13_cpu_create(NULL, g_strdup("sep-cpu"), cpu_id,
                                              0, -1, 'P'));
    } else {
        s->cpu = ARM_CPU(apple_a9_create(NULL, g_strdup("sep-cpu"), cpu_id, 0));
        object_property_set_bool(OBJECT(s->cpu), "aarch64", false, NULL);
        unset_feature(&s->cpu->env, ARM_FEATURE_AARCH64);
    }
    object_property_set_uint(OBJECT(s->cpu), "rvbar", s->base & ~0xFFF, NULL);
    object_property_add_child(OBJECT(dev), DEVICE(s->cpu)->id, OBJECT(s->cpu));

    memory_region_init_io(&s->trng_mr, OBJECT(dev), &trng_reg_ops,
                          &s->trng_state, "sep.trng", 0x10000);
    sysbus_init_mmio(sbd, &s->trng_mr);
    memory_region_init_io(&s->misc0_mr, OBJECT(dev), &misc0_reg_ops, s,
                          "sep.misc0", 0x100);
    sysbus_init_mmio(sbd, &s->misc0_mr);
    memory_region_init_io(&s->misc1_mr, OBJECT(dev), &misc1_reg_ops, s,
                          "sep.misc1", 0x1000);
    sysbus_init_mmio(sbd, &s->misc1_mr);
    memory_region_init_io(&s->misc2_mr, OBJECT(dev), &misc2_reg_ops, s,
                          "sep.misc2", 0x100);
    sysbus_init_mmio(sbd, &s->misc2_mr);
    DTBNode *child = find_dtb_node(node, "iop-sep-nub");
    g_assert(child);
    // SEPFW needs to be loaded by restore, supposedly
    // uint32_t data = 1;
    // set_dtb_prop(child, "sepfw-loaded", sizeof(data), &data);
    return s;
}

static void apple_sep_cpu_reset_work(CPUState *cpu, run_on_cpu_data data)
{
    AppleSEPState *s = data.host_ptr;
    cpu_reset(cpu);
    cpu_set_pc(cpu, s->base);
}

static void apple_sep_realize(DeviceState *dev, Error **errp)
{
    AppleSEPState *s;
    AppleSEPClass *sc;

    s = APPLE_SEP(dev);
    sc = APPLE_SEP_GET_CLASS(dev);
    if (sc->parent_realize) {
        sc->parent_realize(dev, errp);
    }
    qdev_realize(DEVICE(s->cpu), NULL, errp);
    qdev_connect_gpio_out_named(dev, APPLE_A7IOP_IOP_IRQ, 0,
                                qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_IRQ));
}

static void apple_sep_reset(DeviceState *dev)
{
    AppleSEPState *s;
    AppleSEPClass *sc;

    s = APPLE_SEP(dev);
    sc = APPLE_SEP_GET_CLASS(dev);
    if (sc->parent_reset) {
        sc->parent_reset(dev);
    }
    run_on_cpu(CPU(s->cpu), apple_sep_cpu_reset_work, RUN_ON_CPU_HOST_PTR(s));
}

static void apple_sep_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    AppleSEPClass *sc = APPLE_SEP_CLASS(klass);
    device_class_set_parent_realize(dc, apple_sep_realize, &sc->parent_realize);
    device_class_set_parent_reset(dc, apple_sep_reset, &sc->parent_reset);
    dc->desc = "Apple SEP";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_sep_info = {
    .name = TYPE_APPLE_SEP,
    .parent = TYPE_APPLE_A7IOP,
    .instance_size = sizeof(AppleSEPState),
    .class_size = sizeof(AppleSEPClass),
    .class_init = apple_sep_class_init,
};

static void apple_sep_register_types(void)
{
    type_register_static(&apple_sep_info);
}

type_init(apple_sep_register_types);
