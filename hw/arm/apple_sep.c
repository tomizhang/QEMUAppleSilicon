/*
 * Apple SEP.
 *
 * Copyright (c) 2023 Visual Ehrmanntraut.
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
#include "hw/arm/apple_a13.h"
#include "hw/arm/apple_a9.h"
#include "hw/arm/apple_sep.h"
#include "hw/arm/xnu.h"
#include "hw/core/cpu.h"
#include "qapi/error.h"
#include "qemu/log.h"

static const struct AppleMboxOps sep_mailbox_ops = {};

AppleSEPState *apple_sep_create(DTBNode *node, vaddr base, uint32_t cpu_id,
                                uint32_t build_version, bool modern)
{
    DeviceState *dev;
    AppleSEPState *s;
    SysBusDevice *sbd;
    DTBProp *prop;
    uint64_t *reg;

    dev = qdev_new(TYPE_APPLE_SEP);
    s = APPLE_SEP(dev);
    s->base = base;
    s->modern = modern;

    sbd = SYS_BUS_DEVICE(dev);
    if (modern) {
        s->cpu = ARM_CPU(
            apple_a13_cpu_create(NULL, g_strdup("SEP"), cpu_id, 0, -1, 'P'));
    } else {
        s->cpu = ARM_CPU(apple_a9_create(NULL, g_strdup("SEP"), cpu_id, 0));
        object_property_set_bool(OBJECT(s->cpu), "aarch64", false, NULL);
        unset_feature(&s->cpu->env, ARM_FEATURE_AARCH64);
    }
    object_property_set_uint(OBJECT(s->cpu), "rvbar", s->base & ~0xFFF, NULL);
    object_property_add_child(OBJECT(dev), DEVICE(s->cpu)->id, OBJECT(s->cpu));

    prop = find_dtb_prop(node, "reg");
    assert(prop != NULL);
    reg = (uint64_t *)prop->value;

    s->mbox = apple_mbox_create("SEP", s, reg[1],
                                BUILD_VERSION_MAJOR(build_version) - 3,
                                &sep_mailbox_ops);
    apple_mbox_set_real(s->mbox, true);

    qdev_connect_gpio_out_named(DEVICE(s->mbox), APPLE_MBOX_IOP_IRQ, 0,
                                qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_FIQ));

    object_property_add_child(OBJECT(s), "mbox", OBJECT(s->mbox));

    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 0));
    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 1));
    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 2));
    sysbus_pass_irq(sbd, SYS_BUS_DEVICE(s->mbox));
    // sysbus_pass_irq(sbd, SYS_BUS_DEVICE(s->cpu));

    return s;
}

static void apple_sep_cpu_reset_work(CPUState *cpu, run_on_cpu_data data)
{
    AppleSEPState *s = data.host_ptr;
    cpu_reset(cpu);
    cpu_set_pc(cpu, s->base);
}

static void apple_sep_reset(DeviceState *dev)
{
    AppleSEPState *s = APPLE_SEP(dev);
    run_on_cpu(CPU(s->cpu), apple_sep_cpu_reset_work, RUN_ON_CPU_HOST_PTR(s));
}

static void apple_sep_realize(DeviceState *dev, Error **errp)
{
    AppleSEPState *s = APPLE_SEP(dev);
    sysbus_realize(SYS_BUS_DEVICE(s->mbox), errp);
    qdev_realize(DEVICE(s->cpu), NULL, errp);
}

static void apple_sep_unrealize(DeviceState *dev)
{
    AppleSEPState *s = APPLE_SEP(dev);

    qdev_unrealize(DEVICE(s->mbox));
}

static void apple_sep_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_sep_realize;
    dc->unrealize = apple_sep_unrealize;
    dc->reset = apple_sep_reset;
    dc->desc = "Apple SEP";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_sep_info = {
    .name = TYPE_APPLE_SEP,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleSEPState),
    .class_init = apple_sep_class_init,
};

static void apple_sep_register_types(void)
{
    type_register_static(&apple_sep_info);
}

type_init(apple_sep_register_types);
