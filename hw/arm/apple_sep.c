#include "qemu/osdep.h"
#include "hw/arm/apple_a13.h"
#include "hw/arm/apple_sep.h"
#include "hw/arm/xnu.h"
#include "hw/core/cpu.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/bitops.h"
#include "qemu/log.h"

static const struct AppleMboxOps sep_mailbox_ops = {};

AppleSEPState *apple_sep_create(DTBNode *node, vaddr base, uint32_t cpu_id,
                                uint32_t build_version)
{
    DeviceState *dev;
    AppleSEPState *s;
    SysBusDevice *sbd;
    DTBProp *prop;
    uint64_t *reg;

    dev = qdev_new(TYPE_APPLE_SEP);
    s = APPLE_SEP(dev);
    s->base = base;

    sbd = SYS_BUS_DEVICE(dev);

    object_initialize_child(OBJECT(dev), "cluster", &s->cpu_cluster,
                            TYPE_APPLE_A13_CLUSTER);
    qdev_prop_set_uint32(DEVICE(&s->cpu_cluster), "cluster-id", 3);
    s->cpu = apple_a13_cpu_create(NULL, g_strdup("SEP"), cpu_id, 0, 3, 'P');
    object_property_add_child(OBJECT(&s->cpu_cluster), DEVICE(s->cpu)->id,
                              OBJECT(s->cpu));

    prop = find_dtb_prop(node, "reg");
    assert(prop != NULL);
    reg = (uint64_t *)prop->value;

    s->mbox = apple_mbox_create("SEP", s, reg[1],
                                BUILD_VERSION_MAJOR(build_version) - 3,
                                &sep_mailbox_ops);
    apple_mbox_set_real(s->mbox, true);

    object_property_add_child(OBJECT(s), "mbox", OBJECT(s->mbox));

    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 0));
    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 2));
    sysbus_pass_irq(sbd, SYS_BUS_DEVICE(s->mbox));

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
    qdev_realize(DEVICE(&s->cpu_cluster), NULL, errp);
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
