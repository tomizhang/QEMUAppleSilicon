#include "qemu/osdep.h"
#include "block/aio.h"
#include "hw/irq.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/misc/apple-silicon/a7iop/mailbox.h"
#include "hw/misc/apple-silicon/a7iop/private.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "trace.h"

#define CPU_CTRL_RUN BIT(4)

#define A2I_EMPTY BIT(0)
#define A2I_NONEMPTY BIT(4)
#define I2A_EMPTY BIT(8)
#define I2A_NONEMPTY BIT(12)

static inline bool i2a_empty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & I2A_EMPTY) == 0;
}

static inline bool i2a_nonempty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & I2A_NONEMPTY) == 0;
}

static inline bool a2i_empty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & A2I_EMPTY) == 0;
}

static inline bool a2i_nonempty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & A2I_NONEMPTY) == 0;
}

static void apple_a7iop_update_iop_irq(AppleA7IOP *s)
{
    // TODO: Implement properly once KIC is implemented
    bool a2i_empty;
    bool i2a_empty;

    a2i_empty = apple_a7iop_mailbox_is_empty(s->a2i);
    i2a_empty = apple_a7iop_mailbox_is_empty(s->i2a);

    qemu_set_irq(
        s->iop_irq,
        (a2i_nonempty_is_unmasked(s->iop_int_mask) && !a2i_empty) ||
            (a2i_empty_is_unmasked(s->iop_int_mask) && a2i_empty) ||
            (i2a_nonempty_is_unmasked(s->iop_int_mask) && !i2a_empty) ||
            (i2a_empty_is_unmasked(s->iop_int_mask) && i2a_empty));
}

static void apple_a7iop_update_ap_irq(AppleA7IOP *s)
{
    bool a2i_empty;
    bool i2a_empty;
    bool a2i_nonempty_unmasked;
    bool a2i_empty_unmasked;
    bool i2a_nonempty_unmasked;
    bool i2a_empty_unmasked;

    a2i_empty = apple_a7iop_mailbox_is_empty(s->a2i);
    i2a_empty = apple_a7iop_mailbox_is_empty(s->i2a);
    a2i_nonempty_unmasked = a2i_nonempty_is_unmasked(s->int_mask);
    a2i_empty_unmasked = a2i_empty_is_unmasked(s->int_mask);
    i2a_nonempty_unmasked = i2a_nonempty_is_unmasked(s->int_mask);
    i2a_empty_unmasked = i2a_empty_is_unmasked(s->int_mask);

    trace_apple_a7iop_update_ap_irq(
        s->role, a2i_empty, i2a_empty, !a2i_nonempty_unmasked,
        !a2i_empty_unmasked, !i2a_nonempty_unmasked, !i2a_empty_unmasked);

    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_A2I_NONEMPTY],
                 a2i_nonempty_unmasked && !a2i_empty);
    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_A2I_EMPTY],
                 a2i_empty_unmasked && a2i_empty);

    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_I2A_NONEMPTY],
                 i2a_nonempty_unmasked && !i2a_empty);
    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_I2A_EMPTY],
                 i2a_empty_unmasked && i2a_empty);
}

static void apple_a7iop_update_irq(AppleA7IOP *s)
{
    apple_a7iop_update_ap_irq(s);
    apple_a7iop_update_iop_irq(s);
}

void apple_a7iop_send_i2a(AppleA7IOP *s, AppleA7IOPMessage *msg)
{
    QEMU_LOCK_GUARD(&s->lock);
    apple_a7iop_mailbox_send(s->i2a, msg);
    apple_a7iop_update_irq(s);
}

AppleA7IOPMessage *apple_a7iop_recv_i2a(AppleA7IOP *s)
{
    AppleA7IOPMessage *msg;

    QEMU_LOCK_GUARD(&s->lock);
    msg = apple_a7iop_mailbox_recv(s->i2a);
    apple_a7iop_update_irq(s);

    return msg;
}

void apple_a7iop_send_a2i(AppleA7IOP *s, AppleA7IOPMessage *msg)
{
    QEMU_LOCK_GUARD(&s->lock);
    apple_a7iop_mailbox_send(s->a2i, msg);
    apple_a7iop_update_irq(s);
    if (s->bh != NULL) {
        qemu_bh_schedule(s->bh);
    }
}

AppleA7IOPMessage *apple_a7iop_recv_a2i(AppleA7IOP *s)
{
    AppleA7IOPMessage *msg;

    QEMU_LOCK_GUARD(&s->lock);
    msg = apple_a7iop_mailbox_recv(s->a2i);
    apple_a7iop_update_irq(s);
    return msg;
}

uint32_t apple_a7iop_get_int_mask(AppleA7IOP *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return s->int_mask;
}

void apple_a7iop_set_int_mask(AppleA7IOP *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->int_mask |= value;
    apple_a7iop_update_ap_irq(s);
}

void apple_a7iop_clear_int_mask(AppleA7IOP *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->int_mask &= ~value;
    apple_a7iop_update_ap_irq(s);
}

uint32_t apple_a7iop_get_iop_int_mask(AppleA7IOP *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return s->iop_int_mask;
}

void apple_a7iop_set_iop_int_mask(AppleA7IOP *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->iop_int_mask |= value;
    apple_a7iop_update_iop_irq(s);
}

void apple_a7iop_clear_iop_int_mask(AppleA7IOP *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->iop_int_mask &= ~value;
    apple_a7iop_update_iop_irq(s);
}

void apple_a7iop_cpu_start(AppleA7IOP *s, bool wake)
{
    if (s->ops == NULL) {
        return;
    }

    if (wake) {
        if (s->ops->wakeup) {
            s->ops->wakeup(s);
        }
    } else if (s->ops->start) {
        s->ops->start(s);
    }
}

uint32_t apple_a7iop_get_cpu_status(AppleA7IOP *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return s->cpu_status;
}

void apple_a7iop_set_cpu_status(AppleA7IOP *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->cpu_status = value;
}

uint32_t apple_a7iop_get_cpu_ctrl(AppleA7IOP *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return s->cpu_ctrl;
}

void apple_a7iop_set_cpu_ctrl(AppleA7IOP *s, uint32_t value)
{
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        s->cpu_ctrl = value;
    }
    if (value & CPU_CTRL_RUN) {
        apple_a7iop_cpu_start(s, false);
    }
}

void apple_a7iop_init(AppleA7IOP *s, const char *role, uint64_t mmio_size,
                      AppleA7IOPVersion version, const AppleA7IOPOps *ops,
                      QEMUBH *bh)
{
    int i;
    DeviceState *dev;
    SysBusDevice *sbd;
    char name[32];

    dev = DEVICE(s);
    sbd = SYS_BUS_DEVICE(dev);

    s->role = g_strdup(role);
    s->ops = ops;
    s->bh = bh;

    qemu_mutex_init(&s->lock);

    snprintf(name, sizeof(name), "%s_A2I", role);
    s->a2i = apple_a7iop_mailbox_new(name);
    object_property_add_child(OBJECT(dev), "a2i", OBJECT(s->a2i));
    snprintf(name, sizeof(name), "%s_I2A", role);
    s->i2a = apple_a7iop_mailbox_new(name);
    object_property_add_child(OBJECT(dev), "i2a", OBJECT(s->i2a));

    switch (version) {
    case APPLE_A7IOP_V2:
        apple_a7iop_init_mmio_v2(s, mmio_size);
        break;
    case APPLE_A7IOP_V4:
        apple_a7iop_init_mmio_v4(s, mmio_size);
        break;
    }
    s->version = version;

    for (i = 0; i < APPLE_A7IOP_IRQ_MAX; i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }

    qdev_init_gpio_out_named(dev, &s->iop_irq, APPLE_A7IOP_IOP_IRQ, 1);
}

static void apple_a7iop_reset(DeviceState *opaque)
{
    AppleA7IOP *s;

    s = APPLE_A7IOP(opaque);

    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        s->iop_int_mask = 0xFFFFFFFF;
        switch (s->version) {
        case APPLE_A7IOP_V2:
            s->int_mask = 0xFFFFFFFF;
            break;
        case APPLE_A7IOP_V4:
            s->int_mask = 0x00000000;
            break;
        }
        s->cpu_status = 0x00000000;

        apple_a7iop_update_irq(s);
    }
}

static void apple_a7iop_realize(DeviceState *opaque, Error **errp)
{
    AppleA7IOP *s;

    s = APPLE_A7IOP(opaque);

    sysbus_realize(SYS_BUS_DEVICE(s->a2i), errp);
    sysbus_realize(SYS_BUS_DEVICE(s->i2a), errp);

    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        apple_a7iop_update_irq(s);
    }
}

static void apple_a7iop_unrealize(DeviceState *opaque)
{
    AppleA7IOP *s;

    s = APPLE_A7IOP(opaque);

    qdev_unrealize(DEVICE(s->a2i));
    qdev_unrealize(DEVICE(s->i2a));
}

static void apple_a7iop_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc;

    dc = DEVICE_CLASS(oc);
    dc->reset = apple_a7iop_reset;
    dc->realize = apple_a7iop_realize;
    dc->unrealize = apple_a7iop_unrealize;
    dc->desc = "Apple A7IOP";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_a7iop_info = {
    .name = TYPE_APPLE_A7IOP,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleA7IOP),
    .class_init = apple_a7iop_class_init,
};

static void apple_a7iop_register_types(void)
{
    type_register_static(&apple_a7iop_info);
}

type_init(apple_a7iop_register_types);
