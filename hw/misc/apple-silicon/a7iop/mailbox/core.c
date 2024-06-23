#include "qemu/osdep.h"
#include "block/aio.h"
#include "exec/memory.h"
#include "hw/irq.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/misc/apple-silicon/a7iop/mailbox/core.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/queue.h"
#include "private.h"
#include "trace.h"

#define MAX_MESSAGE_COUNT 15

#define CTRL_ENABLE_SHIFT 0
#define CTRL_ENABLE_MASK BIT(CTRL_ENABLE_SHIFT)
#define CTRL_ENABLE(v) (((v) << CTRL_ENABLE_SHIFT) & CTRL_ENABLE_MASK)
#define CTRL_FULL_SHIFT 16
#define CTRL_FULL_MASK BIT(CTRL_FULL_SHIFT)
#define CTRL_FULL(v) (((v) << CTRL_FULL_SHIFT) & CTRL_FULL_MASK)
#define CTRL_EMPTY_SHIFT 17
#define CTRL_EMPTY_MASK BIT(CTRL_EMPTY_SHIFT)
#define CTRL_EMPTY(v) (((v) << CTRL_EMPTY_SHIFT) & CTRL_EMPTY_MASK)
#define CTRL_OVERFLOW_SHIFT 18
#define CTRL_OVERFLOW_MASK BIT(CTRL_OVERFLOW_SHIFT)
#define CTRL_OVERFLOW(v) (((v) << CTRL_OVERFLOW_SHIFT) & CTRL_OVERFLOW_MASK)
#define CTRL_UNDERFLOW_SHIFT 19
#define CTRL_UNDERFLOW_MASK BIT(CTRL_UNDERFLOW_SHIFT)
#define CTRL_UNDERFLOW(v) (((v) << CTRL_UNDERFLOW_SHIFT) & CTRL_UNDERFLOW_MASK)
#define CTRL_COUNT_SHIFT 20
#define CTRL_COUNT_MASK (MAX_MESSAGE_COUNT << CTRL_COUNT_SHIFT)
#define CTRL_COUNT(v) (((v) << CTRL_COUNT_SHIFT) & CTRL_COUNT_MASK)

#define IOP_EMPTY BIT(0)
#define IOP_NONEMPTY BIT(4)
#define AP_EMPTY BIT(8)
#define AP_NONEMPTY BIT(12)

static inline bool iop_empty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & IOP_EMPTY) == 0;
}

static inline bool iop_nonempty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & IOP_NONEMPTY) == 0;
}

static inline bool ap_empty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & AP_EMPTY) == 0;
}

static inline bool ap_nonempty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & AP_NONEMPTY) == 0;
}

static void apple_a7iop_mailbox_update_irq(AppleA7IOPMailbox *s)
{
    bool iop_empty;
    bool ap_empty;
    bool iop_underflow;
    bool ap_underflow;
    bool iop_nonempty_unmasked;
    bool iop_empty_unmasked;
    bool ap_nonempty_unmasked;
    bool ap_empty_unmasked;

    iop_empty = QTAILQ_EMPTY(&s->iop_mailbox->inbox);
    ap_empty = QTAILQ_EMPTY(&s->ap_mailbox->inbox);
    iop_underflow = s->iop_mailbox->underflow;
    ap_underflow = s->ap_mailbox->underflow;
    iop_nonempty_unmasked = iop_nonempty_is_unmasked(s->int_mask);
    iop_empty_unmasked = iop_empty_is_unmasked(s->int_mask);
    ap_nonempty_unmasked = ap_nonempty_is_unmasked(s->int_mask);
    ap_empty_unmasked = ap_empty_is_unmasked(s->int_mask);

    trace_apple_a7iop_mailbox_update_irq(
        s->role, iop_empty, ap_empty, !iop_nonempty_unmasked,
        !iop_empty_unmasked, !ap_nonempty_unmasked, !ap_empty_unmasked);

    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY],
                 (iop_nonempty_unmasked && !iop_empty) || iop_underflow);
    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_IOP_EMPTY],
                 iop_empty_unmasked && iop_empty);

    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_AP_NONEMPTY],
                 (ap_nonempty_unmasked && !ap_empty) || ap_underflow);
    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_AP_EMPTY],
                 ap_empty_unmasked && ap_empty);
}

bool apple_a7iop_mailbox_is_empty(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    if (s->underflow) {
        return true;
    }
    return QTAILQ_EMPTY(&s->inbox);
}

static size_t apple_a7iop_mailbox_count(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return s->count;
}

static void apple_a7iop_mailbox_send(AppleA7IOPMailbox *s,
                                     AppleA7IOPMessage *msg)
{
    g_assert(msg);

    QEMU_LOCK_GUARD(&s->lock);
    trace_apple_a7iop_mailbox_send(s->role, msg->endpoint, msg->data[0],
                                   msg->data[1]);
    QTAILQ_INSERT_TAIL(&s->inbox, msg, entry);
    s->count++;
    apple_a7iop_mailbox_update_irq(s);

    if (s->bh != NULL) {
        qemu_bh_schedule(s->bh);
    }
}

void apple_a7iop_mailbox_send_ap(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg)
{
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        if (!s->ap_dir_en) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s %s direction not enabled.\n",
                          __FUNCTION__, s->role);
            return;
        }
    }

    apple_a7iop_mailbox_send(s->ap_mailbox, msg);
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        apple_a7iop_mailbox_update_irq(s);
    }
}

void apple_a7iop_mailbox_send_iop(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg)
{
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        if (!s->iop_dir_en) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s %s direction not enabled.\n",
                          __FUNCTION__, s->role);
            return;
        }
    }

    apple_a7iop_mailbox_send(s->iop_mailbox, msg);
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        apple_a7iop_mailbox_update_irq(s);
    }
}

static AppleA7IOPMessage *apple_a7iop_mailbox_recv(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    QEMU_LOCK_GUARD(&s->lock);
    if (s->underflow) {
        return NULL;
    }
    msg = QTAILQ_FIRST(&s->inbox);
    if (!msg) {
        s->underflow = true;
        qemu_log_mask(LOG_GUEST_ERROR, "%s %s underflowed.\n", __FUNCTION__,
                      s->role);
        apple_a7iop_mailbox_update_irq(s);
        return NULL;
    }
    QTAILQ_REMOVE(&s->inbox, msg, entry);
    msg->flags |= CTRL_COUNT(s->count);
    trace_apple_a7iop_mailbox_recv(s->role, msg->endpoint, msg->data[0],
                                   msg->data[1]);
    s->count--;
    apple_a7iop_mailbox_update_irq(s);
    return msg;
}

AppleA7IOPMessage *apple_a7iop_mailbox_recv_iop(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        if (!s->iop_dir_en) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s %s direction not enabled.\n",
                          __FUNCTION__, s->role);
            return NULL;
        }
    }

    msg = apple_a7iop_mailbox_recv(s->iop_mailbox);
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        apple_a7iop_mailbox_update_irq(s);
    }
    return msg;
}

AppleA7IOPMessage *apple_a7iop_mailbox_recv_ap(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        if (!s->ap_dir_en) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s %s direction not enabled.\n",
                          __FUNCTION__, s->role);
            return NULL;
        }
    }

    msg = apple_a7iop_mailbox_recv(s->ap_mailbox);
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        apple_a7iop_mailbox_update_irq(s);
    }
    return msg;
}

uint32_t apple_a7iop_mailbox_get_int_mask(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return s->int_mask;
}

void apple_a7iop_mailbox_set_int_mask(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->int_mask |= value;
    apple_a7iop_mailbox_update_irq(s);
}

void apple_a7iop_mailbox_clear_int_mask(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->int_mask &= ~value;
    apple_a7iop_mailbox_update_irq(s);
}

static inline uint32_t apple_a7iop_mailbox_ctrl(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    if (s->underflow) {
        return CTRL_UNDERFLOW(s->underflow);
    }
    return CTRL_FULL(s->count >= MAX_MESSAGE_COUNT) |
           CTRL_EMPTY(QTAILQ_EMPTY(&s->inbox)) |
           CTRL_COUNT(MIN(s->count, MAX_MESSAGE_COUNT));
}

uint32_t apple_a7iop_mailbox_get_iop_ctrl(AppleA7IOPMailbox *s)
{
    uint32_t val;

    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        val = CTRL_ENABLE(s->iop_dir_en);
    }
    val |= apple_a7iop_mailbox_ctrl(s->iop_mailbox);
    return val;
}

void apple_a7iop_mailbox_set_iop_ctrl(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->iop_dir_en = (value & CTRL_ENABLE_MASK) != 0;
}

uint32_t apple_a7iop_mailbox_get_ap_ctrl(AppleA7IOPMailbox *s)
{
    uint32_t val;

    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        val = CTRL_ENABLE(s->ap_dir_en);
    }
    val |= apple_a7iop_mailbox_ctrl(s->ap_mailbox);
    return val;
}

void apple_a7iop_mailbox_set_ap_ctrl(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->ap_dir_en = (value & CTRL_ENABLE_MASK) != 0;
}

AppleA7IOPMailbox *apple_a7iop_mailbox_new(const char *role,
                                           AppleA7IOPVersion version,
                                           AppleA7IOPMailbox *iop_mailbox,
                                           AppleA7IOPMailbox *ap_mailbox,
                                           QEMUBH *bh)
{
    DeviceState *dev;
    SysBusDevice *sbd;
    AppleA7IOPMailbox *s;
    int i;
    char name[128];

    dev = qdev_new(TYPE_APPLE_A7IOP_MAILBOX);
    sbd = SYS_BUS_DEVICE(dev);
    s = APPLE_A7IOP_MAILBOX(dev);
    s->role = g_strdup(role);
    s->iop_mailbox = iop_mailbox ? iop_mailbox : s;
    s->ap_mailbox = ap_mailbox ? ap_mailbox : s;
    s->bh = bh;
    QTAILQ_INIT(&s->inbox);
    qemu_mutex_init(&s->lock);
    for (i = 0; i < APPLE_A7IOP_IRQ_MAX; i++) {
        sysbus_init_irq(sbd, s->irqs + i);
    }
    snprintf(name, sizeof(name), TYPE_APPLE_A7IOP_MAILBOX ".%s.regs", s->role);
    switch (version) {
    case APPLE_A7IOP_V2:
        apple_a7iop_mailbox_init_mmio_v2(s, name);
        break;
    case APPLE_A7IOP_V4:
        apple_a7iop_mailbox_init_mmio_v4(s, name);
        break;
    }
    sysbus_init_mmio(sbd, &s->mmio);

    return s;
}

static void apple_a7iop_mailbox_reset(DeviceState *dev)
{
    AppleA7IOPMailbox *s;
    AppleA7IOPMessage *msg;

    s = APPLE_A7IOP_MAILBOX(dev);

    g_assert(s->iop_mailbox != s->ap_mailbox);
    QEMU_LOCK_GUARD(&s->lock);
    s->count = 0;
    s->iop_dir_en = true;
    s->ap_dir_en = true;
    s->underflow = false;
    bzero(s->iop_recv_reg, sizeof(s->iop_recv_reg));
    bzero(s->ap_recv_reg, sizeof(s->ap_recv_reg));
    bzero(s->iop_send_reg, sizeof(s->iop_send_reg));
    bzero(s->ap_send_reg, sizeof(s->ap_send_reg));

    while (!QTAILQ_EMPTY(&s->inbox)) {
        msg = QTAILQ_FIRST(&s->inbox);
        QTAILQ_REMOVE(&s->inbox, msg, entry);
        g_free(msg);
    }
    apple_a7iop_mailbox_update_irq(s);
}

static void apple_a7iop_mailbox_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc;

    dc = DEVICE_CLASS(klass);

    dc->reset = apple_a7iop_mailbox_reset;
    dc->desc = "Apple A7IOP Mailbox";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_a7iop_mailbox_info = {
    .name = TYPE_APPLE_A7IOP_MAILBOX,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleA7IOPMailbox),
    .class_init = apple_a7iop_mailbox_class_init,
};

static void apple_a7iop_mailbox_register_types(void)
{
    type_register_static(&apple_a7iop_mailbox_info);
}

type_init(apple_a7iop_mailbox_register_types);
