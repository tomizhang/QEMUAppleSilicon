#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/misc/apple-silicon/a7iop/mailbox.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/queue.h"
#include "trace.h"

#define CTRL_ENABLE BIT(0)
#define CTRL_FULL BIT(16)
#define CTRL_EMPTY BIT(17)

uint32_t apple_a7iop_mailbox_get_ctrl(AppleA7IOPMailbox *s)
{
    uint32_t val;

    QEMU_LOCK_GUARD(&s->lock);
    val = s->enabled;
    if (QTAILQ_EMPTY(&s->messages)) {
        val |= CTRL_EMPTY;
    }
    return val;
}

void apple_a7iop_mailbox_set_ctrl(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);
    s->enabled = (value & CTRL_ENABLE) != 0;
}

bool apple_a7iop_mailbox_is_empty(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return QTAILQ_EMPTY(&s->messages);
}

size_t apple_a7iop_mailbox_get_count(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    return s->count;
}

void apple_a7iop_mailbox_send(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg)
{
    g_assert(msg);

    QEMU_LOCK_GUARD(&s->lock);
    if (!s->enabled) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "AppleA7IOPMailbox(%s): Tried to utilise mailbox "
                      "while it's not enabled\n",
                      s->role);
        return;
    }

    trace_apple_a7iop_mailbox_send(s->role, msg->endpoint, msg->data[0],
                                   msg->data[1]);
    QTAILQ_INSERT_TAIL(&s->messages, msg, entry);
    s->count++;
}

AppleA7IOPMessage *apple_a7iop_mailbox_recv(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    QEMU_LOCK_GUARD(&s->lock);
    if (!s->enabled) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "AppleA7IOPMailbox(%s): Tried to utilise mailbox "
                      "while it's not enabled\n",
                      s->role);
        return NULL;
    }

    msg = QTAILQ_FIRST(&s->messages);
    if (msg) {
        QTAILQ_REMOVE(&s->messages, msg, entry);
        trace_apple_a7iop_mailbox_recv(s->role, msg->endpoint, msg->data[0],
                                       msg->data[1]);
        s->count--;
    }

    return msg;
}

AppleA7IOPMailbox *apple_a7iop_mailbox_new(const char *role)
{
    DeviceState *dev;
    AppleA7IOPMailbox *s;

    dev = qdev_new(TYPE_APPLE_A7IOP_MAILBOX);
    s = APPLE_A7IOP_MAILBOX(dev);
    s->role = g_strdup(role);
    QTAILQ_INIT(&s->messages);
    qemu_mutex_init(&s->lock);

    return s;
}

static void apple_a7iop_mailbox_reset(DeviceState *dev)
{
    AppleA7IOPMailbox *s;
    AppleA7IOPMessage *msg;

    s = APPLE_A7IOP_MAILBOX(dev);

    QEMU_LOCK_GUARD(&s->lock);
    s->count = 0;
    s->enabled = true;
    bzero(s->recv_reg, sizeof(s->recv_reg));
    bzero(s->send_reg, sizeof(s->send_reg));

    while (!QTAILQ_EMPTY(&s->messages)) {
        msg = QTAILQ_FIRST(&s->messages);
        QTAILQ_REMOVE(&s->messages, msg, entry);
        g_free(msg);
    }
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
