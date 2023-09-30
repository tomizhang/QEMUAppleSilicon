#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "hw/irq.h"
#include "hw/misc/apple_mbox.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "trace.h"

#define IOP_LOG_MSG(s, t, msg)                                               \
    do {                                                                     \
        qemu_log_mask(LOG_GUEST_ERROR,                                       \
                      "%s: %s message (msg->endpoint: 0x%X "                 \
                      "msg->data[0]: 0x" HWADDR_FMT_plx                      \
                      " msg->data[1]: 0x" HWADDR_FMT_plx                     \
                      " s->ep0_status: 0x%X)\n",                             \
                      s->role, t, msg->endpoint, msg->data[0], msg->data[1], \
                      s->ep0_status);                                        \
    } while (0)

#define IOP_LOG_MGMT_MSG(s, msg)                                             \
    do {                                                                     \
        qemu_log_mask(LOG_GUEST_ERROR,                                       \
                      "%s: IOP received management message (msg->endpoint: " \
                      "0x0 msg->raw: 0x" HWADDR_FMT_plx                      \
                      " s->ep0_status: 0x%X)\n",                             \
                      s->role, msg->raw, s->ep0_status);                     \
    } while (0)

//! ------ V3 ------

#define REG_V3_CPU_CTRL (0x0044)
#define V3_CPU_CTRL_RUN BIT(4)

#define REG_V3_CPU_STATUS (0x0048)
#define V3_CPU_STATUS_IDLE (0x1)

#define REG_V3_NMI0 (0xC04) // ??
#define REG_V3_NMI1 (0xC14) // ??
#define REG_AKF_CONFIG (0x2043) // ??

#define REG_V3_IOP_INT_MASK_SET (0x4100)
#define REG_V3_IOP_INT_MASK_CLR (0x4108)

#define REG_V3_IOP_I2A_CTRL (0x4114)
#define REG_V3_IOP_I2A_SEND0 (0x4820)
#define REG_V3_IOP_I2A_SEND1 (0x4824)
#define REG_V3_IOP_I2A_SEND2 (0x4828)
#define REG_V3_IOP_I2A_SEND3 (0x482C)

#define REG_V3_IOP_A2I_CTRL (0x4110)
#define REG_V3_IOP_A2I_RECV0 (0x4810)
#define REG_V3_IOP_A2I_RECV1 (0x4814)
#define REG_V3_IOP_A2I_RECV2 (0x4818)
#define REG_V3_IOP_A2I_RECV3 (0x481C)

#define REG_V3_INT_MASK_SET (0x8100)
#define REG_V3_INT_MASK_CLR (0x8104)

#define REG_V3_A2I_CTRL (0x8108)
#define REG_V3_I2A_CTRL (0x810C)
#define CTRL_ENABLE BIT(0)
#define CTRL_FULL BIT(16)
#define CTRL_EMPTY BIT(17)
#define V3_CTRL_COUNT_SHIFT (20)
#define V3_CTRL_COUNT_MASK (0xF << V3_CTRL_COUNT_SHIFT)

#define REG_V3_A2I_PUSH0 (0x8800)
#define REG_V3_A2I_PUSH1 (0x8804)
#define REG_V3_A2I_PUSH2 (0x8808)
#define REG_V3_A2I_PUSH3 (0x880C)
#define REG_V3_A2I_POP0 (0x8810) //! Eh?
#define REG_V3_A2I_POP1 (0x8818) //! Eh?

#define REG_V3_I2A_PUSH0 (0x8820) //! Eh?
#define REG_V3_I2A_PUSH1 (0x8828) //! Eh?
#define REG_V3_I2A_POP_0_LOW (0x8830)
#define REG_V3_I2A_POP_0_HIGH (0x8834)
#define REG_V3_I2A_POP_1_LOW (0x8838)
#define REG_V3_I2A_POP_1_HIGH (0x883C)

//! ------ V2 ------

#define REG_V2_INT_MASK_SET (0x4000)
#define REG_V2_INT_MASK_CLR (0x4004)
#define V2_A2I_EMPTY BIT(0)
#define V2_A2I_NONEMPTY BIT(4)
#define V2_I2A_EMPTY BIT(8)
#define V2_I2A_NONEMPTY BIT(12)

#define REG_V2_A2I_CTRL (0x4008)

#define REG_V2_A2I_PUSH_LOW (0x4010)
#define REG_V2_A2I_PUSH_HIGH (0x4014)
#define REG_V2_A2I_POP_LOW (0x4018) //! Eh?
#define REG_V2_A2I_POP_HIGH (0x401C) //! Eh?

#define REG_V2_I2A_CTRL (0x4020)

#define REG_V2_I2A_PUSH_LOW (0x4030) //! Eh?
#define REG_V2_I2A_PUSH_HIGH (0x4034) //! Eh?
#define REG_V2_I2A_POP_LOW (0x4038)
#define REG_V2_I2A_POP_HIGH (0x403C)

#define REG_V2_IOP_INT_MASK_SET (0xB80)
#define REG_V2_IOP_INT_MASK_CLR (0xB84)

#define REG_V2_IOP_A2I_CTRL (0xB88)

#define REG_V2_IOP_A2I_RECV_LOW (0xB98)
#define REG_V2_IOP_A2I_RECV_HIGH (0xB9C)

#define REG_V2_IOP_I2A_CTRL (0xBA0)

#define REG_V2_IOP_I2A_SEND0 (0xBB0)
#define REG_V2_IOP_I2A_SEND1 (0xBB4)

#define MSG_SEND_HELLO (1)
#define MSG_RECV_HELLO (2)

#define MSG_TYPE_PING (3)
#define MSG_PING_ACK (4)

#define MSG_TYPE_EPSTART (5)

#define MSG_TYPE_REQUEST_PSTATE (6)

#define MSG_GET_PSTATE(_x) ((_x)&0xFFF)
#define PSTATE_WAIT_VR (0x201)
#define PSTATE_ON (0x220)
#define PSTATE_PWRGATE (0x202) //! Eh?
#define PSTATE_SLPNOMEM (0x0)

#define MSG_TYPE_POWER (7)
#define MSG_TYPE_ROLLCALL (8)
#define MSG_TYPE_POWERACK (11)

static gint g_uint_cmp(gconstpointer a, gconstpointer b)
{
    return a - b;
}

static bool apple_mbox_outbox_empty(AppleMboxState *s)
{
    return QTAILQ_EMPTY(&s->outbox);
}

static bool apple_mbox_inbox_empty(AppleMboxState *s)
{
    return QTAILQ_EMPTY(&s->inbox);
}

static inline uint32_t iop_outbox_flags(AppleMboxState *s)
{
    uint32_t flags = 0;

    flags = ((s->outboxCount + 1) << V3_CTRL_COUNT_SHIFT) & V3_CTRL_COUNT_MASK;

    return flags;
}

static void iop_update_irq(AppleMboxState *s)
{
    if (s->real) {
        qemu_set_irq(s->iop_irq, (apple_mbox_inbox_empty(s) &&
                                  !(s->iop_int_mask & V2_A2I_EMPTY)) ||
                                     (!apple_mbox_inbox_empty(s) &&
                                      !(s->iop_int_mask & V2_A2I_NONEMPTY)) ||
                                     (apple_mbox_outbox_empty(s) &&
                                      !(s->iop_int_mask & V2_I2A_EMPTY)) ||
                                     (!apple_mbox_outbox_empty(s) &&
                                      !(s->iop_int_mask & V2_I2A_NONEMPTY)));
    }
    smp_mb();
}

static void ap_update_irq(AppleMboxState *s)
{
    if (apple_mbox_outbox_empty(s)) {
        qemu_set_irq(s->irqs[APPLE_MBOX_IRQ_I2A_EMPTY],
                     !(s->int_mask & V2_I2A_EMPTY));
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_I2A_NONEMPTY]);
    } else {
        qemu_set_irq(s->irqs[APPLE_MBOX_IRQ_I2A_NONEMPTY],
                     !(s->int_mask & V2_I2A_NONEMPTY));
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_I2A_EMPTY]);
    }

    if (apple_mbox_inbox_empty(s)) {
        qemu_set_irq(s->irqs[APPLE_MBOX_IRQ_A2I_EMPTY],
                     !(s->int_mask & V2_A2I_EMPTY));
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_A2I_NONEMPTY]);
    } else {
        qemu_set_irq(s->irqs[APPLE_MBOX_IRQ_A2I_NONEMPTY],
                     !(s->int_mask & V2_A2I_NONEMPTY));
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_A2I_EMPTY]);
    }
}

/*
 * Push a message from AP to IOP,
 * take ownership of msg
 */
static void apple_mbox_inbox_push(AppleMboxState *s, apple_mbox_msg_t msg)
{
    QTAILQ_INSERT_TAIL(&s->inbox, msg, entry);
    s->inboxCount++;
    ap_update_irq(s);
    iop_update_irq(s);
    qemu_bh_schedule(s->bh);
}

static apple_mbox_msg_t apple_mbox_inbox_pop(AppleMboxState *s)
{
    apple_mbox_msg_t msg = QTAILQ_FIRST(&s->inbox);
    if (msg) {
        QTAILQ_REMOVE(&s->inbox, msg, entry);
        s->inboxCount--;
    }
    ap_update_irq(s);
    iop_update_irq(s);
    return msg;
}

/*
 * Push a message from IOP to AP,
 * take ownership of msg
 */
static void apple_mbox_outbox_push(AppleMboxState *s, apple_mbox_msg_t msg)
{
    QTAILQ_INSERT_TAIL(&s->outbox, msg, entry);
    s->outboxCount++;
    ap_update_irq(s);
    iop_update_irq(s);
}

static apple_mbox_msg_t apple_mbox_outbox_pop(AppleMboxState *s)
{
    apple_mbox_msg_t msg = QTAILQ_FIRST(&s->outbox);
    if (msg) {
        QTAILQ_REMOVE(&s->outbox, msg, entry);
        s->outboxCount--;
    }
    ap_update_irq(s);
    iop_update_irq(s);
    return msg;
}

void apple_mbox_send_control_message(AppleMboxState *s, uint32_t ep,
                                     uint64_t msg)
{
    apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);
    m->msg = msg;
    m->endpoint = ep;
    apple_mbox_outbox_push(s, m);
}

void apple_mbox_send_message(AppleMboxState *s, uint32_t ep, uint64_t msg)
{
    apple_mbox_send_control_message(s, ep + 31, msg);
}

static gboolean iop_rollcall(gpointer key, gpointer value, gpointer data)
{
    struct iop_rollcall_data *d = (struct iop_rollcall_data *)data;
    AppleMboxState *s = d->s;

    uint32_t ep = (uint64_t)key;
    if ((uint64_t)key < 1) {
        return false;
    }

    if (ep / 32 != d->last_block && d->mask) {
        apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);
        m->mgmt_msg.type = MSG_TYPE_ROLLCALL;
        m->mgmt_msg.rollcall.epMask = d->mask;
        m->mgmt_msg.rollcall.epBlock = (d->last_block);
        m->mgmt_msg.rollcall.epEnded = false;
        QTAILQ_INSERT_TAIL(&s->rollcall, m, entry);
        d->mask = 0;
    }
    d->last_block = ep / 32;
    d->mask |= (1 << (ep & 31));
    return false;
}

static void iop_start_rollcall(AppleMboxState *s)
{
    apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);
    struct iop_rollcall_data d = { 0 };
    d.s = s;
    while (!QTAILQ_EMPTY(&s->rollcall)) {
        apple_mbox_msg_t m = QTAILQ_FIRST(&s->rollcall);
        QTAILQ_REMOVE(&s->rollcall, m, entry);
        g_free(m);
    }
    g_tree_foreach(s->endpoints, iop_rollcall, &d);
    m->mgmt_msg.type = MSG_TYPE_ROLLCALL;
    m->mgmt_msg.rollcall.epMask = d.mask;
    m->mgmt_msg.rollcall.epBlock = (d.last_block);
    m->mgmt_msg.rollcall.epEnded = true;
    s->ep0_status = EP0_WAIT_ROLLCALL;
    QTAILQ_INSERT_TAIL(&s->rollcall, m, entry);

    m = QTAILQ_FIRST(&s->rollcall);
    QTAILQ_REMOVE(&s->rollcall, m, entry);
    apple_mbox_outbox_push(s, m);
}

static void iop_start(AppleMboxState *s)
{
    if (s->ops->start) {
        s->ops->start(s->opaque);
    }
}

static void iop_wakeup(AppleMboxState *s)
{
    if (s->ops->wakeup) {
        s->ops->wakeup(s->opaque);
    }
}

static void iop_handle_management_msg(void *opaque, uint32_t ep,
                                      uint64_t message)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    apple_mbox_mgmt_msg_t msg = (apple_mbox_mgmt_msg_t)&message;
    switch (msg->type) {
    case MSG_TYPE_PING: {
        struct apple_mbox_mgmt_msg m = { 0 };
        m.type = MSG_PING_ACK;
        m.ping.seg = msg->ping.seg;
        m.ping.timestamp = msg->ping.timestamp;
        apple_mbox_send_control_message(s, 0, m.raw);
        return;
    }
    case MSG_TYPE_POWERACK: {
        struct apple_mbox_mgmt_msg m = { 0 };
        m.type = MSG_TYPE_POWERACK;
        m.power.state = msg->power.state;
        apple_mbox_send_control_message(s, 0, m.raw);
        return;
    }
    default:
        break;
    }
    switch (s->ep0_status) {
    case EP0_IDLE:
        switch (msg->type) {
        case MSG_TYPE_REQUEST_PSTATE: {
            struct apple_mbox_mgmt_msg m = { 0 };

            switch (MSG_GET_PSTATE(msg->raw)) {
            case PSTATE_WAIT_VR:
                QEMU_FALLTHROUGH;
            case PSTATE_ON:
                iop_wakeup(s);
                m.type = MSG_SEND_HELLO;
                m.hello.major = s->protocol_version;
                m.hello.minor = s->protocol_version;
                s->ep0_status = EP0_WAIT_HELLO;
                s->regs[REG_V3_CPU_STATUS] &= ~V3_CPU_STATUS_IDLE;
                apple_mbox_send_control_message(s, 0, m.raw);
                break;
            case PSTATE_SLPNOMEM:
                m.type = MSG_TYPE_POWER;
                m.power.state = 0;
                s->regs[REG_V3_CPU_STATUS] = V3_CPU_STATUS_IDLE;
                smp_wmb();
                apple_mbox_send_control_message(s, 0, m.raw);
                break;
            default:
                break;
            }
            break;
        }
        default:
            IOP_LOG_MGMT_MSG(s, msg);
            break;
        }
        break;
    case EP0_WAIT_HELLO:
        if (msg->type == MSG_RECV_HELLO) {
            iop_start_rollcall(s);
        } else {
            IOP_LOG_MGMT_MSG(s, msg);
        }
        break;
    case EP0_WAIT_ROLLCALL:
        switch (msg->type) {
        case MSG_TYPE_ROLLCALL: {
            struct apple_mbox_mgmt_msg m = { 0 };
            if (QTAILQ_EMPTY(&s->rollcall)) {
                m.type = MSG_TYPE_POWER;
                m.power.state = 32;
                s->ep0_status = EP0_IDLE;
                apple_mbox_send_control_message(s, 0, m.raw);
            } else {
                apple_mbox_msg_t m = QTAILQ_FIRST(&s->rollcall);
                QTAILQ_REMOVE(&s->rollcall, m, entry);
                apple_mbox_outbox_push(s, m);
            }
            break;
        }
        case MSG_TYPE_EPSTART: {
            IOP_LOG_MGMT_MSG(s, msg);
            break;
        }
        default:
            IOP_LOG_MGMT_MSG(s, msg);
            break;
        }
        break;
    default:
        IOP_LOG_MGMT_MSG(s, msg);
        break;
    }
}

static void apple_mbox_bh(void *opaque)
{
    AppleMboxState *s = APPLE_MBOX(opaque);

    if (s->real) {
        return;
    }
    WITH_QEMU_LOCK_GUARD(&s->mutex)
    {
        while (!apple_mbox_inbox_empty(s)) {
            apple_mbox_msg_t msg = apple_mbox_inbox_pop(s);
            apple_mbox_ep_handler_data *hd = NULL;
            hd = g_tree_lookup(s->endpoints, GUINT_TO_POINTER(msg->endpoint));
            if (hd && hd->handler) {
                /* TODO: Better API */
                hd->handler(hd->opaque,
                            msg->endpoint >= 31 ? msg->endpoint - 31 :
                                                  msg->endpoint,
                            msg->msg);
            } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: Unexpected message to endpoint %u\n",
                              s->role, msg->endpoint);
                IOP_LOG_MSG(s, "IOP received", msg);
            }
            g_free(msg);
        }
    }
}

static void apple_mbox_v3_reg_write(void *opaque, hwaddr addr,
                                    const uint64_t data, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    apple_mbox_msg_t msg = NULL;

    s->int_mask = 0;
    WITH_QEMU_LOCK_GUARD(&s->mutex)
    {
        memcpy(&s->regs[addr], &data, size);

        switch (addr) {
        case REG_V3_CPU_CTRL:
            if (data & V3_CPU_CTRL_RUN) {
                struct apple_mbox_mgmt_msg m = { 0 };
                s->regs[REG_V3_CPU_STATUS] &= ~V3_CPU_STATUS_IDLE;
                iop_start(s);

                m.type = MSG_SEND_HELLO;
                m.hello.major = s->protocol_version;
                m.hello.minor = s->protocol_version;
                s->ep0_status = EP0_WAIT_HELLO;

                apple_mbox_send_control_message(s, 0, m.raw);
            }
            break;
        case REG_V3_A2I_PUSH0:
            QEMU_FALLTHROUGH;
        case REG_V3_A2I_PUSH1:
            QEMU_FALLTHROUGH;
        case REG_V3_A2I_PUSH2:
            QEMU_FALLTHROUGH;
        case REG_V3_A2I_PUSH3: {
            if (addr + size == REG_V3_A2I_PUSH3 + 4) {
                msg = g_new0(struct apple_mbox_msg, 1);
                memcpy(msg->data, &s->regs[REG_V3_A2I_PUSH0], 16);
                apple_mbox_inbox_push(s, msg);
                IOP_LOG_MSG(s, "IOP received", msg);
            }
            break;
        }
        case REG_V3_A2I_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V3_I2A_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_A2I_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_I2A_CTRL:
            *(uint32_t *)&s->regs[addr] &= CTRL_ENABLE;
            break;
        case REG_V3_INT_MASK_SET:
            s->int_mask |= (uint32_t)data;
            ap_update_irq(s);
            break;
        case REG_V3_INT_MASK_CLR:
            s->int_mask &= ~(uint32_t)data;
            ap_update_irq(s);
            break;
        case REG_V3_IOP_I2A_SEND0:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_I2A_SEND1:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_I2A_SEND2:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_I2A_SEND3:
            if (addr + size == REG_V3_IOP_I2A_SEND3 + 4) {
                msg = g_new0(struct apple_mbox_msg, 1);
                memcpy(msg->data, &s->regs[REG_V3_IOP_I2A_SEND0], 16);
                apple_mbox_outbox_push(s, msg);
                IOP_LOG_MSG(s, "IOP sent", msg);
            }
            break;
        case REG_V3_IOP_INT_MASK_SET:
            s->iop_int_mask |= (uint32_t)data;
            iop_update_irq(s);
            break;
        case REG_V3_IOP_INT_MASK_CLR:
            s->iop_int_mask &= ~(uint32_t)data;
            iop_update_irq(s);
            break;
        default:
            qemu_log_mask(LOG_UNIMP,
                          "%s AKF: Unknown write to 0x" HWADDR_FMT_plx
                          " of value 0x" HWADDR_FMT_plx "\n",
                          s->role, addr, data);
            break;
        }
    }
}

static uint64_t apple_mbox_v3_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    uint64_t ret = 0;
    apple_mbox_msg_t msg = NULL;

    WITH_QEMU_LOCK_GUARD(&s->mutex)
    {
        memcpy(&ret, &s->regs[addr], size);

        switch (addr) {
        case REG_V3_INT_MASK_SET:
            return s->int_mask;
        case REG_V3_INT_MASK_CLR:
            return ~s->int_mask;
        case REG_V3_I2A_POP_0_LOW:
            msg = apple_mbox_outbox_pop(s);
            if (!msg) {
                break;
            }
            msg->flags = iop_outbox_flags(s);
            IOP_LOG_MSG(s, "AP received", msg);

            memcpy(&s->regs[REG_V3_I2A_POP_0_LOW], msg->data, 16);
            memcpy(&ret, &s->regs[addr], size);

            g_free(msg);
            break;
        case REG_V3_I2A_POP_0_HIGH:
            QEMU_FALLTHROUGH;
        case REG_V3_I2A_POP_1_LOW:
            QEMU_FALLTHROUGH;
        case REG_V3_I2A_POP_1_HIGH:
            break;
        case REG_V3_IOP_INT_MASK_SET:
            return s->iop_int_mask;
        case REG_V3_IOP_INT_MASK_CLR:
            return ~s->iop_int_mask;
        case REG_V3_A2I_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_A2I_CTRL:
            if (apple_mbox_inbox_empty(s)) {
                ret |= CTRL_EMPTY;
            } else {
                ret &= ~CTRL_EMPTY;
                ret |=
                    (s->inboxCount << V3_CTRL_COUNT_SHIFT) & V3_CTRL_COUNT_MASK;
            }
            break;
        case REG_V3_I2A_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_I2A_CTRL:
            if (apple_mbox_outbox_empty(s)) {
                ret |= CTRL_EMPTY;
            } else {
                ret &= ~CTRL_EMPTY;
                ret |= (s->outboxCount << V3_CTRL_COUNT_SHIFT) &
                       V3_CTRL_COUNT_MASK;
            }
            break;
        case REG_V3_CPU_STATUS:
            break;
        case REG_V3_IOP_A2I_RECV0:
            msg = apple_mbox_inbox_pop(s);
            if (!msg) {
                break;
            }
            msg->flags = iop_outbox_flags(s);
            IOP_LOG_MSG(s, "IOP received", msg);
            memcpy(&s->regs[addr], msg->data, 16);
            memcpy(&ret, &s->regs[addr], size);
            g_free(msg);
            break;
        case REG_V3_IOP_A2I_RECV1:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_A2I_RECV2:
            QEMU_FALLTHROUGH;
        case REG_V3_IOP_A2I_RECV3:
            break;
        default:
            qemu_log_mask(LOG_UNIMP,
                          "%s AKF: Unknown read from 0x" HWADDR_FMT_plx "\n",
                          s->role, addr);
            break;
        }
    }

    return ret;
}

static const MemoryRegionOps apple_mbox_v3_reg_ops = {
    .write = apple_mbox_v3_reg_write,
    .read = apple_mbox_v3_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};

static void apple_mbox_v2_reg_write(void *opaque, hwaddr addr,
                                    const uint64_t data, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    apple_mbox_msg_t msg = NULL;

    WITH_QEMU_LOCK_GUARD(&s->mutex)
    {
        memcpy(&s->regs[addr], &data, size);

        switch (addr) {
        case REG_V3_CPU_CTRL:
            if (data & V3_CPU_CTRL_RUN) {
                struct apple_mbox_mgmt_msg m = { 0 };
                iop_start(s);

                m.type = MSG_SEND_HELLO;
                m.hello.major = s->protocol_version;
                m.hello.minor = s->protocol_version;
                s->ep0_status = EP0_WAIT_HELLO;

                apple_mbox_send_control_message(s, 0, m.raw);
            }
            break;
        case REG_V2_A2I_PUSH_LOW:
            QEMU_FALLTHROUGH;
        case REG_V2_A2I_PUSH_HIGH: {
            if (addr + size == REG_V2_A2I_PUSH_HIGH + 4) {
                msg = g_new0(struct apple_mbox_msg, 1);
                memcpy(msg->data, &s->regs[REG_V2_A2I_PUSH_LOW], 8);
                apple_mbox_inbox_push(s, msg);
                IOP_LOG_MSG(s, "AP sent", msg);
            }
            break;
        }
        case REG_V2_A2I_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V2_I2A_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V2_IOP_A2I_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V2_IOP_I2A_CTRL:
            *(uint32_t *)&s->regs[addr] &= CTRL_ENABLE;
            break;
        case REG_V2_INT_MASK_SET:
            s->int_mask |= (uint32_t)data;
            ap_update_irq(s);
            break;
        case REG_V2_INT_MASK_CLR:
            s->int_mask &= ~(uint32_t)data;
            ap_update_irq(s);
            break;
        case REG_V2_IOP_I2A_SEND0:
            QEMU_FALLTHROUGH;
        case REG_V2_IOP_I2A_SEND1:
            if (addr + size == REG_V2_IOP_I2A_SEND1 + 4) {
                msg = g_new0(struct apple_mbox_msg, 1);
                memcpy(msg->data, &s->regs[REG_V2_IOP_I2A_SEND0], 8);
                apple_mbox_outbox_push(s, msg);
                IOP_LOG_MSG(s, "IOP sent", msg);
            }
            break;
        case REG_V2_IOP_INT_MASK_SET:
            s->iop_int_mask |= (uint32_t)data;
            iop_update_irq(s);
            break;
        case REG_V2_IOP_INT_MASK_CLR:
            s->iop_int_mask &= ~(uint32_t)data;
            iop_update_irq(s);
            break;
        default:
            qemu_log_mask(LOG_UNIMP,
                          "%s AKF: Unknown write to 0x" HWADDR_FMT_plx
                          " of value 0x" HWADDR_FMT_plx "\n",
                          s->role, addr, data);
            break;
        }
    }
}

static uint64_t apple_mbox_v2_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    uint64_t ret = 0;

    WITH_QEMU_LOCK_GUARD(&s->mutex)
    {
        apple_mbox_msg_t m;
        memcpy(&ret, &s->regs[addr], size);

        switch (addr) {
        case REG_V2_INT_MASK_SET:
            return s->int_mask;
        case REG_V2_INT_MASK_CLR:
            return ~s->int_mask;
        case REG_V2_I2A_POP_LOW:
            m = apple_mbox_outbox_pop(s);
            if (!m) {
                break;
            }
            m->flags = iop_outbox_flags(s);
            IOP_LOG_MSG(s, "AP received", m);

            memcpy(&s->regs[REG_V2_I2A_POP_LOW], m->data, 8);
            memcpy(&ret, &s->regs[addr], size);

            g_free(m);
            break;
        case REG_V2_I2A_POP_HIGH:
            break;
        case REG_V2_IOP_INT_MASK_SET:
            return s->iop_int_mask;
        case REG_V2_IOP_INT_MASK_CLR:
            return ~s->iop_int_mask;
        case REG_V2_A2I_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V2_IOP_A2I_CTRL:
            if (apple_mbox_inbox_empty(s)) {
                ret |= CTRL_EMPTY;
            } else {
                ret &= ~CTRL_EMPTY;
            }
            break;
        case REG_V2_I2A_CTRL:
            QEMU_FALLTHROUGH;
        case REG_V2_IOP_I2A_CTRL:
            if (apple_mbox_outbox_empty(s)) {
                ret |= CTRL_EMPTY;
            } else {
                ret &= ~CTRL_EMPTY;
            }
            break;
        case REG_V2_IOP_A2I_RECV_LOW:
            m = apple_mbox_inbox_pop(s);
            if (!m) {
                break;
            }
            m->flags = iop_outbox_flags(s);
            IOP_LOG_MSG(s, "IOP received", m);
            memcpy(&s->regs[addr], m->data, 8);
            memcpy(&ret, &s->regs[addr], size);
            g_free(m);
            break;
        case REG_V2_IOP_A2I_RECV_HIGH:
            break;
        default:
            qemu_log_mask(LOG_UNIMP,
                          "%s AKF: Unknown read from 0x" HWADDR_FMT_plx "\n",
                          s->role, addr);
            break;
        }
    }

    return ret;
}

static const MemoryRegionOps apple_mbox_v2_reg_ops = {
    .write = apple_mbox_v2_reg_write,
    .read = apple_mbox_v2_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};


void apple_mbox_set_real(AppleMboxState *s, bool real)
{
    s->real = real;
    qemu_log_mask(LOG_GUEST_ERROR, "%s AKF: s->real: %s\n", s->role,
                  real ? "true" : "false");
    smp_wmb();
}

void apple_mbox_register_endpoint(AppleMboxState *s, uint32_t ep,
                                  AppleMboxEPHandler *handler)
{
    g_assert(ep > 0);
    apple_mbox_ep_handler_data *hd = g_new0(apple_mbox_ep_handler_data, 1);
    ep += 31;
    hd->handler = handler;
    hd->opaque = s->opaque;
    g_tree_insert(s->endpoints, GUINT_TO_POINTER(ep), hd);
}

void apple_mbox_unregister_endpoint(AppleMboxState *s, uint32_t ep)
{
    g_assert(ep > 0);
    ep += 31;
    void *hd = g_tree_lookup(s->endpoints, GUINT_TO_POINTER(ep));
    if (hd) {
        g_tree_remove(s->endpoints, GUINT_TO_POINTER(ep));
        g_free(hd);
    }
}

void apple_mbox_register_control_endpoint(AppleMboxState *s, uint32_t ep,
                                          AppleMboxEPHandler *handler)
{
    g_assert(ep < 31);
    apple_mbox_ep_handler_data *hd = g_new0(apple_mbox_ep_handler_data, 1);
    hd->handler = handler;
    hd->opaque = s->opaque;
    g_tree_insert(s->endpoints, GUINT_TO_POINTER(ep), hd);
}

static void
apple_mbox_register_control_endpoint_internal(AppleMboxState *s, uint32_t ep,
                                              AppleMboxEPHandler *handler)
{
    g_assert(ep < 31);
    apple_mbox_ep_handler_data *hd = g_new0(apple_mbox_ep_handler_data, 1);
    hd->handler = handler;
    hd->opaque = s;
    g_tree_insert(s->endpoints, GUINT_TO_POINTER(ep), hd);
}

AppleMboxState *apple_mbox_create(const char *role, void *opaque,
                                  uint64_t mmio_size, uint32_t protocol_version,
                                  const struct AppleMboxOps *ops)
{
    DeviceState *dev;
    SysBusDevice *sbd;
    AppleMboxState *s;
    int i;
    char name[32];

    dev = qdev_new(TYPE_APPLE_MBOX);
    sbd = SYS_BUS_DEVICE(dev);
    s = APPLE_MBOX(dev);

    qemu_mutex_init(&s->mutex);

    s->endpoints = g_tree_new(g_uint_cmp);

    s->opaque = opaque;
    s->protocol_version = protocol_version;
    s->role = g_strdup(role);
    s->ops = ops;

    snprintf(name, sizeof(name), TYPE_APPLE_MBOX ".%s.akf-reg", s->role);

    if (mmio_size > REG_SIZE) {
        mmio_size = REG_SIZE;
    }

    memory_region_init_io(&s->mmio_v3, OBJECT(dev), &apple_mbox_v3_reg_ops, s,
                          name, mmio_size);
    sysbus_init_mmio(sbd, &s->mmio_v3);
    memory_region_init_io(&s->mmio_v2, OBJECT(dev), &apple_mbox_v2_reg_ops, s,
                          name, mmio_size);
    sysbus_init_mmio(sbd, &s->mmio_v2);

    for (i = 0; i < 4; i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }

    qdev_init_gpio_out_named(DEVICE(dev), &s->iop_irq, APPLE_MBOX_IOP_IRQ, 1);
    QTAILQ_INIT(&s->inbox);
    QTAILQ_INIT(&s->outbox);
    QTAILQ_INIT(&s->rollcall);
    apple_mbox_register_control_endpoint_internal(s, EP_MANAGEMENT,
                                                  &iop_handle_management_msg);
    apple_mbox_register_control_endpoint_internal(s, EP_CRASHLOG, NULL);

    return s;
}

static void apple_mbox_realize(DeviceState *dev, Error **errp)
{
    AppleMboxState *s = APPLE_MBOX(dev);
    ap_update_irq(s);

    s->bh = qemu_bh_new(apple_mbox_bh, s);
}

static void apple_mbox_unrealize(DeviceState *dev)
{
}

static void apple_mbox_reset(DeviceState *dev)
{
    AppleMboxState *s = APPLE_MBOX(dev);

    s->ep0_status = EP0_IDLE;

    WITH_QEMU_LOCK_GUARD(&s->mutex)
    {
        while (!QTAILQ_EMPTY(&s->inbox)) {
            apple_mbox_msg_t m = QTAILQ_FIRST(&s->inbox);
            QTAILQ_REMOVE(&s->inbox, m, entry);
            g_free(m);
        }

        while (!QTAILQ_EMPTY(&s->outbox)) {
            apple_mbox_msg_t m = QTAILQ_FIRST(&s->outbox);
            QTAILQ_REMOVE(&s->outbox, m, entry);
            g_free(m);
        }
        s->inboxCount = 0;
        s->outboxCount = 0;
    }
    s->int_mask = 0xFFFFFFFF;
    s->iop_int_mask = 0xFFFFFFFF;
    ap_update_irq(s);
}

static int apple_mbox_post_load(void *opaque, int version_id)
{
    AppleMboxState *s = APPLE_MBOX(opaque);

    WITH_QEMU_LOCK_GUARD(&s->mutex)
    {
        if (!apple_mbox_inbox_empty(s)) {
            qemu_bh_schedule(s->bh);
        }
    }
    return 0;
}

static Property apple_mbox_properties[] = {
    DEFINE_PROP_BOOL("real", AppleMboxState, real, false),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription vmstate_apple_mbox_msg = {
    .name = "apple_mbox_msg",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (VMStateField[]){
            VMSTATE_UINT64_ARRAY(data, struct apple_mbox_msg, 2),
            VMSTATE_END_OF_LIST(),
        }
};

static const VMStateDescription vmstate_apple_mbox = {
    .name = "apple_mbox",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = apple_mbox_post_load,
    .fields =
        (VMStateField[]){
            VMSTATE_BOOL(real, AppleMboxState),
            VMSTATE_UINT32(int_mask, AppleMboxState),
            VMSTATE_UINT32(ep0_status, AppleMboxState),
            VMSTATE_UINT32(protocol_version, AppleMboxState),
            VMSTATE_UINT8_ARRAY(regs, AppleMboxState, REG_SIZE),
            VMSTATE_QTAILQ_V(inbox, AppleMboxState, 1, vmstate_apple_mbox_msg,
                             struct apple_mbox_msg, entry),
            VMSTATE_QTAILQ_V(outbox, AppleMboxState, 1, vmstate_apple_mbox_msg,
                             struct apple_mbox_msg, entry),
            VMSTATE_UINT32(inboxCount, AppleMboxState),
            VMSTATE_UINT32(outboxCount, AppleMboxState),
            VMSTATE_END_OF_LIST(),
        }
};

static void apple_mbox_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_mbox_realize;
    dc->unrealize = apple_mbox_unrealize;
    dc->reset = apple_mbox_reset;
    dc->desc = "Apple IOP Mailbox";
    dc->vmsd = &vmstate_apple_mbox;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, apple_mbox_properties);
}

static const TypeInfo apple_mbox_info = {
    .name = TYPE_APPLE_MBOX,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleMboxState),
    .class_init = apple_mbox_class_init,
};

static void apple_mbox_register_types(void)
{
    type_register_static(&apple_mbox_info);
}

type_init(apple_mbox_register_types);
