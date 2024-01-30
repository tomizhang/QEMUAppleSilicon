#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "private.h"

#define REG_INT_MASK_SET 0x00
#define REG_INT_MASK_CLR 0x04
#define REG_IOP_CTRL 0x08
#define REG_IOP_SEND0 0x10
#define REG_IOP_SEND1 0x14
#define REG_IOP_RECV0 0x18
#define REG_IOP_RECV1 0x1C
#define REG_AP_CTRL 0x20
#define REG_AP_SEND0 0x30
#define REG_AP_SEND1 0x34
#define REG_AP_RECV0 0x38
#define REG_AP_RECV1 0x3C

static void apple_a7iop_mailbox_reg_write_v2(void *opaque, hwaddr addr,
                                             const uint64_t data, unsigned size)
{
    AppleA7IOPMailbox *s;
    AppleA7IOPMessage *msg;

    s = APPLE_A7IOP_MAILBOX(opaque);

    switch (addr) {
    case REG_INT_MASK_SET:
        apple_a7iop_mailbox_set_int_mask(s, (uint32_t)data);
        break;
    case REG_INT_MASK_CLR:
        apple_a7iop_mailbox_clear_int_mask(s, (uint32_t)data);
        break;
    case REG_IOP_CTRL:
        apple_a7iop_mailbox_set_iop_ctrl(s, (uint32_t)data);
        break;
    case REG_AP_CTRL:
        apple_a7iop_mailbox_set_ap_ctrl(s, (uint32_t)data);
        break;
    case REG_IOP_SEND0:
        QEMU_FALLTHROUGH;
    case REG_IOP_SEND1:
        qemu_mutex_lock(&s->lock);
        memcpy(s->iop_send_reg + (addr - REG_IOP_SEND0), &data, size);
        if (addr + size == REG_IOP_SEND1 + 4) {
            msg = g_new0(AppleA7IOPMessage, 1);
            memcpy(msg->data, s->iop_send_reg, sizeof(msg->data));
            qemu_mutex_unlock(&s->lock);
            apple_a7iop_mailbox_send_iop(s, msg);
        } else {
            qemu_mutex_unlock(&s->lock);
        }
        break;
    case REG_AP_SEND0:
        QEMU_FALLTHROUGH;
    case REG_AP_SEND1:
        qemu_mutex_lock(&s->lock);
        memcpy(s->ap_send_reg + (addr - REG_AP_SEND0), &data, size);
        if (addr + size == REG_AP_SEND1 + 4) {
            msg = g_new0(AppleA7IOPMessage, 1);
            memcpy(msg->data, s->ap_send_reg, sizeof(msg->data));
            qemu_mutex_unlock(&s->lock);
            apple_a7iop_mailbox_send_ap(s, msg);
        } else {
            qemu_mutex_unlock(&s->lock);
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s unknown @ 0x" HWADDR_FMT_plx " value 0x%" PRIx64,
                      __FUNCTION__, addr, data);
        break;
    }
}

static uint64_t apple_a7iop_mailbox_reg_read_v2(void *opaque, hwaddr addr,
                                                unsigned size)
{
    AppleA7IOPMailbox *s;
    AppleA7IOPMessage *msg;
    uint64_t ret = 0;

    s = APPLE_A7IOP_MAILBOX(opaque);

    switch (addr) {
    case REG_INT_MASK_SET:
        return apple_a7iop_mailbox_get_int_mask(s);
    case REG_INT_MASK_CLR:
        return ~apple_a7iop_mailbox_get_int_mask(s);
    case REG_IOP_CTRL:
        return apple_a7iop_mailbox_get_iop_ctrl(s);
    case REG_AP_CTRL:
        return apple_a7iop_mailbox_get_ap_ctrl(s);
    case REG_IOP_RECV0:
        msg = apple_a7iop_mailbox_recv_iop(s);
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            if (msg) {
                memcpy(s->iop_recv_reg, msg->data, sizeof(s->iop_recv_reg));
                g_free(msg);
            } else {
                bzero(s->iop_recv_reg, sizeof(s->iop_recv_reg));
            }
        }
        QEMU_FALLTHROUGH;
    case REG_IOP_RECV1:
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            memcpy(&ret, s->iop_recv_reg + (addr - REG_IOP_RECV0), size);
        }
        break;
    case REG_AP_RECV0:
        msg = apple_a7iop_mailbox_recv_ap(s);
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            if (msg) {
                memcpy(s->ap_recv_reg, msg->data, sizeof(s->ap_recv_reg));
                g_free(msg);
            } else {
                bzero(s->ap_recv_reg, sizeof(s->ap_recv_reg));
            }
        }
        QEMU_FALLTHROUGH;
    case REG_AP_RECV1:
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            memcpy(&ret, s->ap_recv_reg + (addr - REG_AP_RECV0), size);
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "%s unknown @ 0x" HWADDR_FMT_plx,
                      __FUNCTION__, addr);
        break;
    }

    return ret;
}

static const MemoryRegionOps apple_a7iop_mailbox_reg_ops_v2 = {
    .write = apple_a7iop_mailbox_reg_write_v2,
    .read = apple_a7iop_mailbox_reg_read_v2,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};

void apple_a7iop_mailbox_init_mmio_v2(AppleA7IOPMailbox *s, const char *name)
{
    memory_region_init_io(&s->mmio, OBJECT(s), &apple_a7iop_mailbox_reg_ops_v2,
                          s, name, REG_AP_RECV1 + 4);
}
