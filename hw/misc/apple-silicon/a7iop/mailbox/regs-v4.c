#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "private.h"

#define REG_INT_MASK_SET 0x000
#define REG_INT_MASK_CLR 0x004
#define REG_IOP_CTRL 0x008
#define REG_AP_CTRL 0x00C
#define REG_IOP_SEND0 0x700
#define REG_IOP_SEND1 0x704
#define REG_IOP_SEND2 0x708
#define REG_IOP_SEND3 0x70C
#define REG_IOP_RECV0 0x710
#define REG_IOP_RECV1 0x714
#define REG_IOP_RECV2 0x718
#define REG_IOP_RECV3 0x71C
#define REG_AP_SEND0 0x720
#define REG_AP_SEND1 0x724
#define REG_AP_SEND2 0x728
#define REG_AP_SEND3 0x72C
#define REG_AP_RECV0 0x730
#define REG_AP_RECV1 0x734
#define REG_AP_RECV2 0x738
#define REG_AP_RECV3 0x73C

static void apple_a7iop_mailbox_reg_write_v4(void *opaque, hwaddr addr,
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
        QEMU_FALLTHROUGH;
    case REG_IOP_SEND2:
        QEMU_FALLTHROUGH;
    case REG_IOP_SEND3:
        qemu_mutex_lock(&s->lock);
        memcpy(s->iop_send_reg + (addr - REG_IOP_SEND0), &data, size);
        if (addr + size == REG_IOP_SEND3 + 4) {
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
        QEMU_FALLTHROUGH;
    case REG_AP_SEND2:
        QEMU_FALLTHROUGH;
    case REG_AP_SEND3:
        qemu_mutex_lock(&s->lock);
        memcpy(s->ap_send_reg + (addr - REG_AP_SEND0), &data, size);
        if (addr + size == REG_AP_SEND3 + 4) {
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

static uint64_t apple_a7iop_mailbox_reg_read_v4(void *opaque, hwaddr addr,
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
        QEMU_FALLTHROUGH;
    case REG_IOP_RECV2:
        QEMU_FALLTHROUGH;
    case REG_IOP_RECV3:
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
        QEMU_FALLTHROUGH;
    case REG_AP_RECV2:
        QEMU_FALLTHROUGH;
    case REG_AP_RECV3:
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

static const MemoryRegionOps apple_a7iop_mailbox_reg_ops_v4 = {
    .write = apple_a7iop_mailbox_reg_write_v4,
    .read = apple_a7iop_mailbox_reg_read_v4,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};

void apple_a7iop_mailbox_init_mmio_v4(AppleA7IOPMailbox *s, const char *name)
{
    memory_region_init_io(&s->mmio, OBJECT(s), &apple_a7iop_mailbox_reg_ops_v4,
                          s, name, REG_AP_RECV3 + 4);
}
