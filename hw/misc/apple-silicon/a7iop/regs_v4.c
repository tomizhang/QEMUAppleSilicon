#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/misc/apple-silicon/a7iop/mailbox.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "private.h"

#define REG_CPU_CTRL 0x0044
#define CPU_CTRL_RUN BIT(4)
#define REG_CPU_STATUS 0x0048
#define REG_NMI0 0xC04 // ??
#define REG_NMI1 0xC14 // ??
#define REG_AKF_CONFIG 0x2043 // ??
#define REG_IOP_INT_MASK_SET 0x4100
#define REG_IOP_INT_MASK_CLR 0x4104
#define REG_IOP_A2I_CTRL 0x4108
#define REG_IOP_I2A_CTRL 0x410C
#define REG_IOP_A2I_RECV0 0x4810
#define REG_IOP_A2I_RECV1 0x4814
#define REG_IOP_A2I_RECV2 0x4818
#define REG_IOP_A2I_RECV3 0x481C
#define REG_IOP_I2A_SEND0 0x4820
#define REG_IOP_I2A_SEND1 0x4824
#define REG_IOP_I2A_SEND2 0x4828
#define REG_IOP_I2A_SEND3 0x482C
#define REG_INT_MASK_SET 0x8100
#define REG_INT_MASK_CLR 0x8104
#define REG_A2I_CTRL 0x8108
#define REG_I2A_CTRL 0x810C
#define CTRL_COUNT_SHIFT 20
#define CTRL_COUNT_MASK (0xF << CTRL_COUNT_SHIFT)
#define REG_A2I_SEND0 0x8800
#define REG_A2I_SEND1 0x8804
#define REG_A2I_SEND2 0x8808
#define REG_A2I_SEND3 0x880C
#define REG_A2I_RECV0 0x8810 //! Eh?
#define REG_A2I_RECV1 0x8818 //! Eh?
#define REG_I2A_SEND0 0x8820 //! Eh?
#define REG_I2A_SEND1 0x8828 //! Eh?
#define REG_I2A_RECV0 0x8830
#define REG_I2A_RECV1 0x8834
#define REG_I2A_RECV2 0x8838
#define REG_I2A_RECV3 0x883C

static inline uint32_t iop_i2a_flags(AppleA7IOP *s)
{
    uint32_t flags = 0;

    flags = (apple_a7iop_mailbox_get_count(s->i2a) << CTRL_COUNT_SHIFT) &
            CTRL_COUNT_MASK;

    return flags;
}

static inline uint32_t iop_a2i_flags(AppleA7IOP *s)
{
    uint32_t flags = 0;

    flags = (apple_a7iop_mailbox_get_count(s->a2i) << CTRL_COUNT_SHIFT) &
            CTRL_COUNT_MASK;

    return flags;
}

static void apple_a7iop_reg_write(void *opaque, hwaddr addr,
                                  const uint64_t data, unsigned size)
{
    AppleA7IOP *s = APPLE_A7IOP(opaque);
    AppleA7IOPMessage *msg;

    switch (addr) {
    case REG_CPU_CTRL:
        apple_a7iop_set_cpu_ctrl(s, (uint32_t)data);
        break;
    case REG_A2I_SEND0:
        QEMU_FALLTHROUGH;
    case REG_A2I_SEND1:
        QEMU_FALLTHROUGH;
    case REG_A2I_SEND2:
        QEMU_FALLTHROUGH;
    case REG_A2I_SEND3:
        memcpy(s->a2i->send_reg + (addr - REG_A2I_SEND0), &data, size);
        if (addr + size == REG_A2I_SEND3 + 4) {
            msg = g_new0(AppleA7IOPMessage, 1);
            memcpy(msg->data, s->a2i->send_reg, sizeof(msg->data));
            apple_a7iop_send_a2i(s, msg);
        }
        break;
    case REG_A2I_CTRL:
        QEMU_FALLTHROUGH;
    case REG_IOP_A2I_CTRL:
        apple_a7iop_mailbox_set_ctrl(s->a2i, (uint32_t)data);
        break;
    case REG_I2A_CTRL:
        QEMU_FALLTHROUGH;
    case REG_IOP_I2A_CTRL:
        apple_a7iop_mailbox_set_ctrl(s->i2a, (uint32_t)data);
        break;
    case REG_INT_MASK_SET:
        apple_a7iop_set_int_mask(s, (uint32_t)data);
        break;
    case REG_INT_MASK_CLR:
        apple_a7iop_clear_int_mask(s, (uint32_t)data);
        break;
    case REG_IOP_I2A_SEND0:
        QEMU_FALLTHROUGH;
    case REG_IOP_I2A_SEND1:
        QEMU_FALLTHROUGH;
    case REG_IOP_I2A_SEND2:
        QEMU_FALLTHROUGH;
    case REG_IOP_I2A_SEND3:
        memcpy(s->i2a->send_reg + (addr - REG_IOP_I2A_SEND0), &data, size);
        if (addr + size == REG_IOP_I2A_SEND3 + 4) {
            msg = g_new0(AppleA7IOPMessage, 1);
            memcpy(msg->data, s->i2a->send_reg, sizeof(msg->data));
            apple_a7iop_send_i2a(s, msg);
        }
        break;
    case REG_IOP_INT_MASK_SET:
        apple_a7iop_set_iop_int_mask(s, (uint32_t)data);
        break;
    case REG_IOP_INT_MASK_CLR:
        apple_a7iop_clear_iop_int_mask(s, (uint32_t)data);
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "A7IOP(%s): Unknown write to 0x" HWADDR_FMT_plx
                      " of value 0x" HWADDR_FMT_plx "\n",
                      s->role, addr, data);
        break;
    }
}

static uint64_t apple_a7iop_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleA7IOP *s = APPLE_A7IOP(opaque);
    uint64_t ret = 0;
    AppleA7IOPMessage *msg;
    uint32_t flags;

    switch (addr) {
    case REG_CPU_CTRL:
        return apple_a7iop_get_cpu_ctrl(s);
    case REG_CPU_STATUS:
        return apple_a7iop_get_cpu_status(s);
    case REG_INT_MASK_SET:
        return apple_a7iop_get_int_mask(s);
    case REG_INT_MASK_CLR:
        return ~apple_a7iop_get_int_mask(s);
    case REG_I2A_RECV0:
        flags = iop_i2a_flags(s);
        msg = apple_a7iop_recv_i2a(s);
        if (msg) {
            msg->flags = flags;
            memcpy(s->i2a->recv_reg, msg->data, sizeof(s->i2a->recv_reg));
            g_free(msg);
        } else {
            bzero(s->i2a->recv_reg, sizeof(s->i2a->recv_reg));
        }
        QEMU_FALLTHROUGH;
    case REG_I2A_RECV1:
        QEMU_FALLTHROUGH;
    case REG_I2A_RECV2:
        QEMU_FALLTHROUGH;
    case REG_I2A_RECV3:
        memcpy(&ret, s->i2a->recv_reg + (addr - REG_I2A_RECV0), size);
        break;
    case REG_IOP_INT_MASK_SET:
        return apple_a7iop_get_iop_int_mask(s);
    case REG_IOP_INT_MASK_CLR:
        return ~apple_a7iop_get_iop_int_mask(s);
    case REG_A2I_CTRL:
        QEMU_FALLTHROUGH;
    case REG_IOP_A2I_CTRL:
        return apple_a7iop_mailbox_get_ctrl(s->a2i) | iop_a2i_flags(s);
    case REG_I2A_CTRL:
        QEMU_FALLTHROUGH;
    case REG_IOP_I2A_CTRL:
        return apple_a7iop_mailbox_get_ctrl(s->i2a) | iop_i2a_flags(s);
    case REG_IOP_A2I_RECV0:
        flags = iop_a2i_flags(s);
        msg = apple_a7iop_recv_a2i(s);
        if (msg) {
            msg->flags = flags;
            memcpy(s->a2i->recv_reg, msg->data, sizeof(s->a2i->recv_reg));
            g_free(msg);
        } else {
            bzero(s->a2i->recv_reg, sizeof(s->a2i->recv_reg));
        }
        QEMU_FALLTHROUGH;
    case REG_IOP_A2I_RECV1:
        QEMU_FALLTHROUGH;
    case REG_IOP_A2I_RECV2:
        QEMU_FALLTHROUGH;
    case REG_IOP_A2I_RECV3:
        memcpy(&ret, s->a2i->recv_reg + (addr - REG_IOP_A2I_RECV0), size);
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "A7IOP(%s): Unknown read from 0x" HWADDR_FMT_plx "\n",
                      s->role, addr);
        break;
    }

    return ret;
}

static const MemoryRegionOps apple_a7iop_reg_ops = {
    .write = apple_a7iop_reg_write,
    .read = apple_a7iop_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};

void apple_a7iop_init_mmio_v4(AppleA7IOP *s, uint64_t mmio_size)
{
    SysBusDevice *sbd;
    char name[32];

    sbd = SYS_BUS_DEVICE(s);
    snprintf(name, sizeof(name), TYPE_APPLE_A7IOP ".%s.regs", s->role);
    memory_region_init_io(&s->mmio, OBJECT(s), &apple_a7iop_reg_ops, s, name,
                          mmio_size);
    sysbus_init_mmio(sbd, &s->mmio);
}
