#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/misc/apple-silicon/a7iop/private.h"
#include "qemu/log.h"

#define REG_CPU_CTRL 0x0044
#define REG_CPU_STATUS 0x0048
#define IOP_MAILBOX_REG_BASE 0xB80

static void apple_a7iop_reg_write(void *opaque, hwaddr addr,
                                  const uint64_t data, unsigned size)
{
    AppleA7IOP *s = APPLE_A7IOP(opaque);

    switch (addr) {
    case REG_CPU_CTRL:
        apple_a7iop_set_cpu_ctrl(s, (uint32_t)data);
        break;
    case REG_CPU_STATUS:
        apple_a7iop_set_cpu_status(s, (uint32_t)data);
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

    switch (addr) {
    case REG_CPU_CTRL:
        return apple_a7iop_get_cpu_ctrl(s);
    case REG_CPU_STATUS:
        return apple_a7iop_get_cpu_status(s);
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

void apple_a7iop_init_mmio_v2(AppleA7IOP *s, uint64_t mmio_size)
{
    SysBusDevice *sbd;
    char name[32];

    sbd = SYS_BUS_DEVICE(s);
    snprintf(name, sizeof(name), TYPE_APPLE_A7IOP ".%s.regs", s->role);
    memory_region_init_io(&s->mmio, OBJECT(s), &apple_a7iop_reg_ops, s, name,
                          mmio_size);
    sysbus_init_mmio(sbd, &s->mmio);

    memory_region_add_subregion_overlap(&s->mmio, IOP_MAILBOX_REG_BASE,
                                        &s->iop_mailbox->mmio, 1);
    memory_region_add_subregion_overlap(&s->mmio, AKF_STRIDE,
                                        &s->ap_mailbox->mmio, 1);
}
