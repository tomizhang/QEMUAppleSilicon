#ifndef HW_MISC_APPLE_SILICON_A7IOP_CORE_H
#define HW_MISC_APPLE_SILICON_A7IOP_CORE_H

#include "qemu/osdep.h"
#include "hw/misc/apple-silicon/a7iop/mailbox.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"

enum {
    APPLE_A7IOP_IRQ_A2I_NONEMPTY = 0,
    APPLE_A7IOP_IRQ_A2I_EMPTY,
    APPLE_A7IOP_IRQ_I2A_NONEMPTY,
    APPLE_A7IOP_IRQ_I2A_EMPTY,
    APPLE_A7IOP_IRQ_MAX,
};

#define APPLE_A7IOP_IOP_IRQ "apple-a7iop-iop-irq"

#define TYPE_APPLE_A7IOP "apple-a7iop"
OBJECT_DECLARE_SIMPLE_TYPE(AppleA7IOP, APPLE_A7IOP)

typedef enum {
    APPLE_A7IOP_V2 = 0,
    APPLE_A7IOP_V4,
} AppleA7IOPVersion;

typedef struct {
    void (*start)(AppleA7IOP *s);
    void (*wakeup)(AppleA7IOP *s);
} AppleA7IOPOps;

struct AppleA7IOP {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    AppleA7IOPVersion version;
    const char *role;
    MemoryRegion mmio;
    const AppleA7IOPOps *ops;
    QemuMutex lock;
    QEMUBH *bh;
    qemu_irq irqs[APPLE_A7IOP_IRQ_MAX];
    qemu_irq iop_irq;
    AppleA7IOPMailbox *a2i;
    AppleA7IOPMailbox *i2a;
    uint32_t int_mask;
    uint32_t iop_int_mask;
    uint32_t cpu_status;
    uint32_t cpu_ctrl;
};

void apple_a7iop_send_i2a(AppleA7IOP *s, AppleA7IOPMessage *msg);
AppleA7IOPMessage *apple_a7iop_recv_i2a(AppleA7IOP *s);
void apple_a7iop_send_a2i(AppleA7IOP *s, AppleA7IOPMessage *msg);
AppleA7IOPMessage *apple_a7iop_recv_a2i(AppleA7IOP *s);
uint32_t apple_a7iop_get_int_mask(AppleA7IOP *s);
void apple_a7iop_set_int_mask(AppleA7IOP *s, uint32_t value);
void apple_a7iop_clear_int_mask(AppleA7IOP *s, uint32_t value);
uint32_t apple_a7iop_get_iop_int_mask(AppleA7IOP *s);
void apple_a7iop_set_iop_int_mask(AppleA7IOP *s, uint32_t value);
void apple_a7iop_clear_iop_int_mask(AppleA7IOP *s, uint32_t value);
void apple_a7iop_cpu_start(AppleA7IOP *s, bool wake);
uint32_t apple_a7iop_get_cpu_status(AppleA7IOP *s);
void apple_a7iop_set_cpu_status(AppleA7IOP *s, uint32_t value);
uint32_t apple_a7iop_get_cpu_ctrl(AppleA7IOP *s);
void apple_a7iop_set_cpu_ctrl(AppleA7IOP *s, uint32_t value);
void apple_a7iop_init(AppleA7IOP *s, const char *role, uint64_t mmio_size,
                      AppleA7IOPVersion version, const AppleA7IOPOps *ops,
                      QEMUBH *bh);

#endif /* HW_MISC_APPLE_SILICON_A7IOP_CORE_H */
