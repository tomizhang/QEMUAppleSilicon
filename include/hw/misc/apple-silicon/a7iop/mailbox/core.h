#ifndef HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_CORE_H
#define HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_CORE_H

#include "qemu/osdep.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/sysbus.h"
#include "qemu/queue.h"

#define TYPE_APPLE_A7IOP_MAILBOX "apple-a7iop-mailbox"
OBJECT_DECLARE_SIMPLE_TYPE(AppleA7IOPMailbox, APPLE_A7IOP_MAILBOX)

typedef struct AppleA7IOPMessage {
    union QEMU_PACKED {
        uint64_t data[2];
        struct QEMU_PACKED {
            uint64_t msg;
            uint32_t endpoint;
            uint32_t flags;
        };
    };
    QTAILQ_ENTRY(AppleA7IOPMessage) entry;
} AppleA7IOPMessage;

struct AppleA7IOPMailbox {
    /*< private >*/
    SysBusDevice parent_obj;

    const char *role;
    QemuMutex lock;
    MemoryRegion mmio;
    QEMUBH *bh;
    QTAILQ_HEAD(, AppleA7IOPMessage) inbox;
    size_t count;
    AppleA7IOPMailbox *iop_mailbox;
    AppleA7IOPMailbox *ap_mailbox;
    qemu_irq irqs[APPLE_A7IOP_IRQ_MAX];
    bool iop_dir_en;
    bool ap_dir_en;
    bool underflow;
    uint32_t int_mask;
    uint8_t iop_recv_reg[16];
    uint8_t ap_recv_reg[16];
    uint8_t iop_send_reg[16];
    uint8_t ap_send_reg[16];
};

bool apple_a7iop_mailbox_is_empty(AppleA7IOPMailbox *s);
void apple_a7iop_mailbox_send_iop(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg);
void apple_a7iop_mailbox_send_ap(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg);
AppleA7IOPMessage *apple_a7iop_mailbox_recv_iop(AppleA7IOPMailbox *s);
AppleA7IOPMessage *apple_a7iop_mailbox_recv_ap(AppleA7IOPMailbox *s);
AppleA7IOPMailbox *apple_a7iop_mailbox_new(const char *role,
                                           AppleA7IOPVersion version,
                                           AppleA7IOPMailbox *iop_mailbox,
                                           AppleA7IOPMailbox *ap_mailbox,
                                           QEMUBH *bh);

#endif /* HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_CORE_H */
