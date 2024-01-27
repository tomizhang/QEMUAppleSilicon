#ifndef HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_H
#define HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_H

#include "qemu/osdep.h"
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

    /*< public >*/
    const char *role;
    QemuMutex lock;
    QTAILQ_HEAD(, AppleA7IOPMessage) messages;
    size_t count;
    bool enabled;
    uint8_t recv_reg[16];
    uint8_t send_reg[16];
};

uint32_t apple_a7iop_mailbox_get_ctrl(AppleA7IOPMailbox *s);
void apple_a7iop_mailbox_set_ctrl(AppleA7IOPMailbox *s, uint32_t value);
bool apple_a7iop_mailbox_is_empty(AppleA7IOPMailbox *s);
size_t apple_a7iop_mailbox_get_count(AppleA7IOPMailbox *s);
void apple_a7iop_mailbox_send(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg);
AppleA7IOPMessage *apple_a7iop_mailbox_recv(AppleA7IOPMailbox *s);
AppleA7IOPMailbox *apple_a7iop_mailbox_new(const char *role);

#endif
