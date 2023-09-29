#ifndef HW_MISC_APPLE_MBOX_H
#define HW_MISC_APPLE_MBOX_H

#include "qemu/osdep.h"
#include "exec/memory.h"
#include "hw/core/cpu.h"
#include "hw/sysbus.h"

#define APPLE_MBOX_IRQ_A2I_NONEMPTY 0
#define APPLE_MBOX_IRQ_A2I_EMPTY 1
#define APPLE_MBOX_IRQ_I2A_NONEMPTY 2
#define APPLE_MBOX_IRQ_I2A_EMPTY 3
#define APPLE_MBOX_IOP_IRQ "apple-mbox-iop-irq"

#define APPLE_MBOX_MMIO_V3 0
#define APPLE_MBOX_MMIO_V2 1

#define TYPE_APPLE_MBOX "apple.mbox"
OBJECT_DECLARE_SIMPLE_TYPE(AppleMboxState, APPLE_MBOX)

#define REG_SIZE (0x10000)

#define EP_MANAGEMENT (0)
#define EP_CRASHLOG (1)

enum apple_mbox_ep0_state {
    EP0_IDLE,
    EP0_WAIT_HELLO,
    EP0_WAIT_ROLLCALL,
    EP0_DONE,
};

typedef struct QEMU_PACKED apple_mbox_mgmt_msg {
    union {
        uint64_t raw;
        struct QEMU_PACKED {
            union {
                struct QEMU_PACKED {
                    uint16_t major;
                    uint16_t minor;
                } hello;
                struct QEMU_PACKED {
                    uint32_t seg;
                    uint16_t timestamp;
                } ping;
                struct QEMU_PACKED {
                    uint32_t state;
                    uint32_t ep;
                } epstart;
                struct QEMU_PACKED {
                    uint32_t state;
                } power;
                struct QEMU_PACKED {
                    uint32_t epMask;
                    /* bit x -> endpoint ((epBlock * 32) + x) */
                    uint8_t epBlock : 6;
                    uint16_t unk38 : 13;
                    uint8_t epEnded : 1;
                } rollcall;
            };
        };
        struct QEMU_PACKED {
            uint32_t field_0;
            uint16_t field_32;
            uint8_t field_48 : 4;
            uint8_t type : 4;
        };
    };
} *apple_mbox_mgmt_msg_t;

typedef struct apple_mbox_msg {
    union QEMU_PACKED {
        uint64_t data[2];
        struct QEMU_PACKED {
            union QEMU_PACKED {
                uint64_t msg;
                struct apple_mbox_mgmt_msg mgmt_msg;
            };
            uint32_t endpoint;
            uint32_t flags;
        };
    };
    QTAILQ_ENTRY(apple_mbox_msg) entry;
} *apple_mbox_msg_t;

typedef void AppleMboxEPHandler(void *opaque, uint32_t ep, uint64_t msg);
typedef struct apple_mbox_ep_handler_data {
    AppleMboxEPHandler *handler;
    void *opaque;
} apple_mbox_ep_handler_data;

struct AppleMboxState {
    SysBusDevice parent_obj;

    MemoryRegion mmio_v3;
    MemoryRegion mmio_v2;
    QemuMutex mutex;
    void *opaque;
    const struct AppleMboxOps *ops;
    char *role;
    uint32_t ep0_status;
    uint32_t protocol_version;
    qemu_irq irqs[4];
    qemu_irq iop_irq;
    QTAILQ_HEAD(, apple_mbox_msg) inbox;
    QTAILQ_HEAD(, apple_mbox_msg) outbox;
    QTAILQ_HEAD(, apple_mbox_msg) rollcall;
    uint32_t inboxCount;
    uint32_t outboxCount;

    GTree *endpoints;
    QEMUBH *bh;
    uint8_t regs[REG_SIZE];
    uint32_t int_mask;
    uint32_t iop_int_mask;
    bool real;
};

struct iop_rollcall_data {
    AppleMboxState *s;
    uint32_t mask;
    uint32_t last_block;
};


struct AppleMboxOps {
    void (*start)(void *opaque);
    void (*wakeup)(void *opaque);
};

/*
 * Send message to an endpoint
 */
void apple_mbox_send_message(AppleMboxState *s, uint32_t ep, uint64_t msg);

/*
 * Send message to a control endpoint
 */
void apple_mbox_send_control_message(AppleMboxState *s, uint32_t ep,
                                     uint64_t msg);

/*
 * Register inbox endpoint listener.
 */
void apple_mbox_register_endpoint(AppleMboxState *s, uint32_t ep,
                                  AppleMboxEPHandler *handler);

/*
 * Unregister inbox endpoint listener.
 */
void apple_mbox_unregister_endpoint(AppleMboxState *s, uint32_t ep);

/*
 * Register control inbox endpoint listener.
 */
void apple_mbox_register_control_endpoint(AppleMboxState *s, uint32_t ep,
                                          AppleMboxEPHandler *handler);

void apple_mbox_set_real(AppleMboxState *s, bool real);

AppleMboxState *apple_mbox_create(const char *role, void *opaque,
                                  uint64_t mmio_size, uint32_t protocol_version,
                                  const struct AppleMboxOps *ops);

#endif /* HW_MISC_APPLE_MBOX_H */
