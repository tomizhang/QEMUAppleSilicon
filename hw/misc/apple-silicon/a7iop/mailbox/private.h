#ifndef HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_PRIVATE_H
#define HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_PRIVATE_H

#include "hw/misc/apple-silicon/a7iop/mailbox/core.h"

uint32_t apple_a7iop_mailbox_get_int_mask(AppleA7IOPMailbox *s);
void apple_a7iop_mailbox_set_int_mask(AppleA7IOPMailbox *s, uint32_t value);
void apple_a7iop_mailbox_clear_int_mask(AppleA7IOPMailbox *s, uint32_t value);
uint32_t apple_a7iop_mailbox_get_iop_ctrl(AppleA7IOPMailbox *s);
void apple_a7iop_mailbox_set_iop_ctrl(AppleA7IOPMailbox *s, uint32_t value);
uint32_t apple_a7iop_mailbox_get_ap_ctrl(AppleA7IOPMailbox *s);
void apple_a7iop_mailbox_set_ap_ctrl(AppleA7IOPMailbox *s, uint32_t value);
void apple_a7iop_mailbox_init_mmio_v2(AppleA7IOPMailbox *s, const char *name);
void apple_a7iop_mailbox_init_mmio_v4(AppleA7IOPMailbox *s, const char *name);

#endif /* HW_MISC_APPLE_SILICON_A7IOP_MAILBOX_PRIVATE_H */
