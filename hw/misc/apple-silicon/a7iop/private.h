#ifndef HW_MISC_APPLE_SILICON_A7IOP_PRIVATE_H
#define HW_MISC_APPLE_SILICON_A7IOP_PRIVATE_H

#include "qemu/osdep.h"
#include "hw/misc/apple-silicon/a7iop/core.h"

#define CPU_STATUS_IDLE 0x1
#define AKF_STRIDE 0x4000

void apple_a7iop_init_mmio_v2(AppleA7IOP *s, uint64_t mmio_size);
void apple_a7iop_init_mmio_v4(AppleA7IOP *s, uint64_t mmio_size);

#endif /* HW_MISC_APPLE_SILICON_A7IOP_PRIVATE_H */
