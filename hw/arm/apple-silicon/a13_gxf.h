#ifndef HW_ARM_APPLE_A13_GXF_H
#define HW_ARM_APPLE_A13_GXF_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/a13.h"

void apple_a13_init_gxf(AppleA13State *cpu);

void apple_a13_init_gxf_override(AppleA13State *cpu);

#endif
