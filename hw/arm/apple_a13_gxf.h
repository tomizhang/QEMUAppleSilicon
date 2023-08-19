#ifndef HW_ARM_APPLE_A13_GXF_H
#define HW_ARM_APPLE_A13_GXF_H

#include "qemu/osdep.h"
#include "hw/arm/apple_a13.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "target/arm/cpu.h"

void apple_a13_init_gxf(AppleA13State *cpu);

void apple_a13_init_gxf_override(AppleA13State *cpu);

#endif
