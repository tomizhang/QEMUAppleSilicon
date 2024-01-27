#ifndef APPLE_ANS_H
#define APPLE_ANS_H

#include "hw/arm/apple-silicon/dtb.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/sysbus.h"
#include "qemu/queue.h"
#include "qom/object.h"

SysBusDevice *apple_ans_create(DTBNode *node, AppleA7IOPVersion version,
                               uint32_t protocol_version);

#endif /* APPLE_ANS_H */
