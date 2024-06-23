#ifndef HW_WATCHDOG_APPLE_WDT_H
#define HW_WATCHDOG_APPLE_WDT_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/sysbus.h"

SysBusDevice *apple_wdt_create(DTBNode *node);

#endif /* HW_WATCHDOG_APPLE_WDT_H */
