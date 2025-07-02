#ifndef HW_MISC_APPLE_SILICON_SPMI_BASEBAND_H
#define HW_MISC_APPLE_SILICON_SPMI_BASEBAND_H

#include "hw/arm/apple-silicon/dtb.h"
#include "hw/spmi/spmi.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_SPMI_BASEBAND "apple.spmi.baseband"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSPMIBasebandState, APPLE_SPMI_BASEBAND)

struct AppleSPMIBasebandState {
    /*< private >*/
    SPMISlave parent_obj;

    /*< public >*/
#if 1
    qemu_irq irq;
#endif
#if 0
    QEMUTimer *timer;
    uint64_t rtc_offset;
    uint64_t tick_offset;
    uint32_t tick_period;
    uint32_t reg_leg_scrpad;
    uint32_t reg_rtc;
    uint32_t reg_rtc_irq_mask;
    uint32_t reg_alarm;
    uint32_t reg_alarm_ctrl;
    uint32_t reg_alarm_event;
#endif
    uint8_t reg[0xFFFF];
    uint16_t addr;
};

void apple_spmi_baseband_set_irq(AppleSPMIBasebandState *s, int value);
DeviceState *apple_spmi_baseband_create(DTBNode *node);
#endif /* HW_MISC_APPLE_SILICON_SPMI_BASEBAND_H */
