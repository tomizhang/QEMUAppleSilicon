#ifndef HW_MISC_APPLE_SILICON_SPMI_PMU_H
#define HW_MISC_APPLE_SILICON_SPMI_PMU_H

#include "hw/arm/apple-silicon/dtb.h"
#include "hw/spmi/spmi.h"
#include "hw/sysbus.h"
#include "qom/object.h"

DeviceState *apple_spmi_pmu_create(DTBNode *node);
#endif /* HW_MISC_APPLE_SILICON_SPMI_PMU_H */
