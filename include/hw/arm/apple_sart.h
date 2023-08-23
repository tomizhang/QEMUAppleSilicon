#ifndef HW_ARM_APPLE_SART_H
#define HW_ARM_APPLE_SART_H

#include "qemu/osdep.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/sysbus.h"
#include "qemu/queue.h"
#include "qom/object.h"

typedef struct AppleSARTState AppleSARTState;

#define TYPE_APPLE_SART "apple.sart"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSARTState, APPLE_SART)

#define TYPE_APPLE_SART_IOMMU_MEMORY_REGION "apple.sart.iommu"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSARTIOMMUMemoryRegion,
                           APPLE_SART_IOMMU_MEMORY_REGION)

SysBusDevice *apple_sart_create(DTBNode *node);

#endif
