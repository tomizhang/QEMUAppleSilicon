#ifndef HW_ARM_APPLE_SEP_H
#define HW_ARM_APPLE_SEP_H

#include "qemu/osdep.h"
#include "hw/arm/apple_a13.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/misc/apple_mbox.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_SEP "apple.sep"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSEPState, APPLE_SEP)

struct AppleSEPState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    vaddr base;
    AppleA13Cluster cpu_cluster;
    AppleA13State *cpu;
    AppleMboxState *mbox;
    MemoryRegion *dma_mr;
    AddressSpace *dma_as;
};

AppleSEPState *apple_sep_create(DTBNode *node, vaddr base, uint32_t cpu_id,
                                uint32_t build_version);

#endif
