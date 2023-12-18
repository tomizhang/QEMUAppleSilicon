#ifndef HW_ARM_XNU_PF_H
#define HW_ARM_XNU_PF_H
#include "hw/arm/xnu.h"

typedef struct {
    uint64_t va;
    uint64_t size;
    uint8_t *cacheable_base;
} ApplePfRange;

ApplePfRange *xnu_pf_range_from_va(uint64_t va, uint64_t size);

ApplePfRange *xnu_pf_segment(MachoHeader64 *header, const char *segment_name);
#endif
