#include "hw/arm/xnu.h"
#include "hw/arm/xnu_pf.h"
#include "qemu/error-report.h"

ApplePfRange *xnu_pf_range_from_va(uint64_t va, uint64_t size)
{
    ApplePfRange *range = g_malloc0(sizeof(ApplePfRange));
    range->va = va;
    range->size = size;
    range->cacheable_base = ((uint8_t *)(va - g_virt_base + g_phys_base));

    return range;
}

ApplePfRange *xnu_pf_segment(MachoHeader64 *header, const char *segment_name)
{
    MachoSegmentCommand64 *seg = macho_get_segment(header, segment_name);
    if (!seg) {
        return NULL;
    }

    if (header != xnu_header) {
        return xnu_pf_range_from_va(xnu_slide_value(xnu_header) +
                                        (0xffff000000000000 | seg->vmaddr),
                                    seg->filesize);
    }

    return xnu_pf_range_from_va(xnu_slide_hdr_va(header, seg->vmaddr),
                                seg->filesize);
}
