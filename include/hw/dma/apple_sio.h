#ifndef HW_DMA_APPLE_SIO_H
#define HW_DMA_APPLE_SIO_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/sysbus.h"

#define TYPE_APPLE_SIO "apple.sio"
OBJECT_DECLARE_TYPE(AppleSIOState, AppleSIOClass, APPLE_SIO)

typedef struct AppleSIODMAEndpoint AppleSIODMAEndpoint;

int apple_sio_dma_read(AppleSIODMAEndpoint *ep, void *buffer, size_t len);
int apple_sio_dma_write(AppleSIODMAEndpoint *ep, void *buffer, size_t len);
int apple_sio_dma_remaining(AppleSIODMAEndpoint *ep);
AppleSIODMAEndpoint *apple_sio_get_endpoint(AppleSIOState *s, int ep);
AppleSIODMAEndpoint *apple_sio_get_endpoint_from_node(AppleSIOState *s,
                                                      DTBNode *node, int idx);
SysBusDevice *apple_sio_create(DTBNode *node, AppleA7IOPVersion version,
                               uint32_t rtkit_protocol_version,
                               uint32_t protocol);

#endif /* HW_DMA_APPLE_SIO_H */
