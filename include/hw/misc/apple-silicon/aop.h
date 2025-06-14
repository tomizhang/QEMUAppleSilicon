#ifndef HW_MISC_APPLE_SILICON_AOP_H
#define HW_MISC_APPLE_SILICON_AOP_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/sysbus.h"

#define TYPE_APPLE_AOP "apple.aop"
OBJECT_DECLARE_TYPE(AppleAOPState, AppleAOPClass, APPLE_AOP)

typedef struct AppleAOPEndpoint AppleAOPEndpoint;

typedef enum {
    AOP_EP_TYPE_HID,
    AOP_EP_TYPE_MUX,
    AOP_EP_TYPE_APP,
} AppleAOPEndpointType;

typedef enum {
    AOP_RESULT_OK,
    AOP_RESULT_TIMEOUT,
    AOP_RESULT_ABORTED,
    AOP_RESULT_ERROR,
} AppleAOPResult;

typedef struct {
    AppleAOPEndpointType type;
    uint32_t align;
    const char *service_name;
    uint32_t service_id;
    uint32_t interface_num;
    uint32_t rx_len;
    uint32_t tx_len;
    AppleAOPResult (*get_property)(void *opaque, uint32_t property, void *data);
    AppleAOPResult (*handle_command)(void *opaque, uint32_t type,
                                     uint8_t category, uint16_t seq,
                                     void *payload, uint32_t len,
                                     void *payload_out, uint32_t out_len);
} AppleAOPEndpointDescription;

SysBusDevice *apple_aop_create(DTBNode *node, AppleA7IOPVersion version,
                               uint32_t rtkit_protocol_version);
AppleAOPEndpoint *apple_aop_ep_create(AppleAOPState *s, void *opaque,
                                      const AppleAOPEndpointDescription *descr);
/// NOTE: Must be used while state is locked.
MemTxResult apple_aop_ep_send_report_locked(AppleAOPEndpoint *s,
                                            uint16_t packet_type,
                                            const void *payload,
                                            uint32_t payload_len,
                                            uint32_t out_len);
MemTxResult apple_aop_ep_send_report(AppleAOPEndpoint *s, uint16_t packet_type,
                                     const void *payload, uint32_t payload_len,
                                     uint32_t out_len);
/// NOTE: Must be used while state is locked.
MemTxResult apple_aop_ep_send_reply_locked(AppleAOPEndpoint *s,
                                           uint16_t packet_type, uint16_t seq,
                                           const void *payload,
                                           uint32_t payload_len,
                                           uint32_t out_len);
MemTxResult apple_aop_ep_send_reply(AppleAOPEndpoint *s, uint16_t packet_type,
                                    uint16_t seq, const void *payload,
                                    uint32_t payload_len, uint32_t out_len);

#endif /* HW_MISC_APPLE_SILICON_AOP_H */
