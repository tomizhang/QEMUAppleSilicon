#ifndef HW_MISC_APPLE_SILICON_SMC_H
#define HW_MISC_APPLE_SILICON_SMC_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "hw/sysbus.h"

#define APPLE_SMC_MMIO_ASC (1)
#define APPLE_SMC_MMIO_SRAM (2)

#define TYPE_APPLE_SMC_IOP "apple.smc"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSMCState, APPLE_SMC_IOP)

// #define DEBUG_SMC

#ifdef DEBUG_SMC
#define SMC_LOG_MSG(ep, msg)       \
    qemu_log_mask(LOG_GUEST_ERROR, \
                  "SMC: message: ep=%u msg=0x" HWADDR_FMT_plx "\n", ep, msg)
#else
#define SMC_LOG_MSG(ep, msg) \
    do {                     \
    } while (0)
#endif

#define SMC_FORMAT_KEY(v)                                            \
    (((v) >> 24) & 0xFF), (((v) >> 16) & 0xFF), (((v) >> 8) & 0xFF), \
        ((v) & 0xFF)

enum {
    SMCKeyTypeFlag = 'flag',
    SMCKeyTypeHex = 'hex_',
    SMCKeyTypeSInt8 = 'si8 ',
    SMCKeyTypeSInt16 = 'si16',
    SMCKeyTypeSInt32 = 'si32',
    SMCKeyTypeSInt64 = 'si64',
    SMCKeyTypeUInt8 = 'ui8 ',
    SMCKeyTypeUInt16 = 'ui16',
    SMCKeyTypeUInt32 = 'ui32',
    SMCKeyTypeUInt64 = 'ui64',
    SMCKeyTypeSP78 = 'Sp78',
    SMCKeyTypeClh = '{clh',
    SMCKeyTypeIOFT = 'ioft',
    SMCKeyTypeFLT = 'flt ',
};

enum SMCCommand {
    SMC_READ_KEY = 0x10,
    SMC_WRITE_KEY = 0x11,
    SMC_GET_KEY_BY_INDEX = 0x12,
    SMC_GET_KEY_INFO = 0x13,
    SMC_GET_SRAM_ADDR = 0x17,
    SMC_NOTIFICATION = 0x18,
    SMC_READ_KEY_PAYLOAD = 0x20,
};

enum SMCResult {
    kSMCSuccess = 0,
    kSMCError = 1,
    kSMCCommCollision = 0x80,
    kSMCSpuriousData = 0x81,
    kSMCBadCommand = 0x82,
    kSMCBadParameter = 0x83,
    kSMCKeyNotFound = 0x84,
    kSMCKeyNotReadable = 0x85,
    kSMCKeyNotWritable = 0x86,
    kSMCKeySizeMismatch = 0x87,
    kSMCFramingError = 0x88,
    kSMCBadArgumentError = 0x89,
    kSMCTimeoutError = 0xB7,
    kSMCKeyIndexRangeError = 0xB8,
    kSMCBadFuncParameter = 0xC0,
    kSMCEventBuffWrongOrder = 0xC4,
    kSMCEventBuffReadError = 0xC5,
    kSMCDeviceAccessError = 0xC7,
    kSMCUnsupportedFeature = 0xCB,
    kSMCSMBAccessError = 0xCC,
};

enum SMCEventType {
    kSMCEventSystemStateNotify = 0x70,
    kSMCEventPowerStateNotify = 0x71,
    kSMCEventHIDEventNotify = 0x72,
    kSMCEventBatteryAuthNotify = 0x73,
    kSMCEventGGFwUpdateNotify = 0x74,
};

enum SMCSystemStateNotifyType {
    kSMCSystemStateNotifySMCPanicDone = 0xA,
    kSMCSystemStateNotifySMCPanicProgress = 0x22,
};

enum SMCAttr {
    SMC_ATTR_LITTLE_ENDIAN = BIT(2),
    SMC_ATTR_FUNCTION = BIT(4),
    SMC_ATTR_WRITEABLE = BIT(6),
    SMC_ATTR_READABLE = BIT(7),
    SMC_ATTR_DEFAULT = SMC_ATTR_READABLE | SMC_ATTR_WRITEABLE,
    SMC_ATTR_DEFAULT_LE = SMC_ATTR_LITTLE_ENDIAN | SMC_ATTR_DEFAULT,
};

typedef struct SMCKey SMCKey;
typedef struct SMCKeyData SMCKeyData;

typedef uint8_t (*KeyReader)(AppleSMCState *s, SMCKey *key, SMCKeyData *data,
                             void *payload, uint8_t length);
typedef uint8_t (*KeyWriter)(AppleSMCState *s, SMCKey *key, SMCKeyData *data,
                             void *payload, uint8_t length);

typedef struct {
    uint8_t size;
    uint32_t type;
    uint8_t attr;
} QEMU_PACKED SMCKeyInfo;

struct SMCKey {
    uint32_t key;
    SMCKeyInfo info;
    KeyReader read;
    KeyWriter write;
    QTAILQ_ENTRY(SMCKey) next;
};

struct SMCKeyData {
    uint32_t key;
    uint32_t size;
    void *data;
    QTAILQ_ENTRY(SMCKeyData) next;
};

SysBusDevice *apple_smc_create(DTBNode *node, AppleA7IOPVersion version,
                               uint32_t protocol_version, uint32_t sram_size);

SMCKey *apple_smc_get_key(AppleSMCState *s, uint32_t key);
SMCKeyData *apple_smc_get_key_data(AppleSMCState *s, uint32_t key);
SMCKey *apple_smc_create_key(AppleSMCState *s, uint32_t key, uint32_t size,
                             uint32_t type, uint32_t attr, void *data);
SMCKey *apple_smc_create_key_func(AppleSMCState *s, uint32_t key, uint32_t size,
                                  uint32_t type, uint32_t attr,
                                  KeyReader reader, KeyWriter writer);
uint8_t apple_smc_set_key(AppleSMCState *s, uint32_t key, uint32_t size,
                          void *data);

#endif /* HW_MISC_APPLE_SILICON_SMC_H */
