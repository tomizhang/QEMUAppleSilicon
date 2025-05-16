#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "hw/misc/apple-silicon/smc.h"
#include "hw/qdev-core.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/queue.h"
#include "system/runstate.h"

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

#define SMC_MAKE_IDENTIFIER(A, B, C, D)                           \
    ((uint32_t)(((uint32_t)(A) << 24U) | ((uint32_t)(B) << 16U) | \
                ((uint32_t)(C) << 8U) | (uint32_t)(D)))
#define SMC_MAKE_KEY_TYPE(A, B, C, D) SMC_MAKE_IDENTIFIER((A), (B), (C), (D))

#define SMC_FORMAT_KEY(v)                                            \
    (((v) >> 24) & 0xFF), (((v) >> 16) & 0xFF), (((v) >> 8) & 0xFF), \
        ((v) & 0xFF)

enum {
    SMCKeyTypeFlag = SMC_MAKE_KEY_TYPE('f', 'l', 'a', 'g'),
    SMCKeyTypeHex = SMC_MAKE_KEY_TYPE('h', 'e', 'x', '_'),
    SMCKeyTypeSInt8 = SMC_MAKE_KEY_TYPE('s', 'i', '8', ' '),
    SMCKeyTypeSInt16 = SMC_MAKE_KEY_TYPE('s', 'i', '1', '6'),
    SMCKeyTypeSInt32 = SMC_MAKE_KEY_TYPE('s', 'i', '3', '2'),
    SMCKeyTypeSInt64 = SMC_MAKE_KEY_TYPE('s', 'i', '6', '4'),
    SMCKeyTypeUInt8 = SMC_MAKE_KEY_TYPE('u', 'i', '8', ' '),
    SMCKeyTypeUInt16 = SMC_MAKE_KEY_TYPE('u', 'i', '1', '6'),
    SMCKeyTypeUInt32 = SMC_MAKE_KEY_TYPE('u', 'i', '3', '2'),
    SMCKeyTypeUInt64 = SMC_MAKE_KEY_TYPE('u', 'i', '6', '4'),
    SMCKeyTypeSP78 = SMC_MAKE_KEY_TYPE('S', 'p', '7', '8'),
    SMCKeyTypeClh = SMC_MAKE_KEY_TYPE('{', 'c', 'l', 'h'),
    SMCKeyTypeIOFT = SMC_MAKE_KEY_TYPE('i', 'o', 'f', 't'),
    SMCKeyTypeFLT = SMC_MAKE_KEY_TYPE('f', 'l', 't', ' '),
};

enum {
    SMCKeyNKEY = SMC_MAKE_IDENTIFIER('#', 'K', 'E', 'Y'),
    SMCKeyCLKH = SMC_MAKE_IDENTIFIER('C', 'L', 'K', 'H'),
    SMCKeyRGEN = SMC_MAKE_IDENTIFIER('R', 'G', 'E', 'N'),
    SMCKeyMBSE = SMC_MAKE_IDENTIFIER('M', 'B', 'S', 'E'),
    SMCKeyLGPB = SMC_MAKE_IDENTIFIER('L', 'G', 'P', 'B'),
    SMCKeyLGPE = SMC_MAKE_IDENTIFIER('L', 'G', 'P', 'E'),
    SMCKeyNESN = SMC_MAKE_IDENTIFIER('N', 'E', 'S', 'N'),
    SMCKeyADC_ = SMC_MAKE_IDENTIFIER('a', 'D', 'C', '#'),
    SMCKeyAC_N = SMC_MAKE_IDENTIFIER('A', 'C', '-', 'N'),
    SMCKeyBNCB = SMC_MAKE_IDENTIFIER('B', 'N', 'C', 'B'),
    SMCKeyTG0B = SMC_MAKE_IDENTIFIER('T', 'G', '0', 'B'),
    SMCKeyTG0V = SMC_MAKE_IDENTIFIER('T', 'G', '0', 'V'),
    SMCKeyTP1A = SMC_MAKE_IDENTIFIER('T', 'P', '1', 'A'),
    SMCKeyTP2C = SMC_MAKE_IDENTIFIER('T', 'P', '2', 'C'),
    SMCKeyTP3R = SMC_MAKE_IDENTIFIER('T', 'P', '3', 'R'),
    SMCKeyTP4H = SMC_MAKE_IDENTIFIER('T', 'P', '4', 'H'),
    SMCKeyTP5d = SMC_MAKE_IDENTIFIER('T', 'P', '5', 'd'),
    SMCKeyTP0Z = SMC_MAKE_IDENTIFIER('T', 'P', '0', 'Z'),
    SMCKeyB0AP = SMC_MAKE_IDENTIFIER('B', '0', 'A', 'P'),
};

enum SMCCommand {
    SMC_READ_KEY = 0x10,
    SMC_WRITE_KEY = 0x11,
    SMC_GET_KEY_BY_INDEX = 0x12,
    SMC_GET_KEY_INFO = 0x13,
    SMC_GET_SRAM_ADDR = 0x17,
    SMC_NOTIFICATION = 0x18,
    SMC_READ_KEY_PAYLOAD = 0x20
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

enum SMCNotifyType {
    kSMCSystemStateNotify = 'p',
    kSMCPowerStateNotify = 'q',
    kSMCHIDEventNotify = 'r',
    kSMCBatteryAuthNotify = 's',
    kSMCGGFwUpdateNotify = 't',
};

enum SMCNotify {
    kSMCNotifySMCPanicDone = 0xA,
    kSMCNotifySMCPanicProgress = 0x22,
};

#define kSMCKeyEndpoint 0

typedef struct {
    uint8_t cmd;
    uint8_t tag_and_id;
    uint8_t length;
    uint8_t payload_length;
    uint32_t key;
} QEMU_PACKED KeyMessage;

typedef struct {
    union {
        struct {
            uint8_t status;
            uint8_t tag_and_id;
            uint8_t length;
            uint8_t unk3;
            uint8_t response[4];
        };
        uint64_t raw;
    };
} QEMU_PACKED KeyResponse;

typedef struct {
    uint8_t size;
    uint32_t type;
    uint8_t attr;
} QEMU_PACKED SMCKeyInfo;

enum SMCAttr {
    SMC_ATTR_LITTLE_ENDIAN = (1 << 2),
};

typedef struct SMCKey SMCKey;
typedef struct SMCKeyData SMCKeyData;

typedef uint8_t (*KeyReader)(AppleSMCState *s, SMCKey *key, SMCKeyData *data,
                             void *payload, uint8_t length);
typedef uint8_t (*KeyWriter)(AppleSMCState *s, SMCKey *key, SMCKeyData *data,
                             void *payload, uint8_t length);

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

struct AppleSMCState {
    AppleRTKit parent_obj;

    MemoryRegion *iomems[3];
    QTAILQ_HEAD(, SMCKey) keys;
    QTAILQ_HEAD(, SMCKeyData) key_data;
    uint32_t key_count;
    uint8_t sram[0x4000];
};

static SMCKey *smc_get_key(AppleSMCState *s, uint32_t key)
{
    SMCKey *key_entry;

    QTAILQ_FOREACH (key_entry, &s->keys, next) {
        if (key_entry->key == key) {
            return key_entry;
        }
    }

    return NULL;
}

static SMCKeyData *smc_get_key_data(AppleSMCState *s, uint32_t key)
{
    SMCKeyData *data_entry;

    QTAILQ_FOREACH (data_entry, &s->key_data, next) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }

    return NULL;
}

static SMCKey *smc_create_key(AppleSMCState *s, uint32_t key, uint32_t size,
                              uint32_t type, uint32_t attr, void *data)
{
    SMCKey *key_entry;
    SMCKeyData *data_entry;

    g_assert_null(smc_get_key(s, key));

    key_entry = g_new0(SMCKey, 1);
    data_entry = g_new0(SMCKeyData, 1);

    s->key_count += 1;
    key_entry->key = key;
    key_entry->info.size = size;
    key_entry->info.type = type;
    key_entry->info.attr = attr;
    data_entry->key = key;
    data_entry->data = g_malloc(size);
    data_entry->size = size;

    if (data == NULL) {
        memset(data_entry->data, 0, size);
    } else {
        memcpy(data_entry->data, data, size);
    }

    QTAILQ_INSERT_TAIL(&s->keys, key_entry, next);
    QTAILQ_INSERT_TAIL(&s->key_data, data_entry, next);

    return key_entry;
}

static SMCKey *smc_create_key_func(AppleSMCState *s, uint32_t key,
                                   uint32_t size, uint32_t type, uint32_t attr,
                                   KeyReader reader, KeyWriter writer)
{
    SMCKey *key_entry;

    key_entry = smc_create_key(s, key, size, type, attr, NULL);

    key_entry->read = reader;
    key_entry->write = writer;

    return key_entry;
}

static uint8_t smc_set_key(AppleSMCState *s, uint32_t key, uint32_t size,
                           void *data)
{
    SMCKey *key_entry;
    SMCKeyData *data_entry;

    key_entry = smc_get_key(s, key);
    data_entry = smc_get_key_data(s, key);

    if (key_entry == NULL) {
        return kSMCKeyNotFound;
    }

    if (key_entry->info.size != size) {
        return kSMCBadArgumentError;
    }

    if (data_entry->data == NULL) {
        data_entry->data = g_malloc(key_entry->info.size);
    }

    memcpy(data_entry->data, data, size);

    return kSMCSuccess;
}

static uint8_t smc_key_reject_read(AppleSMCState *s, SMCKey *key,
                                   SMCKeyData *data, void *payload,
                                   uint8_t length)
{
    return kSMCKeyNotReadable;
}

static uint8_t smc_key_reject_write(AppleSMCState *s, SMCKey *key,
                                    SMCKeyData *data, void *payload,
                                    uint8_t length)
{
    return kSMCKeyNotWritable;
}

static uint8_t smc_key_count_read(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    uint32_t key_count;

    key_count = cpu_to_le32(s->key_count);

    if (data->data == NULL) {
        data->data = g_malloc(key->info.size);
    }

    memcpy(data->data, &key_count, sizeof(key_count));

    return kSMCSuccess;
}

static uint8_t smc_key_mbse_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    AppleRTKit *rtk;
    uint32_t value;
    KeyResponse r;

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    rtk = APPLE_RTKIT(s);
    value = ldl_le_p(payload);

    switch (value) {
    case SMC_MAKE_IDENTIFIER('o', 'f', 'f', 'w'):
    case SMC_MAKE_IDENTIFIER('o', 'f', 'f', '1'):
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('s', 'u', 's', 'p'):
        qemu_system_suspend_request();
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('r', 'e', 's', 't'):
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('s', 'l', 'p', 'w'):
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('p', 'a', 'n', 'b'): {
        memset(&r, 0, sizeof(r));
        r.status = SMC_NOTIFICATION;
        r.response[2] = kSMCNotifySMCPanicProgress;
        r.response[3] = kSMCSystemStateNotify;
        apple_rtkit_send_user_msg(rtk, kSMCKeyEndpoint, r.raw);
        return kSMCSuccess;
    }
    case SMC_MAKE_IDENTIFIER('p', 'a', 'n', 'e'): {
        memset(&r, 0, sizeof(r));
        r.status = SMC_NOTIFICATION;
        r.response[2] = kSMCNotifySMCPanicDone;
        r.response[3] = kSMCSystemStateNotify;
        apple_rtkit_send_user_msg(rtk, kSMCKeyEndpoint, r.raw);
        return kSMCSuccess;
    }
    default:
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_lgpb_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    return smc_set_key(s, key->key, length, payload);
}

static uint8_t smc_key_lgpe_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    return smc_set_key(s, key->key, length, payload);
}

static uint8_t smc_key_nesn_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    return smc_set_key(s, key->key, length, payload);
}

static void apple_smc_handle_key_endpoint(void *opaque, const uint32_t ep,
                                          const uint64_t msg)
{
    AppleRTKit *rtk;
    AppleSMCState *s;
    const KeyMessage *kmsg;
    KeyResponse resp;
    SMCKey *key_entry;
    SMCKeyData *data_entry;

    s = APPLE_SMC_IOP(opaque);
    rtk = APPLE_RTKIT(opaque);
    kmsg = (const KeyMessage *)&msg;

    memset(&resp, 0, sizeof(resp));
    SMC_LOG_MSG(ep, msg);

    switch (kmsg->cmd) {
    case SMC_GET_SRAM_ADDR: {
        apple_rtkit_send_user_msg(rtk, ep,
                                  s->iomems[APPLE_SMC_MMIO_SRAM]->addr);
        break;
    }
    case SMC_READ_KEY:
    case SMC_READ_KEY_PAYLOAD: {
        key_entry = smc_get_key(s, kmsg->key);
        data_entry = smc_get_key_data(s, kmsg->key);
        if (key_entry == NULL) {
            resp.status = kSMCKeyNotFound;
        } else {
            g_assert_nonnull(data_entry);

            if (key_entry->read != NULL) {
                resp.status = key_entry->read(s, key_entry, data_entry, s->sram,
                                              kmsg->payload_length);
            }
            if (resp.status == kSMCSuccess) {
                resp.length = key_entry->info.size;
                if (key_entry->info.size <= 4) {
                    memcpy(resp.response, data_entry->data,
                           key_entry->info.size);
                } else {
                    memcpy(s->sram, data_entry->data, key_entry->info.size);
                }
                resp.status = kSMCSuccess;
            }
        }
        resp.tag_and_id = kmsg->tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, resp.raw);
        break;
    }
    case SMC_WRITE_KEY: {
        key_entry = smc_get_key(s, kmsg->key);
        data_entry = smc_get_key_data(s, kmsg->key);
        if (key_entry == NULL) {
            resp.status = kSMCKeyNotFound;
        } else {
            g_assert_nonnull(data_entry);

            if (key_entry->write != NULL) {
                resp.status = key_entry->write(s, key_entry, data_entry,
                                               s->sram, kmsg->length);
            } else {
                resp.status = smc_set_key(s, kmsg->key, kmsg->length, s->sram);
            }
            resp.length = kmsg->length;
        }
        resp.tag_and_id = kmsg->tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, resp.raw);
        break;
    }
    case SMC_GET_KEY_BY_INDEX: {
        key_entry = QTAILQ_FIRST(&s->keys);

        for (int i = 0; i < kmsg->key && key_entry != NULL; i++) {
            key_entry = QTAILQ_NEXT(key_entry, next);
        }

        if (key_entry == NULL) {
            resp.status = kSMCKeyIndexRangeError;
        } else {
            resp.status = kSMCSuccess;
            stl_be_p(resp.response, cpu_to_be32(key_entry->key));
        }

        resp.tag_and_id = kmsg->tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, resp.raw);
        break;
    }
    case SMC_GET_KEY_INFO: {
        key_entry = smc_get_key(s, kmsg->key);
        if (key_entry == NULL) {
            resp.status = kSMCKeyNotFound;
        } else {
            memcpy(s->sram, &key_entry->info, sizeof(key_entry->info));
            resp.status = kSMCSuccess;
        }
        resp.tag_and_id = kmsg->tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, resp.raw);
        break;
    }
    default: {
        resp.status = kSMCBadCommand;
        resp.tag_and_id = kmsg->tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, resp.raw);
        fprintf(stderr, "SMC: Unknown SMC Command: 0x%02x\n", kmsg->cmd);
        break;
    }
    }
}

static void ascv2_core_reg_write(void *opaque, hwaddr addr, uint64_t data,
                                 unsigned size)
{
    qemu_log_mask(LOG_UNIMP,
                  "SMC: AppleASCWrapV2 core reg WRITE @ 0x" HWADDR_FMT_plx
                  " value: 0x" HWADDR_FMT_plx "\n",
                  addr, data);
}

static uint64_t ascv2_core_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    qemu_log_mask(LOG_UNIMP,
                  "SMC: AppleASCWrapV2 core reg READ @ 0x" HWADDR_FMT_plx "\n",
                  addr);
    return 0;
}

static const MemoryRegionOps ascv2_core_reg_ops = {
    .write = ascv2_core_reg_write,
    .read = ascv2_core_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 8,
    .impl.max_access_size = 8,
    .valid.min_access_size = 8,
    .valid.max_access_size = 8,
    .valid.unaligned = false,
};

SysBusDevice *apple_smc_create(DTBNode *node, AppleA7IOPVersion version,
                               uint32_t protocol_version)
{
    DeviceState *dev;
    AppleSMCState *s;
    AppleRTKit *rtk;
    SysBusDevice *sbd;
    DTBNode *child;
    DTBProp *prop;
    uint64_t *reg;
    uint8_t data[8] = { 0x00, 0x00, 0x70, 0x80, 0x00, 0x01, 0x19, 0x40 };
    uint64_t value;

    dev = qdev_new(TYPE_APPLE_SMC_IOP);
    s = APPLE_SMC_IOP(dev);
    rtk = APPLE_RTKIT(dev);
    sbd = SYS_BUS_DEVICE(dev);

    child = dtb_get_node(node, "iop-smc-nub");
    g_assert_nonnull(child);

    prop = dtb_find_prop(node, "reg");
    g_assert_nonnull(prop);

    reg = (uint64_t *)prop->data;

    apple_rtkit_init(rtk, NULL, "SMC", reg[1], version, protocol_version, NULL);
    apple_rtkit_register_user_ep(rtk, kSMCKeyEndpoint, s,
                                 &apple_smc_handle_key_endpoint);

    s->iomems[APPLE_SMC_MMIO_ASC] = g_new(MemoryRegion, 1);
    memory_region_init_io(s->iomems[APPLE_SMC_MMIO_ASC], OBJECT(dev),
                          &ascv2_core_reg_ops, s,
                          TYPE_APPLE_SMC_IOP ".ascv2-core-reg", reg[3]);
    sysbus_init_mmio(sbd, s->iomems[APPLE_SMC_MMIO_ASC]);

    s->iomems[APPLE_SMC_MMIO_SRAM] = g_new(MemoryRegion, 1);
    memory_region_init_ram_device_ptr(s->iomems[APPLE_SMC_MMIO_SRAM],
                                      OBJECT(dev), TYPE_APPLE_SMC_IOP ".sram",
                                      sizeof(s->sram), s->sram);
    sysbus_init_mmio(sbd, s->iomems[APPLE_SMC_MMIO_SRAM]);


    dtb_set_prop_u32(child, "pre-loaded", 1);
    dtb_set_prop_u32(child, "running", 1);

    QTAILQ_INIT(&s->keys);
    QTAILQ_INIT(&s->key_data);

    smc_create_key_func(s, SMCKeyNKEY, 4, SMCKeyTypeUInt32,
                        SMC_ATTR_LITTLE_ENDIAN, &smc_key_count_read,
                        &smc_key_reject_write);

    smc_create_key(s, SMCKeyCLKH, 8, SMCKeyTypeClh, SMC_ATTR_LITTLE_ENDIAN,
                   data);

    data[0] = 3;
    smc_create_key(s, SMCKeyRGEN, 1, SMCKeyTypeUInt8, SMC_ATTR_LITTLE_ENDIAN,
                   data);

    value = 0;
    smc_create_key(s, SMCKeyADC_, 4, SMCKeyTypeUInt32, SMC_ATTR_LITTLE_ENDIAN,
                   &value);

    smc_create_key_func(s, SMCKeyMBSE, 4, SMCKeyTypeHex, SMC_ATTR_LITTLE_ENDIAN,
                        &smc_key_reject_read, &smc_key_mbse_write);

    smc_create_key_func(s, SMCKeyLGPB, 1, SMCKeyTypeFlag,
                        SMC_ATTR_LITTLE_ENDIAN, NULL, &smc_key_lgpb_write);
    smc_create_key_func(s, SMCKeyLGPE, 1, SMCKeyTypeFlag,
                        SMC_ATTR_LITTLE_ENDIAN, NULL, &smc_key_lgpe_write);
    smc_create_key_func(s, SMCKeyNESN, 4, SMCKeyTypeHex, SMC_ATTR_LITTLE_ENDIAN,
                        &smc_key_reject_read, &smc_key_nesn_write);

    value = 1;
    smc_create_key(s, SMCKeyAC_N, 1, SMCKeyTypeUInt8, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    value = 0;
    smc_create_key(s, SMC_MAKE_IDENTIFIER('C', 'H', 'A', 'I'), 4,
                   SMCKeyTypeUInt32, SMC_ATTR_LITTLE_ENDIAN, &value);
    smc_create_key(s, SMCKeyTG0B, 8, SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    smc_create_key(s, SMCKeyTG0V, 8, SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    smc_create_key(s, SMCKeyTP1A, 8, SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    smc_create_key(s, SMCKeyTP2C, 8, SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    for (char i = '1'; i <= '5'; i++) {
        smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'P', i, 'd'), 8,
                       SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN, &value);
    }
    smc_create_key(s, SMCKeyTP3R, 8, SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    smc_create_key(s, SMCKeyTP4H, 8, SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    smc_create_key(s, SMCKeyTP0Z, 8, SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    smc_create_key(s, SMCKeyB0AP, 4, SMCKeyTypeSInt32, SMC_ATTR_LITTLE_ENDIAN,
                   &value);
    for (char i = '0'; i <= '2'; i++) {
        smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'h', i, 'a'), 8,
                       SMCKeyTypeFLT, SMC_ATTR_LITTLE_ENDIAN, &value);
        smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'h', i, 'f'), 8,
                       SMCKeyTypeFLT, SMC_ATTR_LITTLE_ENDIAN, &value);
        smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'h', i, 'x'), 8,
                       SMCKeyTypeFLT, SMC_ATTR_LITTLE_ENDIAN, &value);
        smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'c', i, 'a'), 8,
                       SMCKeyTypeFLT, SMC_ATTR_LITTLE_ENDIAN, &value);
        smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'c', i, 'f'), 8,
                       SMCKeyTypeFLT, SMC_ATTR_LITTLE_ENDIAN, &value);
        smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'c', i, 'x'), 8,
                       SMCKeyTypeFLT, SMC_ATTR_LITTLE_ENDIAN, &value);
    }
    smc_create_key(s, SMC_MAKE_IDENTIFIER('D', '0', 'V', 'R'), 2,
                   SMCKeyTypeUInt16, SMC_ATTR_LITTLE_ENDIAN, &value);
    smc_create_key(s, SMC_MAKE_IDENTIFIER('T', 'V', '0', 's'), 8,
                   SMCKeyTypeIOFT, SMC_ATTR_LITTLE_ENDIAN, &value);

    return sbd;
}

static const VMStateDescription vmstate_apple_smc_key_data = {
    .name = "SMCKeyData",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT32(key, SMCKeyData),
            VMSTATE_UINT32(size, SMCKeyData),
            VMSTATE_VBUFFER_ALLOC_UINT32(data, SMCKeyData, 0, NULL, size),
            VMSTATE_END_OF_LIST(),
        },
};

static int vmstate_apple_smc_post_load(void *opaque, int version_id)
{
    AppleSMCState *s;
    SMCKey *key;
    SMCKey *key_next;
    SMCKeyData *data;
    SMCKeyData *data_next;

    s = APPLE_SMC_IOP(opaque);

    QTAILQ_FOREACH_SAFE (data, &s->key_data, next, data_next) {
        key = smc_get_key(s, data->key);
        if (key == NULL) {
            fprintf(stderr, "Removing key `%c%c%c%c` as it no longer exists\n",
                    SMC_FORMAT_KEY(data->key));
            g_free(data->data);
            QTAILQ_REMOVE(&s->key_data, data, next);
        }
        if (key->info.size != data->size) {
            fprintf(stderr,
                    "Key `%c%c%c%c` has mismatched length, state cannot be "
                    "loaded.\n",
                    SMC_FORMAT_KEY(data->key));
            return -1;
        }
    }

    QTAILQ_FOREACH_SAFE (key, &s->keys, next, key_next) {
        data = smc_get_key_data(s, key->key);
        if (data == NULL) {
            data = g_new0(SMCKeyData, 1);
            data->data = g_malloc(key->info.size);
            data->size = key->info.size;
            memset(data->data, 0, key->info.size);
            QTAILQ_INSERT_TAIL(&s->key_data, data, next);
        }
    }

    return 0;
}

static const VMStateDescription vmstate_apple_smc = {
    .name = "AppleSMCState",
    .version_id = 0,
    .minimum_version_id = 0,
    .post_load = vmstate_apple_smc_post_load,
    .fields =
        (const VMStateField[]){
            VMSTATE_APPLE_RTKIT(parent_obj, AppleSMCState),
            VMSTATE_QTAILQ_V(key_data, AppleSMCState, 0,
                             vmstate_apple_smc_key_data, SMCKeyData, next),
            VMSTATE_UINT32(key_count, AppleSMCState),
            VMSTATE_BUFFER(sram, AppleSMCState),
            VMSTATE_END_OF_LIST(),
        },
};

static void apple_smc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc;

    dc = DEVICE_CLASS(klass);

    /* device_class_set_legacy_reset(dc, apple_smc_reset); */
    dc->desc = "Apple SMC IOP";
    dc->vmsd = &vmstate_apple_smc;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_smc_info = {
    .name = TYPE_APPLE_SMC_IOP,
    .parent = TYPE_APPLE_RTKIT,
    .instance_size = sizeof(AppleSMCState),
    .class_init = apple_smc_class_init,
};

static void apple_smc_register_types(void)
{
    type_register_static(&apple_smc_info);
}

type_init(apple_smc_register_types);
