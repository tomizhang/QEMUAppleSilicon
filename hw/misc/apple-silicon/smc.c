#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "hw/misc/apple-silicon/smc.h"
#include "hw/qdev-core.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/queue.h"
#include "system/runstate.h"

#define TYPE_APPLE_SMC_IOP "apple.smc"
OBJECT_DECLARE_TYPE(AppleSMCState, AppleSMCClass, APPLE_SMC_IOP)

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

typedef struct QEMU_PACKED {
    uint8_t cmd;
    uint8_t ui8_tag_and_id;
    uint8_t length;
    uint8_t payload_length;
    uint32_t key;
} KeyMessage;

typedef struct QEMU_PACKED {
    union {
        struct {
            uint8_t status;
            uint8_t ui8_tag_and_id;
            uint8_t length;
            uint8_t unk3;
            uint8_t response[4];
        };
        uint64_t raw;
    };
} KeyResponse;

typedef struct QEMU_PACKED {
    uint8_t size;
    uint32_t type;
    uint8_t attr;
} SMCKeyInfo;

enum SMCAttr {
    SMC_ATTR_LITTLE_ENDIAN = (1 << 2),
};

typedef struct SMCKey SMCKey;

typedef uint8_t (*KeyReader)(AppleSMCState *s, SMCKey *k, void *payload,
                             uint8_t length);
typedef uint8_t (*KeyWriter)(AppleSMCState *s, SMCKey *k, void *payload,
                             uint8_t length);

struct SMCKey {
    uint32_t key;
    SMCKeyInfo info;
    void *data;

    QTAILQ_ENTRY(SMCKey) entry;
    KeyReader read;
    KeyWriter write;
};

struct AppleSMCClass {
    /*< private >*/
    AppleRTKitClass base_class;

    /*< public >*/
    DeviceRealize parent_realize;
};

struct AppleSMCState {
    AppleRTKit parent_obj;

    MemoryRegion *iomems[3];
    QTAILQ_HEAD(, SMCKey) keys;
    uint32_t key_count;
    uint64_t sram_addr;
    uint8_t sram[0x4000];
};

static SMCKey *smc_get_key(AppleSMCState *s, uint32_t key)
{
    SMCKey *d;
    QTAILQ_FOREACH (d, &s->keys, entry) {
        if (d->key == key) {
            return d;
        }
    }
    return NULL;
}

static SMCKey *smc_create_key(AppleSMCState *s, uint32_t key, uint32_t size,
                              uint32_t type, uint32_t attr, void *data)
{
    SMCKey *k;

    g_assert_null(smc_get_key(s, key));

    k = g_new0(SMCKey, 1);
    QTAILQ_INSERT_TAIL(&s->keys, k, entry);
    s->key_count++;
    k->key = key;
    k->info.size = size;
    k->info.type = type;
    k->info.attr = attr;
    k->data = g_malloc(size);
    if (data == NULL) {
        memset(k->data, 0, size);
    } else {
        memcpy(k->data, data, size);
    }

    return k;
}

static SMCKey *smc_create_key_func(AppleSMCState *s, uint32_t key,
                                   uint32_t size, uint32_t type, uint32_t attr,
                                   KeyReader reader, KeyWriter writer)
{
    SMCKey *k;

    k = smc_create_key(s, key, size, type, attr, NULL);

    k->read = reader;
    k->write = writer;

    return k;
}

static uint8_t smc_set_key(AppleSMCState *s, uint32_t key, uint32_t size,
                           void *data)
{
    SMCKey *k;

    k = smc_get_key(s, key);

    if (k == NULL) {
        return kSMCKeyNotFound;
    }

    k->info.size = size;
    g_free(k->data);
    k->data = g_malloc(size);
    memcpy(k->data, data, size);

    return kSMCSuccess;
}

static uint8_t smc_key_reject_read(AppleSMCState *s, SMCKey *k, void *payload,
                                   uint8_t length)
{
    return kSMCKeyNotReadable;
}

static uint8_t smc_key_reject_write(AppleSMCState *s, SMCKey *k, void *payload,
                                    uint8_t length)
{
    return kSMCKeyNotWritable;
}

static uint8_t G_GNUC_UNUSED smc_key_noop_read(AppleSMCState *s, SMCKey *k,
                                               void *payload, uint8_t length)
{
    return kSMCSuccess;
}

static uint8_t G_GNUC_UNUSED smc_key_copy_write(AppleSMCState *s, SMCKey *k,
                                                void *payload, uint8_t length)
{
    return smc_set_key(s, k->key, length, payload);
}

static uint8_t smc_key_count_read(AppleSMCState *s, SMCKey *k, void *payload,
                                  uint8_t length)
{
    k->info.size = 4;
    k->data = g_realloc(k->data, 4);
    *(uint32_t *)k->data = s->key_count;
    return kSMCSuccess;
}

static uint8_t smc_key_mbse_write(AppleSMCState *s, SMCKey *k, void *payload,
                                  uint8_t length)
{
    AppleRTKit *rtk;
    uint32_t value;

    if (payload == NULL || length != k->info.size) {
        return kSMCBadArgumentError;
    }

    rtk = APPLE_RTKIT(s);
    value = *(uint32_t *)payload;

    switch (value) {
    case SMC_MAKE_IDENTIFIER('o', 'f', 'f', 'w'):
    case SMC_MAKE_IDENTIFIER('o', 'f', 'f', '1'):
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('s', 'u', 's', 'p'):
        qemu_system_suspend_request();
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('r', 'e', 's', 't'):
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('s', 'l', 'p', 'w'):
        return kSMCSuccess;
    case SMC_MAKE_IDENTIFIER('p', 'a', 'n', 'b'): {
        KeyResponse r = { 0 };
        r.status = SMC_NOTIFICATION;
        r.response[2] = kSMCNotifySMCPanicProgress;
        r.response[3] = kSMCSystemStateNotify;
        apple_rtkit_send_user_msg(rtk, kSMCKeyEndpoint, r.raw);
        return kSMCSuccess;
    }
    case SMC_MAKE_IDENTIFIER('p', 'a', 'n', 'e'): {
        KeyResponse r = { 0 };
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

static uint8_t smc_key_lgpb_write(AppleSMCState *s, SMCKey *k, void *payload,
                                  uint8_t length)
{
    /* fprintf(stderr, "LGPB: payload: 0x%x\n", *(uint8_t *)payload); */
    return smc_set_key(s, k->key, length, payload);
}

static uint8_t smc_key_lgpe_write(AppleSMCState *s, SMCKey *k, void *payload,
                                  uint8_t length)
{
    /* fprintf(stderr, "LGPE: payload: 0x%x\n", *(uint8_t *)payload); */
    return smc_set_key(s, k->key, length, payload);
}

static uint8_t smc_key_nesn_write(AppleSMCState *s, SMCKey *k, void *payload,
                                  uint8_t length)
{
#if 0
    key_response r = { 0 };
    uint8_t *p = (uint8_t *)payload;
    fprintf(stderr, "NESN: payload: 0x%x\n", *(uint32_t *)payload);
#endif
    return smc_set_key(s, k->key, length, payload);
}

static void apple_smc_handle_key_endpoint(void *opaque, uint32_t ep,
                                          uint64_t msg)
{
    AppleRTKit *rtk;
    AppleSMCState *s;
    KeyMessage *kmsg;
    KeyResponse r;

    s = APPLE_SMC_IOP(opaque);
    rtk = APPLE_RTKIT(opaque);
    kmsg = (KeyMessage *)&msg;

    memset(&r, 0, sizeof(r));
    SMC_LOG_MSG(ep, msg);

    switch (kmsg->cmd) {
    case SMC_GET_SRAM_ADDR: {
        apple_rtkit_send_user_msg(rtk, ep, s->sram_addr);
        break;
    }
    case SMC_READ_KEY:
    case SMC_READ_KEY_PAYLOAD: {
        SMCKey *k = smc_get_key(s, kmsg->key);
        if (k == NULL) {
            r.status = kSMCKeyNotFound;
        } else {
            if (k->read != NULL) {
                r.status = k->read(s, k, s->sram, kmsg->payload_length);
            }
            if (r.status == kSMCSuccess) {
                r.length = k->info.size;
                if (k->info.size <= 4) {
                    memcpy(r.response, k->data, k->info.size);
                } else {
                    memcpy(s->sram, k->data, k->info.size);
                }
                r.status = kSMCSuccess;
            }
        }
        r.ui8_tag_and_id = kmsg->ui8_tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, r.raw);
        break;
    }
    case SMC_WRITE_KEY: {
        SMCKey *k = smc_get_key(s, kmsg->key);
        if (k == NULL) {
            r.status = kSMCKeyNotFound;
        } else {
            if (k->write != NULL) {
                r.status = k->write(s, k, s->sram, kmsg->length);
            } else {
                r.status = smc_set_key(s, kmsg->key, kmsg->length, s->sram);
            }
            r.length = kmsg->length;
        }
        r.ui8_tag_and_id = kmsg->ui8_tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, r.raw);
        break;
    }
    case SMC_GET_KEY_BY_INDEX: {
        uint32_t idx = kmsg->key;
        SMCKey *k = QTAILQ_FIRST(&s->keys);

        for (int i = 0; i < idx && k; i++) {
            k = QTAILQ_NEXT(k, entry);
        }

        if (k == NULL) {
            r.status = kSMCKeyIndexRangeError;
        } else {
            r.status = kSMCSuccess;
            memcpy(r.response, &k->key, 4);
            bswap32s((uint32_t *)r.response);
        }
        r.ui8_tag_and_id = kmsg->ui8_tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, r.raw);
        break;
    }
    case SMC_GET_KEY_INFO: {
        SMCKey *k = smc_get_key(s, kmsg->key);
        if (k == NULL) {
            r.status = kSMCKeyNotFound;
        } else {
            memcpy(s->sram, &k->info, sizeof(k->info));
            r.status = kSMCSuccess;
        }
        r.ui8_tag_and_id = kmsg->ui8_tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, r.raw);
        break;
    }
    default: {
        r.status = kSMCBadCommand;
        r.ui8_tag_and_id = kmsg->ui8_tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, r.raw);
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

    s->iomems[1] = g_new(MemoryRegion, 1);
    memory_region_init_io(s->iomems[1], OBJECT(dev), &ascv2_core_reg_ops, s,
                          TYPE_APPLE_SMC_IOP ".ascv2-core-reg", reg[3]);
    sysbus_init_mmio(sbd, s->iomems[1]);

    prop = dtb_find_prop(child, "sram-addr");
    g_assert_nonnull(prop);
    g_assert_cmpuint(prop->length, ==, 8);

    s->sram_addr = *(uint64_t *)prop->data;
    s->iomems[2] = g_new(MemoryRegion, 1);
    memory_region_init_ram_device_ptr(s->iomems[2], OBJECT(dev),
                                      TYPE_APPLE_SMC_IOP ".sram",
                                      sizeof(s->sram), s->sram);
    sysbus_init_mmio(sbd, s->iomems[2]);

    dtb_set_prop_u32(child, "pre-loaded", 1);
    dtb_set_prop_u32(child, "running", 1);

    QTAILQ_INIT(&s->keys);

    return sbd;
}

static void apple_smc_realize(DeviceState *dev, Error **errp)
{
    AppleSMCState *s;
    AppleSMCClass *sc;
    uint8_t data[8] = { 0x00, 0x00, 0x70, 0x80, 0x00, 0x01, 0x19, 0x40 };
    uint64_t value;

    s = APPLE_SMC_IOP(dev);
    sc = APPLE_SMC_IOP_GET_CLASS(dev);

    if (sc->parent_realize != NULL) {
        sc->parent_realize(dev, errp);
    }

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
}

static void apple_smc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc;
    AppleSMCClass *sc;

    dc = DEVICE_CLASS(klass);
    sc = APPLE_SMC_IOP_CLASS(klass);

    device_class_set_parent_realize(dc, apple_smc_realize, &sc->parent_realize);
    /* device_class_set_legacy_reset(dc, apple_smc_reset); */
    dc->desc = "Apple SMC IOP";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_smc_info = {
    .name = TYPE_APPLE_SMC_IOP,
    .parent = TYPE_APPLE_RTKIT,
    .instance_size = sizeof(AppleSMCState),
    .class_size = sizeof(AppleSMCClass),
    .class_init = apple_smc_class_init,
};

static void apple_smc_register_types(void)
{
    type_register_static(&apple_smc_info);
}

type_init(apple_smc_register_types);
