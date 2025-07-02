#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/misc/apple-silicon/smc.h"
#include "hw/qdev-core.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/queue.h"
#include "system/runstate.h"

#define kSMCKeyEndpoint 0

struct AppleSMCState {
    AppleRTKit parent_obj;

    MemoryRegion *iomems[3];
    QTAILQ_HEAD(, SMCKey) keys;
    QTAILQ_HEAD(, SMCKeyData) key_data;
    uint32_t key_count;
    uint8_t *sram;
    uint32_t sram_size;
};

SMCKey *apple_smc_get_key(AppleSMCState *s, uint32_t key)
{
    SMCKey *key_entry;

    QTAILQ_FOREACH (key_entry, &s->keys, next) {
        if (key_entry->key == key) {
            return key_entry;
        }
    }

    return NULL;
}

SMCKeyData *apple_smc_get_key_data(AppleSMCState *s, uint32_t key)
{
    SMCKeyData *data_entry;

    QTAILQ_FOREACH (data_entry, &s->key_data, next) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }

    return NULL;
}

SMCKey *apple_smc_create_key(AppleSMCState *s, uint32_t key, uint32_t size,
                             uint32_t type, uint32_t attr, void *data)
{
    SMCKey *key_entry;
    SMCKeyData *data_entry;

    g_assert_null(apple_smc_get_key(s, key));

    key_entry = g_new0(SMCKey, 1);
    data_entry = g_new0(SMCKeyData, 1);

    s->key_count += 1;
    key_entry->key = key;
    key_entry->info.size = size;
    key_entry->info.type = cpu_to_be32(type);
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

SMCKey *apple_smc_create_key_func(AppleSMCState *s, uint32_t key, uint32_t size,
                                  uint32_t type, uint32_t attr,
                                  KeyReader reader, KeyWriter writer)
{
    SMCKey *key_entry;

    attr |= SMC_ATTR_FUNCTION;
    if (reader != NULL) {
        attr |= SMC_ATTR_READABLE;
    }
    if (writer != NULL) {
        attr |= SMC_ATTR_WRITEABLE;
    }

    key_entry = apple_smc_create_key(s, key, size, type, attr, NULL);

    key_entry->read = reader;
    key_entry->write = writer;

    return key_entry;
}

uint8_t apple_smc_set_key(AppleSMCState *s, uint32_t key, uint32_t size,
                          void *data)
{
    SMCKey *key_entry;
    SMCKeyData *data_entry;

    key_entry = apple_smc_get_key(s, key);
    data_entry = apple_smc_get_key_data(s, key);

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

static uint8_t apple_smc_mbse_write(AppleSMCState *s, SMCKey *key,
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
    case 'offw':
    case 'off1':
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return kSMCSuccess;
    case 'susp':
        qemu_system_suspend_request();
        return kSMCSuccess;
    case 'rest':
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
        return kSMCSuccess;
    case 'slpw':
        return kSMCSuccess;
    case 'panb': {
        memset(&r, 0, sizeof(r));
        r.status = SMC_NOTIFICATION;
        r.response[2] = kSMCSystemStateNotifySMCPanicProgress;
        r.response[3] = kSMCEventSystemStateNotify;
        apple_rtkit_send_user_msg(rtk, kSMCKeyEndpoint, r.raw);
        return kSMCSuccess;
    }
    case 'pane': {
        memset(&r, 0, sizeof(r));
        r.status = SMC_NOTIFICATION;
        r.response[2] = kSMCSystemStateNotifySMCPanicDone;
        r.response[3] = kSMCEventSystemStateNotify;
        apple_rtkit_send_user_msg(rtk, kSMCKeyEndpoint, r.raw);
        return kSMCSuccess;
    }
    default:
        return kSMCBadFuncParameter;
    }
}

static void apple_smc_handle_key_endpoint(void *opaque, const uint32_t ep,
                                          const uint64_t msg)
{
    AppleRTKit *rtk;
    AppleSMCState *s;
    KeyMessage *kmsg;
    KeyResponse resp;
    SMCKey *key_entry;
    SMCKeyData *data_entry;

    s = APPLE_SMC_IOP(opaque);
    rtk = APPLE_RTKIT(opaque);
    kmsg = (KeyMessage *)&msg;

    kmsg->key = le32_to_cpu(kmsg->key);

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
        key_entry = apple_smc_get_key(s, kmsg->key);
        data_entry = apple_smc_get_key_data(s, kmsg->key);
        if (key_entry == NULL) {
            resp.status = kSMCKeyNotFound;
        } else if (key_entry->info.attr & SMC_ATTR_READABLE) {
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
        } else {
            resp.status = kSMCKeyNotReadable;
        }
        resp.tag_and_id = kmsg->tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, resp.raw);
        break;
    }
    case SMC_WRITE_KEY: {
        key_entry = apple_smc_get_key(s, kmsg->key);
        data_entry = apple_smc_get_key_data(s, kmsg->key);
        if (key_entry == NULL) {
            resp.status = kSMCKeyNotFound;
        } else if (key_entry->info.attr & SMC_ATTR_WRITEABLE) {
            g_assert_nonnull(data_entry);

            if (key_entry->write != NULL) {
                resp.status = key_entry->write(s, key_entry, data_entry,
                                               s->sram, kmsg->length);
            } else {
                resp.status =
                    apple_smc_set_key(s, kmsg->key, kmsg->length, s->sram);
            }
            resp.length = kmsg->length;
        } else {
            resp.status = kSMCKeyNotWritable;
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
            stl_le_p(resp.response, cpu_to_le32(key_entry->key));
        }

        resp.tag_and_id = kmsg->tag_and_id;
        apple_rtkit_send_user_msg(rtk, ep, resp.raw);
        break;
    }
    case SMC_GET_KEY_INFO: {
        key_entry = apple_smc_get_key(s, kmsg->key);
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
        fprintf(stderr, "SMC: Unknown command 0x%02x\n", kmsg->cmd);
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
                               uint32_t protocol_version, uint32_t sram_size)
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
    s->sram = g_aligned_alloc0(1, sram_size, 0x4000);
    s->sram_size = sram_size;
    memory_region_init_ram_device_ptr(s->iomems[APPLE_SMC_MMIO_SRAM],
                                      OBJECT(dev), TYPE_APPLE_SMC_IOP ".sram",
                                      s->sram_size, s->sram);
    sysbus_init_mmio(sbd, s->iomems[APPLE_SMC_MMIO_SRAM]);


    dtb_set_prop_u32(child, "pre-loaded", 1);
    dtb_set_prop_u32(child, "running", 1);

    QTAILQ_INIT(&s->keys);
    QTAILQ_INIT(&s->key_data);

    apple_smc_create_key_func(s, '#KEY', 4, SMCKeyTypeUInt32,
                              SMC_ATTR_LITTLE_ENDIAN, &smc_key_count_read,
                              NULL);

    apple_smc_create_key(s, 'CLKH', 8, SMCKeyTypeClh, SMC_ATTR_DEFAULT_LE,
                         data);

    data[0] = 3;
    apple_smc_create_key(s, 'RGEN', 1, SMCKeyTypeUInt8, SMC_ATTR_DEFAULT_LE,
                         data);

    apple_smc_create_key(s, 'aDC#', 4, SMCKeyTypeUInt32, SMC_ATTR_DEFAULT_LE,
                         NULL);

    apple_smc_create_key_func(s, 'MBSE', 4, SMCKeyTypeHex,
                              SMC_ATTR_LITTLE_ENDIAN, NULL,
                              &apple_smc_mbse_write);

    apple_smc_create_key(s, 'LGPB', 1, SMCKeyTypeFlag,
                         SMC_ATTR_LITTLE_ENDIAN | SMC_ATTR_WRITEABLE, NULL);
    apple_smc_create_key(s, 'LGPE', 1, SMCKeyTypeFlag,
                         SMC_ATTR_LITTLE_ENDIAN | SMC_ATTR_WRITEABLE, NULL);
    apple_smc_create_key(s, 'NESN', 4, SMCKeyTypeHex,
                         SMC_ATTR_LITTLE_ENDIAN | SMC_ATTR_WRITEABLE, NULL);

    value = 1;
    apple_smc_create_key(s, 'AC-N', 1, SMCKeyTypeUInt8, SMC_ATTR_DEFAULT_LE,
                         &value);
    apple_smc_create_key(s, 'CHAI', 4, SMCKeyTypeUInt32, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TG0B', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TG0V', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP1A', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP2C', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP1d', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP2d', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP3d', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP4d', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP5d', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP3R', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP4H', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TP0Z', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'B0AP', 4, SMCKeyTypeSInt32, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th0a', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th1a', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th2a', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th0f', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th1f', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th2f', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th0x', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th1x', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Th2x', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc0a', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc1a', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc2a', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc0f', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc1f', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc2f', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc0x', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc1x', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'Tc2x', 8, SMCKeyTypeFLT, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'D0VR', 2, SMCKeyTypeUInt16, SMC_ATTR_DEFAULT_LE,
                         NULL);
    apple_smc_create_key(s, 'TV0s', 8, SMCKeyTypeIOFT, SMC_ATTR_DEFAULT_LE,
                         NULL);

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
        key = apple_smc_get_key(s, data->key);
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
        data = apple_smc_get_key_data(s, key->key);
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
            VMSTATE_VBUFFER_ALLOC_UINT32(sram, AppleSMCState, 0, NULL,
                                         sram_size),
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
