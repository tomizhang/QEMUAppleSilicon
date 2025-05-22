#include "qemu/osdep.h"
#include "hw/dma/apple_sio.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "system/dma.h"

// #define DEBUG_SIO

#ifdef DEBUG_SIO
#define SIO_LOG_MSG(ep, msg)                                                \
    do {                                                                    \
        qemu_log_mask(LOG_GUEST_ERROR,                                      \
                      "SIO: message: ep=%u msg=0x" HWADDR_FMT_plx "\n", ep, \
                      msg);                                                 \
    } while (0)
#else
#define SIO_LOG_MSG(ep, msg) \
    do {                     \
    } while (0)
#endif

#define SIO_NUM_EPS (0xDB)

typedef struct {
    uint32_t xfer;
    uint32_t timeout;
    uint32_t fifo;
    uint32_t trigger;
    uint32_t depth;
    uint32_t field_14;
    uint32_t field_18;
} QEMU_PACKED SIODMAConfig;

typedef struct {
    uint64_t addr;
    uint32_t len;
} QEMU_PACKED SIODMASegment;

struct AppleSIODMAEndpoint {
    SIODMAConfig config;
    SIODMASegment *segments;
    QEMUSGList sgl;
    QEMUIOVector iov;
    uint32_t segment_count;
    uint32_t bytes_accessed;
    uint32_t id;
    uint32_t tag;
    bool mapped;
    DMADirection direction;
};

struct AppleSIOClass {
    /*< private >*/
    AppleRTKitClass base_class;

    /*< public >*/
    DeviceRealize parent_realize;
    ResettablePhases parent_reset;
};

struct AppleSIOState {
    /*< private >*/
    AppleRTKit parent_obj;

    /*< public >*/
    MemoryRegion ascv2_iomem;
    MemoryRegion *dma_mr;
    AddressSpace dma_as;

    AppleSIODMAEndpoint eps[SIO_NUM_EPS];
    uint32_t params[0x100];
};

typedef enum {
    OP_GET_PARAM = 2,
    OP_GET_PARAM_RETURN = 103,
    OP_CONFIG_SHIM = 5,
    OP_SET_PARAM = 3,
    OP_ERROR = 2,
    OP_SET_PARAM_ERROR = 3,
    OP_START_DMA = 6,
    OP_QUERY_DMA = 7,
    OP_STOP_DMA = 8,
    OP_ACK = 101,
    OP_ASYNC_ERROR = 102,
    OP_DMA_COMPLETE = 104,
    OP_QUERY_DMA_OK = 105,
} SIOOp;

typedef enum {
    EP_CONTROL = 0,
    EP_PERF = 3,
} SIOEndpoint;

typedef enum {
    PARAM_PROTOCOL = 0,
    PARAM_DMA_SEGMENT_BASE = 1,
    PARAM_DMA_SEGMENT_SIZE = 2,
    PARAM_DMA_RESPONSE_BASE = 11,
    PARAM_DMA_RESPONSE_SIZE = 12,
    PARAM_PERF_BUF_BASE = 13,
    PARAM_PERF_BUF_SIZE = 14,
    PARAM_PANIC_BASE = 15,
    PARAM_PANIC_SIZE = 16,
    PARAM_PIO_BASE = 26,
    PARAM_PIO_SIZE = 27,
    PARAM_DEVICES_BASE = 28,
    PARAM_DEVICES_SIZE = 29,
    PARAM_TUNABLE_0_BASE = 30,
    PARAM_TUNABLE_0_SIZE = 31,
    PARAM_TUNABLE_1_BASE = 32,
    PARAM_TUNABLE_1_SIZE = 33,
    PARAM_PS_REGS_BASE = 36,
    PARAM_PS_REGS_SIZE = 37,
    PARAM_FORWARD_IRQS_BASE = 38,
    PARAM_FORWARD_IRQS_SIZE = 39,
} SIOParamId;

typedef struct QEMU_PACKED {
    union {
        uint64_t raw;
        struct QEMU_PACKED {
            uint8_t ep;
            uint8_t tag;
            uint8_t op;
            uint8_t param;
            uint32_t data;
        };
    };
} SIOMessage;

static void apple_sio_map_dma(AppleSIOState *s, AppleSIODMAEndpoint *ep)
{
    if (ep->mapped) {
        return;
    }

    qemu_iovec_init(&ep->iov, ep->segment_count);
    for (int i = 0; i < ep->segment_count; i++) {
        dma_addr_t base = ep->sgl.sg[i].base;
        dma_addr_t len = ep->sgl.sg[i].len;

        while (len) {
            dma_addr_t xlen = len;
            void *mem = dma_memory_map(&s->dma_as, base, &xlen, ep->direction,
                                       MEMTXATTRS_UNSPECIFIED);
            if (mem == NULL) {
                qemu_log_mask(LOG_GUEST_ERROR, "%s: unable to map memory\n",
                              __func__);
                continue;
            }

            if (xlen > len) {
                xlen = len;
            }
            qemu_iovec_add(&ep->iov, mem, xlen);
            len -= xlen;
            base += xlen;
        }
    }

    ep->mapped = true;
    ep->bytes_accessed = 0;
}

static void apple_sio_unmap_dma(AppleSIOState *s, AppleSIODMAEndpoint *ep)
{
    int i;
    int unmap_length;
    int access_len;

    ep->mapped = false;
    unmap_length = ep->bytes_accessed;
    for (i = 0; i < ep->iov.niov; i++) {
        access_len = ep->iov.iov[i].iov_len;
        if (access_len > unmap_length) {
            access_len = unmap_length;
        }

        dma_memory_unmap(&s->dma_as, ep->iov.iov[i].iov_base,
                         ep->iov.iov[i].iov_len, ep->direction, access_len);
        unmap_length -= access_len;
    }
    qemu_iovec_destroy(&ep->iov);
    ep->segment_count = 0;
    ep->bytes_accessed = 0;
    ep->tag = 0;
    g_free(ep->segments);
    ep->segments = NULL;
    qemu_sglist_destroy(&ep->sgl);
}

static void apple_sio_dma_writeback(AppleSIOState *s, AppleSIODMAEndpoint *ep)
{
    AppleRTKit *rtk;
    SIOMessage m = { 0 };

    rtk = APPLE_RTKIT(s);

    m.op = OP_DMA_COMPLETE;
    m.ep = ep->id;
    m.param = (1 << 7);
    m.tag = ep->tag;
    m.data = ep->bytes_accessed;

    apple_sio_unmap_dma(s, ep);

    apple_rtkit_send_user_msg(rtk, EP_CONTROL, m.raw);
}

int apple_sio_dma_read(AppleSIODMAEndpoint *ep, void *buffer, size_t len)
{
    AppleSIOState *s;
    int xlen;

    s = container_of(ep, AppleSIOState, eps[ep->id]);

    if (!ep->mapped) {
        return 0;
    }

    g_assert_cmpuint(ep->direction, ==, DMA_DIRECTION_TO_DEVICE);
    xlen = qemu_iovec_to_buf(&ep->iov, ep->bytes_accessed, buffer, len);
    ep->bytes_accessed += xlen;
    if (ep->bytes_accessed >= ep->iov.size) {
        apple_sio_dma_writeback(s, ep);
    }

    return xlen;
}

int apple_sio_dma_write(AppleSIODMAEndpoint *ep, void *buffer, size_t len)
{
    AppleSIOState *s;
    int xlen;

    s = container_of(ep, AppleSIOState, eps[ep->id]);

    if (!ep->mapped) {
        return 0;
    }

    g_assert_cmpuint(ep->direction, ==, DMA_DIRECTION_FROM_DEVICE);
    xlen = qemu_iovec_from_buf(&ep->iov, ep->bytes_accessed, buffer, len);
    ep->bytes_accessed += xlen;
    if (ep->bytes_accessed >= ep->iov.size) {
        apple_sio_dma_writeback(s, ep);
    }

    return xlen;
}

int apple_sio_dma_remaining(AppleSIODMAEndpoint *ep)
{
    return ep->iov.size - ep->bytes_accessed;
}

static void apple_sio_control(AppleSIOState *s, AppleSIODMAEndpoint *ep,
                              SIOMessage *m)
{
    AppleRTKit *rtk;
    SIOMessage reply = { 0 };

    rtk = APPLE_RTKIT(s);

    reply.ep = m->ep;
    reply.tag = m->tag;
    switch (m->op) {
    case OP_GET_PARAM: {
        reply.data = s->params[m->param];
        reply.op = OP_GET_PARAM_RETURN;
        break;
    }
    case OP_SET_PARAM: {
        s->params[m->param] = m->data;
        reply.op = OP_ACK;
        break;
    }
    default:
        break;
    }
    apple_rtkit_send_user_msg(rtk, EP_CONTROL, reply.raw);
};

static void apple_sio_dma(AppleSIOState *s, AppleSIODMAEndpoint *ep,
                          SIOMessage m)
{
    AppleRTKit *rtk;
    SIOMessage reply = { 0 };
    dma_addr_t config_addr;
    dma_addr_t handle_addr;
    uint32_t segment_count;
    int i;

    rtk = APPLE_RTKIT(s);
    reply.ep = m.ep;
    reply.tag = m.tag;
    switch (m.op) {
    case OP_CONFIG_SHIM: {
        config_addr = (s->params[PARAM_DMA_SEGMENT_BASE] << 12) + m.data * 12;
        if (dma_memory_read(&s->dma_as, config_addr, &ep->config,
                            sizeof(ep->config),
                            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            return;
        }
        reply.op = OP_ACK;
        break;
    }
    case OP_START_DMA: {
        if (ep->mapped) {
            qemu_log_mask(LOG_GUEST_ERROR, "SIO: Another DMA is running\n");
            reply.op = OP_ERROR;
            break;
        }

        handle_addr = (s->params[PARAM_DMA_SEGMENT_BASE] << 12) + m.data * 12;
        if (dma_memory_read(&s->dma_as, handle_addr + 0x3C, &segment_count,
                            sizeof(segment_count),
                            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            return;
        }

        qemu_sglist_init(&ep->sgl, DEVICE(s), segment_count, &s->dma_as);
        ep->tag = m.tag;
        ep->segment_count = segment_count;
        ep->segments = g_new0(SIODMASegment, segment_count);
        dma_memory_read(&s->dma_as, handle_addr + 0x48, ep->segments,
                        segment_count * sizeof(SIODMASegment),
                        MEMTXATTRS_UNSPECIFIED);
        for (i = 0; i < segment_count; i++) {
            qemu_sglist_add(&ep->sgl, ep->segments[i].addr,
                            ep->segments[i].len);
        }
        apple_sio_map_dma(s, ep);
        reply.op = OP_ACK;
        break;
    }
    case OP_QUERY_DMA:
        if (ep->mapped) {
            reply.op = OP_QUERY_DMA_OK;
            reply.data = ep->bytes_accessed;
            break;
        }
        reply.op = OP_ERROR;
        break;
    case OP_STOP_DMA:
        if (ep->mapped) {
            reply.op = OP_ACK;
            apple_sio_unmap_dma(s, ep);
            break;
        }
        reply.op = OP_ERROR;
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "%s: Unknown SIO op: %d\n", __func__, m.op);
        reply.op = OP_ERROR;
        break;
    }
    apple_rtkit_send_user_msg(rtk, EP_CONTROL, reply.raw);
};

static void apple_sio_handle_endpoint(void *opaque, uint32_t ep, uint64_t msg)
{
    AppleSIOState *sio;
    SIOMessage m = { 0 };

    sio = APPLE_SIO(opaque);
    m.raw = msg;

    SIO_LOG_MSG(ep, msg);

    switch (m.ep) {
    case EP_CONTROL:
    case EP_PERF:
        apple_sio_control(sio, &sio->eps[EP_CONTROL], &m);
        break;
    default:
        if (m.ep >= SIO_NUM_EPS) {
            qemu_log_mask(LOG_UNIMP, "%s: Unknown SIO ep: %d\n", __func__,
                          m.ep);
        } else {
            apple_sio_dma(sio, &sio->eps[m.ep], m);
        }
        break;
    }
}

AppleSIODMAEndpoint *apple_sio_get_endpoint(AppleSIOState *s, int ep)
{
    if (ep <= EP_PERF || ep >= SIO_NUM_EPS) {
        return NULL;
    }

    return &s->eps[ep];
}

AppleSIODMAEndpoint *apple_sio_get_endpoint_from_node(AppleSIOState *s,
                                                      DTBNode *node, int idx)
{
    DTBProp *prop;
    uint32_t *data;
    int count;

    prop = dtb_find_prop(node, "dma-channels");
    if (prop == NULL) {
        return NULL;
    }

    count = prop->length / 32;
    if (idx >= count) {
        return NULL;
    }
    data = (uint32_t *)prop->data;
    return apple_sio_get_endpoint(s, data[8 * idx]);
}

static void ascv2_core_reg_write(void *opaque, hwaddr addr, uint64_t data,
                                 unsigned size)
{
#ifdef DEBUG_SIO
    qemu_log_mask(LOG_UNIMP,
                  "SIO: AppleASCWrapV2 core reg WRITE @ 0x" HWADDR_FMT_plx
                  " value: 0x" HWADDR_FMT_plx "\n",
                  addr, data);
#endif
}

static uint64_t ascv2_core_reg_read(void *opaque, hwaddr addr, unsigned size)
{
#ifdef DEBUG_SIO
    qemu_log_mask(LOG_UNIMP,
                  "SIO: AppleASCWrapV2 core reg READ @ 0x" HWADDR_FMT_plx "\n",
                  addr);
#endif
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

static void apple_sio_realize(DeviceState *dev, Error **errp)
{
    AppleSIOState *s;
    AppleSIOClass *sioc;
    Object *obj;

    s = APPLE_SIO(dev);
    sioc = APPLE_SIO_GET_CLASS(dev);

    if (sioc->parent_realize != NULL) {
        sioc->parent_realize(dev, errp);
    }

    obj = object_property_get_link(OBJECT(dev), "dma-mr", &error_abort);

    s->dma_mr = MEMORY_REGION(obj);
    g_assert_nonnull(s->dma_mr);
    address_space_init(&s->dma_as, s->dma_mr, "sio.dma-as");

    for (int i = 0; i < SIO_NUM_EPS; i++) {
        s->eps[i].id = i;
        s->eps[i].direction =
            (i & 1) ? DMA_DIRECTION_FROM_DEVICE : DMA_DIRECTION_TO_DEVICE;
    }
}

static void apple_sio_reset_hold(Object *obj, ResetType type)
{
    AppleSIOState *s;
    AppleSIOClass *sioc;
    uint32_t protocol;

    s = APPLE_SIO(obj);
    sioc = APPLE_SIO_GET_CLASS(obj);

    if (sioc->parent_reset.hold != NULL) {
        sioc->parent_reset.hold(obj, type);
    }

    protocol = s->params[PARAM_PROTOCOL];
    memset(s->params, 0, sizeof(s->params));
    s->params[PARAM_PROTOCOL] = protocol;

    for (int i = 0; i < SIO_NUM_EPS; i++) {
        if (s->eps[i].mapped) {
            apple_sio_unmap_dma(s, &s->eps[i]);
        }

        memset(&s->eps[i].config, 0, sizeof(s->eps[i].config));
    }
}

static const VMStateDescription vmstate_apple_sio_dma_config = {
    .name = "SIODMAConfig",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT32(xfer, SIODMAConfig),
            VMSTATE_UINT32(timeout, SIODMAConfig),
            VMSTATE_UINT32(fifo, SIODMAConfig),
            VMSTATE_UINT32(trigger, SIODMAConfig),
            VMSTATE_UINT32(depth, SIODMAConfig),
            VMSTATE_UINT32(field_14, SIODMAConfig),
            VMSTATE_UINT32(field_18, SIODMAConfig),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription vmstate_apple_sio_dma_segment = {
    .name = "SIODMASegment",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT64(addr, SIODMASegment),
            VMSTATE_UINT32(len, SIODMASegment),
            VMSTATE_END_OF_LIST(),
        },
};

static int vmstate_apple_sio_dma_endpoint_pre_load(void *opaque)
{
    AppleSIODMAEndpoint *ep;
    AppleSIOState *s;

    ep = (AppleSIODMAEndpoint *)opaque;
    s = container_of(ep, AppleSIOState, eps[ep->id]);

    apple_sio_unmap_dma(s, ep);

    return 0;
}

static int vmstate_apple_sio_dma_endpoint_post_load(void *opaque,
                                                    int version_id)
{
    AppleSIODMAEndpoint *ep;
    AppleSIOState *s;
    uint32_t bytes_accessed;

    ep = (AppleSIODMAEndpoint *)opaque;
    s = container_of(ep, AppleSIOState, eps[ep->id]);

    if (ep->mapped) {
        ep->mapped = false;
        bytes_accessed = ep->bytes_accessed;
        apple_sio_map_dma(s, ep);
        ep->bytes_accessed = bytes_accessed;
    }

    return 0;
}

static const VMStateDescription vmstate_apple_sio_dma_endpoint = {
    .name = "AppleSIODMAEndpoint",
    .version_id = 0,
    .minimum_version_id = 0,
    .pre_load = vmstate_apple_sio_dma_endpoint_pre_load,
    .post_load = vmstate_apple_sio_dma_endpoint_post_load,
    .fields =
        (const VMStateField[]){
            VMSTATE_STRUCT(config, AppleSIODMAEndpoint, 0,
                           vmstate_apple_sio_dma_config, SIODMAConfig),
            VMSTATE_STRUCT_VARRAY_UINT32_ALLOC(
                segments, AppleSIODMAEndpoint, segment_count, 0,
                vmstate_apple_sio_dma_segment, SIODMASegment),
            VMSTATE_UINT32(segment_count, AppleSIODMAEndpoint),
            VMSTATE_UINT32(bytes_accessed, AppleSIODMAEndpoint),
            VMSTATE_UINT32(id, AppleSIODMAEndpoint),
            VMSTATE_UINT32(tag, AppleSIODMAEndpoint),
            VMSTATE_BOOL(mapped, AppleSIODMAEndpoint),
            VMSTATE_UINT32(direction, AppleSIODMAEndpoint),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription vmstate_apple_sio = {
    .name = "AppleSIOState",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_APPLE_RTKIT(parent_obj, AppleSIOState),
            VMSTATE_STRUCT_ARRAY(eps, AppleSIOState, SIO_NUM_EPS, 0,
                                 vmstate_apple_sio_dma_endpoint,
                                 AppleSIODMAEndpoint),
            VMSTATE_UINT32_ARRAY(params, AppleSIOState, 0x100),
            VMSTATE_END_OF_LIST(),
        },
};

static void apple_sio_class_init(ObjectClass *klass, void *data)
{
    ResettableClass *rc;
    DeviceClass *dc;
    AppleSIOClass *sioc;

    rc = RESETTABLE_CLASS(klass);
    dc = DEVICE_CLASS(klass);
    sioc = APPLE_SIO_CLASS(klass);

    device_class_set_parent_realize(dc, apple_sio_realize,
                                    &sioc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, apple_sio_reset_hold, NULL,
                                       &sioc->parent_reset);
    dc->desc = "Apple Smart IO DMA Controller";
    dc->user_creatable = false;
    dc->vmsd = &vmstate_apple_sio;
}

static const TypeInfo apple_sio_info = {
    .name = TYPE_APPLE_SIO,
    .parent = TYPE_APPLE_RTKIT,
    .instance_size = sizeof(AppleSIOState),
    .class_size = sizeof(AppleSIOClass),
    .class_init = apple_sio_class_init,
};

static void apple_sio_register_types(void)
{
    type_register_static(&apple_sio_info);
}

type_init(apple_sio_register_types);

SysBusDevice *apple_sio_create(DTBNode *node, AppleA7IOPVersion version,
                               uint32_t rtkit_protocol_version,
                               uint32_t protocol)
{
    DeviceState *dev;
    AppleSIOState *s;
    SysBusDevice *sbd;
    AppleRTKit *rtk;
    DTBNode *child;
    DTBProp *prop;
    uint64_t *reg;

    dev = qdev_new(TYPE_APPLE_SIO);
    s = APPLE_SIO(dev);
    sbd = SYS_BUS_DEVICE(dev);
    rtk = APPLE_RTKIT(dev);
    dev->id = g_strdup("sio");

    s->params[PARAM_PROTOCOL] = protocol;

    child = dtb_get_node(node, "iop-sio-nub");
    g_assert_nonnull(child);

    prop = dtb_find_prop(node, "reg");
    g_assert_nonnull(prop);

    reg = (uint64_t *)prop->data;

    apple_rtkit_init(rtk, NULL, "SIO", reg[1], version, rtkit_protocol_version,
                     NULL);
    apple_rtkit_register_user_ep(rtk, EP_CONTROL, s, apple_sio_handle_endpoint);

    memory_region_init_io(&s->ascv2_iomem, OBJECT(dev), &ascv2_core_reg_ops, s,
                          TYPE_APPLE_SIO ".ascv2-core-reg", reg[3]);
    sysbus_init_mmio(sbd, &s->ascv2_iomem);

    dtb_set_prop_u32(child, "pre-loaded", 1);
    // dtb_set_prop_u32(child, "running", 1);

    return sbd;
}
