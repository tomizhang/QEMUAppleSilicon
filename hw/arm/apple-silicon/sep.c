/*
 * Apple SEP.
 *
 * Copyright (c) 2023 Visual Ehrmanntraut.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/boot.h"
#include "hw/arm/apple-silicon/sep.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/misc/apple-silicon/a7iop/mailbox/core.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"

typedef enum {
    SEP_STATUS_SLEEPING = 0,
    SEP_STATUS_BOOTSTRAP = 1,
    SEP_STATUS_ACTIVE = 2,
} AppleSEPStatus;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t param;
    uint32_t data;
} QEMU_PACKED AppleSEPMessage;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t id;
    uint32_t name;
} QEMU_PACKED AppleSEPDiscoveryAdvertiseMessage;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t id;
    uint8_t ool_in_min_pages;
    uint8_t ool_in_max_pages;
    uint8_t ool_out_min_pages;
    uint8_t ool_out_max_pages;
} QEMU_PACKED AppleSEPDiscoveryExposeMessage;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint16_t size;
    uint32_t address;
} QEMU_PACKED AppleSEPL4InfoMessage;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t id;
    uint32_t data;
} QEMU_PACKED AppleSEPSetOOLMessage;

typedef enum {
    EP_CONTROL = 0, // 'cntl'
    EP_LOGGER = 1, // 'log '
    EP_XART_STORAGE = 2, // 'arts'
    EP_XART_REQUESTS = 3, // 'artr'
    EP_TRACER = 4, // 'trac'
    EP_DEBUG = 5, // 'debu'
    // 6..=7 = ???
    EP_MESA = 8, // 'mesa'
    EP_SPEARL = 9, // 'sprl'
    EP_SECURE_CREDENTIAL = 10, // 'scrd'
    // 11 = ??
    EP_SECURE_ELEMENT = 12, // 'sse '
    // 13..=14 = ??
    EP_UNIT_TESTING = 15, // 'unit'
    EP_XART_SLAVE = 16, // 'xars'
    // 17 = ??
    EP_KEYSTORE = 18, // 'sks '
    EP_XART_MASTER = 19, // 'xarm'
    EP_DISCOVERY = 253,
    EP_L4INFO = 254,
    EP_BOOTSTRAP = 255,
} AppleSEPEndpoint;

typedef enum {
    CONTROL_OP_NOP = 0,
    CONTROL_OP_ACK = 1,
    CONTROL_OP_SET_OOL_IN_ADDR = 2,
    CONTROL_OP_SET_OOL_OUT_ADDR = 3,
    CONTROL_OP_SET_OOL_IN_SIZE = 4,
    CONTROL_OP_SET_OOL_OUT_SIZE = 5,
    CONTROL_OP_TTY_IN = 10,
    CONTROL_OP_SLEEP = 12,
    CONTROL_OP_NOTIFY_ALIVE = 13,
    CONTROL_OP_NAP = 19,
    CONTROL_OP_GET_SECURITY_MODE = 20,
    CONTROL_OP_SELF_TEST = 24,
    CONTROL_OP_ERASE = 37,
    CONTROL_OP_L4_PANIC = 38,
    CONTROL_OP_SEP_OS_PANIC = 39,
} AppleSEPControlOpcode;

typedef enum {
    DISCOVERY_OP_ADVERTISE = 0,
    DISCOVERY_OP_EXPOSE = 1,
} AppleSEPDiscoveryOpcode;

typedef enum {
    BOOTSTRAP_OP_PING = 1,
    BOOTSTRAP_OP_GET_STATUS = 2,
    BOOTSTRAP_OP_GENERATE_NONCE = 3,
    BOOTSTRAP_OP_GET_NONCE_WORD = 4,
    BOOTSTRAP_OP_CHECK_TZ0 = 5,
    BOOTSTRAP_OP_BOOT_IMG4 = 6,
    BOOTSTRAP_OP_SET_ART = 7,
    BOOTSTRAP_OP_NOTIFY_OS_ACTIVE_ASYNC = 13,
    BOOTSTRAP_OP_SEND_DPA = 15,
    BOOTSTRAP_OP_NOTIFY_OS_ACTIVE = 21,
    BOOTSTRAP_OP_PING_ACK = 101,
    BOOTSTRAP_OP_STATUS_REPLY = 102,
    BOOTSTRAP_OP_NONCE_GENERATED = 103,
    BOOTSTRAP_OP_NONCE_WORD_REPLY = 104,
    BOOTSTRAP_OP_TZ0_ACCEPTED = 105,
    BOOTSTRAP_OP_IMG4_ACCEPTED = 106,
    BOOTSTRAP_OP_ART_ACCEPTED = 107,
    BOOTSTRAP_OP_RESUMED_FROM_RAM = 108,
    BOOTSTRAP_OP_DPA_SENT = 115,
    BOOTSTRAP_OP_LOG_RAW = 201,
    BOOTSTRAP_OP_LOG_PRINTABLE = 202,
    BOOTSTRAP_OP_ANNOUNCE_STATUS = 210,
    BOOTSTRAP_OP_PANIC = 255,
} AppleSEPBootstrapOpcode;

static void apple_sep_handle_control_msg(AppleSEPState *s, AppleSEPMessage *msg)
{
    AppleA7IOP *a7iop;
    AppleA7IOPMessage *sent_msg;
    AppleSEPMessage *sent_sep_msg;
    AppleSEPSetOOLMessage *set_ool_msg;

    a7iop = APPLE_A7IOP(s);

    switch (msg->op) {
    case CONTROL_OP_NOP:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: CONTROL_OP_NOP\n");
        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_CONTROL;
        sent_sep_msg->tag = msg->tag;
        sent_sep_msg->op = CONTROL_OP_ACK;
        apple_a7iop_send_ap(a7iop, sent_msg);
        break;
    case CONTROL_OP_SET_OOL_IN_ADDR:
        QEMU_FALLTHROUGH;
    case CONTROL_OP_SET_OOL_OUT_ADDR:
        QEMU_FALLTHROUGH;
    case CONTROL_OP_SET_OOL_IN_SIZE:
        QEMU_FALLTHROUGH;
    case CONTROL_OP_SET_OOL_OUT_SIZE:
        set_ool_msg = (AppleSEPSetOOLMessage *)msg;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_CONTROL: SET_OOL (%d) for (%d) data (0x%X)\n",
                      msg->op, set_ool_msg->id, set_ool_msg->data);
        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_CONTROL;
        sent_sep_msg->tag = msg->tag;
        sent_sep_msg->op = CONTROL_OP_ACK;
        apple_a7iop_send_ap(a7iop, sent_msg);
        break;
    case CONTROL_OP_GET_SECURITY_MODE:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_CONTROL: CONTROL_OP_GET_SECURITY_MODE\n");
        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_CONTROL;
        sent_sep_msg->tag = msg->tag;
        sent_sep_msg->op = CONTROL_OP_ACK;
        sent_sep_msg->data = cpu_to_le32(3);
        apple_a7iop_send_ap(a7iop, sent_msg);
        break;
    case CONTROL_OP_ERASE:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: CONTROL_OP_ERASE\n");
        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_CONTROL;
        sent_sep_msg->tag = msg->tag;
        sent_sep_msg->op = CONTROL_OP_ACK;
        apple_a7iop_send_ap(a7iop, sent_msg);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: Unknown opcode %d\n",
                      msg->op);
        break;
    }
}

static void apple_sep_handle_l4info(AppleSEPState *s,
                                    AppleSEPL4InfoMessage *msg)
{
    qemu_log_mask(LOG_GUEST_ERROR, "EP_L4INFO: address 0x%llX size 0x%llX\n",
                  (uint64_t)msg->address << 12, (uint64_t)msg->size << 12);
}

static void apple_sep_do_discovery(AppleSEPState *s)
{
    AppleA7IOP *a7iop;
    AppleA7IOPMessage *msg;
    AppleSEPDiscoveryAdvertiseMessage *advertise_msg;
    AppleSEPDiscoveryExposeMessage *expose_msg;

    a7iop = APPLE_A7IOP(s);

    const AppleSEPEndpoint eps[] = {
        EP_CONTROL,    EP_XART_STORAGE, EP_XART_REQUESTS, EP_SECURE_CREDENTIAL,
        EP_XART_SLAVE, EP_KEYSTORE,     EP_XART_MASTER,
    };
    const uint32_t ep_ids[] = {
        'cntl', 'arts', 'artr', 'scrd', 'xars', 'sks ', 'xarm',
    };
    for (size_t i = 0; i < (sizeof(eps) / sizeof(AppleSEPEndpoint)); i++) {
        msg = g_new0(AppleA7IOPMessage, 1);
        advertise_msg = (AppleSEPDiscoveryAdvertiseMessage *)msg->data;
        advertise_msg->ep = EP_DISCOVERY;
        advertise_msg->op = DISCOVERY_OP_ADVERTISE;
        advertise_msg->id = eps[i];
        advertise_msg->name = cpu_to_le32(ep_ids[i]);
        apple_a7iop_send_ap(a7iop, msg);

        msg = g_new0(AppleA7IOPMessage, 1);
        expose_msg = (AppleSEPDiscoveryExposeMessage *)msg->data;
        expose_msg->ep = EP_DISCOVERY;
        expose_msg->op = DISCOVERY_OP_EXPOSE;
        expose_msg->id = eps[i];
        if (eps[i] == EP_XART_STORAGE || eps[i] == EP_XART_REQUESTS) {
            expose_msg->ool_in_max_pages = 1;
            expose_msg->ool_in_min_pages = 1;
            expose_msg->ool_out_max_pages = 1;
            expose_msg->ool_out_min_pages = 1;
        } else {
            expose_msg->ool_in_max_pages = 2;
            expose_msg->ool_in_min_pages = 2;
            expose_msg->ool_out_max_pages = 2;
            expose_msg->ool_out_min_pages = 2;
        }
        apple_a7iop_send_ap(a7iop, msg);
    }
}

static void apple_sep_handle_bootstrap_msg(AppleSEPState *s,
                                           AppleSEPMessage *msg)
{
    AppleA7IOP *a7iop;
    AppleA7IOPMessage *sent_msg;
    AppleSEPMessage *sent_sep_msg;

    a7iop = APPLE_A7IOP(s);

    switch (msg->op) {
    case BOOTSTRAP_OP_GET_STATUS:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_BOOTSTRAP: BOOTSTRAP_OP_GET_STATUS\n");

        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_BOOTSTRAP;
        sent_sep_msg->tag = msg->tag;
        sent_sep_msg->op = BOOTSTRAP_OP_STATUS_REPLY;
        sent_sep_msg->data = s->status;
        apple_a7iop_send_ap(a7iop, sent_msg);
        break;
    case BOOTSTRAP_OP_CHECK_TZ0:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_BOOTSTRAP: BOOTSTRAP_OP_CHECK_TZ0\n");

        s->status = SEP_STATUS_ACTIVE;
        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_BOOTSTRAP;
        sent_sep_msg->tag = msg->tag;
        sent_sep_msg->op = BOOTSTRAP_OP_TZ0_ACCEPTED;
        apple_a7iop_send_ap(a7iop, sent_msg);
        break;
    case BOOTSTRAP_OP_BOOT_IMG4: {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_BOOTSTRAP: BOOTSTRAP_OP_BOOT_IMG4\n");

        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_BOOTSTRAP;
        sent_sep_msg->tag = msg->tag;
        sent_sep_msg->op = BOOTSTRAP_OP_IMG4_ACCEPTED;
        apple_a7iop_send_ap(a7iop, sent_msg);

        sent_msg = g_new0(AppleA7IOPMessage, 1);
        sent_sep_msg = (AppleSEPMessage *)sent_msg->data;
        sent_sep_msg->ep = EP_CONTROL;
        sent_sep_msg->op = CONTROL_OP_NOTIFY_ALIVE;
        apple_a7iop_send_ap(a7iop, sent_msg);

        apple_sep_do_discovery(s);
        break;
    }
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: Unknown opcode %d\n",
                      msg->op);
        break;
    }
}

static void apple_sep_bh(void *opaque)
{
    AppleSEPState *s;
    AppleA7IOP *a7iop;
    AppleA7IOPMessage *msg;
    AppleSEPMessage *sep_msg;

    s = APPLE_SEP(opaque);
    a7iop = APPLE_A7IOP(opaque);

    QEMU_LOCK_GUARD(&s->lock);

    while (!apple_a7iop_mailbox_is_empty(a7iop->iop_mailbox)) {
        msg = apple_a7iop_recv_iop(a7iop);
        sep_msg = (AppleSEPMessage *)msg->data;

        switch (sep_msg->ep) {
        case EP_CONTROL:
            apple_sep_handle_control_msg(s, sep_msg);
            break;
        case EP_XART_STORAGE:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "EP_XART_STORAGE: Unknown opcode %d\n", sep_msg->op);
            break;
        case EP_SECURE_CREDENTIAL:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "EP_SECURE_CREDENTIAL: Unknown opcode %d\n",
                          sep_msg->op);
            break;
        case EP_XART_SLAVE:
            qemu_log_mask(LOG_GUEST_ERROR, "EP_XART_SLAVE: Unknown opcode %d\n",
                          sep_msg->op);
            break;
        case EP_KEYSTORE:
            qemu_log_mask(LOG_GUEST_ERROR, "EP_KEYSTORE: Unknown opcode %d\n",
                          sep_msg->op);
            break;
        case EP_XART_MASTER:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "EP_XART_MASTER: Unknown opcode %d\n", sep_msg->op);
            break;
        case EP_DISCOVERY:
            qemu_log_mask(LOG_GUEST_ERROR, "EP_DISCOVERY: Unknown opcode %d\n",
                          sep_msg->op);
            break;
        case EP_L4INFO:
            apple_sep_handle_l4info(s, (AppleSEPL4InfoMessage *)sep_msg);
            break;
        case EP_BOOTSTRAP:
            apple_sep_handle_bootstrap_msg(s, sep_msg);
            break;
        default:
            qemu_log_mask(LOG_GUEST_ERROR, "EP_UNKNOWN_%d\n", sep_msg->ep);
            break;
        }

        g_free(msg);
    }
}

AppleSEPState *apple_sep_create(DTBNode *node, bool modern)
{
    DeviceState *dev;
    AppleA7IOP *a7iop;
    AppleSEPState *s;
    DTBProp *prop;
    uint64_t *reg;

    dev = qdev_new(TYPE_APPLE_SEP);
    a7iop = APPLE_A7IOP(dev);
    s = APPLE_SEP(dev);

    prop = find_dtb_prop(node, "reg");
    g_assert(prop);
    reg = (uint64_t *)prop->value;

    apple_a7iop_init(a7iop, "SEP", reg[1],
                     modern ? APPLE_A7IOP_V4 : APPLE_A7IOP_V2, NULL,
                     qemu_bh_new(apple_sep_bh, s));

    qemu_mutex_init(&s->lock);

    //! SEPFW needs to be loaded by restore, supposedly
    // DTBNode *child = find_dtb_node(node, "iop-sep-nub");
    // g_assert(child);
    // uint32_t data = 1;
    // set_dtb_prop(child, "sepfw-loaded", sizeof(data), &data);
    return s;
}

static void apple_sep_realize(DeviceState *dev, Error **errp)
{
    AppleSEPState *s;
    AppleSEPClass *sc;

    s = APPLE_SEP(dev);
    sc = APPLE_SEP_GET_CLASS(dev);
    if (sc->parent_realize) {
        sc->parent_realize(dev, errp);
    }
}

static void apple_sep_reset(DeviceState *dev)
{
    AppleSEPState *s;
    AppleSEPClass *sc;
    AppleA7IOP *a7iop;
    AppleA7IOPMessage *msg;
    AppleSEPMessage *sep_msg;

    s = APPLE_SEP(dev);
    sc = APPLE_SEP_GET_CLASS(dev);
    a7iop = APPLE_A7IOP(dev);
    if (sc->parent_reset) {
        sc->parent_reset(dev);
    }

    QEMU_LOCK_GUARD(&s->lock);
    a7iop->iop_mailbox->ap_dir_en = true;
    a7iop->iop_mailbox->iop_dir_en = true;
    a7iop->ap_mailbox->iop_dir_en = true;
    a7iop->ap_mailbox->ap_dir_en = true;
    s->status = SEP_STATUS_BOOTSTRAP;

    msg = g_new0(AppleA7IOPMessage, 1);
    sep_msg = (AppleSEPMessage *)msg->data;
    sep_msg->ep = EP_BOOTSTRAP;
    sep_msg->op = BOOTSTRAP_OP_ANNOUNCE_STATUS;
    sep_msg->data = s->status;
    apple_a7iop_send_ap(a7iop, msg);
}

static void apple_sep_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    AppleSEPClass *sc = APPLE_SEP_CLASS(klass);
    device_class_set_parent_realize(dc, apple_sep_realize, &sc->parent_realize);
    device_class_set_parent_reset(dc, apple_sep_reset, &sc->parent_reset);
    dc->desc = "Apple SEP";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_sep_info = {
    .name = TYPE_APPLE_SEP,
    .parent = TYPE_APPLE_A7IOP,
    .instance_size = sizeof(AppleSEPState),
    .class_size = sizeof(AppleSEPClass),
    .class_init = apple_sep_class_init,
};

static void apple_sep_register_types(void)
{
    type_register_static(&apple_sep_info);
}

type_init(apple_sep_register_types);
