/*
 * Apple PMU D2255.
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
#include "hw/i2c/apple_i2c.h"
#include "hw/i2c/i2c.h"
#include "hw/misc/pmu_d2255.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/log.h"

#define DIALOG_MASK_REV_CODE (0x200)
#define DIALOG_TRIM_REL_CODE (0x201)
#define DIALOG_PLATFORM_ID (0x202)
#define DIALOG_DEVICE_ID0 (0x203)
#define DIALOG_DEVICE_ID1 (0x204)
#define DIALOG_DEVICE_ID2 (0x205)
#define DIALOG_DEVICE_ID3 (0x206)
#define DIALOG_DEVICE_ID4 (0x207)
#define DIALOG_DEVICE_ID5 (0x208)
#define DIALOG_DEVICE_ID6 (0x209)
#define DIALOG_DEVICE_ID7 (0x20a)

static int pmu_d2255_event(I2CSlave *i2c, enum i2c_event event)
{
    PMUD2255State *s;

    s = PMU_D2255(i2c);

    switch (event) {
    case I2C_START_RECV:
        if (s->op_state != PMU_OP_STATE_NONE) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "PMU D2255: attempted to start transaction while a "
                          "transaction is already ongoing.\n");
            return -1;
        }

        s->op_state = PMU_OP_STATE_RECV;
        info_report("PMU D2255: recv started.");
        return 0;
    case I2C_START_SEND:
        if (s->op_state != PMU_OP_STATE_NONE) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "PMU D2255: attempted to start transaction while a "
                          "transaction is already ongoing.\n");
            return -1;
        }

        s->op_state = PMU_OP_STATE_SEND;
        s->address = 0;
        s->address_state = PMU_ADDR_UPPER;
        info_report("PMU D2255: send started.");
        return 0;
    case I2C_FINISH:
        s->op_state = PMU_OP_STATE_NONE;
        info_report("PMU D2255: transaction end.");
        return 0;
    default:
        return -1;
    }
}

static uint8_t pmu_d2255_rx(I2CSlave *i2c)
{
    PMUD2255State *s;

    s = PMU_D2255(i2c);

    if (s->op_state != PMU_OP_STATE_RECV) {
        qemu_log_mask(
            LOG_GUEST_ERROR,
            "PMU D2255: RX attempted with but transaction is not recv.\n");
        return 0x00;
    }

    if (s->address_state != PMU_ADDR_RECEIVED) {
        qemu_log_mask(LOG_GUEST_ERROR, "PMU D2255: no address was sent.\n");
        return 0x00;
    }

    if (s->address + 1 > sizeof(s->reg)) {
        qemu_log_mask(LOG_GUEST_ERROR, "PMU D2255: 0x%X -> 0x%X is INVALID.\n",
                      s->address, s->reg[s->address]);
        return 0x00;
    }
    info_report("PMU D2255: 0x%X -> 0x%X.", s->address, s->reg[s->address]);

    return s->reg[s->address++];
}

static int pmu_d2255_tx(I2CSlave *i2c, uint8_t data)
{
    PMUD2255State *s;

    s = PMU_D2255(i2c);

    if (s->op_state != PMU_OP_STATE_SEND) {
        qemu_log_mask(
            LOG_GUEST_ERROR,
            "PMU D2255: TX attempted with but transaction is not send.\n");
        return 0x00;
    }

    switch (s->address_state) {
    case PMU_ADDR_UPPER:
        s->address |= data << 8;
        s->address_state = PMU_ADDR_LOWER;
        break;
    case PMU_ADDR_LOWER:
        s->address |= data;
        s->address = le16_to_cpu(s->address);
        s->address_state = PMU_ADDR_RECEIVED;
        info_report("PMU D2255: address set to 0x%X.", s->address);
        break;
    case PMU_ADDR_RECEIVED:
        if (s->op_state == PMU_OP_STATE_RECV) {
            qemu_log_mask(
                LOG_GUEST_ERROR,
                "PMU D2255: send transaction attempted but transaction "
                "is recv.\n");
            return -1;
        }

        if (s->address + 1 > sizeof(s->reg)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "PMU D2255: 0x%X <- 0x%X is INVALID.\n", s->address,
                          data);
            return -1;
        }

        info_report("PMU D2255: 0x%X <- 0x%X.", s->address, data);
        s->reg[s->address++] = data;
        break;
    }
    return 0;
}

static void pmu_d2255_reset(DeviceState *device)
{
    PMUD2255State *s;

    s = PMU_D2255(device);
    s->op_state = PMU_OP_STATE_NONE;
    s->address = 0;
    s->address_state = PMU_ADDR_UPPER;
    memset(s->reg, 0, sizeof(s->reg));
    memset(s->reg + DIALOG_MASK_REV_CODE, 0xFF,
           DIALOG_DEVICE_ID7 - DIALOG_MASK_REV_CODE);
}

static void pmu_d2255_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *c = I2C_SLAVE_CLASS(klass);

    dc->desc = "Apple PMU D2255";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->reset = pmu_d2255_reset;

    c->event = pmu_d2255_event;
    c->recv = pmu_d2255_rx;
    c->send = pmu_d2255_tx;
}

static const TypeInfo pmu_d2255_type_info = {
    .name = TYPE_PMU_D2255,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(PMUD2255State),
    .class_init = pmu_d2255_class_init,
};

static void pmu_d2255_register_types(void)
{
    type_register_static(&pmu_d2255_type_info);
}

type_init(pmu_d2255_register_types);

void pmu_d2255_create(MachineState *machine, uint8_t addr)
{
    AppleI2CState *i2c = APPLE_I2C(
        object_property_get_link(OBJECT(machine), "i2c0", &error_fatal));
    i2c_slave_create_simple(i2c->bus, TYPE_PMU_D2255, addr);
}
