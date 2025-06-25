/*
 * Apple CS35L27 Amp.
 *
 * Copyright (c) 2025 Visual Ehrmanntraut.
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
#include "hw/audio/apple-silicon/cs35l27.h"
#include "hw/i2c/i2c.h"
#include "migration/vmstate.h"

// #define DEBUG_CS35L27

#ifdef DEBUG_CS35L27
#define DPRINTF(v, ...) fprintf(stderr, v, ##__VA_ARGS__)
#else
#define DPRINTF(v, ...) \
    do {                \
    } while (0)
#endif

#define CS35L27_REG_SIZE (0x1000000)

struct AppleCS35L27State {
    /*< private >*/
    I2CSlave i2c;

    /*< public >*/
    uint32_t addr;
    uint32_t tx_bytes;
    uint8_t regs[CS35L27_REG_SIZE];
};

#define VPBR_PAC_INT_INT_REGISTER_6 (0x2824)

static uint8_t apple_cs35l27_rx(I2CSlave *i2c)
{
    AppleCS35L27State *s;
    uint8_t ret = 0x00;

    s = APPLE_CS35L27(i2c);

    switch (s->addr) {
    case 0x0:
    case 0x1:
    case 0x2:
    case 0x3:
        ret = (cpu_to_be32(0x0035A270) >> (s->addr * 8)) & 0xFF;
        break;
    case VPBR_PAC_INT_INT_REGISTER_6:
    case VPBR_PAC_INT_INT_REGISTER_6 + 1:
    case VPBR_PAC_INT_INT_REGISTER_6 + 2:
    case VPBR_PAC_INT_INT_REGISTER_6 + 3:
        ret = (cpu_to_be32(0x8000000) >>
               ((s->addr - VPBR_PAC_INT_INT_REGISTER_6) * 8)) &
              0xFF;
        break;
    default:
        if (s->addr < 0x1000000) {
            ret = s->regs[s->addr];
        }
        break;
    }

    DPRINTF("%s: addr=0x%X, ret=0x%X\n", __func__, s->addr, ret);

    s->addr += 1;
    if (s->addr == 4) {
        s->addr = 0;
        s->tx_bytes = 0;
    }

    return ret;
}

static int apple_cs35l27_tx(I2CSlave *i2c, uint8_t data)
{
    AppleCS35L27State *s;

    s = APPLE_CS35L27(i2c);

    DPRINTF("%s: 0x%02X\n", __func__, data);

    if (s->tx_bytes < 4) {
        s->addr |= ((uint32_t)data) << (s->tx_bytes * 8);
        if (s->tx_bytes == 3) {
            s->addr = be32_to_cpu(s->addr);
            DPRINTF("%s: set addr=0x%X\n", __func__, s->addr);
        }
        s->tx_bytes += 1;
    } else if (s->tx_bytes < 0x40) {
        DPRINTF("%s: addr=0x%X,data=0x%02X\n", __func__, s->addr, data);
        if (s->addr < 0x1000000) {
            s->regs[s->addr] = data;
        }
        s->addr += 1;
        s->tx_bytes += 1;
    } else {
        DPRINTF("%s: chunk end\n", __func__);
        s->addr = 0;
        s->tx_bytes = 0;
    }

    return 0;
}

static int apple_cs35l27_event(I2CSlave *i2c, enum i2c_event event)
{
    AppleCS35L27State *s;

    s = APPLE_CS35L27(i2c);

    switch (event) {
    case I2C_START_RECV:
        DPRINTF("%s: I2C_START_RECV\n", __func__);
        break;
    case I2C_START_SEND:
        DPRINTF("%s: I2C_START_SEND\n", __func__);
        break;
    case I2C_START_SEND_ASYNC:
        DPRINTF("%s: I2C_START_SEND_ASYNC\n", __func__);
        break;
    case I2C_FINISH:
        DPRINTF("%s: I2C_FINISH\n", __func__);
        s->addr = 0;
        s->tx_bytes = 0;
        break;
    case I2C_NACK:
        DPRINTF("%s: I2C_NACK\n", __func__);
        break;
    }
    return 0;
}

static const VMStateDescription vmstate_apple_cs35l27 = {
    .name = "AppleCS35L27State",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_I2C_SLAVE(i2c, AppleCS35L27State),
            VMSTATE_UINT32(addr, AppleCS35L27State),
            VMSTATE_UINT32(tx_bytes, AppleCS35L27State),
            VMSTATE_BUFFER(regs, AppleCS35L27State),
            VMSTATE_END_OF_LIST(),
        },
};

static void apple_cs35l27_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *c = I2C_SLAVE_CLASS(klass);

    dc->desc = "Apple CS35L27 Amp";
    dc->user_creatable = false;
    dc->vmsd = &vmstate_apple_cs35l27;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    c->recv = apple_cs35l27_rx;
    c->send = apple_cs35l27_tx;
    c->event = apple_cs35l27_event;
}

static const TypeInfo apple_cs35l27_type_info = {
    .name = TYPE_APPLE_CS35L27,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(AppleCS35L27State),
    .class_init = apple_cs35l27_class_init,
};

static void apple_cs35l27_register_types(void)
{
    type_register_static(&apple_cs35l27_type_info);
}

type_init(apple_cs35l27_register_types);
