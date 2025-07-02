
// used spmi-pmu as a template

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "hw/irq.h"
#include "hw/misc/apple-silicon/spmi-baseband.h"
#include "migration/vmstate.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "system/runstate.h"
#include "system/system.h"

#define DEBUG_SPMI_BASEBAND

#ifdef DEBUG_SPMI_BASEBAND
#define DPRINTF(v, ...) fprintf(stderr, v, ##__VA_ARGS__)
#else
#define DPRINTF(v, ...) \
    do {                \
    } while (0)
#endif

#if 0
#define LEG_SCRPAD_OFFSET_SECS_OFFSET (4)
#define LEG_SCRPAD_OFFSET_TICKS_OFFSET (21)
#define RTC_TICK_FREQ (32768)
#define RTC_CONTROL_MONITOR (1 << 0)
#define RTC_CONTROL_ALARM_EN (1 << 6)
#define RTC_EVENT_ALARM (1 << 0)
#endif

#define RREG32(off) ldl_le_p(&s->reg[off])
#define WREG32(off, val) stl_le_p(&s->reg[off], val)
#define WREG32_OR(off, val) WREG32(off, RREG32(off) | val)

#if 0
static unsigned int frq_to_period_ns(unsigned int freq_hz)
{
    return NANOSECONDS_PER_SECOND > freq_hz ? NANOSECONDS_PER_SECOND / freq_hz :
                                              1;
}

static uint64_t tick_to_ns(AppleSPMIBasebandState *p, uint64_t tick)
{
    return (tick >> 15) * NANOSECONDS_PER_SECOND +
           (tick & 0x7FFF) * p->tick_period;
}

static uint64_t rtc_get_tick(AppleSPMIBasebandState *p, uint64_t *out_ns)
{
    uint64_t now = qemu_clock_get_ns(rtc_clock);
    uint64_t offset = p->rtc_offset;
    if (out_ns) {
        *out_ns = now;
    }
    now -= offset;
    return ((now / NANOSECONDS_PER_SECOND) << 15) |
           ((now / p->tick_period) & 0x7FFF);
}

static uint64_t apple_spmi_baseband_get_tick_offset(AppleSPMIBasebandState *s)
{
    uint64_t tick_offset = 0;

    tick_offset =
        ((uint64_t)RREG32(s->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET)
         << 15) +
        (RREG32(s->reg_leg_scrpad + LEG_SCRPAD_OFFSET_TICKS_OFFSET) & 0x7FFF);

    return tick_offset;
}

static void apple_spmi_baseband_set_tick_offset(AppleSPMIBasebandState *s,
                                           uint64_t tick_offset)
{
    WREG32(s->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET,
           tick_offset >> 15);
    s->reg[s->reg_leg_scrpad + LEG_SCRPAD_OFFSET_TICKS_OFFSET + 0] =
        tick_offset & 0xff;
    s->reg[s->reg_leg_scrpad + LEG_SCRPAD_OFFSET_TICKS_OFFSET + 1] =
        (tick_offset >> 8) & 0x7f;
}

static void apple_spmi_baseband_update_irq(AppleSPMIBasebandState *s)
{
    if (RREG32(s->reg_rtc_irq_mask) & RREG32(s->reg_alarm_event)) {
        qemu_irq_raise(s->irq);
    } else {
        qemu_irq_lower(s->irq);
    }
}

static void apple_spmi_baseband_alarm(void *opaque)
{
    AppleSPMIBasebandState *s = APPLE_SPMI_BASEBAND(opaque);
    WREG32_OR(s->reg_alarm_event, RTC_EVENT_ALARM);
    apple_spmi_baseband_update_irq(s);
    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_RTC, NULL);
}

static void apple_spmi_baseband_set_alarm(AppleSPMIBasebandState *s)
{
    uint32_t seconds = RREG32(s->reg_alarm) - (rtc_get_tick(s, NULL) >> 15);
    if (RREG32(s->reg_alarm_ctrl) & RTC_CONTROL_ALARM_EN) {
        if (seconds == 0) {
            timer_del(s->timer);
            apple_spmi_baseband_alarm(s);
        } else {
            int64_t now = qemu_clock_get_ns(rtc_clock);
            timer_mod_ns(s->timer,
                         now + (int64_t)seconds * NANOSECONDS_PER_SECOND);
        }
    } else {
        timer_del(s->timer);
    }
}
#endif

void apple_spmi_baseband_set_irq(AppleSPMIBasebandState *s, int value)
{
    if (value) {
        qemu_irq_raise(s->irq);
    } else {
        qemu_irq_lower(s->irq);
    }
}

static int apple_spmi_baseband_send(SPMISlave *s, uint8_t *data, uint8_t len)
{
    AppleSPMIBasebandState *p = APPLE_SPMI_BASEBAND(s);
    //bool aflg = false;
    uint16_t addr;
    DPRINTF("%s: addr 0x%x len 0x%x\n", __func__, p->addr, len);

    for (addr = p->addr; addr < p->addr + len; addr++) {
        p->reg[addr] = data[addr - p->addr];
#if 0
        if (addr == p->reg_alarm_ctrl) {
            aflg = true;
        }
        if (addr >= p->reg_alarm && addr < p->reg_alarm + 4) {
            aflg = true;
        }
        if ((addr >= p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET &&
             addr < p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET + 4) ||
            (addr >= p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_TICKS_OFFSET &&
             addr < p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_TICKS_OFFSET + 2)) {
            p->tick_offset = apple_spmi_baseband_get_tick_offset(p);
        }
#endif
    }
    p->addr = addr;
#if 0
    if (aflg) {
        apple_spmi_baseband_set_alarm(p);
    }
#endif
    return len;
}

static int apple_spmi_baseband_recv(SPMISlave *s, uint8_t *data, uint8_t len)
{
    AppleSPMIBasebandState *p = APPLE_SPMI_BASEBAND(s);
    uint16_t addr;
    DPRINTF("%s: addr 0x%x len 0x%x\n", __func__, p->addr, len);

    for (addr = p->addr; addr < p->addr + len; addr++) {
#if 0
        if (addr >= p->reg_rtc && addr < p->reg_rtc + 6) {
            uint64_t now = rtc_get_tick(p, NULL);
            p->reg[p->reg_rtc] = (now << 1) & 0xFF;
            p->reg[p->reg_rtc + 1] = (now >> 7) & 0xFF;
            p->reg[p->reg_rtc + 2] = (now >> 15) & 0xFF;
            p->reg[p->reg_rtc + 3] = (now >> 23) & 0xFF;
            p->reg[p->reg_rtc + 4] = (now >> 31) & 0xFF;
            p->reg[p->reg_rtc + 5] = (now >> 39) & 0xFF;
        }
#endif
        data[addr - p->addr] = p->reg[addr];
    }
    p->addr = addr;
    return len;
}

static int apple_spmi_baseband_command(SPMISlave *s, uint8_t opcode, uint16_t addr)
{
    AppleSPMIBasebandState *p = APPLE_SPMI_BASEBAND(s);
    p->addr = addr;
    DPRINTF("%s: opcode 0x%x addr 0x%x\n", __func__, opcode, addr);

    switch (opcode) {
    case SPMI_CMD_EXT_READ:
    case SPMI_CMD_EXT_READL:
    case SPMI_CMD_EXT_WRITE:
    case SPMI_CMD_EXT_WRITEL:
        return 0;
    default:
        return 1;
    }
}

DeviceState *apple_spmi_baseband_create(DTBNode *node)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_SPMI_BASEBAND);
    AppleSPMIBasebandState *p = APPLE_SPMI_BASEBAND(dev);
    DTBProp *prop;

    prop = dtb_find_prop(node, "reg");
    g_assert_nonnull(prop);
    spmi_set_slave_sid(SPMI_SLAVE(dev), *(uint32_t *)prop->data);

#if 0
    prop = dtb_find_prop(node, "info-rtc");
    p->reg_rtc = *(uint32_t *)prop->data;

    prop = dtb_find_prop(node, "info-rtc_alarm_offset");
    p->reg_alarm = *(uint32_t *)prop->data;

    prop = dtb_find_prop(node, "info-rtc_alarm_ctrl");
    p->reg_alarm_ctrl = *(uint32_t *)prop->data;

    prop = dtb_find_prop(node, "info-rtc_alarm_event");
    p->reg_alarm_event = *(uint32_t *)prop->data;

    prop = dtb_find_prop(node, "info-rtc_irq_mask_offset");
    p->reg_rtc_irq_mask = *(uint32_t *)prop->data;

    prop = dtb_find_prop(node, "info-leg_scrpad");
    p->reg_leg_scrpad = *(uint32_t *)prop->data;

    p->tick_period = frq_to_period_ns(RTC_TICK_FREQ);
    p->tick_offset = rtc_get_tick(p, &p->rtc_offset);
    apple_spmi_baseband_set_tick_offset(p, p->tick_offset);

    p->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, apple_spmi_baseband_alarm, p);
    qemu_system_wakeup_enable(QEMU_WAKEUP_REASON_RTC, true);

#endif
#if 1
    qdev_init_gpio_out(dev, &p->irq, 1);
#endif
    return dev;
}

static const VMStateDescription vmstate_apple_spmi_baseband = {
    .name = "apple_spmi_baseband",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
#if 0
            VMSTATE_UINT64(tick_offset, AppleSPMIBasebandState),
            VMSTATE_UINT64(rtc_offset, AppleSPMIBasebandState),
#endif
            VMSTATE_UINT16(addr, AppleSPMIBasebandState),
            VMSTATE_UINT8_ARRAY(reg, AppleSPMIBasebandState, 0xFFFF),
#if 0
            VMSTATE_TIMER_PTR(timer, AppleSPMIBasebandState),
#endif
            VMSTATE_END_OF_LIST(),
        }
};

static void apple_spmi_baseband_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SPMISlaveClass *sc = SPMI_SLAVE_CLASS(klass);

    dc->desc = "Apple SPMI Baseband";
    dc->vmsd = &vmstate_apple_spmi_baseband;

    sc->send = apple_spmi_baseband_send;
    sc->recv = apple_spmi_baseband_recv;
    sc->command = apple_spmi_baseband_command;
}

static const TypeInfo apple_spmi_baseband_type_info = {
    .name = TYPE_APPLE_SPMI_BASEBAND,
    .parent = TYPE_SPMI_SLAVE,
    .instance_size = sizeof(AppleSPMIBasebandState),
    .class_init = apple_spmi_baseband_class_init,
};

static void apple_spmi_baseband_register_types(void)
{
    type_register_static(&apple_spmi_baseband_type_info);
}

type_init(apple_spmi_baseband_register_types)
