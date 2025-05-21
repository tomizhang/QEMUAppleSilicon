#ifndef APPLE_GPIO_H
#define APPLE_GPIO_H

#include "hw/arm/apple-silicon/dtb.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_GPIO "apple.gpio"
OBJECT_DECLARE_SIMPLE_TYPE(AppleGPIOState, APPLE_GPIO)

struct AppleGPIOState {
    SysBusDevice parent_obj;
    MemoryRegion *iomem;
    uint32_t pin_count;
    uint32_t irq_group_count;
    qemu_irq *irqs;
    qemu_irq *out;
    uint32_t *gpio_cfg;
    uint32_t int_config_len;
    uint32_t *int_config;
    uint32_t in_len;
    uint32_t *in;
    uint32_t *in_old;
    uint32_t npl;
};

DeviceState *apple_gpio_create(const char *name, uint64_t mmio_size,
                               uint32_t pin_count, uint32_t irq_group_count);
DeviceState *apple_gpio_create_from_node(DTBNode *node);
#endif
