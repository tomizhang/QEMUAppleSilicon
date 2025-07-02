/*
 * Copyright (c) 2019 Jonathan Afek <jonyafek@me.com>
 * Copyright (c) 2024 Visual Ehrmanntraut (VisualEhrmanntraut).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef HW_ARM_APPLE_SILICON_DTB_H
#define HW_ARM_APPLE_SILICON_DTB_H

#include "qemu/osdep.h"
#include "exec/hwaddr.h"

typedef struct {
    uint32_t length;
    bool placeholder;
    uint8_t *data;
} DTBProp;

typedef struct {
    GHashTable *props;
    GList *children;
} DTBNode;

DTBNode *dtb_create_node(DTBNode *parent, const char *name);
DTBNode *dtb_deserialise(uint8_t *dtb_blob);
void dtb_serialise(uint8_t *buf, DTBNode *root);
bool dtb_remove_node_named(DTBNode *parent, const char *name);
void dtb_remove_node(DTBNode *node, DTBNode *child);
bool dtb_remove_prop_named(DTBNode *node, const char *name);
DTBProp *dtb_set_prop(DTBNode *n, const char *name, uint32_t size,
                      const void *val);
DTBProp *dtb_set_prop_null(DTBNode *node, const char *name);
DTBProp *dtb_set_prop_u32(DTBNode *node, const char *name, uint32_t val);
DTBProp *dtb_set_prop_u64(DTBNode *node, const char *name, uint64_t val);
DTBProp *dtb_set_prop_hwaddr(DTBNode *node, const char *name, hwaddr val);
DTBProp *dtb_set_prop_str(DTBNode *node, const char *name, const char *val);
DTBProp *dtb_set_prop_strn(DTBNode *node, const char *name, uint32_t max_len,
                           const char *val);
DTBNode *dtb_get_node(DTBNode *n, const char *path);
uint64_t dtb_get_serialised_node_size(DTBNode *node);
DTBProp *dtb_find_prop(DTBNode *node, const char *name);
void connect_function_prop_out_in(DeviceState *target_device, DeviceState *src_device, DTBProp *function_prop, const char *name);
void connect_function_prop_out_in_gpio(DeviceState *src_device, DTBProp *function_prop, const char *gpio_name);
void connect_function_prop_in_out(DeviceState *target_device, DeviceState *src_device, DTBProp *function_prop, const char *name);
void connect_function_prop_in_out_gpio(DeviceState *src_device, DTBProp *function_prop, const char *gpio_name);

#endif /* HW_ARM_APPLE_SILICON_DTB_H */
