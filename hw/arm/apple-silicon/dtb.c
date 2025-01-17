/*
 *
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

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dtb.h"
#include "qemu/bswap.h"
#include "qemu/cutils.h"

static uint64_t align_4_high_num(uint64_t num)
{
    return (num + (4 - 1)) & ~(4 - 1);
}

static void *align_4_high_ptr(void *ptr)
{
    return (void *)align_4_high_num((uint64_t)ptr);
}

static DTBProp *dtb_read_prop(uint8_t **dtb_blob, char *name)
{
    g_assert_nonnull(dtb_blob);
    g_assert_nonnull(*dtb_blob);
    g_assert_nonnull(name);

    DTBProp *prop;

    *dtb_blob = align_4_high_ptr(*dtb_blob);

    prop = g_new0(DTBProp, 1);
    memcpy(name, *dtb_blob, DTB_PROP_NAME_LEN);
    *dtb_blob += DTB_PROP_NAME_LEN;

    prop->length = ldl_le_p(*dtb_blob) & DT_PROP_SIZE_MASK;
    prop->flags =
        (ldl_le_p(*dtb_blob) >> DT_PROP_FLAGS_SHIFT) & DT_PROP_FLAGS_MASK;
    *dtb_blob += sizeof(uint32_t);

    if (prop->length != 0) {
        prop->value = g_malloc0(prop->length);
        g_assert_nonnull(prop->value);
        memcpy(prop->value, *dtb_blob, prop->length);
        *dtb_blob += prop->length;
    }

    return prop;
}

static void dtb_prop_destroy(gpointer data)
{
    DTBProp *prop;

    prop = data;

    g_assert_nonnull(prop);
    g_free(prop->value);
    g_free(prop);
}

static DTBNode *dtb_read_node(uint8_t **dtb_blob)
{
    uint32_t i;
    DTBNode *node;
    DTBNode *child;
    DTBProp *prop;
    char *key;

    g_assert_nonnull(dtb_blob);
    g_assert_nonnull(*dtb_blob);

    *dtb_blob = align_4_high_ptr(*dtb_blob);
    node = g_new0(DTBNode, 1);
    node->prop_count = ldl_le_p(*dtb_blob);
    *dtb_blob += sizeof(uint32_t);
    node->child_node_count = ldl_le_p(*dtb_blob);
    *dtb_blob += sizeof(uint32_t);

    node->props = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                        dtb_prop_destroy);

    for (i = 0; i < node->prop_count; i++) {
        key = g_new0(char, DTB_PROP_NAME_LEN);
        prop = dtb_read_prop(dtb_blob, key);
        g_assert_nonnull(prop);
        g_assert_true(g_hash_table_insert(node->props, key, prop));
    }

    for (i = 0; i < node->child_node_count; i++) {
        child = dtb_read_node(dtb_blob);
        g_assert_nonnull(child);
        node->child_nodes = g_list_append(node->child_nodes, child);
    }

    return node;
}

static void dtb_destroy_node(DTBNode *node)
{
    g_assert_nonnull(node);

    g_hash_table_unref(node->props);

    if (node->child_nodes != NULL) {
        g_list_free_full(node->child_nodes, (GDestroyNotify)dtb_destroy_node);
    }

    g_free(node);
}

DTBNode *dtb_unserialise(uint8_t *dtb_blob)
{
    return dtb_read_node(&dtb_blob);
}

static void dtb_serialise_node(DTBNode *node, uint8_t **buf)
{
    GHashTableIter ht_iter;
    gpointer key, value;
    DTBProp *prop;

    g_assert_nonnull(node);
    g_assert_nonnull(buf);
    g_assert_nonnull(*buf);

    *buf = align_4_high_ptr(*buf);

    memcpy(*buf, &node->prop_count, sizeof(node->prop_count));
    *buf += sizeof(node->prop_count);
    memcpy(*buf, &node->child_node_count, sizeof(node->child_node_count));
    *buf += sizeof(node->child_node_count);

    g_hash_table_iter_init(&ht_iter, node->props);
    while (g_hash_table_iter_next(&ht_iter, &key, &value)) {
        prop = (DTBProp *)value;
        g_assert_nonnull(prop);

        *buf = align_4_high_ptr(*buf);

        memcpy(*buf, key, DTB_PROP_NAME_LEN);
        *buf += DTB_PROP_NAME_LEN;
        stl_le_p(*buf, prop->length);
        *buf += sizeof(uint32_t);

        if (prop->length == 0) {
            g_assert_null(prop->value);
        } else {
            g_assert_nonnull(prop->value);
            memcpy(*buf, prop->value, prop->length);
            *buf += prop->length;
        }
    }

    g_list_foreach(node->child_nodes, (GFunc)dtb_serialise_node, buf);
}

void dtb_remove_node(DTBNode *parent, DTBNode *node)
{
    GList *iter;

    g_assert_nonnull(parent);
    g_assert_nonnull(node);

    for (iter = parent->child_nodes; iter != NULL; iter = iter->next) {
        if (node != iter->data) {
            continue;
        }

        dtb_destroy_node(node);
        parent->child_nodes = g_list_delete_link(parent->child_nodes, iter);

        g_assert_cmpuint(parent->child_node_count, >, 0);
        parent->child_node_count--;
        return;
    }

    g_assert_not_reached();
}

bool dtb_remove_node_named(DTBNode *parent, const char *name)
{
    DTBNode *node;

    g_assert_nonnull(parent);
    g_assert_nonnull(name);

    node = dtb_find_node(parent, name);

    if (node == NULL) {
        return false;
    }

    dtb_remove_node(parent, node);
    return true;
}

bool dtb_remove_prop_named(DTBNode *node, const char *name)
{
    g_assert_nonnull(node);
    g_assert_nonnull(name);

    if (g_hash_table_remove(node->props, name)) {
        g_assert_cmpuint(node->prop_count, >, 0);
        node->prop_count--;
        return true;
    }

    return false;
}

DTBProp *dtb_set_prop(DTBNode *node, const char *name, const uint32_t size,
                      const void *val)
{
    DTBProp *prop;

    g_assert_nonnull(node);
    g_assert_nonnull(name);

    if (val == NULL) {
        g_assert_cmpuint(size, ==, 0);
    } else {
        g_assert_cmpuint(size, !=, 0);
    }

    g_assert_cmpint(strnlen(name, DTB_PROP_NAME_LEN), <, DTB_PROP_NAME_LEN);

    prop = dtb_find_prop(node, name);

    if (prop == NULL) {
        prop = g_new0(DTBProp, 1);
        g_hash_table_insert(node->props, g_strdup(name), prop);
        node->prop_count++;
    } else {
        g_free(prop->value);
        memset(prop, 0, sizeof(DTBProp));
    }

    prop->length = size;

    if (val != NULL) {
        prop->value = g_malloc0(size);
        memcpy(prop->value, val, size);
    }

    return prop;
}

DTBProp *dtb_set_prop_null(DTBNode *node, const char *name)
{
    return dtb_set_prop(node, name, 0, NULL);
}

DTBProp *dtb_set_prop_u32(DTBNode *node, const char *name, const uint32_t val)
{
    return dtb_set_prop(node, name, sizeof(val), &val);
}

DTBProp *dtb_set_prop_u64(DTBNode *node, const char *name, const uint64_t val)
{
    return dtb_set_prop(node, name, sizeof(val), &val);
}

DTBProp *dtb_set_prop_hwaddr(DTBNode *node, const char *name, const hwaddr val)
{
    return dtb_set_prop(node, name, sizeof(val), &val);
}

void dtb_serialise(uint8_t *buf, DTBNode *root)
{
    g_assert_nonnull(buf);
    g_assert_nonnull(root);

    // TODO: handle cases where the buffer is not 4 bytes aligned though this is
    // never expected to happen and the code is simpler this way
    g_assert_true(align_4_high_ptr(buf) == buf);

    dtb_serialise_node(root, &buf);
}

static uint64_t dtb_get_serialised_prop_size(DTBProp *prop)
{
    g_assert_nonnull(prop);

    return align_4_high_num(DTB_PROP_NAME_LEN + sizeof(prop->length) +
                            prop->length);
}

uint64_t dtb_get_serialised_node_size(DTBNode *node)
{
    g_assert_nonnull(node);

    GHashTableIter ht_iter;
    gpointer key, value;
    uint64_t size;
    DTBProp *prop;
    DTBNode *child;
    GList *iter;

    size = sizeof(node->prop_count) + sizeof(node->child_node_count);

    g_hash_table_iter_init(&ht_iter, node->props);
    while (g_hash_table_iter_next(&ht_iter, &key, &value)) {
        prop = (DTBProp *)value;
        g_assert_nonnull(prop);
        size += dtb_get_serialised_prop_size(prop);
    }

    for (iter = node->child_nodes; iter != NULL; iter = iter->next) {
        child = (DTBNode *)iter->data;
        g_assert_nonnull(child);
        size += dtb_get_serialised_node_size(child);
    }

    return size;
}

DTBProp *dtb_find_prop(DTBNode *node, const char *name)
{
    return g_hash_table_lookup(node->props, name);
}

DTBNode *dtb_find_node(DTBNode *node, const char *path)
{
    g_assert_nonnull(node);
    g_assert_nonnull(path);

    GList *iter;
    DTBProp *prop;
    DTBNode *child;
    char *s;
    const char *next;
    bool found;

    s = g_strdup(path);

    while (node != NULL && ((next = qemu_strsep(&s, "/")))) {
        if (strlen(next) == 0) {
            continue;
        }

        found = false;

        for (iter = node->child_nodes; iter; iter = iter->next) {
            child = (DTBNode *)iter->data;

            g_assert_nonnull(child);

            prop = dtb_find_prop(child, "name");

            if (prop == NULL) {
                continue;
            }

            if (strncmp((const char *)prop->value, next, prop->length) == 0) {
                node = child;
                found = true;
            }
        }

        if (!found) {
            g_free(s);
            return NULL;
        }
    }

    g_free(s);
    return node;
}

DTBNode *dtb_get_node(DTBNode *node, const char *path)
{
    g_assert_nonnull(node);
    g_assert_nonnull(path);

    GList *iter = NULL;
    DTBProp *prop = NULL;
    DTBNode *child = NULL;
    char *s;
    const char *name;
    bool found;
    size_t name_len;

    s = g_strdup(path);

    while (node != NULL && ((name = qemu_strsep(&s, "/")))) {
        name_len = strlen(name);
        if (name_len == 0) {
            continue;
        }

        found = false;

        for (iter = node->child_nodes; iter; iter = iter->next) {
            child = (DTBNode *)iter->data;

            g_assert_nonnull(child);

            prop = dtb_find_prop(child, "name");

            if (prop == NULL) {
                continue;
            }

            if (strncmp((const char *)prop->value, name, prop->length) == 0) {
                node = child;
                found = true;
            }
        }

        if (!found) {
            child = g_new0(DTBNode, 1);

            dtb_set_prop(child, "name", name_len + 1, (uint8_t *)name);
            node->child_nodes = g_list_append(node->child_nodes, child);
            node->child_node_count++;
            node = child;
        }
    }

    g_free(s);
    return node;
}
