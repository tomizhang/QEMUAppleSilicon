/*
 * General Apple XNU memory utilities.
 *
 * Copyright (c) 2023-2024 Visual Ehrmanntraut (VisualEhrmanntraut).
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
#include "exec/hwaddr.h"
#include "exec/memory.h"
#include "hw/arm/apple-silicon/mem.h"
#include "qapi/error.h"

hwaddr g_virt_base, g_phys_base, g_virt_slide, g_phys_slide;

hwaddr vtop_bases(hwaddr va, hwaddr phys_base, hwaddr virt_base)
{
    g_assert(phys_base && virt_base);

    return va - virt_base + phys_base;
}

hwaddr ptov_bases(hwaddr pa, hwaddr phys_base, hwaddr virt_base)
{
    g_assert(phys_base && virt_base);

    return pa - phys_base + virt_base;
}

hwaddr vtop_static(hwaddr va)
{
    return vtop_bases(va, g_phys_base, g_virt_base);
}

hwaddr ptov_static(hwaddr pa)
{
    return ptov_bases(pa, g_phys_base, g_virt_base);
}

uint8_t get_highest_different_bit_index(hwaddr addr1, hwaddr addr2)
{
    g_assert(addr1 && addr2 && addr1 != addr2);

    return 64 - __builtin_clzll(addr1 ^ addr2);
}

hwaddr align_16k_low(hwaddr addr)
{
    return addr & ~0x3fffull;
}

hwaddr align_16k_high(hwaddr addr)
{
    return align_up(addr, 0x4000);
}

hwaddr align_up(hwaddr addr, hwaddr alignment)
{
    return (addr + (alignment - 1)) & ~(alignment - 1);
}

uint8_t get_lowest_non_zero_bit_index(hwaddr addr)
{
    g_assert(addr);

    return __builtin_ctzll(addr);
}

hwaddr get_low_bits_mask_for_bit_index(uint8_t bit_index)
{
    g_assert(bit_index < 64);

    return (1 << bit_index) - 1;
}

void allocate_ram(MemoryRegion *top, const char *name, hwaddr addr, hwaddr size,
                  int priority)
{
    MemoryRegion *sec = g_new(MemoryRegion, 1);
    memory_region_init_ram(sec, NULL, name, size, &error_fatal);
    memory_region_add_subregion_overlap(top, addr, sec, priority);
}
