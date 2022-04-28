/*
 * Allwinner sun8i-ce cryptographic offloader emulation
 *
 * Copyright (C) 2022 Corentin Labbe <clabbe.montjoie@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_CRYPTO_ALLWINNER_SUN8I_CE_H
#define HW_CRYPTO_ALLWINNER_SUN8I_CE_H

#include "qom/object.h"
#include "hw/sysbus.h"

#define TYPE_AW_SUN8I_CE "allwinner-sun8i-ce"
OBJECT_DECLARE_SIMPLE_TYPE(AwSun8iCEState, AW_SUN8I_CE)

/**
 * Allwinner sun8i-ce crypto object instance state
 */
struct AwSun8iCEState {
    SysBusDevice  parent_obj;
    MemoryRegion iomem;
    qemu_irq     irq;
    MemoryRegion *dma_mr;
    AddressSpace dma_as;

    uint32_t    tdq;
    uint32_t    ctr;
    uint32_t    icr;
    uint32_t    isr;
    uint32_t    tlr;
    uint32_t    tsr;
    uint32_t    esr;

};

#endif /* HW_CRYPTO_ALLWINNER_SUN8I_CE_H */
