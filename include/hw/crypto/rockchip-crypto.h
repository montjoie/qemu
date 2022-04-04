/*
 * Rockchip rk3288 crypto emulation
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

#ifndef HW_CRYPTO_ROCKCHIP_H
#define HW_CRYPTO_ROCKCHIP_H

#include "qom/object.h"
#include "hw/sysbus.h"

/**
 * Object model
 * @{
 */

#define TYPE_RK_CRYPTO "rockchip-crypto"
OBJECT_DECLARE_SIMPLE_TYPE(RkCryptoState, RK_CRYPTO)

/** @} */

/**
 * Rockchip rk3288 crypto object instance state
 */
struct RkCryptoState {
    /*< private >*/
    SysBusDevice  parent_obj;
    /*< public >*/

    /** Maps I/O registers in physical memory */
    MemoryRegion iomem;

    /** Interrupt output signal to notify CPU */
    qemu_irq     irq;

    /** Memory region where DMA transfers are done */
    MemoryRegion *dma_mr;

    /** Address space used internally for DMA transfers */
    AddressSpace dma_as;

    /** @} */

    /**
     * @name Hardware Registers
     * @{
     */

    uint32_t    intsts;
    uint32_t    intena;
    uint32_t    ctrl;
    uint32_t    conf;
    uint32_t    brdmas;
    uint32_t    btdmas;
    uint32_t    brdmal;
    uint32_t    hrdmas;
    uint32_t    hrdmal;
    uint32_t    aes_ctrl;
    uint32_t    iv[4];
    uint32_t    key[8];
    uint32_t    tdes_ctrl;
    uint32_t    tiv[2];
    uint32_t    tkey[6];
    uint32_t    hash_ctrl;
    uint32_t    hash[8];

    /** @} */

};

#endif /* HW_CRYPTO_ROCKCHIP_RK3288_H */
