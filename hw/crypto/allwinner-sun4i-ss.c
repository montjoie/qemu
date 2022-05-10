/*
 * Allwinner sun4i-ss cryptographic offloader emulation
 *
 * Copyright (C) 2022 Corentin Labbe <clabbe@baylibre.com>
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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "qemu/log.h"
#include "trace.h"
#include "qemu/module.h"
#include "exec/cpu-common.h"
#include "hw/crypto/allwinner-sun4i-ss.h"

#include "crypto/cipher.h"
#include "crypto/hash.h"

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8
#define DES3_BLOCK_SIZE 8
#define MD5_BLOCK_SIZE 64
#define SHA1_BLOCK_SIZE 64

/* PRNG start bit - bit 15 */
#define SS_PRNG_CONTINUE (1 << 15)

#define SS_IV_ARBITRARY (1 << 14)

/* SS operation mode - bits 12-13 */
#define SS_ECB (0 << 12)
#define SS_CBC (1 << 12)

/* Key size for AES - bits 8-9 */
#define SS_AES_128BITS (0 << 8)
#define SS_AES_192BITS (1 << 8)
#define SS_AES_256BITS (2 << 8)

/* Operation direction - bit 7 */
#define SS_ENCRYPTION  (0 << 7)
#define SS_DECRYPTION  (1 << 7)

/* SS Method - bits 4-6 */
#define SS_OP_AES      (0 << 4)
#define SS_OP_DES      (1 << 4)
#define SS_OP_3DES     (2 << 4)
#define SS_OP_SHA1     (3 << 4)
#define SS_OP_MD5      (4 << 4)
#define SS_OP_PRNG     (5 << 4)

/* Data end bit - bit 2 */
#define SS_DATA_END (1 << 2)

/* PRNG start bit - bit 1 */
#define SS_PRNG_START (1 << 1)

/* SS Enable bit - bit 0 */
#define SS_ENABLED (1 << 0)

enum {
    REG_CTL        = 0x0000,
    REG_KEY_0      = 0x0004,
    REG_KEY_1      = 0x0008,
    REG_KEY_2      = 0x000c,
    REG_KEY_3      = 0x0010,
    REG_KEY_4      = 0x0014,
    REG_KEY_5      = 0x0018,
    REG_KEY_6      = 0x001c,
    REG_KEY_7      = 0x0020,
    REG_IV_0       = 0x0024,
    REG_IV_1       = 0x0028,
    REG_IV_2       = 0x002c,
    REG_IV_3       = 0x0030,
    REG_IV_4       = 0x0034,
    REG_FCSR       = 0x0044,
    REG_ICSR       = 0x0048,
    REG_MD0        = 0x004c,
    REG_MD1        = 0x0050,
    REG_MD2        = 0x0054,
    REG_MD3        = 0x0058,
    REG_MD4        = 0x005c,
    REG_RXFIFO     = 0x0200,
    REG_TXFIFO     = 0x0204,
};

static bool allwinner_sun4i_ss_cipher_suport(QCryptoCipherAlgorithm alg)
{
    if (!qcrypto_cipher_supports(alg, QCRYPTO_CIPHER_MODE_CBC)) {
        return false;
    }
    if (!qcrypto_cipher_supports(alg, QCRYPTO_CIPHER_MODE_ECB)) {
        return false;
    }
    return true;
}

int allwinner_sun4i_can_be_emulated(void)
{
    /* gcrypt fail for AES weak keys which lead to invalid emulation */
#if (defined(CONFIG_GCRYPT))
    printf("GCRYPT not supported\n");
    return false;
#endif
    if (!qcrypto_hash_supports(QCRYPTO_HASH_ALG_MD5)) {
        return false;
    }
    if (!qcrypto_hash_supports(QCRYPTO_HASH_ALG_SHA1)) {
        return false;
    }
    if (!allwinner_sun4i_ss_cipher_suport(QCRYPTO_CIPHER_ALG_AES_128)) {
        return false;
    }
    if (!allwinner_sun4i_ss_cipher_suport(QCRYPTO_CIPHER_ALG_AES_192)) {
        return false;
    }
    if (!allwinner_sun4i_ss_cipher_suport(QCRYPTO_CIPHER_ALG_AES_256)) {
        return false;
    }
    if (!allwinner_sun4i_ss_cipher_suport(QCRYPTO_CIPHER_ALG_DES)) {
        return false;
    }
    if (!allwinner_sun4i_ss_cipher_suport(QCRYPTO_CIPHER_ALG_3DES)) {
        return false;
    }

    return true;
}

static void allwinner_sun4i_ss_try_work(AwSun4iSSState *s);

/* return number of possible operation wih block size=bs */
static unsigned int can_work(AwSun4iSSState *s, unsigned int bs)
{
    unsigned int free_space_rx = s->rxc / (bs / 4);
    unsigned int free_space_tx = (SS_TX_MAX - s->txc) / (bs / 4);

    if (free_space_rx > free_space_tx) {
        return free_space_tx;
    }
    return free_space_rx;
}

/*
 * Without any knowledge on the PRNG, the only solution is
 * to emulate it via g_random_int()
 */
static void do_prng(AwSun4iSSState *s)
{
    unsigned int size = 20;
    int i;

    for (i = 0; i < size / 4; i++) {
        s->tx[i] = g_random_int();
    }
    s->txc += size / 4;

    s->ctl &= ~SS_PRNG_START;
}

/* continue mode fill whole TX with random data */
static void do_prng_continue(AwSun4iSSState *s)
{
    unsigned int size = SS_TX_MAX;
    int i;

    for (i = 0; i < size; i++) {
        s->tx[i] = g_random_int();
    }
    s->txc = size;
}

/* remove pop u32 words from RX */
static void rx_pop(AwSun4iSSState *s, unsigned int pop)
{
    uint32_t *rx = (uint32_t *)s->rx;
    int i;

    for (i = 0; i < s->rxc; i++) {
        rx[i] = rx[i + pop];
    }
}

static void do_md5(AwSun4iSSState *s)
{
    size_t size = MD5_BLOCK_SIZE;
    const char *src = (const char *)s->rx;
    Error *errp = NULL;
    int err;

    err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_MD5, src, size,
                                 (uint64_t *)s->md, &errp);
    /* sun4i-ss has no error reporting */
    assert(err == 0);

    s->rxc -= size / 4;
    if (s->rxc > 0) {
        rx_pop(s, size / 4);
        allwinner_sun4i_ss_try_work(s);
    }
}

static void do_sha1(AwSun4iSSState *s)
{
    size_t size = SHA1_BLOCK_SIZE;
    const char *src = (const char *)s->rx;
    Error *errp = NULL;
    int err;

    err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_SHA1, src, size,
                                 (uint64_t *)s->md, &errp);
    assert(err == 0);

    s->rxc -= size / 4;
    if (s->rxc > 0) {
        rx_pop(s, size / 4);
        allwinner_sun4i_ss_try_work(s);
    }
}

static void do_cipher(AwSun4iSSState *s)
{
    unsigned char *src = s->rx;
    unsigned char *dst = s->tx + s->txc * 4;
    unsigned char *key = (unsigned char *)s->key;
    unsigned int size = AES_BLOCK_SIZE;
    unsigned char biv[AES_BLOCK_SIZE];
    const unsigned char *iv = (const unsigned char *)s->iv;
    QCryptoCipher *cipher = NULL;
    QCryptoCipherAlgorithm alg;
    QCryptoCipherMode mode;
    size_t nkey;
    Error *errp = NULL;
    int err;
    size_t niv = AES_BLOCK_SIZE;

    if ((s->ctl & 0x70) == SS_OP_DES) {
        niv = DES_BLOCK_SIZE;
        alg = QCRYPTO_CIPHER_ALG_DES;
        nkey = 8;
        size = DES_BLOCK_SIZE;
    }
    if ((s->ctl & 0x70) == SS_OP_3DES) {
        niv = DES3_BLOCK_SIZE;
        alg = QCRYPTO_CIPHER_ALG_3DES;
        nkey = 24;
        size = DES3_BLOCK_SIZE;
    }
    if ((s->ctl & 0x70) == SS_OP_AES) {
        switch (s->ctl & 0x300) {
        case SS_AES_128BITS:
            alg = QCRYPTO_CIPHER_ALG_AES_128;
            nkey = 16;
            break;
        case SS_AES_192BITS:
            alg = QCRYPTO_CIPHER_ALG_AES_192;
            nkey = 24;
            break;
        case SS_AES_256BITS:
            alg = QCRYPTO_CIPHER_ALG_AES_256;
            nkey = 32;
            break;
        default:
            goto error;
        }
    }
    if (s->ctl & SS_CBC) {
        mode = QCRYPTO_CIPHER_MODE_CBC;
    } else {
        mode = QCRYPTO_CIPHER_MODE_ECB;
    }

    cipher = qcrypto_cipher_new(alg, mode, key, nkey, &errp);
    if (!cipher) {
        goto error;
    }

    if (mode == QCRYPTO_CIPHER_MODE_CBC) {
        err = qcrypto_cipher_setiv(cipher, iv, niv, &errp);
        if (err) {
            goto error;
        }
    }

    if (s->ctl & SS_DECRYPTION) {
        if (mode == QCRYPTO_CIPHER_MODE_CBC) {
            memcpy(biv, src, niv);
        }
        err = qcrypto_cipher_decrypt(cipher, src, dst, size, &errp);
        if (err) {
            goto error;
        }
        if (mode == QCRYPTO_CIPHER_MODE_CBC) {
            memcpy(s->iv, biv, niv);
        }
    } else {
        err = qcrypto_cipher_encrypt(cipher, src, dst, size, &errp);
        if (err) {
            goto error;
        }
        if (mode == QCRYPTO_CIPHER_MODE_CBC) {
            /* Copy next IV in registers */
            memcpy(s->iv, dst, niv);
        }
    }

error:
    qcrypto_cipher_free(cipher);
    s->txc += size / 4;
    s->rxc -= size / 4;

    if (s->rxc > 0) {
        rx_pop(s, size / 4);
        allwinner_sun4i_ss_try_work(s);
    }
}

static void allwinner_sun4i_ss_update_fcsr(AwSun4iSSState *s)
{
    assert(s->txc <= SS_TX_MAX);
    assert(s->rxc <= SS_RX_MAX);
    s->fcsr = (s->txc << 16) | ((32 - s->rxc) << 24);
}

static void allwinner_sun4i_ss_try_work(AwSun4iSSState *s)
{
    if (!(s->ctl & SS_ENABLED)) {
        return;
    }
    if ((s->ctl & 0x70) == SS_OP_AES && can_work(s, AES_BLOCK_SIZE)) {
        do_cipher(s);
        allwinner_sun4i_ss_update_fcsr(s);
        return;
    }
    if ((s->ctl & 0x70) == SS_OP_DES && can_work(s, DES_BLOCK_SIZE)) {
        do_cipher(s);
        allwinner_sun4i_ss_update_fcsr(s);
        return;
    }
    if ((s->ctl & 0x70) == SS_OP_3DES && can_work(s, DES3_BLOCK_SIZE)) {
        do_cipher(s);
        allwinner_sun4i_ss_update_fcsr(s);
        return;
    }
    if ((s->ctl & 0x70) == SS_OP_MD5 && s->rxc >= MD5_BLOCK_SIZE / 4) {
        do_md5(s);
        allwinner_sun4i_ss_update_fcsr(s);
        return;
    }
    if ((s->ctl & 0x70) == SS_OP_SHA1 && s->rxc >= SHA1_BLOCK_SIZE / 4) {
        do_sha1(s);
        allwinner_sun4i_ss_update_fcsr(s);
        return;
    }
    if ((s->ctl & 0x70) == SS_OP_PRNG && s->ctl & SS_PRNG_CONTINUE) {
        do_prng_continue(s);
        allwinner_sun4i_ss_update_fcsr(s);
        return;
    }
}

static uint32_t tx_pop(AwSun4iSSState *s)
{
    uint32_t *tx = (uint32_t *)s->tx;
    uint32_t v = 0;
    int i;

    if (s->txc > 0) {
        v = tx[0];
        s->txc--;
        for (i = 0; i < s->txc; i++) {
            tx[i] = tx[i + 1];
        }
        allwinner_sun4i_ss_update_fcsr(s);
        allwinner_sun4i_ss_try_work(s);
    }
    return v;
}

static void allwinner_sun4i_ss_reset_common(AwSun4iSSState *s)
{
    s->ctl = 0;
    s->txc = 0;
    s->rxc = 0;
    allwinner_sun4i_ss_update_fcsr(s);
}

static void allwinner_sun4i_ss_reset(DeviceState *dev)
{
    AwSun4iSSState *s = AW_SUN4I_SS(dev);

    trace_allwinner_sun4i_ss_reset();

    allwinner_sun4i_ss_reset_common(s);
}

static uint64_t allwinner_sun4i_ss_read(void *opaque, hwaddr offset,
                                          unsigned size)
{
    AwSun4iSSState *s = AW_SUN4I_SS(opaque);
    uint64_t value = 0;

    switch (offset) {
    case REG_CTL:
        value = s->ctl;
        break;
    case REG_IV_0:
        value = s->iv[0];
        break;
    case REG_IV_1:
        value = s->iv[1];
        break;
    case REG_IV_2:
        value = s->iv[2];
        break;
    case REG_IV_3:
        value = s->iv[3];
        break;
    case REG_IV_4:
        value = s->iv[4];
        break;
    case REG_FCSR:
        value = s->fcsr;
        break;
    case REG_KEY_0:
        value = s->key[0];
        break;
    case REG_KEY_1:
        value = s->key[1];
        break;
    case REG_KEY_2:
        value = s->key[2];
        break;
    case REG_KEY_3:
        value = s->key[3];
        break;
    case REG_KEY_4:
        value = s->key[4];
        break;
    case REG_KEY_5:
        value = s->key[5];
        break;
    case REG_KEY_6:
        value = s->key[6];
        break;
    case REG_KEY_7:
        value = s->key[7];
        break;
    case REG_MD0:
        value = s->md[0];
        break;
    case REG_MD1:
        value = s->md[1];
        break;
    case REG_MD2:
        value = s->md[2];
        break;
    case REG_MD3:
        value = s->md[3];
        break;
    case REG_MD4:
        value = s->md[4];
        break;
    case REG_TXFIFO:
        value = tx_pop(s);
        break;
    case REG_RXFIFO:
        value = s->rx[0];
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "allwinner_sun4i_ss: read access to unknown "
                                 "CRYPTO register 0x" TARGET_FMT_plx "\n",
                                  offset);
    }

    trace_allwinner_sun4i_ss_read(offset, value);
    return value;
}

static void rx_push(AwSun4iSSState *s, uint32_t value)
{
    uint32_t *rx = (uint32_t *)s->rx;

    if (!(s->ctl & SS_ENABLED)) {
        return;
    }
    if (s->rxc > SS_RX_MAX) {
        return;
    }
    rx[s->rxc] = value;
    s->rxc++;
    allwinner_sun4i_ss_update_fcsr(s);
    allwinner_sun4i_ss_try_work(s);

    return;
}

static void allwinner_sun4i_ss_write(void *opaque, hwaddr offset,
                                       uint64_t value, unsigned size)
{
    AwSun4iSSState *s = AW_SUN4I_SS(opaque);
    bool was_disabled = !(s->ctl & SS_ENABLED);

    trace_allwinner_sun4i_ss_write(offset, value);

    switch (offset) {
    case REG_CTL:
        s->ctl = value;
        if (!(s->ctl & SS_ENABLED)) {
            allwinner_sun4i_ss_reset_common(s);
            return;
        }
        if (was_disabled) {
            if (s->ctl & SS_IV_ARBITRARY) {
                s->md[0] = s->iv[0];
                s->md[1] = s->iv[1];
                s->md[2] = s->iv[2];
                s->md[3] = s->iv[3];
                s->md[4] = s->iv[4];
            } else {
                if ((s->ctl & 0x70) == SS_OP_MD5) {
                    s->md[0] = 0x67452301;
                    s->md[1] = 0xefcdab89;
                    s->md[2] = 0x98badcfe;
                    s->md[3] = 0x10325476;
                } else {
                    s->md[0] = 0x67452301;
                    s->md[1] = 0xefcdab89;
                    s->md[2] = 0x98badcfe;
                    s->md[3] = 0x10325476;
                    s->md[4] = 0xC3D2E1F0;
                }
            }
        }
        if ((s->ctl & 0x70) == SS_OP_PRNG && s->ctl & SS_PRNG_START) {
            do_prng(s);
            allwinner_sun4i_ss_update_fcsr(s);
            return;
        }
        if ((s->ctl & 0x70) == SS_OP_PRNG && s->ctl & SS_PRNG_CONTINUE) {
            do_prng_continue(s);
            allwinner_sun4i_ss_update_fcsr(s);
            return;
        }
        if ((s->ctl & 0x70) == SS_OP_MD5 && s->ctl & SS_DATA_END) {
            s->ctl &= ~SS_DATA_END;
            return;
        }
        if ((s->ctl & 0x70) == SS_OP_SHA1 && s->ctl & SS_DATA_END) {
            s->ctl &= ~SS_DATA_END;
            return;
        }
        break;
    case REG_IV_0:
        s->iv[0] = value;
        break;
    case REG_IV_1:
        s->iv[1] = value;
        break;
    case REG_IV_2:
        s->iv[2] = value;
        break;
    case REG_IV_3:
        s->iv[3] = value;
        break;
    case REG_IV_4:
        s->iv[4] = value;
        break;
    case REG_KEY_0:
        s->key[0] = value;
        break;
    case REG_KEY_1:
        s->key[1] = value;
        break;
    case REG_KEY_2:
        s->key[2] = value;
        break;
    case REG_KEY_3:
        s->key[3] = value;
        break;
    case REG_KEY_4:
        s->key[4] = value;
        break;
    case REG_KEY_5:
        s->key[5] = value;
        break;
    case REG_KEY_6:
        s->key[6] = value;
        break;
    case REG_KEY_7:
        s->key[7] = value;
        break;
    case REG_RXFIFO:
        rx_push(s, value);
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "allwinner_sun4i_ss: write access to unknown "
                                 "CRYPTO register 0x" TARGET_FMT_plx "\n",
                                  offset);
    }
}

static const MemoryRegionOps allwinner_sun4i_ss_mem_ops = {
    .read = allwinner_sun4i_ss_read,
    .write = allwinner_sun4i_ss_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl.min_access_size = 4,
};

static void allwinner_sun4i_ss_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    AwSun4iSSState *s = AW_SUN4I_SS(obj);

    memory_region_init_io(&s->iomem, OBJECT(s), &allwinner_sun4i_ss_mem_ops,
                           s, TYPE_AW_SUN4I_SS, 4 * KiB);
    sysbus_init_mmio(sbd, &s->iomem);
}

static const VMStateDescription vmstate_allwinner_sun4i_ss = {
    .name = "allwinner-sun4i-ss",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(ctl, AwSun4iSSState),
        VMSTATE_UINT32(fcsr, AwSun4iSSState),
        VMSTATE_UINT32(rxc, AwSun4iSSState),
        VMSTATE_UINT8_ARRAY(rx, AwSun4iSSState, SS_RX_MAX * 4),
        VMSTATE_UINT32(txc, AwSun4iSSState),
        VMSTATE_UINT8_ARRAY(tx, AwSun4iSSState, SS_TX_MAX * 4),
        VMSTATE_UINT32_ARRAY(iv, AwSun4iSSState, 5),
        VMSTATE_UINT32_ARRAY(key, AwSun4iSSState, 8),
        VMSTATE_UINT32_ARRAY(md, AwSun4iSSState, 5),
        VMSTATE_END_OF_LIST()
    }
};

static void allwinner_sun4i_ss_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = allwinner_sun4i_ss_reset;
    dc->vmsd = &vmstate_allwinner_sun4i_ss;
}

static const TypeInfo allwinner_sun4i_ss_info = {
    .name           = TYPE_AW_SUN4I_SS,
    .parent         = TYPE_SYS_BUS_DEVICE,
    .instance_size  = sizeof(AwSun4iSSState),
    .instance_init  = allwinner_sun4i_ss_init,
    .class_init     = allwinner_sun4i_ss_class_init,
};

static void allwinner_sun4i_ss_register_types(void)
{
    type_register_static(&allwinner_sun4i_ss_info);
}

type_init(allwinner_sun4i_ss_register_types)
