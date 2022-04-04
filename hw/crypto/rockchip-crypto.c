/*
 * Rockchip 3288 crypto emulation
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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "qemu/log.h"
#include "trace.h"
#include "qemu/module.h"
#include "exec/cpu-common.h"
#include "sysemu/dma.h"
#include "hw/crypto/rockchip-crypto.h"

#include <nettle/aes.h>
#include <nettle/cbc.h>
#include <nettle/des.h>
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>

#define _SBF(v, f)                      ((v) << (f))

/* RK_CRYPTO_INTSTS */
#define RK_CRYPTO_HASH_DONE_INT     BIT(4)
#define RK_CRYPTO_HRDMA_ERR_INT     BIT(3)
#define RK_CRYPTO_HRDMA_DONE_INT    BIT(2)
#define RK_CRYPTO_BCDMA_ERR_INT     BIT(1)
#define RK_CRYPTO_BCDMA_DONE_INT    BIT(0)

/* RK_CRYPTO_INTENA */
#define RK_CRYPTO_PKA_DONE_ENA      BIT(5)
#define RK_CRYPTO_HASH_DONE_ENA     BIT(4)
#define RK_CRYPTO_HRDMA_ERR_ENA     BIT(3)
#define RK_CRYPTO_HRDMA_DONE_ENA    BIT(2)
#define RK_CRYPTO_BCDMA_ERR_ENA     BIT(1)
#define RK_CRYPTO_BCDMA_DONE_ENA    BIT(0)

/* RK_CRYPTO_CTRL */
#define RK_CRYPTO_HASH_START        BIT(3)
#define RK_CRYPTO_BLOCK_START       BIT(2)

/* RK_CRYPTO_CONF */
/* AES = 0 OR DES = 1 */
#define RK_CRYPTO_DESSEL                BIT(2)

/* RK_CRYPTO_AES_CTRL */
#define RK_CRYPTO_AES_ECB_MODE        _SBF(0x00, 4)
#define RK_CRYPTO_AES_CBC_MODE        _SBF(0x01, 4)
#define RK_CRYPTO_AES_CTR_MODE        _SBF(0x02, 4)
#define RK_CRYPTO_AES_128BIT_key    _SBF(0x00, 2)
#define RK_CRYPTO_AES_192BIT_key    _SBF(0x01, 2)
#define RK_CRYPTO_AES_256BIT_key    _SBF(0x02, 2)
/* Slave = 0 / fifo = 1 */
#define RK_CRYPTO_AES_FIFO_MODE        BIT(1)
/* Encryption = 0 , Decryption = 1 */
#define RK_CRYPTO_AES_DEC        BIT(0)

/* RK_CRYPTO_TDES_CTRL */
/* 0: ECB, 1: CBC */
#define RK_CRYPTO_TDES_CHAINMODE_CBC    BIT(4)
/* 0: DES, 1:TDES */
#define RK_CRYPTO_TDES_SELECT        BIT(2)
/* 0: Slave, 1:Fifo */
#define RK_CRYPTO_TDES_FIFO_MODE    BIT(1)
/* Encryption = 0 , Decryption = 1 */
#define RK_CRYPTO_TDES_DEC        BIT(0)

/* RK_CRYPTO_HASH_CTRL */
#define RK_CRYPTO_HASH_SHA1        _SBF(0x00, 0)
#define RK_CRYPTO_HASH_MD5        _SBF(0x01, 0)
#define RK_CRYPTO_HASH_SHA256        _SBF(0x02, 0)

#define RK_CRYPTO_HASH_DONE        BIT(0)

enum {
    REG_INT_STS        = 0x0000,
    REG_INT_ENA        = 0x0004,
    REG_CTRL           = 0x0008,
    REG_CONF           = 0x000c,
    REG_BRDMAS         = 0x0010,
    REG_BTDMAS         = 0x0014,
    REG_BRDMAL         = 0x0018,
    REG_HRDMAS         = 0x001c,
    REG_HRDMAL         = 0x0020,
    REG_AES_CTRL       = 0x0080,
    REG_AES_STS        = 0x0084,
    REG_AES_IV_0       = 0x00a8,
    REG_AES_IV_1       = 0x00ac,
    REG_AES_IV_2       = 0x00b0,
    REG_AES_IV_3       = 0x00b4,
    REG_AES_KEY_0      = 0x00b8,
    REG_AES_KEY_1      = 0x00bc,
    REG_AES_KEY_2      = 0x00c0,
    REG_AES_KEY_3      = 0x00c4,
    REG_AES_KEY_4      = 0x00c8,
    REG_AES_KEY_5      = 0x00cc,
    REG_AES_KEY_6      = 0x00d0,
    REG_AES_KEY_7      = 0x00d4,
    REG_TDES_CTRL      = 0x0100,
    REG_TDES_STS       = 0x0104,
    REG_TDES_IV_0      = 0x0118,
    REG_TDES_IV_1      = 0x011c,
    REG_TDES_KEY1_0    = 0x0120,
    REG_TDES_KEY1_1    = 0x0124,
    REG_TDES_KEY2_0    = 0x0128,
    REG_TDES_KEY2_1    = 0x012c,
    REG_TDES_KEY3_0    = 0x0130,
    REG_TDES_KEY3_1    = 0x0134,
    REG_HASH_CTRL      = 0x0180,
    REG_HASH_STS       = 0x0184,
    REG_HASH_MSG_LEN   = 0x0188,
    REG_HASH_DOUT_0    = 0x018c,
    REG_HASH_DOUT_1    = 0x0190,
    REG_HASH_DOUT_2    = 0x0194,
    REG_HASH_DOUT_3    = 0x0198,
    REG_HASH_DOUT_4    = 0x019c,
    REG_HASH_DOUT_5    = 0x01a0,
    REG_HASH_DOUT_6    = 0x01a4,
    REG_HASH_DOUT_7    = 0x01a8,
};

static int do_md5(RkCryptoState *s)
{
    struct md5_ctx ctx;
    unsigned int size = s->hrdmal * 4;
    unsigned char *src;
    unsigned char digest[MD5_DIGEST_SIZE];

    if (!size) {
        return 1;
    }

    src = g_malloc(size);
    dma_memory_read(&s->dma_as, s->hrdmas, src, size);
    md5_init(&ctx);
    md5_update(&ctx, size, src);
    md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

    memcpy(s->hash, digest, MD5_DIGEST_SIZE);
    g_free(src);
    return 0;
}

static int do_sha1(RkCryptoState *s)
{
    struct sha1_ctx ctx;
    unsigned int size = s->hrdmal * 4;
    unsigned char *src;
    unsigned char digest[SHA1_DIGEST_SIZE];

    if (!size) {
        return 1;
    }

    src = g_malloc(size);

    dma_memory_read(&s->dma_as, s->hrdmas, src, size);
    sha1_init(&ctx);
    sha1_update(&ctx, size, src);
    sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

    memcpy(s->hash, digest, SHA1_DIGEST_SIZE);
    g_free(src);
    return 0;
}

static int do_sha256(RkCryptoState *s)
{
    struct sha256_ctx ctx;
    unsigned int size = s->hrdmal * 4;
    unsigned char *src;
    unsigned char digest[SHA256_DIGEST_SIZE];

    if (!size) {
        return 1;
    }

    src = g_malloc(size);

    dma_memory_read(&s->dma_as, s->hrdmas, src, size);
    sha256_init(&ctx);
    sha256_update(&ctx, size, src);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

    memcpy(s->hash, digest, SHA256_DIGEST_SIZE);
    g_free(src);
    return 0;
}

static void start_hash(RkCryptoState *s)
{
    int err;

    if ((s->hash_ctrl & 0x3) == RK_CRYPTO_HASH_SHA1) {
        err = do_sha1(s);
        s->intsts = RK_CRYPTO_HASH_DONE_INT;
        if (err && s->intena & RK_CRYPTO_HRDMA_ERR_ENA) {
            s->intsts |= RK_CRYPTO_HRDMA_ERR_INT;
        }
        qemu_set_irq(s->irq, 1);
    }
    if ((s->hash_ctrl & 0x3) == RK_CRYPTO_HASH_SHA256) {
        err = do_sha256(s);
        s->intsts = RK_CRYPTO_HASH_DONE_INT;
        if (err && s->intena & RK_CRYPTO_HRDMA_ERR_ENA) {
            s->intsts |= RK_CRYPTO_HRDMA_ERR_INT;
        }
        qemu_set_irq(s->irq, 1);
    }
    if ((s->hash_ctrl & 0x3) == RK_CRYPTO_HASH_MD5) {
        err = do_md5(s);
        s->intsts = RK_CRYPTO_HASH_DONE_INT;
        if (err && s->intena & RK_CRYPTO_HRDMA_ERR_ENA) {
            s->intsts |= RK_CRYPTO_HRDMA_ERR_INT;
        }
        qemu_set_irq(s->irq, 1);
    }
}

static int do_des(RkCryptoState *s)
{
    unsigned char *src = NULL;
    unsigned char *dst = NULL;
    int err = 0;
    struct CBC_CTX(struct des_ctx, DES_BLOCK_SIZE) cdes;
    struct CBC_CTX(struct des3_ctx, DES3_BLOCK_SIZE) cdes3;
    unsigned char *key = (unsigned char *)s->tkey;
    struct des_ctx des;
    struct des3_ctx des3;
    unsigned int size = s->brdmal * 4;

    src = g_malloc(size);
    dst = g_malloc(size);

    dma_memory_read(&s->dma_as, s->brdmas, src, size);

    if (s->tdes_ctrl & RK_CRYPTO_TDES_CHAINMODE_CBC) {
        if (s->tdes_ctrl & RK_CRYPTO_TDES_SELECT) {
            CBC_SET_IV(&cdes3, s->tiv);
            if (s->tdes_ctrl & RK_CRYPTO_TDES_DEC) {
                des3_set_key(&cdes3.ctx, key);
                CBC_DECRYPT(&cdes3, des3_decrypt, size, dst, src);
            } else {
                des3_set_key(&cdes3.ctx, key);
                CBC_ENCRYPT(&cdes3, des3_encrypt, size, dst, src);
            }
        } else {
            CBC_SET_IV(&cdes, s->tiv);
            if (s->tdes_ctrl & RK_CRYPTO_TDES_DEC) {
                des_set_key(&cdes.ctx, key);
                CBC_DECRYPT(&cdes, des_decrypt, size, dst, src);
            } else {
                des_set_key(&cdes.ctx, key);
                CBC_ENCRYPT(&cdes, des_encrypt, size, dst, src);
            }
        }
    } else {
        if (s->tdes_ctrl & RK_CRYPTO_TDES_SELECT) {
            if (s->tdes_ctrl & RK_CRYPTO_TDES_DEC) {
                des3_set_key(&des3, key);
                des3_decrypt(&des3, size, dst, src);
            } else {
                des3_set_key(&des3, key);
                des3_encrypt(&des3, size, dst, src);
            }
        } else {
            if (s->tdes_ctrl & RK_CRYPTO_TDES_DEC) {
                des_set_key(&des, key);
                des_decrypt(&des, size, dst, src);
            } else {
                des_set_key(&des, key);
                des_encrypt(&des, size, dst, src);
            }
        }
    }

    dma_memory_write(&s->dma_as, s->btdmas, dst, size);

    g_free(src);
    g_free(dst);
    return err;
}

static int do_aes(RkCryptoState *s)
{
    unsigned char *src;
    unsigned char *dst;
    int err = 0;
    struct CBC_CTX(struct aes128_ctx, AES_BLOCK_SIZE) aes128;
    struct CBC_CTX(struct aes192_ctx, AES_BLOCK_SIZE) aes192;
    struct CBC_CTX(struct aes256_ctx, AES_BLOCK_SIZE) aes256;
    unsigned char *key = (unsigned char *)s->key;
    struct aes128_ctx ecb128;
    struct aes192_ctx ecb192;
    struct aes256_ctx ecb256;
    unsigned int size = s->brdmal * 4;

    src = g_malloc(size);
    dst = g_malloc(size);

    dma_memory_read(&s->dma_as, s->brdmas, src, size);

    if (s->aes_ctrl & RK_CRYPTO_AES_CBC_MODE) {
        switch (s->aes_ctrl & 0xC) {
        case RK_CRYPTO_AES_128BIT_key:
            CBC_SET_IV(&aes128, s->iv);

            if (s->aes_ctrl & RK_CRYPTO_AES_DEC) {
                aes128_set_decrypt_key(&aes128.ctx, key);
                CBC_DECRYPT(&aes128, aes128_decrypt, size, dst, src);
            } else {
                aes128_set_encrypt_key(&aes128.ctx, key);
                CBC_ENCRYPT(&aes128, aes128_encrypt, size, dst, src);
            }
            break;
        case RK_CRYPTO_AES_192BIT_key:
            CBC_SET_IV(&aes192, s->iv);

            if (s->aes_ctrl & RK_CRYPTO_AES_DEC) {
                aes192_set_decrypt_key(&aes192.ctx, key);
                CBC_DECRYPT(&aes192, aes192_decrypt, size, dst, src);
            } else {
                aes192_set_encrypt_key(&aes192.ctx, key);
                CBC_ENCRYPT(&aes192, aes192_encrypt, size, dst, src);
            }
            break;
        case RK_CRYPTO_AES_256BIT_key:
            CBC_SET_IV(&aes256, s->iv);

            if (s->aes_ctrl & RK_CRYPTO_AES_DEC) {
                aes256_set_decrypt_key(&aes256.ctx, key);
                CBC_DECRYPT(&aes256, aes256_decrypt, size, dst, src);
            } else {
                aes256_set_encrypt_key(&aes256.ctx, key);
                CBC_ENCRYPT(&aes256, aes256_encrypt, size, dst, src);
            }
            break;
        default:
            printf("ERROR: bad key size\n");
            err = 1;
            goto error;
        }
    } else {
        switch (s->aes_ctrl & 0xC) {
        case RK_CRYPTO_AES_128BIT_key:
            if (s->aes_ctrl & RK_CRYPTO_AES_DEC) {
                aes128_set_decrypt_key(&ecb128, key);
                aes128_decrypt(&ecb128, size, dst, src);
            } else {
                aes128_set_encrypt_key(&ecb128, key);
                aes128_encrypt(&ecb128, size, dst, src);
            }
            break;
        case RK_CRYPTO_AES_192BIT_key:
            if (s->aes_ctrl & RK_CRYPTO_AES_DEC) {
                aes192_set_decrypt_key(&ecb192, key);
                aes192_decrypt(&ecb192, size, dst, src);
            } else {
                aes192_set_encrypt_key(&ecb192, key);
                aes192_encrypt(&ecb192, size, dst, src);
            }
            break;
        case RK_CRYPTO_AES_256BIT_key:
            if (s->aes_ctrl & RK_CRYPTO_AES_DEC) {
                aes256_set_decrypt_key(&ecb256, key);
                aes256_decrypt(&ecb256, size, dst, src);
            } else {
                aes256_set_encrypt_key(&ecb256, key);
                aes256_encrypt(&ecb256, size, dst, src);
            }
            break;
        default:
            printf("ERROR: bad key size\n");
            err = 1;
            goto error;
        }
    }

    dma_memory_write(&s->dma_as, s->btdmas, dst, size);

error:
    g_free(src);
    g_free(dst);
    return err;
}

static void rk_crypto_reset(DeviceState *dev)
{
    RkCryptoState *s = RK_CRYPTO(dev);

    trace_rk_crypto_reset();

    s->intsts = 0;
    s->intena = 0;
}

static uint64_t rk_crypto_read(void *opaque, hwaddr offset,
                                          unsigned size)
{
    RkCryptoState *s = RK_CRYPTO(opaque);
    uint64_t value = 0;

    switch (offset) {
    case REG_INT_STS:
        value = s->intsts;
        break;
    case REG_INT_ENA:
        value = s->intena;
        break;
    case REG_CTRL:
    value = s->ctrl;
        break;
    case REG_CONF:
    value = s->conf;
        break;
    case REG_BRDMAS:
    case REG_BTDMAS:
    case REG_BRDMAL:
    case REG_HRDMAS:
    case REG_HRDMAL:
    case REG_AES_CTRL:
        value = s->aes_ctrl;
    break;
    case REG_AES_STS:
    break;
    case REG_AES_IV_0:
        value = s->iv[0];
    break;
    case REG_AES_IV_1:
        value = s->iv[1];
    break;
    case REG_AES_IV_2:
        value = s->iv[2];
    break;
    case REG_AES_IV_3:
        value = s->iv[3];
    break;
    case REG_AES_KEY_0:
        value = s->key[0];
    break;
    case REG_AES_KEY_1:
        value = s->key[1];
    break;
    case REG_AES_KEY_2:
        value = s->key[2];
    break;
    case REG_AES_KEY_3:
        value = s->key[3];
    break;
    case REG_AES_KEY_4:
        value = s->key[4];
    break;
    case REG_AES_KEY_5:
        value = s->key[5];
    break;
    case REG_AES_KEY_6:
        value = s->key[6];
    break;
    case REG_AES_KEY_7:
        value = s->key[7];
    break;
    case REG_TDES_CTRL:
        value = s->tdes_ctrl;
    break;
    case REG_TDES_STS:
    break;
    case REG_TDES_IV_0:
        value = s->tiv[0];
    break;
    case REG_TDES_IV_1:
        value = s->tiv[1];
    break;
    case REG_TDES_KEY1_0:
        value = s->tkey[0];
    break;
    case REG_TDES_KEY1_1:
        value = s->tkey[1];
    break;
    case REG_TDES_KEY2_0:
        value = s->tkey[2];
    break;
    case REG_TDES_KEY2_1:
        value = s->tkey[3];
    break;
    case REG_TDES_KEY3_0:
        value = s->tkey[4];
    break;
    case REG_TDES_KEY3_1:
        value = s->tkey[5];
    break;
    case REG_HASH_CTRL:
        value = s->hash_ctrl;
    break;
    case REG_HASH_STS:
        value = 0;
    break;
    case REG_HASH_MSG_LEN:
        value = s->hrdmal;
    break;
    case REG_HASH_DOUT_0:
        value = s->hash[0];
    break;
    case REG_HASH_DOUT_1:
        value = s->hash[1];
    break;
    case REG_HASH_DOUT_2:
        value = s->hash[2];
    break;
    case REG_HASH_DOUT_3:
        value = s->hash[3];
    break;
    case REG_HASH_DOUT_4:
        value = s->hash[4];
    break;
    case REG_HASH_DOUT_5:
        value = s->hash[5];
    break;
    case REG_HASH_DOUT_6:
        value = s->hash[6];
    break;
    case REG_HASH_DOUT_7:
        value = s->hash[7];
    break;
    default:
        qemu_log_mask(LOG_UNIMP, "rk_crypto: read access to unknown "
                                 "CRYPTO register 0x" TARGET_FMT_plx "\n",
                                  offset);
    }

    trace_rk_crypto_read(offset, value);
    return value;
}

static int start_block(RkCryptoState *s)
{
    int err;
/* TODO: sanity check of mode CBC/ECB*/

    if (s->conf & RK_CRYPTO_DESSEL) {
        err = do_des(s);
    } else {
        err = do_aes(s);
    }

    /* TODO check current mode */
    s->intsts = RK_CRYPTO_BCDMA_DONE_INT;
    if (err && s->intena & RK_CRYPTO_BCDMA_ERR_ENA) {
        s->intsts |= RK_CRYPTO_BCDMA_ERR_INT;
    }
    qemu_set_irq(s->irq, 1);
    return 0;
}

static void rk_crypto_write(void *opaque, hwaddr offset,
                                       uint64_t value, unsigned size)
{
    RkCryptoState *s = RK_CRYPTO(opaque);

    trace_rk_crypto_write(offset, value);

    switch (offset) {
    case REG_INT_STS:
        s->intsts &= ~value;
        qemu_set_irq(s->irq, 0);
        break;
    case REG_INT_ENA:
        s->intena = value;
        break;
    case REG_CTRL:
        if (value & RK_CRYPTO_BLOCK_START) {
            start_block(s);
        }
        if (value & RK_CRYPTO_HASH_START) {
            start_hash(s);
        }
        break;
    case REG_CONF:
        s->conf = value;
        break;
    case REG_BRDMAS:
        s->brdmas = value;
        break;
    case REG_BTDMAS:
        s->btdmas = value;
        break;
    case REG_BRDMAL:
        s->brdmal = value;
        break;
    case REG_HRDMAS:
        s->hrdmas = value;
        break;
    case REG_HRDMAL:
        s->hrdmal = value;
        break;
    case REG_AES_CTRL:
        s->aes_ctrl = value;
        break;
    case REG_AES_STS:
        break;
    case REG_AES_IV_0:
        s->iv[0] = value;
        break;
    case REG_AES_IV_1:
        s->iv[1] = value;
        break;
    case REG_AES_IV_2:
        s->iv[2] = value;
        break;
    case REG_AES_IV_3:
        s->iv[3] = value;
        break;
    case REG_AES_KEY_0:
        s->key[0] = value;
        break;
    case REG_AES_KEY_1:
        s->key[1] = value;
        break;
    case REG_AES_KEY_2:
        s->key[2] = value;
        break;
    case REG_AES_KEY_3:
        s->key[3] = value;
        break;
    case REG_AES_KEY_4:
        s->key[4] = value;
        break;
    case REG_AES_KEY_5:
        s->key[5] = value;
        break;
    case REG_AES_KEY_6:
        s->key[6] = value;
        break;
    case REG_AES_KEY_7:
        s->key[7] = value;
        break;
    case REG_TDES_CTRL:
        s->tdes_ctrl = value;
        break;
    case REG_TDES_STS:
        break;
    case REG_TDES_IV_0:
        s->tiv[0] = value;
        break;
    case REG_TDES_IV_1:
        s->tiv[1] = value;
        break;
    case REG_TDES_KEY1_0:
        s->tkey[0] = value;
        break;
    case REG_TDES_KEY1_1:
        s->tkey[1] = value;
        break;
    case REG_TDES_KEY2_0:
        s->tkey[2] = value;
        break;
    case REG_TDES_KEY2_1:
        s->tkey[3] = value;
        break;
    case REG_TDES_KEY3_0:
        s->tkey[4] = value;
        break;
    case REG_TDES_KEY3_1:
        s->tkey[5] = value;
        break;
    case REG_HASH_CTRL:
        s->hash_ctrl = value;
        break;
    case REG_HASH_STS:
        break;
    case REG_HASH_MSG_LEN:
        s->hrdmal = value * 4;
        break;
        break;
    case REG_HASH_DOUT_0:
    case REG_HASH_DOUT_1:
    case REG_HASH_DOUT_2:
    case REG_HASH_DOUT_3:
    case REG_HASH_DOUT_4:
    case REG_HASH_DOUT_5:
    case REG_HASH_DOUT_6:
    case REG_HASH_DOUT_7:
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "rk_crypto: write access to unknown "
                                 "CRYPTO register 0x" TARGET_FMT_plx "\n",
                                  offset);
    }
}

static const MemoryRegionOps rk_crypto_mem_ops = {
    .read = rk_crypto_read,
    .write = rk_crypto_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl.min_access_size = 4,
};

static void rk_crypto_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    RkCryptoState *s = RK_CRYPTO(obj);

    memory_region_init_io(&s->iomem, OBJECT(s), &rk_crypto_mem_ops,
                           s, TYPE_RK_CRYPTO, 4 * KiB);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static void rk_crypto_realize(DeviceState *dev, Error **errp)
{
    RkCryptoState *s = RK_CRYPTO(dev);

    if (!s->dma_mr) {
        error_setg(errp, TYPE_RK_CRYPTO " 'dma-memory' link not set");
        return;
    }

    address_space_init(&s->dma_as, s->dma_mr, "crypto-dma");
}

static Property rk_crypto_properties[] = {
    DEFINE_PROP_LINK("dma-memory", RkCryptoState, dma_mr,
                     TYPE_MEMORY_REGION, MemoryRegion *),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription vmstate_rk_crypto = {
    .name = "rockchip-crypto",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(intsts, RkCryptoState),
        VMSTATE_UINT32(intena, RkCryptoState),
        VMSTATE_UINT32(ctrl, RkCryptoState),
        VMSTATE_UINT32(conf, RkCryptoState),
        VMSTATE_UINT32(brdmas, RkCryptoState),
        VMSTATE_UINT32(btdmas, RkCryptoState),
        VMSTATE_UINT32(brdmal, RkCryptoState),
        VMSTATE_UINT32(hrdmas, RkCryptoState),
        VMSTATE_UINT32(hrdmal, RkCryptoState),
        VMSTATE_UINT32(aes_ctrl, RkCryptoState),
        VMSTATE_UINT32(tdes_ctrl, RkCryptoState),
        VMSTATE_END_OF_LIST()
    }
};

static void rk_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = rk_crypto_realize;
    dc->reset = rk_crypto_reset;
    dc->vmsd = &vmstate_rk_crypto;
    device_class_set_props(dc, rk_crypto_properties);
}

static const TypeInfo rk_crypto_info = {
    .name           = TYPE_RK_CRYPTO,
    .parent         = TYPE_SYS_BUS_DEVICE,
    .instance_size  = sizeof(RkCryptoState),
    .instance_init  = rk_crypto_init,
    .class_init     = rk_crypto_class_init,
};

static void rk_crypto_register_types(void)
{
    type_register_static(&rk_crypto_info);
}

type_init(rk_crypto_register_types)
