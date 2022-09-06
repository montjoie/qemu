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
#include "hw/crypto/allwinner-sun8i-ce.h"
#include "crypto/cipher.h"
#include "crypto/hash.h"

enum {
    REG_TDQ = 0x0000,
    REG_CTR = 0x0004,
    REG_ICR = 0x0008,
    REG_ISR = 0x000C,
    REG_TLR = 0x0010,
    REG_TSR = 0x0014,
    REG_ESR = 0x0018,
};

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE  8
#define DES3_BLOCK_SIZE 8

#define MD5_DIGEST_SIZE 16

#define SHA1_DIGEST_SIZE 20

#define SHA224_DIGEST_SIZE 28

#define SHA256_DIGEST_SIZE 32

#define SHA384_DIGEST_SIZE 48

#define SHA512_DIGEST_SIZE 64

#define CE_ALG_AES        0
#define CE_ALG_DES        1
#define CE_ALG_3DES       2
#define CE_ALG_MD5       16
#define CE_ALG_SHA1      17
#define CE_ALG_SHA224    18
#define CE_ALG_SHA256    19
#define CE_ALG_SHA384    20
#define CE_ALG_SHA512    21
#define CE_ALG_RSA       32
#define CE_ALG_PRNG      49

#define CE_ENCRYPTION     0
#define CE_DECRYPTION     BIT(8)

#define CE_COMM_INT       BIT(31)

#define CE_AES_128BITS    0
#define CE_AES_192BITS    1
#define CE_AES_256BITS    2

#define CE_OP_ECB         0
#define CE_OP_CBC         (1 << 8)

#define CE_ERR_ALGO_NOTSUP   BIT(0)
#define CE_ERR_DATALEN       BIT(1)
#define CE_ERR_KEYSRAM       BIT(2)
#define CE_ERR_ADDR_INVALID  BIT(5)
#define CE_ERR_KEYLADDER     BIT(6)

#define MAX_SG 8

struct sginfo {
    uint32_t addr;
    uint32_t len;
};

struct ce_task {
    uint32_t t_id;
    uint32_t t_common_ctl;
    uint32_t t_sym_ctl;
    uint32_t t_asym_ctl;
    uint32_t t_key;
    uint32_t t_iv;
    uint32_t t_ctr;
    uint32_t t_dlen;
    struct sginfo t_src[MAX_SG];
    struct sginfo t_dst[MAX_SG];
    uint32_t next;
    uint32_t reserved[3];
};

static void allwinner_sun8i_ce_reset(DeviceState *dev)
{
    AwSun8iCEState *s = AW_SUN8I_CE(dev);

    trace_allwinner_sun8i_ce_reset();

    s->tdq = 0;
    s->ctr = 0;
    s->icr = 0;
    s->isr = 0;
    s->tlr = 0;
    s->tsr = 0;
    s->esr = 0;
}

static uint64_t allwinner_sun8i_ce_read(void *opaque, hwaddr offset,
                                          unsigned size)
{
    AwSun8iCEState *s = AW_SUN8I_CE(opaque);
    uint64_t value = 0;

    switch (offset) {
    case REG_ICR:
        value = s->icr;
        break;
    case REG_ISR:
        value = s->isr;
        break;
    case REG_ESR:
        value = s->esr;
        break;
    case REG_CTR:
        value = s->ctr;
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "allwinner_sun8i_ce: read access to unknown "
                                 "CRYPTO register 0x" TARGET_FMT_plx "\n",
                                  offset);
    }

    trace_allwinner_sun8i_ce_read(offset, value);
    return value;
}

static int do_task(AwSun8iCEState *s, struct ce_task *t)
{
    const uint32_t ivmd5[MD5_DIGEST_SIZE / 4] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
    };
    static const uint32_t iv_sha1[SHA1_DIGEST_SIZE / 4] = {
        0x67452301L, 0xEFCDAB89L, 0x98BADCFEL, 0x10325476L, 0xC3D2E1F0L,
    };
    static const uint32_t iv_sha224[SHA256_DIGEST_SIZE] = {
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
    };
    static const uint32_t iv_sha256[SHA256_DIGEST_SIZE] = {
        0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
        0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL,
    };
    static const uint64_t iv_sha384[SHA512_DIGEST_SIZE / 8] = {
        0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL,
        0x9159015A3070DD17ULL, 0x152FECD8F70E5939ULL,
        0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL,
        0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL,
    };
    static const uint64_t iv_sha512[SHA512_DIGEST_SIZE / 8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
    };
    unsigned char *src;
    unsigned char *dst;
    unsigned char biv[AES_BLOCK_SIZE];
    QCryptoCipher *cipher = NULL;
    QCryptoCipherAlgorithm alg;
    QCryptoCipherMode mode;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char key[32];
    size_t nkey = 0;
    Error *errp = NULL;
    int err;
    size_t niv = 0;
    uint32_t dlen;
    int i;
    uint32_t size, ssize, dsize;
    int flow;
    uint32_t sgs, sgd, off;
    uint32_t addr;
    uint32_t algo;
    uint32_t *hash, *prng;
    uint64_t *hash64;

    t = g_malloc(sizeof(struct ce_task));

    dma_memory_read(&s->dma_as, s->tdq, t, sizeof(struct ce_task),
                    MEMTXATTRS_UNSPECIFIED);
    flow = t->t_id;
    s->esr = 0;
    if (!t->t_dlen) {
        s->esr = CE_ERR_DATALEN;
        return 1;
    }
    algo = t->t_common_ctl & 0x7F;

    if (algo == CE_ALG_DES) {
        alg = QCRYPTO_CIPHER_ALG_DES;
        nkey = 8;
    }
    if (algo == CE_ALG_3DES) {
        alg = QCRYPTO_CIPHER_ALG_3DES;
        nkey = 24;
    }
    if (algo == CE_ALG_AES) {
        switch (t->t_sym_ctl & 0x3) {
        case CE_AES_128BITS:
            alg = QCRYPTO_CIPHER_ALG_AES_128;
            nkey = 16;
            break;
        case CE_AES_192BITS:
            alg = QCRYPTO_CIPHER_ALG_AES_192;
            nkey = 24;
            break;
        case CE_AES_256BITS:
            alg = QCRYPTO_CIPHER_ALG_AES_256;
            nkey = 32;
            break;
        default:
            s->esr = CE_ERR_ALGO_NOTSUP;
            return CE_ERR_ALGO_NOTSUP;
        }
    }
    if (t->t_sym_ctl & CE_OP_CBC) {
        mode = QCRYPTO_CIPHER_MODE_CBC;
        switch (algo) {
        case CE_ALG_AES:
            niv = AES_BLOCK_SIZE;
            break;
        case CE_ALG_DES:
            niv = DES_BLOCK_SIZE;
            break;
        case CE_ALG_3DES:
            niv = DES3_BLOCK_SIZE;
            break;
        default:
            s->esr = CE_ERR_ALGO_NOTSUP;
            return 1;
        };
    } else {
        mode = QCRYPTO_CIPHER_MODE_ECB;
    }

    if (nkey > 0) {
        if (!t->t_key) {
            return CE_ERR_ADDR_INVALID;
        }
        dma_memory_read(&s->dma_as, t->t_key, key, nkey,
                        MEMTXATTRS_UNSPECIFIED);
    }

    switch (algo) {
    case CE_ALG_AES:
    case CE_ALG_DES:
    case CE_ALG_3DES:
        cipher = qcrypto_cipher_new(alg, mode, key, nkey, &errp);
        if (!cipher) {
            return 1;
        }
        break;
    }
    if (niv > 0) {
        dma_memory_read(&s->dma_as, t->t_iv, iv, niv,
                        MEMTXATTRS_UNSPECIFIED);
        if (cipher) {
            err = qcrypto_cipher_setiv(cipher, iv, niv, &errp);
            assert(err == 0);
        }
    }

    dlen = t->t_dlen;
    for (i = 0; i < MAX_SG; i++) {
        size = t->t_src[i].len;
        if (!size) {
            continue;
        }
        dlen -= size;
    }
    if (dlen && algo != CE_ALG_PRNG) {
        printf("ERROR: data size\n");
        s->esr = CE_ERR_DATALEN;
        return 1;
    }

/* TODO check size modulo for hashs*/

    sgs = 0;
    sgd = 0;
    off = 0;
    dlen = t->t_dlen;
    ssize = dlen * 4;
    dsize = dlen * 4;
    switch (algo) {
    case CE_ALG_PRNG:
        ssize = 0;
        break;
    case CE_ALG_MD5:
        dsize = MD5_DIGEST_SIZE;
        break;
    case CE_ALG_SHA1:
        dsize = SHA1_DIGEST_SIZE;
        break;
    case CE_ALG_SHA224:
    case CE_ALG_SHA256:
        dsize = SHA256_DIGEST_SIZE;
        break;
    case CE_ALG_SHA384:
    case CE_ALG_SHA512:
        dsize = SHA512_DIGEST_SIZE;
        break;
    }
    src = g_malloc(ssize);
    /* TODO */
    dst = g_malloc(dsize + 128);

    while (sgs < MAX_SG && off < ssize) {
        addr = t->t_src[sgs].addr;
        size = t->t_src[sgs].len * 4;
        dma_memory_read(&s->dma_as, addr, src + off, size,
                        MEMTXATTRS_UNSPECIFIED);
        off += size;
        sgs++;
    }
    if (off != ssize) {
        s->esr = CE_ERR_DATALEN;
        return 1;
    }

    switch (algo) {
    case CE_ALG_AES:
    case CE_ALG_DES:
    case CE_ALG_3DES:
        if (t->t_common_ctl & CE_DECRYPTION) {
            if (mode == QCRYPTO_CIPHER_MODE_CBC) {
                memcpy(biv, src, niv);
            }
            err = qcrypto_cipher_decrypt(cipher, src, dst, ssize, &errp);
            assert(err == 0);
            if (mode == QCRYPTO_CIPHER_MODE_CBC) {
                memcpy(iv, biv, niv);
            }
        } else {
            err = qcrypto_cipher_encrypt(cipher, src, dst, ssize, &errp);
            assert(err == 0);
            if (mode == QCRYPTO_CIPHER_MODE_CBC) {
                memcpy(iv, dst, niv);
            }
        }
        qcrypto_cipher_free(cipher);
        break;
    case CE_ALG_MD5:
        hash = (uint32_t *)dst;
        memcpy(dst, ivmd5, dsize);
        err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_MD5, (const char *)src,
                                     ssize, (uint64_t *)hash, &errp);
        if (err) {
            s->esr = CE_ERR_ALGO_NOTSUP;
            goto error;
	}
        break;
    case CE_ALG_SHA1:
        hash = (uint32_t *)dst;
        memcpy(dst, iv_sha1, dsize);
        err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_SHA1, (const char *)src,
                                     ssize, (uint64_t *)hash, &errp);
        if (err) {
            s->esr = CE_ERR_ALGO_NOTSUP;
            goto error;
	}
        for (i = 0; i < dsize / 4; i++) {
            hash[i] = cpu_to_be32(hash[i]);
        }
        break;
    case CE_ALG_SHA224:
        hash = (uint32_t *)dst;
        memcpy(dst, iv_sha224, dsize);
        err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_SHA224, (const char *)src,
                                     ssize, (uint64_t *)hash, &errp);
        if (err) {
            s->esr = CE_ERR_ALGO_NOTSUP;
            goto error;
	}
        for (i = 0; i < dsize / 4; i++) {
            hash[i] = cpu_to_be32(hash[i]);
        }
        break;
    case CE_ALG_SHA256:
        hash = (uint32_t *)dst;
        memcpy(dst, iv_sha256, dsize);
        err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_SHA256, (const char *)src,
                                     ssize, (uint64_t *)hash, &errp);
        if (err) {
            s->esr = CE_ERR_ALGO_NOTSUP;
            goto error;
	}
        for (i = 0; i < dsize / 4; i++) {
            hash[i] = cpu_to_be32(hash[i]);
        }
        break;
    case CE_ALG_SHA384:
        hash64 = (uint64_t *)dst;
        memcpy(dst, iv_sha384, dsize);
        err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_SHA384, (const char *)src,
                                     ssize, hash64, &errp);
        if (err) {
            s->esr = CE_ERR_ALGO_NOTSUP;
            goto error;
	}
        for (i = 0; i < dsize / 8; i++) {
            hash64[i] = cpu_to_be64(hash64[i]);
        }
        break;
    case CE_ALG_SHA512:
        hash64 = (uint64_t *)dst;
        memcpy(dst, iv_sha512, dsize);
        err = qcrypto_compress_bytes(QCRYPTO_HASH_ALG_SHA512, (const char *)src,
                                     ssize, hash64, &errp);
        if (err) {
            s->esr = CE_ERR_ALGO_NOTSUP;
            goto error;
	}
        for (i = 0; i < dsize / 8; i++) {
            hash64[i] = cpu_to_be64(hash64[i]);
        }
        break;
    case CE_ALG_PRNG:
        prng = (uint32_t *)dst;
        for (i = 0; i < dsize / 4; i++) {
            prng[i] = g_random_int();
        }
        break;
    default:
        s->esr = CE_ERR_ALGO_NOTSUP;
        goto error;
    }

    /* put new IV */

    sgd = 0;
    off = 0;
    while (sgd < MAX_SG && off < dsize) {
        addr = t->t_dst[sgd].addr;
        size = t->t_dst[sgd].len * 4;
        dma_memory_write(&s->dma_as, addr, dst + off, size,
                         MEMTXATTRS_UNSPECIFIED);
        off += size;
        sgd++;
    }
    if (off != dsize) {
        printf("ERROR: bad dst off=%u dsize=%u\n", off, dsize);
        s->esr = CE_ERR_DATALEN;
        goto error;
    }


error:
    if (t->t_common_ctl & CE_COMM_INT && s->icr & (1 << flow)) {
        s->isr |= 1 << flow;
        qemu_set_irq(s->irq, 1);
    }

    g_free(src);
    g_free(dst);
    return 0;
}


static int start_task(AwSun8iCEState *s)
{
    struct ce_task *t;
    uint32_t v, algo;

    if (!(s->tlr & 1)) {
        /* NO TASK to start */
        return -1;
    }

    t = g_malloc(sizeof(struct ce_task));

    dma_memory_read(&s->dma_as, s->tdq, t, sizeof(struct ce_task),
                    MEMTXATTRS_UNSPECIFIED);
    if (t->t_id > 3) {
        goto theend;
    }

    algo = t->t_common_ctl & 0x7F;
    v = (s->tlr >> 8) & 0x7F;
    if (algo != v) {
        goto theend;
    }
    switch (v) {
    case CE_ALG_DES:
    case CE_ALG_3DES:
    case CE_ALG_AES:
    case CE_ALG_PRNG:
    case CE_ALG_MD5:
    case CE_ALG_SHA1:
    case CE_ALG_SHA224:
    case CE_ALG_SHA256:
    case CE_ALG_SHA384:
    case CE_ALG_SHA512:
        do_task(s, t);
        break;
    default:
        s->esr = CE_ERR_ALGO_NOTSUP;
    }

theend:
    g_free(t);

    return 0;
}

static void allwinner_sun8i_ce_write(void *opaque, hwaddr offset,
                                       uint64_t value, unsigned size)
{
    AwSun8iCEState *s = AW_SUN8I_CE(opaque);

    trace_allwinner_sun8i_ce_write(offset, value);

    switch (offset) {
    case REG_TDQ:
        s->tdq = value;
        break;
    case REG_TLR:
        s->tlr = value;
        start_task(s);
        break;
    case REG_ISR:
        s->isr &= ~value;
        qemu_set_irq(s->irq, 0);
        break;
    case REG_ICR:
        s->icr = value;
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "allwinner_sun8i_ce: write access to unknown "
                                 "CRYPTO register 0x" TARGET_FMT_plx "\n",
                                  offset);
    }
}

static const MemoryRegionOps allwinner_sun8i_ce_mem_ops = {
    .read = allwinner_sun8i_ce_read,
    .write = allwinner_sun8i_ce_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl.min_access_size = 4,
};

static void allwinner_sun8i_ce_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    AwSun8iCEState *s = AW_SUN8I_CE(obj);

    memory_region_init_io(&s->iomem, OBJECT(s), &allwinner_sun8i_ce_mem_ops,
                           s, TYPE_AW_SUN8I_CE, 4 * KiB);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static void allwinner_sun8i_ce_realize(DeviceState *dev, Error **errp)
{
    AwSun8iCEState *s = AW_SUN8I_CE(dev);

    if (!s->dma_mr) {
        error_setg(errp, TYPE_AW_SUN8I_CE " 'dma-memory' link not set");
        return;
    }

    address_space_init(&s->dma_as, s->dma_mr, "crypto-dma");
}

static Property allwinner_sun8i_ce_properties[] = {
    DEFINE_PROP_LINK("dma-memory", AwSun8iCEState, dma_mr,
                     TYPE_MEMORY_REGION, MemoryRegion *),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription vmstate_allwinner_sun8i_ce = {
    .name = "allwinner-sun8i-ce",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(icr, AwSun8iCEState),
        VMSTATE_END_OF_LIST()
    }
};

static void allwinner_sun8i_ce_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = allwinner_sun8i_ce_realize;
    dc->reset = allwinner_sun8i_ce_reset;
    dc->vmsd = &vmstate_allwinner_sun8i_ce;
    device_class_set_props(dc, allwinner_sun8i_ce_properties);
}

static const TypeInfo allwinner_sun8i_ce_info = {
    .name           = TYPE_AW_SUN8I_CE,
    .parent         = TYPE_SYS_BUS_DEVICE,
    .instance_size  = sizeof(AwSun8iCEState),
    .instance_init  = allwinner_sun8i_ce_init,
    .class_init     = allwinner_sun8i_ce_class_init,
};

static void allwinner_sun8i_ce_register_types(void)
{
    type_register_static(&allwinner_sun8i_ce_info);
}

type_init(allwinner_sun8i_ce_register_types)
