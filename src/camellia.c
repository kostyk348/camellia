/*
 * camellia.c - Implementation of the Camellia block cipher (RFC 3713).
 *
 * Clean-room, portable, dependency-free C99. Conforms to RFC 3713.
 *
 * SPDX-License-Identifier: MIT
 */
#include "camellia.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static inline uint32_t rotl32(uint32_t x, unsigned n)
{
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

static inline uint64_t rotl64(uint64_t x, unsigned n)
{
    n &= 63;
    return (x << n) | (x >> (64 - n));
}

static inline uint8_t rotl8(uint8_t x, unsigned n)
{
    n &= 7;
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

/* Rotate a 128-bit value (hi:lo) left by n bits (0 <= n < 128). */
static void rot128(uint64_t *hi, uint64_t *lo, int n)
{
    if (n == 0)
        return;
    if (n < 64) {
        uint64_t nh = (*hi << n) | (*lo >> (64 - n));
        uint64_t nl = (*lo << n) | (*hi >> (64 - n));
        *hi = nh;
        *lo = nl;
    } else {
        int m = n - 64;
        uint64_t nh = (*lo << m) | (*hi >> (64 - m));
        uint64_t nl = (*hi << m) | (*lo >> (64 - m));
        *hi = nh;
        *lo = nl;
    }
}

/* Extract the two 64-bit halves of (hi:lo) rotated left by n bits. */
static void half128(uint64_t hi, uint64_t lo, int n, uint64_t *h, uint64_t *l)
{
    rot128(&hi, &lo, n);
    *h = hi;   /* (x <<< n) >> 64 */
    *l = lo;   /* (x <<< n) & MASK64 */
}

static void be64_load(const uint8_t *p, uint64_t *hi, uint64_t *lo)
{
    int i;
    *hi = 0; *lo = 0;
    for (i = 0; i < 8; i++) {
        *hi = (*hi << 8) | p[i];
        *lo = (*lo << 8) | p[8 + i];
    }
}

static void be64_store(uint8_t *p, uint64_t hi, uint64_t lo)
{
    int i;
    for (i = 0; i < 8; i++) {
        p[i]      = (uint8_t)(hi >> (56 - 8 * i));
        p[8 + i]  = (uint8_t)(lo >> (56 - 8 * i));
    }
}

/* ------------------------------------------------------------------ */
/* S-boxes                                                            */
/* ------------------------------------------------------------------ */

/* SBOX1 as defined in RFC 3713 (SBOX1[0x3d] == 86, SBOX1[0] == 112). */
static const uint8_t SBOX1[256] = {
    /* 0x00 */ 0x70,0x82,0x2c,0xec,0xb3,0x27,0xc0,0xe5,0xe4,0x85,0x57,0x35,0xea,0x0c,0xae,0x41,
    /* 0x10 */ 0x23,0xef,0x6b,0x93,0x45,0x19,0xa5,0x21,0xed,0x0e,0x4f,0x4e,0x1d,0x65,0x92,0xbd,
    /* 0x20 */ 0x86,0xb8,0xaf,0x8f,0x7c,0xeb,0x1f,0xce,0x3e,0x30,0xdc,0x5f,0x5e,0xc5,0x0b,0x1a,
    /* 0x30 */ 0xa6,0xe1,0x39,0xca,0xd5,0x47,0x5d,0x3d,0xd9,0x01,0x5a,0xd6,0x51,0x56,0x6c,0x4d,
    /* 0x40 */ 0x8b,0x0d,0x9a,0x66,0xfb,0xcc,0xb0,0x2d,0x74,0x12,0x2b,0x20,0xf0,0xb1,0x84,0x99,
    /* 0x50 */ 0xdf,0x4c,0xcb,0xc2,0x34,0x7e,0x76,0x05,0x6d,0xb7,0xa9,0x31,0xd1,0x17,0x04,0xd7,
    /* 0x60 */ 0x14,0x58,0x3a,0x61,0xde,0x1b,0x11,0x1c,0x32,0x0f,0x9c,0x16,0x53,0x18,0xf2,0x22,
    /* 0x70 */ 0xfe,0x44,0xcf,0xb2,0xc3,0xb5,0x7a,0x91,0x24,0x08,0xe8,0xa8,0x60,0xfc,0x69,0x50,
    /* 0x80 */ 0xaa,0xd0,0xa0,0x7d,0xa1,0x89,0x62,0x97,0x54,0x5b,0x1e,0x95,0xe0,0xff,0x64,0xd2,
    /* 0x90 */ 0x10,0xc4,0x00,0x48,0xa3,0xf7,0x75,0xdb,0x8a,0x03,0xe6,0xda,0x09,0x3f,0xdd,0x94,
    /* 0xa0 */ 0x87,0x5c,0x83,0x02,0xcd,0x4a,0x90,0x33,0x73,0x67,0xf6,0xf3,0x9d,0x7f,0xbf,0xe2,
    /* 0xb0 */ 0x52,0x9b,0xd8,0x26,0xc8,0x37,0xc6,0x3b,0x81,0x96,0x6f,0x4b,0x13,0xbe,0x63,0x2e,
    /* 0xc0 */ 0xe9,0x79,0xa7,0x8c,0x9f,0x6e,0xbc,0x8e,0x29,0xf5,0xf9,0xb6,0x2f,0xfd,0xb4,0x59,
    /* 0xd0 */ 0x78,0x98,0x06,0x6a,0xe7,0x46,0x71,0xba,0xd4,0x25,0xab,0x42,0x88,0xa2,0x8d,0xfa,
    /* 0xe0 */ 0x72,0x07,0xb9,0x55,0xf8,0xee,0xac,0x0a,0x36,0x49,0x2a,0x68,0x3c,0x38,0xf1,0xa4,
    /* 0xf0 */ 0x40,0x28,0xd3,0x7b,0xbb,0xc9,0x43,0xc1,0x15,0xe3,0xad,0xf4,0x77,0xc7,0x80,0x9e
};

/* Derived tables (RFC 3713 section 2.4.1):
 *   SBOX2[x] = SBOX1[x] <<< 1
 *   SBOX3[x] = SBOX1[x] <<< 7
 *   SBOX4[x] = SBOX1[x <<< 1]
 */
static uint8_t SBOX2[256];
static uint8_t SBOX3[256];
static uint8_t SBOX4[256];
static int     sbox_ready = 0;

static void init_sboxes(void)
{
    int i;
    if (sbox_ready)
        return;
    for (i = 0; i < 256; i++) {
        SBOX2[i] = rotl8(SBOX1[i], 1);
        SBOX3[i] = rotl8(SBOX1[i], 7);
        SBOX4[i] = SBOX1[rotl8((uint8_t)i, 1)];   /* SBOX4[x] = SBOX1[x<<<1] */
    }
    sbox_ready = 1;
}

/* ------------------------------------------------------------------ */
/* Primitive functions                                                 */
/* ------------------------------------------------------------------ */

/* F-function (RFC 3713 section 2.4.1). */
static uint64_t camellia_f(uint64_t x, uint64_t ke)
{
    uint64_t t = x ^ ke;
    uint8_t t1 = SBOX1[(t >> 56) & 0xff];
    uint8_t t2 = SBOX2[(t >> 48) & 0xff];
    uint8_t t3 = SBOX3[(t >> 40) & 0xff];
    uint8_t t4 = SBOX4[(t >> 32) & 0xff];
    uint8_t t5 = SBOX2[(t >> 24) & 0xff];
    uint8_t t6 = SBOX3[(t >> 16) & 0xff];
    uint8_t t7 = SBOX4[(t >> 8)  & 0xff];
    uint8_t t8 = SBOX1[t & 0xff];

    uint8_t y1 = (uint8_t)(t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8);
    uint8_t y2 = (uint8_t)(t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8);
    uint8_t y3 = (uint8_t)(t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8);
    uint8_t y4 = (uint8_t)(t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7);
    uint8_t y5 = (uint8_t)(t1 ^ t2 ^ t6 ^ t7 ^ t8);
    uint8_t y6 = (uint8_t)(t2 ^ t3 ^ t5 ^ t7 ^ t8);
    uint8_t y7 = (uint8_t)(t3 ^ t4 ^ t5 ^ t6 ^ t8);
    uint8_t y8 = (uint8_t)(t1 ^ t4 ^ t5 ^ t6 ^ t7);

    return ((uint64_t)y1 << 56) | ((uint64_t)y2 << 48) | ((uint64_t)y3 << 40) |
           ((uint64_t)y4 << 32) | ((uint64_t)y5 << 24) | ((uint64_t)y6 << 16) |
           ((uint64_t)y7 << 8)  | (uint64_t)y8;
}

/* FL-function (RFC 3713 section 2.4.2). */
static uint64_t camellia_fl(uint64_t x, uint64_t ke)
{
    uint32_t x1 = (uint32_t)(x >> 32);
    uint32_t x2 = (uint32_t)(x & 0xffffffffu);
    uint32_t k1 = (uint32_t)(ke >> 32);
    uint32_t k2 = (uint32_t)(ke & 0xffffffffu);
    x2 ^= rotl32(x1 & k1, 1);
    x1 ^= (x2 | k2);
    return ((uint64_t)x1 << 32) | (uint64_t)x2;
}

/* FLINV-function (RFC 3713 section 2.4.2). */
static uint64_t camellia_flinv(uint64_t y, uint64_t ke)
{
    uint32_t y1 = (uint32_t)(y >> 32);
    uint32_t y2 = (uint32_t)(y & 0xffffffffu);
    uint32_t k1 = (uint32_t)(ke >> 32);
    uint32_t k2 = (uint32_t)(ke & 0xffffffffu);
    y1 ^= (y2 | k2);
    y2 ^= rotl32(y1 & k1, 1);
    return ((uint64_t)y1 << 32) | (uint64_t)y2;
}

/* ------------------------------------------------------------------ */
/* Key schedule                                                        */
/* ------------------------------------------------------------------ */

/* 64-bit constants used as "keys" inside the key schedule (Sigma1..6). */
#define SIGMA1 0xA09E667F3BCC908Bull
#define SIGMA2 0xB67AE8584CAA73B2ull
#define SIGMA3 0xC6EF372FE94F82BEull
#define SIGMA4 0x54FF53A5F1D36F1Cull
#define SIGMA5 0x10E527FADE682D1Dull
#define SIGMA6 0xB05688C2B3E6C1FDull

static camellia_status camellia_set_key_128(camellia_ctx *ctx,
                                            uint64_t kl_hi, uint64_t kl_lo)
{
    uint64_t ka_hi, ka_lo;
    uint64_t d1, d2;
    uint64_t t;

    /* KA = KL for 128-bit (KR = 0). */
    /* Compute KA (RFC 3713 2.2) with KR = 0. */
    d1 = kl_hi;                       /* (KL ^ KR) >> 64, KR=0 */
    d2 = kl_lo;                       /* (KL ^ KR) & MASK64    */
    d2 = d2 ^ camellia_f(d1, SIGMA1);
    d1 = d1 ^ camellia_f(d2, SIGMA2);
    d1 = d1 ^ kl_hi;
    d2 = d2 ^ kl_lo;
    d2 = d2 ^ camellia_f(d1, SIGMA3);
    d1 = d1 ^ camellia_f(d2, SIGMA4);
    ka_hi = d1; ka_lo = d2;
    /* KB not used for 128-bit. */

    /* Subkeys (RFC 3713 2.2, 128-bit list). */
    half128(kl_hi, kl_lo,   0, &ctx->kw[0], &ctx->kw[1]);
    half128(ka_hi, ka_lo,   0, &ctx->k[0],  &ctx->k[1]);
    half128(kl_hi, kl_lo,  15, &ctx->k[2],  &ctx->k[3]);
    half128(ka_hi, ka_lo,  15, &ctx->k[4],  &ctx->k[5]);
    half128(ka_hi, ka_lo,  30, &ctx->ke[0], &ctx->ke[1]);
    half128(kl_hi, kl_lo,  45, &ctx->k[6],  &ctx->k[7]);
    half128(ka_hi, ka_lo,  45, &ctx->k[8], &t);            /* k9  = high(KA<<<45); low unused */
    half128(kl_hi, kl_lo,  60, &t,         &ctx->k[9]);     /* k10 = low(KL<<<60) */
    half128(ka_hi, ka_lo,  60, &ctx->k[10], &ctx->k[11]);   /* k11, k12 */
    half128(kl_hi, kl_lo,  77, &ctx->ke[2], &ctx->ke[3]);
    half128(kl_hi, kl_lo,  94, &ctx->k[12], &ctx->k[13]);
    half128(ka_hi, ka_lo,  94, &ctx->k[14], &ctx->k[15]);
    half128(kl_hi, kl_lo, 111, &ctx->k[16], &ctx->k[17]);
    half128(ka_hi, ka_lo, 111, &ctx->kw[2], &ctx->kw[3]);

    ctx->rounds   = 18;
    ctx->key_bits = 128;
    return CAMELLIA_SUCCESS;
}

static camellia_status camellia_set_key_192_256(camellia_ctx *ctx,
                                               uint64_t kl_hi, uint64_t kl_lo,
                                               uint64_t kr_hi, uint64_t kr_lo)
{
    uint64_t ka_hi, ka_lo, kb_hi, kb_lo;
    uint64_t d1, d2;

    /* KA */
    d1 = kl_hi ^ kr_hi;
    d2 = kl_lo ^ kr_lo;
    d2 = d2 ^ camellia_f(d1, SIGMA1);
    d1 = d1 ^ camellia_f(d2, SIGMA2);
    d1 = d1 ^ kl_hi;
    d2 = d2 ^ kl_lo;
    d2 = d2 ^ camellia_f(d1, SIGMA3);
    d1 = d1 ^ camellia_f(d2, SIGMA4);
    ka_hi = d1; ka_lo = d2;

    /* KB */
    d1 = ka_hi ^ kr_hi;
    d2 = ka_lo ^ kr_lo;
    d2 = d2 ^ camellia_f(d1, SIGMA5);
    d1 = d1 ^ camellia_f(d2, SIGMA6);
    kb_hi = d1; kb_lo = d2;

    /* Subkeys (RFC 3713 2.2, 192/256-bit list). */
    half128(kl_hi, kl_lo,   0, &ctx->kw[0], &ctx->kw[1]);
    half128(kb_hi, kb_lo,   0, &ctx->k[0],  &ctx->k[1]);
    half128(kr_hi, kr_lo,  15, &ctx->k[2],  &ctx->k[3]);
    half128(ka_hi, ka_lo,  15, &ctx->k[4],  &ctx->k[5]);
    half128(kr_hi, kr_lo,  30, &ctx->ke[0], &ctx->ke[1]);
    half128(kb_hi, kb_lo,  30, &ctx->k[6],  &ctx->k[7]);
    half128(kl_hi, kl_lo,  45, &ctx->k[8],  &ctx->k[9]);
    half128(ka_hi, ka_lo,  45, &ctx->k[10], &ctx->k[11]);
    half128(kl_hi, kl_lo,  60, &ctx->ke[2], &ctx->ke[3]);
    half128(kr_hi, kr_lo,  60, &ctx->k[12], &ctx->k[13]);
    half128(kb_hi, kb_lo,  60, &ctx->k[14], &ctx->k[15]);
    half128(kl_hi, kl_lo,  77, &ctx->k[16], &ctx->k[17]);
    half128(ka_hi, ka_lo,  77, &ctx->ke[4], &ctx->ke[5]);
    half128(kr_hi, kr_lo,  94, &ctx->k[18], &ctx->k[19]);
    half128(ka_hi, ka_lo,  94, &ctx->k[20], &ctx->k[21]);
    half128(kl_hi, kl_lo, 111, &ctx->k[22], &ctx->k[23]);
    half128(kb_hi, kb_lo, 111, &ctx->kw[2], &ctx->kw[3]);

    ctx->rounds   = 24;
    return CAMELLIA_SUCCESS;
}

camellia_status camellia_set_key(camellia_ctx *ctx,
                                 const uint8_t *key,
                                 size_t key_len)
{
    uint64_t keyw[4] = {0, 0, 0, 0};
    size_t i;

    init_sboxes();

    if (key_len != 16 && key_len != 24 && key_len != 32)
        return CAMELLIA_INVALID_KEYLEN;

    for (i = 0; i < key_len; i++)
        keyw[i / 8] = (keyw[i / 8] << 8) | key[i];

    if (key_len == 16) {
        ctx->key_bits = 128;
        return camellia_set_key_128(ctx, keyw[0], keyw[1]);
    } else if (key_len == 24) {
        ctx->key_bits = 192;
        /* KR = (K_low64 << 64) | (~K_low64) */
        return camellia_set_key_192_256(ctx, keyw[0], keyw[1],
                                        keyw[2], ~keyw[2]);
    } else { /* 32 */
        ctx->key_bits = 256;
        return camellia_set_key_192_256(ctx, keyw[0], keyw[1],
                                        keyw[2], keyw[3]);
    }
}

/* ------------------------------------------------------------------ */
/* Data randomizing part                                               */
/* ------------------------------------------------------------------ */

void camellia_encrypt_block(const camellia_ctx *ctx,
                            const uint8_t in[CAMELLIA_BLOCK_SIZE],
                            uint8_t out[CAMELLIA_BLOCK_SIZE])
{
    uint64_t d1, d2;
    const uint64_t *k = ctx->k;
    const uint64_t *ke = ctx->ke;
    const uint64_t *kw = ctx->kw;

    init_sboxes();
    be64_load(in, &d1, &d2);

    if (ctx->rounds == 18) {
        d1 ^= kw[0]; d2 ^= kw[1];
        d2 ^= camellia_f(d1, k[0]);   d1 ^= camellia_f(d2, k[1]);
        d2 ^= camellia_f(d1, k[2]);   d1 ^= camellia_f(d2, k[3]);
        d2 ^= camellia_f(d1, k[4]);   d1 ^= camellia_f(d2, k[5]);
        d1 = camellia_fl(d1, ke[0]);  d2 = camellia_flinv(d2, ke[1]);
        d2 ^= camellia_f(d1, k[6]);   d1 ^= camellia_f(d2, k[7]);
        d2 ^= camellia_f(d1, k[8]);   d1 ^= camellia_f(d2, k[9]);
        d2 ^= camellia_f(d1, k[10]);  d1 ^= camellia_f(d2, k[11]);
        d1 = camellia_fl(d1, ke[2]);  d2 = camellia_flinv(d2, ke[3]);
        d2 ^= camellia_f(d1, k[12]);  d1 ^= camellia_f(d2, k[13]);
        d2 ^= camellia_f(d1, k[14]);  d1 ^= camellia_f(d2, k[15]);
        d2 ^= camellia_f(d1, k[16]);  d1 ^= camellia_f(d2, k[17]);
        d2 ^= kw[2]; d1 ^= kw[3];
    } else { /* 24 rounds */
        d1 ^= kw[0]; d2 ^= kw[1];
        d2 ^= camellia_f(d1, k[0]);   d1 ^= camellia_f(d2, k[1]);
        d2 ^= camellia_f(d1, k[2]);   d1 ^= camellia_f(d2, k[3]);
        d2 ^= camellia_f(d1, k[4]);   d1 ^= camellia_f(d2, k[5]);
        d1 = camellia_fl(d1, ke[0]);  d2 = camellia_flinv(d2, ke[1]);
        d2 ^= camellia_f(d1, k[6]);   d1 ^= camellia_f(d2, k[7]);
        d2 ^= camellia_f(d1, k[8]);   d1 ^= camellia_f(d2, k[9]);
        d2 ^= camellia_f(d1, k[10]);  d1 ^= camellia_f(d2, k[11]);
        d1 = camellia_fl(d1, ke[2]);  d2 = camellia_flinv(d2, ke[3]);
        d2 ^= camellia_f(d1, k[12]);  d1 ^= camellia_f(d2, k[13]);
        d2 ^= camellia_f(d1, k[14]);  d1 ^= camellia_f(d2, k[15]);
        d2 ^= camellia_f(d1, k[16]);  d1 ^= camellia_f(d2, k[17]);
        d1 = camellia_fl(d1, ke[4]);  d2 = camellia_flinv(d2, ke[5]);
        d2 ^= camellia_f(d1, k[18]);  d1 ^= camellia_f(d2, k[19]);
        d2 ^= camellia_f(d1, k[20]);  d1 ^= camellia_f(d2, k[21]);
        d2 ^= camellia_f(d1, k[22]);  d1 ^= camellia_f(d2, k[23]);
        d2 ^= kw[2]; d1 ^= kw[3];
    }

    be64_store(out, d2, d1);   /* C = (D2 << 64) | D1 */
}

void camellia_decrypt_block(const camellia_ctx *ctx,
                            const uint8_t in[CAMELLIA_BLOCK_SIZE],
                            uint8_t out[CAMELLIA_BLOCK_SIZE])
{
    uint64_t d1, d2;
    const uint64_t *k = ctx->k;
    const uint64_t *ke = ctx->ke;
    const uint64_t *kw = ctx->kw;

    init_sboxes();
    be64_load(in, &d2, &d1);

    if (ctx->rounds == 18) {
        /* Subkeys reversed (RFC 3713 2.3.3): kw1<->kw3, kw2<->kw4,
           k1<->k18..k9<->k10, ke1<->ke4, ke2<->ke3. */
        d1 ^= kw[3]; d2 ^= kw[2];
        d1 ^= camellia_f(d2, k[17]);  d2 ^= camellia_f(d1, k[16]);
        d1 ^= camellia_f(d2, k[15]);  d2 ^= camellia_f(d1, k[14]);
        d1 ^= camellia_f(d2, k[13]);  d2 ^= camellia_f(d1, k[12]);
        d2 = camellia_fl(d2, ke[3]);  d1 = camellia_flinv(d1, ke[2]);
        d1 ^= camellia_f(d2, k[11]);  d2 ^= camellia_f(d1, k[10]);
        d1 ^= camellia_f(d2, k[9]);   d2 ^= camellia_f(d1, k[8]);
        d1 ^= camellia_f(d2, k[7]);   d2 ^= camellia_f(d1, k[6]);
        d2 = camellia_fl(d2, ke[1]);  d1 = camellia_flinv(d1, ke[0]);
        d1 ^= camellia_f(d2, k[5]);   d2 ^= camellia_f(d1, k[4]);
        d1 ^= camellia_f(d2, k[3]);   d2 ^= camellia_f(d1, k[2]);
        d1 ^= camellia_f(d2, k[1]);   d2 ^= camellia_f(d1, k[0]);
        d2 ^= kw[1]; d1 ^= kw[0];
    } else { /* 24 rounds */
        d1 ^= kw[3]; d2 ^= kw[2];
        d1 ^= camellia_f(d2, k[23]);  d2 ^= camellia_f(d1, k[22]);
        d1 ^= camellia_f(d2, k[21]);  d2 ^= camellia_f(d1, k[20]);
        d1 ^= camellia_f(d2, k[19]);  d2 ^= camellia_f(d1, k[18]);
        d2 = camellia_fl(d2, ke[5]);  d1 = camellia_flinv(d1, ke[4]);
        d1 ^= camellia_f(d2, k[17]);  d2 ^= camellia_f(d1, k[16]);
        d1 ^= camellia_f(d2, k[15]);  d2 ^= camellia_f(d1, k[14]);
        d1 ^= camellia_f(d2, k[13]);  d2 ^= camellia_f(d1, k[12]);
        d2 = camellia_fl(d2, ke[3]);  d1 = camellia_flinv(d1, ke[2]);
        d1 ^= camellia_f(d2, k[11]);  d2 ^= camellia_f(d1, k[10]);
        d1 ^= camellia_f(d2, k[9]);   d2 ^= camellia_f(d1, k[8]);
        d1 ^= camellia_f(d2, k[7]);   d2 ^= camellia_f(d1, k[6]);
        d2 = camellia_fl(d2, ke[1]);  d1 = camellia_flinv(d1, ke[0]);
        d1 ^= camellia_f(d2, k[5]);   d2 ^= camellia_f(d1, k[4]);
        d1 ^= camellia_f(d2, k[3]);   d2 ^= camellia_f(d1, k[2]);
        d1 ^= camellia_f(d2, k[1]);   d2 ^= camellia_f(d1, k[0]);
        d2 ^= kw[1]; d1 ^= kw[0];
    }

    be64_store(out, d1, d2);   /* plaintext P = (D1 << 64) | D2 */
}

/* ------------------------------------------------------------------ */
/* Modes of operation                                                  */
/* ------------------------------------------------------------------ */

camellia_status camellia_encrypt(camellia_ctx *ctx,
                                 camellia_mode mode,
                                 const uint8_t *iv,
                                 const uint8_t *in,
                                 size_t len,
                                 uint8_t *out)
{
    uint8_t ks[CAMELLIA_BLOCK_SIZE];
    uint8_t reg[CAMELLIA_BLOCK_SIZE];
    uint8_t prev[CAMELLIA_BLOCK_SIZE];
    size_t i, blk, rem;

    if (mode == CAMELLIA_MODE_ECB || mode == CAMELLIA_MODE_CBC ||
        mode == CAMELLIA_MODE_CFB || mode == CAMELLIA_MODE_OFB) {
        if (len % CAMELLIA_BLOCK_SIZE != 0)
            return CAMELLIA_INVALID_LENGTH;
    }

    switch (mode) {
    case CAMELLIA_MODE_ECB:
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE)
            camellia_encrypt_block(ctx, in + blk, out + blk);
        return CAMELLIA_SUCCESS;

    case CAMELLIA_MODE_CBC:
        if (iv) memcpy(prev, iv, CAMELLIA_BLOCK_SIZE);
        else    memset(prev, 0, CAMELLIA_BLOCK_SIZE);
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE) {
            for (i = 0; i < CAMELLIA_BLOCK_SIZE; i++)
                out[blk + i] = in[blk + i] ^ prev[i];
            camellia_encrypt_block(ctx, out + blk, out + blk);
            memcpy(prev, out + blk, CAMELLIA_BLOCK_SIZE);
        }
        return CAMELLIA_SUCCESS;

    case CAMELLIA_MODE_CTR:
        if (iv) memcpy(reg, iv, CAMELLIA_BLOCK_SIZE);
        else    memset(reg, 0, CAMELLIA_BLOCK_SIZE);
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE) {
            camellia_encrypt_block(ctx, reg, ks);
            rem = (len - blk < CAMELLIA_BLOCK_SIZE) ? (len - blk) : CAMELLIA_BLOCK_SIZE;
            for (i = 0; i < rem; i++)
                out[blk + i] = in[blk + i] ^ ks[i];
            /* increment counter (128-bit big-endian) */
            for (i = CAMELLIA_BLOCK_SIZE; i-- > 0; ) {
                if (++reg[i] != 0)
                    break;
            }
        }
        return CAMELLIA_SUCCESS;

    case CAMELLIA_MODE_CFB:
        if (iv) memcpy(reg, iv, CAMELLIA_BLOCK_SIZE);
        else    memset(reg, 0, CAMELLIA_BLOCK_SIZE);
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE) {
            camellia_encrypt_block(ctx, reg, ks);
            for (i = 0; i < CAMELLIA_BLOCK_SIZE; i++) {
                out[blk + i] = in[blk + i] ^ ks[i];
                reg[i] = out[blk + i];   /* CFB feedback uses ciphertext */
            }
        }
        return CAMELLIA_SUCCESS;

    case CAMELLIA_MODE_OFB:
        if (iv) memcpy(reg, iv, CAMELLIA_BLOCK_SIZE);
        else    memset(reg, 0, CAMELLIA_BLOCK_SIZE);
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE) {
            camellia_encrypt_block(ctx, reg, reg);
            for (i = 0; i < CAMELLIA_BLOCK_SIZE; i++)
                out[blk + i] = in[blk + i] ^ reg[i];
        }
        return CAMELLIA_SUCCESS;

    default:
        return CAMELLIA_INVALID_MODE;
    }
}

camellia_status camellia_decrypt(camellia_ctx *ctx,
                                 camellia_mode mode,
                                 const uint8_t *iv,
                                 const uint8_t *in,
                                 size_t len,
                                 uint8_t *out)
{
    uint8_t ks[CAMELLIA_BLOCK_SIZE];
    uint8_t reg[CAMELLIA_BLOCK_SIZE];
    uint8_t prev[CAMELLIA_BLOCK_SIZE];
    size_t i, blk;

    if (mode == CAMELLIA_MODE_ECB || mode == CAMELLIA_MODE_CBC ||
        mode == CAMELLIA_MODE_CFB || mode == CAMELLIA_MODE_OFB) {
        if (len % CAMELLIA_BLOCK_SIZE != 0)
            return CAMELLIA_INVALID_LENGTH;
    }

    switch (mode) {
    case CAMELLIA_MODE_ECB:
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE)
            camellia_decrypt_block(ctx, in + blk, out + blk);
        return CAMELLIA_SUCCESS;

    case CAMELLIA_MODE_CBC:
        if (iv) memcpy(prev, iv, CAMELLIA_BLOCK_SIZE);
        else    memset(prev, 0, CAMELLIA_BLOCK_SIZE);
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE) {
            uint8_t ct[CAMELLIA_BLOCK_SIZE];
            memcpy(ct, in + blk, CAMELLIA_BLOCK_SIZE);   /* save ciphertext */
            camellia_decrypt_block(ctx, ct, out + blk);
            for (i = 0; i < CAMELLIA_BLOCK_SIZE; i++)
                out[blk + i] ^= prev[i];
            memcpy(prev, ct, CAMELLIA_BLOCK_SIZE);
        }
        return CAMELLIA_SUCCESS;

    case CAMELLIA_MODE_CTR:
        /* CTR is symmetric. */
        return camellia_encrypt(ctx, mode, iv, in, len, out);

    case CAMELLIA_MODE_CFB:
        if (iv) memcpy(reg, iv, CAMELLIA_BLOCK_SIZE);
        else    memset(reg, 0, CAMELLIA_BLOCK_SIZE);
        for (blk = 0; blk < len; blk += CAMELLIA_BLOCK_SIZE) {
            uint8_t ct[CAMELLIA_BLOCK_SIZE];
            camellia_encrypt_block(ctx, reg, ks);
            memcpy(ct, in + blk, CAMELLIA_BLOCK_SIZE);   /* save ciphertext */
            for (i = 0; i < CAMELLIA_BLOCK_SIZE; i++)
                out[blk + i] = ct[i] ^ ks[i];
            memcpy(reg, ct, CAMELLIA_BLOCK_SIZE);        /* feedback = ciphertext */
        }
        return CAMELLIA_SUCCESS;

    case CAMELLIA_MODE_OFB:
        /* OFB is symmetric. */
        return camellia_encrypt(ctx, mode, iv, in, len, out);

    default:
        return CAMELLIA_INVALID_MODE;
    }
}

/* ------------------------------------------------------------------ */
/* PKCS#7 padding                                                      */
/* ------------------------------------------------------------------ */

size_t camellia_pad_pkcs7(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap)
{
    size_t pad = CAMELLIA_BLOCK_SIZE - (in_len % CAMELLIA_BLOCK_SIZE);
    size_t total = in_len + pad;
    size_t i;
    if (out_cap < total)
        return 0;
    for (i = 0; i < in_len; i++)
        out[i] = in[i];
    for (i = 0; i < pad; i++)
        out[in_len + i] = (uint8_t)pad;
    return total;
}

size_t camellia_unpad_pkcs7(const uint8_t *in, size_t in_len,
                            uint8_t *out)
{
    size_t pad, i;
    if (in_len == 0 || in_len % CAMELLIA_BLOCK_SIZE != 0)
        return 0;
    pad = in[in_len - 1];
    if (pad == 0 || pad > CAMELLIA_BLOCK_SIZE || pad > in_len)
        return 0;
    for (i = in_len - pad; i < in_len; i++)
        if (in[i] != pad)
            return 0;
    for (i = 0; i < in_len - pad; i++)
        out[i] = in[i];
    return in_len - pad;
}

/* ------------------------------------------------------------------ */
/* Self-test (RFC 3713 Appendix A)                                     */
/* ------------------------------------------------------------------ */

int camellia_selftest(void)
{
    static const struct {
        int    key_bits;
        uint8_t key[32];
        uint8_t plain[CAMELLIA_BLOCK_SIZE];
        uint8_t cipher[CAMELLIA_BLOCK_SIZE];
    } vectors[3] = {
        { 128,
          {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
          {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
          {0x67,0x67,0x31,0x38,0x54,0x96,0x69,0x73,0x08,0x57,0x06,0x56,0x48,0xea,0xbe,0x43} },
        { 192,
          {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
           0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77},
          {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
          {0xb4,0x99,0x34,0x01,0xb3,0xe9,0x96,0xf8,0x4e,0xe5,0xce,0xe7,0xd7,0x9b,0x09,0xb9} },
        { 256,
          {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
           0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
          {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
          {0x9a,0xcc,0x23,0x7d,0xff,0x16,0xd7,0x6c,0x20,0xef,0x7c,0x91,0x9e,0x3a,0x75,0x09} }
    };
    int failures = 0;
    int v;
    for (v = 0; v < 3; v++) {
        camellia_ctx ctx;
        uint8_t out[CAMELLIA_BLOCK_SIZE];
        uint8_t dec[CAMELLIA_BLOCK_SIZE];
        size_t klen = vectors[v].key_bits / 8;
        if (camellia_set_key(&ctx, vectors[v].key, klen) != CAMELLIA_SUCCESS)
            return -1;
        camellia_encrypt_block(&ctx, vectors[v].plain, out);
        if (memcmp(out, vectors[v].cipher, CAMELLIA_BLOCK_SIZE) != 0)
            failures |= (1 << v);
        camellia_decrypt_block(&ctx, vectors[v].cipher, dec);
        if (memcmp(dec, vectors[v].plain, CAMELLIA_BLOCK_SIZE) != 0)
            failures |= (1 << (v + 8));
    }
    return failures;
}
