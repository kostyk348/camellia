/*
 * test_camellia.c - Runs RFC 3713 self-test and mode roundtrip checks.
 *
 * SPDX-License-Identifier: MIT
 */
#include "camellia.h"
#include <stdio.h>
#include <string.h>

static int hexeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

/* Quick deterministic PRNG so we don't depend on <stdlib.h> randomness. */
static uint32_t lcg = 0x12345678u;
static uint8_t rnd_byte(void)
{
    lcg = lcg * 1664525u + 1013904223u;
    return (uint8_t)(lcg >> 16);
}

static int test_modes(void)
{
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t iv[CAMELLIA_BLOCK_SIZE] = {
        0xde,0xad,0xbe,0xef,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb
    };
    camellia_ctx ctx;
    uint8_t pt[64], ct[64], dt[64];
    camellia_mode modes[] = {
        CAMELLIA_MODE_ECB, CAMELLIA_MODE_CBC, CAMELLIA_MODE_CTR,
        CAMELLIA_MODE_CFB, CAMELLIA_MODE_OFB
    };
    const char *names[] = { "ECB", "CBC", "CTR", "CFB", "OFB" };
    int i, m, ok = 1;

    /* 256-bit key. */
    if (camellia_set_key(&ctx, key, sizeof(key)) != CAMELLIA_SUCCESS)
        return 0;

    for (i = 0; i < (int)sizeof(pt); i++)
        pt[i] = rnd_byte();

    for (m = 0; m < 5; m++) {
        size_t plen = 64; /* multiple of block for all modes */
        if (camellia_encrypt(&ctx, modes[m], iv, pt, plen, ct) != CAMELLIA_SUCCESS) {
            printf("  mode %s: encrypt FAILED (api)\n", names[m]); ok = 0; continue;
        }
        if (hexeq(pt, ct, plen)) {
            printf("  mode %s: plaintext == ciphertext (BAD)\n", names[m]); ok = 0; continue;
        }
        if (camellia_decrypt(&ctx, modes[m], iv, ct, plen, dt) != CAMELLIA_SUCCESS) {
            printf("  mode %s: decrypt FAILED (api)\n", names[m]); ok = 0; continue;
        }
        if (!hexeq(pt, dt, plen)) {
            printf("  mode %s: roundtrip MISMATCH\n", names[m]); ok = 0; continue;
        }
        printf("  mode %s: OK\n", names[m]);
    }

    /* CTR streaming: encrypt/decrypt arbitrary (non-block-aligned) length. */
    {
        uint8_t pt2[37], ct2[37], dt2[37];
        for (i = 0; i < 37; i++) pt2[i] = rnd_byte();
        camellia_encrypt(&ctx, CAMELLIA_MODE_CTR, iv, pt2, 37, ct2);
        camellia_decrypt(&ctx, CAMELLIA_MODE_CTR, iv, ct2, 37, dt2);
        if (!hexeq(pt2, dt2, 37)) { printf("  CTR(37B): roundtrip MISMATCH\n"); ok = 0; }
        else printf("  CTR(37B): OK\n");
    }

    /* PKCS#7 padding roundtrip. */
    {
        uint8_t p[20], buf[64], unp[64];
        size_t plen = 20, padded, unplen;
        for (i = 0; i < 20; i++) p[i] = rnd_byte();
        padded = camellia_pad_pkcs7(p, plen, buf, sizeof(buf));
        camellia_encrypt(&ctx, CAMELLIA_MODE_CBC, iv, buf, padded, buf);
        camellia_decrypt(&ctx, CAMELLIA_MODE_CBC, iv, buf, padded, buf);
        unplen = camellia_unpad_pkcs7(buf, padded, unp);
        if (unplen != plen || !hexeq(p, unp, plen)) {
            printf("  PKCS7: roundtrip MISMATCH\n"); ok = 0;
        } else printf("  PKCS7: OK\n");
    }
    return ok;
}

int main(void)
{
    int rc = camellia_selftest();
    if (rc != 0) {
        printf("RFC 3713 self-test FAILED (mask=0x%04x)\n", rc);
        return 1;
    }
    printf("RFC 3713 self-test: PASS (128/192/256 vectors)\n");

    if (!test_modes()) {
        printf("Mode roundtrip: FAILED\n");
        return 1;
    }
    printf("Mode roundtrip: PASS\n");
    printf("ALL TESTS PASSED\n");
    return 0;
}
