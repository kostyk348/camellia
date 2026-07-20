/*
 * camellia.h - Public API for the Camellia block cipher (RFC 3713).
 *
 * 128-bit block cipher with 128/192/256-bit keys, designed by NTT and
 * Mitsubishi Electric (2000). Suitable for both software and hardware,
 * including 8-bit smart cards and embedded/IoT targets.
 *
 * This is a clean-room, dependency-free, portable C99 implementation
 * intended as a drop-in lightweight alternative to AES where code size
 * or key agility matters (e.g. constrained IoT/edge devices).
 *
 * Reference: RFC 3713 "A Description of the Camellia Encryption Algorithm".
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef CAMELLIA_H
#define CAMELLIA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAMELLIA_BLOCK_SIZE    16u
#define CAMELLIA_MAX_KEY_BYTES 32u   /* 256-bit key */

typedef enum {
    CAMELLIA_SUCCESS         = 0,
    CAMELLIA_INVALID_KEYLEN  = -1,  /* key length not 16/24/32 bytes */
    CAMELLIA_INVALID_LENGTH  = -2,  /* data length not a multiple of block for
                                       block-aligned modes (ECB/CBC/CFB/OFB) */
    CAMELLIA_INVALID_MODE    = -3,
    CAMELLIA_INVALID_PADDING = -4   /* PKCS#7 unpad failed */
} camellia_status;

typedef enum {
    CAMELLIA_MODE_ECB = 0,
    CAMELLIA_MODE_CBC,
    CAMELLIA_MODE_CTR,
    CAMELLIA_MODE_CFB,
    CAMELLIA_MODE_OFB
} camellia_mode;

/* Opaque-ish context holding expanded subkeys. */
typedef struct {
    uint64_t kw[4];   /* whitening subkeys  (kw1..kw4) */
    uint64_t k[24];   /* round subkeys      (k1..k24)  */
    uint64_t ke[6];   /* FL/FLINV subkeys   (ke1..ke6) */
    int      rounds;  /* 18 (128-bit key) or 24 (192/256-bit key) */
    int      key_bits;
} camellia_ctx;

/*
 * Expand a key of 16, 24 or 32 bytes (128/192/256 bits) into a context.
 * Returns CAMELLIA_INVALID_KEYLEN for other lengths.
 */
camellia_status camellia_set_key(camellia_ctx *ctx,
                                 const uint8_t *key,
                                 size_t key_len);

/* Encrypt/decrypt a single 16-byte block in-place compatible manner. */
void camellia_encrypt_block(const camellia_ctx *ctx,
                            const uint8_t in[CAMELLIA_BLOCK_SIZE],
                            uint8_t out[CAMELLIA_BLOCK_SIZE]);
void camellia_decrypt_block(const camellia_ctx *ctx,
                            const uint8_t in[CAMELLIA_BLOCK_SIZE],
                            uint8_t out[CAMELLIA_BLOCK_SIZE]);

/*
 * High-level mode helpers.
 *
 *   iv        : CAMELLIA_BLOCK_SIZE bytes.
 *               ECB  -> ignored.
 *               CBC  -> initialization vector.
 *               CTR  -> initial counter block (treated as a 128-bit
 *                       big-endian integer, incremented per block).
 *               CFB/OFB -> initialization vector.
 *   in/out    : may alias (in == out) for in-place operation.
 *
 * Length rules:
 *   ECB/CBC/CFB/OFB require len to be a multiple of CAMELLIA_BLOCK_SIZE.
 *   CTR accepts any length (streaming mode).
 * Returns CAMELLIA_INVALID_LENGTH otherwise.
 */
camellia_status camellia_encrypt(camellia_ctx *ctx,
                                 camellia_mode mode,
                                 const uint8_t *iv,
                                 const uint8_t *in,
                                 size_t len,
                                 uint8_t *out);
camellia_status camellia_decrypt(camellia_ctx *ctx,
                                 camellia_mode mode,
                                 const uint8_t *iv,
                                 const uint8_t *in,
                                 size_t len,
                                 uint8_t *out);

/* PKCS#7 padding. Returns padded length (multiple of block size).
 * out must have capacity in_len + CAMELLIA_BLOCK_SIZE. */
size_t camellia_pad_pkcs7(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap);

/* PKCS#7 unpadding. Returns unpadded length, or 0 on invalid padding. */
size_t camellia_unpad_pkcs7(const uint8_t *in, size_t in_len,
                            uint8_t *out);

/* Self-test against RFC 3713 test vectors. Returns 0 on success,
 * non-zero (bitmask of failed vectors) on failure. */
int camellia_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* CAMELLIA_H */
