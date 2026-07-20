/*
 * bench.c - Throughput benchmark: Camellia vs OpenSSL AES (optional).
 *
 * Build without OpenSSL:  cc -O2 -o bench bench.c camellia.c -I../include
 * Build with OpenSSL:     cc -O2 -DHAVE_OPENSSL -o bench bench.c camellia.c \
 *                              -I../include -lcrypto
 *
 * SPDX-License-Identifier: MIT
 */
#include "camellia.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

static double now_sec(void)
{
    return (double)clock() / CLOCKS_PER_SEC;
}

static double bench_camellia(long nblocks)
{
    camellia_ctx ctx;
    static const uint8_t key[32] = {0};
    uint8_t *buf = malloc(nblocks * CAMELLIA_BLOCK_SIZE);
    uint8_t *out = malloc(nblocks * CAMELLIA_BLOCK_SIZE);
    long i;
    double t0, t1;
    if (!buf || !out) { fprintf(stderr, "oom\n"); exit(1); }
    for (i = 0; i < nblocks * CAMELLIA_BLOCK_SIZE; i++) buf[i] = (uint8_t)(i * 31);
    camellia_set_key(&ctx, key, 32);
    t0 = now_sec();
    for (i = 0; i < nblocks; i++)
        camellia_encrypt_block(&ctx, buf + i * CAMELLIA_BLOCK_SIZE,
                                     out + i * CAMELLIA_BLOCK_SIZE);
    t1 = now_sec();
    free(buf); free(out);
    return (double)nblocks * CAMELLIA_BLOCK_SIZE / (1024.0 * 1024.0) / (t1 - t0);
}

#ifdef HAVE_OPENSSL
static double bench_openssl_aes(long nblocks)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    static const uint8_t key[32] = {0};
    static const uint8_t iv[16] = {0};
    uint8_t *buf = malloc(nblocks * CAMELLIA_BLOCK_SIZE);
    uint8_t *out = malloc(nblocks * CAMELLIA_BLOCK_SIZE);
    long i;
    double t0, t1;
    int outl, tot;
    if (!c || !buf || !out) { fprintf(stderr, "oom\n"); exit(1); }
    for (i = 0; i < nblocks * CAMELLIA_BLOCK_SIZE; i++) buf[i] = (uint8_t)(i * 31);
    EVP_EncryptInit_ex(c, EVP_aes_256_ecb(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(c, 0);
    t0 = now_sec();
    for (i = 0; i < nblocks; i++) {
        EVP_EncryptUpdate(c, out + i * CAMELLIA_BLOCK_SIZE, &outl,
                             buf + i * CAMELLIA_BLOCK_SIZE, CAMELLIA_BLOCK_SIZE);
    }
    EVP_EncryptFinal_ex(c, out, &tot);
    t1 = now_sec();
    EVP_CIPHER_CTX_free(c);
    free(buf); free(out);
    return (double)nblocks * CAMELLIA_BLOCK_SIZE / (1024.0 * 1024.0) / (t1 - t0);
}
#endif

int main(int argc, char **argv)
{
    long mb = (argc >= 2) ? atol(argv[1]) : 32;
    if (mb <= 0) mb = 32;
    long nblocks = mb * 1024L * 1024L / CAMELLIA_BLOCK_SIZE;

    printf("Encrypting %ld MB of data (ECB, 256-bit key)...\n", mb);
    printf("  Camellia-256 : %8.2f MB/s\n", bench_camellia(nblocks));
#ifdef HAVE_OPENSSL
    printf("  AES-256 (OSSL): %8.2f MB/s\n", bench_openssl_aes(nblocks));
#else
    printf("  AES-256 (OSSL):    (build with -DHAVE_OPENSSL -lcrypto to compare)\n");
#endif
    return 0;
}
