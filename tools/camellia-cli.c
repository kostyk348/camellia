/*
 * camellia-cli.c - Command-line tool for the Camellia cipher.
 *
 * Usage:
 *   camellia-cli selftest
 *   camellia-cli bench [megabytes]
 *   camellia-cli enc -m <ecb|cbc|ctr|cfb|ofb> -k <hexkey> [-v <hexiv>]
 *                    -i <infile> -o <outfile>
 *   camellia-cli dec -m <mode> -k <hexkey> [-v <hexiv>] -i <infile> -o <outfile>
 *
 * Key length selects 128/192/256 bits (16/24/32 hex bytes).
 * ECB/CBC/CFB/OFB are auto PKCS#7 padded on encrypt and unpadded on decrypt;
 * CTR is a streaming mode (no padding).
 *
 * SPDX-License-Identifier: MIT
 */
#include "camellia.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int parse_hex(const char *s, uint8_t *out, size_t maxout, size_t *outlen)
{
    size_t n = strlen(s);
    size_t i, j = 0;
    if (n % 2 != 0)
        return -1;
    for (i = 0; i < n; i += 2) {
        int hi = -1, lo = -1;
        char c1 = s[i], c2 = s[i + 1];
        hi = (c1 >= '0' && c1 <= '9') ? c1 - '0' :
             (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 :
             (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
        lo = (c2 >= '0' && c2 <= '9') ? c2 - '0' :
             (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 :
             (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
        if (hi < 0 || lo < 0 || j >= maxout)
            return -1;
        out[j++] = (uint8_t)((hi << 4) | lo);
    }
    *outlen = j;
    return 0;
}

static int read_all(FILE *f, uint8_t **buf, size_t *len)
{
    size_t cap = 1 << 16, sz = 0;
    uint8_t *b = malloc(cap);
    if (!b) return -1;
    for (;;) {
        if (sz == cap) {
            cap *= 2;
            b = realloc(b, cap);
            if (!b) return -1;
        }
        size_t r = fread(b + sz, 1, cap - sz, f);
        sz += r;
        if (r == 0) {
            if (feof(f)) break;
            if (ferror(f)) { free(b); return -1; }
        }
    }
    *buf = b;
    *len = sz;
    return 0;
}

static camellia_mode parse_mode(const char *s)
{
    if (!strcmp(s, "ecb"))  return CAMELLIA_MODE_ECB;
    if (!strcmp(s, "cbc"))  return CAMELLIA_MODE_CBC;
    if (!strcmp(s, "ctr"))  return CAMELLIA_MODE_CTR;
    if (!strcmp(s, "cfb"))  return CAMELLIA_MODE_CFB;
    if (!strcmp(s, "ofb"))  return CAMELLIA_MODE_OFB;
    return (camellia_mode)-1;
}

static int do_cipher(int encrypt, camellia_mode mode, const char *keyhex,
                     const char *ivhex, const char *infile, const char *outfile)
{
    uint8_t key[32], iv[CAMELLIA_BLOCK_SIZE];
    uint8_t *in = NULL, *out = NULL, *padded = NULL;
    size_t keylen = 0, inlen = 0, outlen = 0, padlen = 0;
    camellia_ctx ctx;
    FILE *fin = NULL, *fout = NULL;
    int rc = 1;

    if (parse_hex(keyhex, key, sizeof(key), &keylen) != 0 ||
        (keylen != 16 && keylen != 24 && keylen != 32)) {
        fprintf(stderr, "invalid key (need 16/24/32 hex bytes)\n");
        return 1;
    }
    if (ivhex) {
        size_t ivlen = 0;
        if (parse_hex(ivhex, iv, sizeof(iv), &ivlen) != 0 || ivlen != CAMELLIA_BLOCK_SIZE) {
            fprintf(stderr, "invalid iv (need 16 hex bytes)\n");
            return 1;
        }
    } else {
        memset(iv, 0, sizeof(iv));
    }

    if (camellia_set_key(&ctx, key, keylen) != CAMELLIA_SUCCESS) {
        fprintf(stderr, "key setup failed\n");
        return 1;
    }

    fin = strcmp(infile, "-") == 0 ? stdin : fopen(infile, "rb");
    if (!fin) { perror("open input"); goto done; }
    if (read_all(fin, &in, &inlen) != 0) { fprintf(stderr, "read failed\n"); goto done; }

    const uint8_t *src = in;   /* buffer actually fed to the cipher */
    if (encrypt) {
        if (mode == CAMELLIA_MODE_CTR) {
            outlen = inlen;
        } else {
            padlen = CAMELLIA_BLOCK_SIZE - (inlen % CAMELLIA_BLOCK_SIZE);
            padded = malloc(inlen + padlen);
            if (!padded) { fprintf(stderr, "oom\n"); goto done; }
            outlen = camellia_pad_pkcs7(in, inlen, padded, inlen + padlen);
            src = padded;      /* cipher from the PKCS#7-padded buffer */
        }
    } else {
        if (inlen % CAMELLIA_BLOCK_SIZE != 0 && mode != CAMELLIA_MODE_CTR) {
            fprintf(stderr, "ciphertext length not a multiple of block size\n");
            goto done;
        }
        outlen = inlen;
    }

    out = malloc(outlen ? outlen : 1);
    if (!out) { fprintf(stderr, "oom\n"); goto done; }

    camellia_status st = encrypt
        ? camellia_encrypt(&ctx, mode, iv, src, outlen, out)
        : camellia_decrypt(&ctx, mode, iv, src, outlen, out);
    if (st != CAMELLIA_SUCCESS) {
        fprintf(stderr, "cipher error %d\n", st);
        goto done;
    }

    if (!encrypt && mode != CAMELLIA_MODE_CTR) {
        size_t unp = camellia_unpad_pkcs7(out, outlen, out);
        if (unp == 0) {
            fprintf(stderr, "invalid PKCS#7 padding (wrong key or corrupt data?)\n");
            goto done;
        }
        outlen = unp;
    }

    fout = strcmp(outfile, "-") == 0 ? stdout : fopen(outfile, "wb");
    if (!fout) { perror("open output"); goto done; }
    if (fwrite(out, 1, outlen, fout) != outlen) {
        fprintf(stderr, "write failed\n"); goto done;
    }
    rc = 0;
done:
    if (fin && fin != stdin) fclose(fin);
    if (fout && fout != stdout) fclose(fout);
    free(in); free(out); free(padded);
    return rc;
}

static int do_bench(long megabytes)
{
    camellia_ctx ctx;
    static const uint8_t key[32] = {0};
    long total = megabytes * 1024L * 1024L;
    long nblocks = total / CAMELLIA_BLOCK_SIZE;
    uint8_t *buf = malloc(total ? total : 1);
    uint8_t *out = malloc(total ? total : 1);
    clock_t t0, t1;
    double secs, mbps;
    long i;
    int rc = 1;
    if (!buf || !out) { fprintf(stderr, "oom\n"); goto done; }
    for (i = 0; i < total; i++) buf[i] = (uint8_t)i;

    if (camellia_set_key(&ctx, key, 32) != CAMELLIA_SUCCESS) goto done;
    t0 = clock();
    for (i = 0; i < nblocks; i++)
        camellia_encrypt_block(&ctx, buf + i * CAMELLIA_BLOCK_SIZE,
                                     out + i * CAMELLIA_BLOCK_SIZE);
    t1 = clock();
    secs = (double)(t1 - t0) / CLOCKS_PER_SEC;
    mbps = secs > 0 ? (double)total / (1024.0 * 1024.0) / secs : 0;
    printf("Camellia-256 ECB: %.2f MB/s  (%.3f s for %ld MB)\n", mbps, secs, megabytes);
    rc = 0;
done:
    free(buf); free(out);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "selftest")) {
        int rc = camellia_selftest();
        if (rc != 0) { printf("self-test FAILED (mask=0x%04x)\n", rc); return 1; }
        printf("self-test PASS\n");
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "bench")) {
        long mb = (argc >= 3) ? atol(argv[2]) : 16;
        if (mb <= 0) mb = 16;
        return do_bench(mb);
    }
    if (argc >= 2 && (!strcmp(argv[1], "enc") || !strcmp(argv[1], "dec"))) {
        int encrypt = !strcmp(argv[1], "enc");
        const char *mode = "cbc", *key = NULL, *iv = NULL, *in = NULL, *out = "-";
        int i;
        for (i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "-m") && i + 1 < argc) mode = argv[++i];
            else if (!strcmp(argv[i], "-k") && i + 1 < argc) key = argv[++i];
            else if (!strcmp(argv[i], "-v") && i + 1 < argc) iv = argv[++i];
            else if (!strcmp(argv[i], "-i") && i + 1 < argc) in = argv[++i];
            else if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
            else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 1; }
        }
        if (!key || !in) {
            fprintf(stderr, "usage: camellia-cli %s -m <mode> -k <hexkey> [-v <hexiv>] -i <in> -o <out>\n",
                    encrypt ? "enc" : "dec");
            return 1;
        }
        camellia_mode m = parse_mode(mode);
        if (m < 0) { fprintf(stderr, "bad mode\n"); return 1; }
        return do_cipher(encrypt, m, key, iv, in, out);
    }
    fprintf(stderr,
        "usage:\n"
        "  camellia-cli selftest\n"
        "  camellia-cli bench [megabytes]\n"
        "  camellia-cli enc -m <ecb|cbc|ctr|cfb|ofb> -k <hexkey> [-v <hexiv>] -i <in> -o <out>\n"
        "  camellia-cli dec -m <mode> -k <hexkey> [-v <hexiv>] -i <in> -o <out>\n");
    return 1;
}
