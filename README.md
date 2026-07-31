# Camellia — a clean C implementation

> *A forgotten Japanese cipher (NTT & Mitsubishi, 2000), revived as a small,
> dependency-free, drop-in library for modern software and IoT/edge targets.*

Camellia is a 128-bit block cipher with **128/192/256-bit keys**, designed by
[Nippon Telegraph and Telephone](https://www.ntt.co.jp) and
[Mitsubishi Electric](https://www.mitsubishielectric.com) in 2000. It has the
**same interface as AES** (block size + key sizes), was standardized as
**ISO/IEC 18033-3**, selected by Japan's **CRYPTREC** and the EU's **NESSIE**
project, and is specified in **RFC 3713**.

Despite being a solid, AES-comparable cipher, Camellia is rarely used outside
of Japanese government and Sony/Nintendo ecosystems — while the world defaulted
to AES everywhere. This repository revives it as a compact, auditable,
portable C library you can actually drop into a project today.

### Why reach for Camellia?

- **Zero dependencies, portable C99** — runs on 8-bit MCUs, smart cards, and servers alike.
- **Small code & data footprint** — ideal where AES code size or *key agility* matters (Camellia's key setup is notably fast).
- **Already standardized** — ISO/IEC 18033-3, RFC 3713, CRYPTREC, NESSIE. No "experimental" risk.
- **Companion to CLEFIA** (Sony, ISO/IEC 29192-2) for even lighter 128-bit-block lightweight crypto.

> Note: this library implements the raw cipher + standard modes. For
> production use, prefer it through a vetted TLS/IPS stack; this repo is meant
> for embedded, research, and "bring-your-own-crypto" contexts.

## Features

- Key sizes: 128 / 192 / 256 bits
- Modes: **ECB, CBC, CTR, CFB, OFB** (+ PKCS#7 padding helpers)
- Single-file core (`src/camellia.c`, ~600 lines, no external deps)
- Self-test against the official RFC 3713 vectors
- C API + Python `ctypes` bindings
- CMake + Make builds; GitHub Actions CI

## Build

### Make
```sh
make            # builds static + shared lib, CLI, benchmark, runs tests
make test       # run RFC 3713 self-test + mode roundtrips
./camellia-cli selftest
```

### CMake
```sh
cmake -S . -B build && cmake --build build && ctest --test-dir build
```

### Python bindings
```sh
make python             # builds libcamellia.so into python/
cd python && python3 camellia.py
```

## Usage (C)

```c
#include "camellia.h"

uint8_t key[32] = { /* 256-bit key */ };
uint8_t iv[16]  = { /* CBC IV */ };
camellia_ctx ctx;
camellia_set_key(&ctx, key, sizeof(key));

uint8_t ct[16], pt[16] = "hello world!!!";
camellia_encrypt_block(&ctx, pt, ct);     /* raw block */
camellia_decrypt_block(&ctx, ct, pt);

/* High-level modes */
uint8_t out[64];
camellia_encrypt(&ctx, CAMELLIA_MODE_CBC, iv, pt, 16, out);
camellia_decrypt(&ctx, CAMELLIA_MODE_CBC, iv, out, 16, pt);
```

### CLI
```sh
# key = 001122... (32 hex bytes = 256-bit); IV optional (defaults to zero)
camellia-cli enc -m cbc -k 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
                 -v 00000000000000000000000000000000 -i plain.bin -o cipher.bin
camellia-cli dec -m cbc -k <hexkey> -i cipher.bin -o plain.bin
camellia-cli bench 32     # MB/s throughput
```

### Python
```python
from camellia import Camellia, pkcs7_pad, pkcs7_unpad
c = Camellia(bytes(range(32)))
ct = c.encrypt(pkcs7_pad(b"secret message"), mode="cbc", iv=b"\x00"*16)
pt = pkcs7_unpad(c.decrypt(ct, mode="cbc", iv=b"\x00"*16))
```

## Correctness

The implementation is verified against the three official test vectors from
**RFC 3713, Appendix A** (128/192/256-bit keys), plus ECB/CBC/CTR/CFB/OFB
roundtrip and PKCS#7 padding checks. `camellia_selftest()` returns 0 on success.

| Key bits | Plaintext (`0123…3210`) | Ciphertext (RFC 3713) |
|---------:|-------------------------|------------------------|
| 128 | `0123456789abcdef fedcba9876543210` | `67673138 54966973 08570656 48eabe43` |
| 192 | same | `b4993401 b3e996f8 4ee5cee7 d79b09b9` |
| 256 | same | `9acc237d ff16d76c 20ef7c91 9e3a7509` |

## Benchmark

`tools/bench.c` measures ECB bulk encryption throughput and, when built with
OpenSSL (`-DHAVE_OPENSSL -lcrypto`), compares against OpenSSL's AES-256.

```sh
cc -O2 -DHAVE_OPENSSL -o bench tools/bench.c src/camellia.c -Iinclude -lcrypto
./bench 64
```

On x86-64 with OpenSSL's hardware-accelerated AES-NI, bulk Camellia (this
portable C build, no SIMD) measures roughly **100 MB/s vs ~880 MB/s** for
AES-256 — about 9× slower, which is expected: Camellia here is pure software
while OpenSSL uses AES-NI instructions. The point of this library is **not** to
outrun AES-NI on the desktop. It is to provide a small, auditable,
standardized cipher that is genuinely competitive on the platforms that *lack*
AES hardware — the bulk of 8/32-bit MCUs and embedded/IoT targets — where
Camellia's compact code size and notably fast key setup are what matter. If you
need maximum desktop throughput, use OpenSSL; if you need a dependency-free
cipher you can ship into a microcontroller, this is it.

## References

- RFC 3713 — *A Description of the Camellia Encryption Algorithm* (Matsui, Nakajima, Moriai)
- Aoki, Ichikawa, Kanda, Matsui, Moriai, Nakajima, Tokita — *Camellia: A 128-Bit Block Cipher Suitable for Multiple Platforms* (SAC 2000)
- ISO/IEC 18033-3 (block ciphers), CRYPTREC, NESSIE
- Companion cipher: **CLEFIA** (Sony, ISO/IEC 29192-2) for lightweight 128-bit-block encryption

## License

Apache 2.0 — see [LICENSE](LICENSE). Camellia algorithm itself is unpatented and
royalty-free (NTT/Mitsubishi).
