"""
camellia.py - Python ctypes bindings for the Camellia C library.

Build the shared library first:
    cc -shared -fPIC -O2 -o libcamellia.so ../src/camellia.c -I../include

Then use:
    from camellia import Camellia
    c = Camellia(b'\\x00' * 32)           # 256-bit key
    ct = c.encrypt(b'hello world!!', mode='cbc', iv=b'\\x00' * 16)
    pt = c.decrypt(ct, mode='cbc', iv=b'\\x00' * 16)

SPDX-License-Identifier: MIT
"""
import ctypes
import os

_MODES = {"ecb": 0, "cbc": 1, "ctr": 2, "cfb": 3, "ofb": 4}
_BLOCK = 16


def _load_lib():
    name = os.environ.get("CAMELLIA_LIB")
    candidates = []
    if name:
        candidates.append(name)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates += [
        os.path.join(here, "libcamellia.so"),
        os.path.join(here, "..", "libcamellia.so"),
        "libcamellia.so",
        "/usr/local/lib/libcamellia.so",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return ctypes.CDLL(c)
    raise RuntimeError("libcamellia.so not found; build it or set CAMELLIA_LIB")


_lib = _load_lib()

_lib.camellia_set_key.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
_lib.camellia_set_key.restype = ctypes.c_int

_lib.camellia_encrypt.argtypes = [
    ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8)]
_lib.camellia_encrypt.restype = ctypes.c_int

_lib.camellia_decrypt.argtypes = _lib.camellia_encrypt.argtypes
_lib.camellia_decrypt.restype = ctypes.c_int

_lib.camellia_pad_pkcs7.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
_lib.camellia_pad_pkcs7.restype = ctypes.c_size_t

_lib.camellia_unpad_pkcs7.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8)]
_lib.camellia_unpad_pkcs7.restype = ctypes.c_size_t

_lib.camellia_selftest.argtypes = []
_lib.camellia_selftest.restype = ctypes.c_int

# Opaque context struct size: 4*8 + 24*8 + 6*8 + 4 + 4 = 32+192+48+8 = 280 bytes.
_CTX_SIZE = 4 * 8 + 24 * 8 + 6 * 8 + 4 + 4


class CamelliaError(Exception):
    pass


class Camellia:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise CamelliaError("key must be 16/24/32 bytes")
        self._ctx = ctypes.create_string_buffer(_CTX_SIZE)
        res = _lib.camellia_set_key(self._ctx, (ctypes.c_uint8 * len(key))(*key), len(key))
        if res != 0:
            raise CamelliaError("key setup failed: %d" % res)

    @staticmethod
    def selftest() -> bool:
        return _lib.camellia_selftest() == 0

    def _run(self, func, data: bytes, mode: str, iv):
        m = _MODES.get(mode)
        if m is None:
            raise CamelliaError("unknown mode %r" % mode)
        blocking = mode in ("ecb", "cbc", "cfb", "ofb")
        if blocking and len(data) % _BLOCK != 0:
            raise CamelliaError("data length must be a multiple of 16 for %s" % mode)
        ivb = iv if iv is not None else (b"\x00" * _BLOCK)
        if len(ivb) != _BLOCK:
            raise CamelliaError("iv must be 16 bytes")
        inp = (ctypes.c_uint8 * len(data))(*data)
        out = (ctypes.c_uint8 * len(data))()
        ivarr = (ctypes.c_uint8 * _BLOCK)(*ivb)
        res = func(self._ctx, m, ivarr, inp, len(data), out)
        if res != 0:
            raise CamelliaError("cipher error %d" % res)
        return bytes(out)

    def encrypt(self, data: bytes, mode: str = "cbc", iv: bytes = None) -> bytes:
        return self._run(_lib.camellia_encrypt, data, mode, iv)

    def decrypt(self, data: bytes, mode: str = "cbc", iv: bytes = None) -> bytes:
        return self._run(_lib.camellia_decrypt, data, mode, iv)


def pkcs7_pad(data: bytes) -> bytes:
    pad = _BLOCK - (len(data) % _BLOCK)
    out = (ctypes.c_uint8 * (len(data) + pad))()
    res = _lib.camellia_pad_pkcs7(
        (ctypes.c_uint8 * len(data))(*data), len(data), out, len(out))
    if res == 0:
        raise CamelliaError("pad failed")
    return bytes(out[:res])


def pkcs7_unpad(data: bytes) -> bytes:
    out = (ctypes.c_uint8 * len(data))()
    res = _lib.camellia_unpad_pkcs7((ctypes.c_uint8 * len(data))(*data), len(data), out)
    if res == 0:
        raise CamelliaError("invalid padding")
    return bytes(out[:res])


if __name__ == "__main__":
    ok = Camellia.selftest()
    print("self-test:", "PASS" if ok else "FAIL")
    key = bytes(range(32))
    c = Camellia(key)
    msg = b"Camellia revived from Japan, 2000 -> today."
    iv = b"\x00" * 16
    padded = pkcs7_pad(msg)
    ct = c.encrypt(padded, mode="cbc", iv=iv)
    pt = c.decrypt(ct, mode="cbc", iv=iv)
    print("roundtrip:", "PASS" if pkcs7_unpad(pt) == msg else "FAIL")
