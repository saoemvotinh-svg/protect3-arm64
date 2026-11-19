"""IETF ChaCha20 for at-rest .text transformation. Keys remain in the loader."""

import struct


def chacha20(data, key, nonce, counter=1):
    if len(key) != 32 or len(nonce) != 12 or not 0 <= counter < 1 << 32:
        raise ValueError("ChaCha20 requires a 32-byte key, 12-byte nonce and uint32 counter.")
    if (len(data) + 63) // 64 + counter > 1 << 32:
        raise ValueError("ChaCha20 block counter would overflow.")
    result = bytearray(data)
    initial = list(struct.unpack("<4I", b"expand 32-byte k") + struct.unpack("<8I", key)
                   + (counter,) + struct.unpack("<3I", nonce))

    def rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def qr(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rotate(x[b] ^ x[c], 7)

    for offset in range(0, len(result), 64):
        x = initial.copy()
        for _ in range(10):
            for indices in ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                            (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)):
                qr(x, *indices)
        block = struct.pack("<16I", *((a+b) & 0xFFFFFFFF for a, b in zip(x, initial)))
        for j in range(min(64, len(result) - offset)):
            result[offset+j] ^= block[j]
        initial[12] = (initial[12] + 1) & 0xFFFFFFFF
    return bytes(result)
