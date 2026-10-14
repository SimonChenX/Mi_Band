"""Small crypto helpers used by the Huami "2021" protocol.

All primitives match Gadgetbridge (``CryptoUtils`` / ``CheckSums``):

* AES-128 in ECB mode with **no padding**,
* standard CRC-32 (zlib).
"""

from __future__ import annotations

import zlib

from Crypto.Cipher import AES


def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """AES/ECB/NoPadding encrypt. ``data`` must be a multiple of 16 bytes."""
    if len(data) % 16 != 0:
        raise ValueError("AES/ECB/NoPadding requires a multiple of 16 bytes")
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """AES/ECB/NoPadding decrypt. ``data`` must be a multiple of 16 bytes."""
    if len(data) % 16 != 0:
        raise ValueError("AES/ECB/NoPadding requires a multiple of 16 bytes")
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def crc32(data: bytes) -> int:
    """CRC-32 (same polynomial as java.util.zip.CRC32 / zlib)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def calc_max_write_chunk(mtu: int) -> int:
    """Gadgetbridge ``AbstractBTLEDeviceSupport.calcMaxWriteChunk``."""
    safe_mtu = max(23, mtu)
    return min(512, safe_mtu - 3)