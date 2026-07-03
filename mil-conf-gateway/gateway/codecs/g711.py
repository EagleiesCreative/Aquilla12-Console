"""G.711 u-law / A-law.

Pure-Python implementation using ITU-T reference lookup tables.  Fast
enough at 8 kHz — encode/decode is memory-bound not CPU-bound.
"""
from __future__ import annotations

import numpy as np


# ---------- u-law (RFC 3551 PT 0) --------------------------------------- #
def linear_to_ulaw(pcm: np.ndarray) -> bytes:
    x = pcm.astype(np.int32)
    BIAS = 0x84
    CLIP = 32635
    sign = (x < 0).astype(np.uint8) * 0x80
    mag = np.clip(np.abs(x), 0, CLIP) + BIAS
    # exponent: position of highest bit
    exp = np.zeros_like(mag, dtype=np.uint8)
    for e in range(7, 0, -1):
        mask = (mag >= (1 << (e + 7))) & (exp == 0)
        exp[mask] = e
    mantissa = ((mag >> (exp + 3)) & 0x0F).astype(np.uint8)
    ulaw = ~(sign | (exp << 4) | mantissa) & 0xFF
    return ulaw.astype(np.uint8).tobytes()


def ulaw_to_linear(buf: bytes) -> np.ndarray:
    u = np.frombuffer(buf, dtype=np.uint8).astype(np.int32) ^ 0xFF
    sign = u & 0x80
    exp = (u >> 4) & 0x07
    mantissa = u & 0x0F
    magnitude = ((mantissa << 3) + 0x84) << exp
    magnitude -= 0x84
    out = np.where(sign, -magnitude, magnitude).astype(np.int16)
    return out


# ---------- A-law (RFC 3551 PT 8) --------------------------------------- #
def linear_to_alaw(pcm: np.ndarray) -> bytes:
    x = pcm.astype(np.int32)
    sign = (x < 0).astype(np.uint8) * 0x80
    mag = np.clip(np.abs(x), 0, 32635)
    exp = np.zeros_like(mag, dtype=np.uint8)
    for e in range(7, 0, -1):
        mask = (mag >= (1 << (e + 4))) & (exp == 0)
        exp[mask] = e
    mantissa = np.where(exp == 0, (mag >> 4) & 0x0F,
                        (mag >> (exp + 3)) & 0x0F).astype(np.uint8)
    alaw = (sign | (exp << 4) | mantissa) ^ 0x55
    return alaw.astype(np.uint8).tobytes()


def alaw_to_linear(buf: bytes) -> np.ndarray:
    a = np.frombuffer(buf, dtype=np.uint8).astype(np.int32) ^ 0x55
    sign = a & 0x80
    exp = (a >> 4) & 0x07
    mantissa = a & 0x0F
    magnitude = np.where(exp == 0, (mantissa << 4) + 8,
                         ((mantissa << 4) + 0x108) << (exp - 1))
    out = np.where(sign, -magnitude, magnitude).astype(np.int16)
    return out
