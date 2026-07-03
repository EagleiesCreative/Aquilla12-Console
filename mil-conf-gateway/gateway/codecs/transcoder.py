"""Codec factory + resampling glue.

Every ``CodecInstance`` exposes the same tiny protocol:

    encode(pcm_bus_bytes) -> payload_bytes
    decode(payload_bytes) -> pcm_bus_bytes
    samples_per_frame     : int (native samples, for RTP timestamp delta)
    payload_type          : int (RTP PT)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import numpy as np

from . import g711
from .opus_codec import OpusCodec


BUS_RATE = 16000
FRAME_MS = 20
BUS_SAMPLES = BUS_RATE * FRAME_MS // 1000       # 320 samples / frame


# --------------------------------------------------------------------------- #
def _resample_down(pcm16k: np.ndarray, target_rate: int) -> np.ndarray:
    """Cheap decimation.  BUS_RATE / target_rate must be integer."""
    ratio = BUS_RATE // target_rate
    if ratio == 1:
        return pcm16k
    # box-filter to cut aliasing, then decimate
    kernel = np.ones(ratio, dtype=np.int32)
    conv = np.convolve(pcm16k.astype(np.int32), kernel, mode="same") // ratio
    return conv[::ratio].astype(np.int16)


def _resample_up(pcm_low: np.ndarray, source_rate: int) -> np.ndarray:
    ratio = BUS_RATE // source_rate
    if ratio == 1:
        return pcm_low
    out = np.repeat(pcm_low, ratio)             # zero-order hold, cheap
    return out.astype(np.int16)


# --------------------------------------------------------------------------- #
@dataclass
class CodecInstance:
    name: str
    payload_type: int
    samples_per_frame: int          # native sample count per RTP packet
    encode: Callable[[bytes], bytes]
    decode: Callable[[bytes], bytes]


# ---- G.711 factories ----
def _make_pcmu() -> CodecInstance:
    native_rate = 8000
    n_samples = native_rate * FRAME_MS // 1000      # 160

    def enc(pcm_bus: bytes) -> bytes:
        arr = np.frombuffer(pcm_bus, dtype=np.int16)
        down = _resample_down(arr, native_rate)
        return g711.linear_to_ulaw(down)

    def dec(payload: bytes) -> bytes:
        pcm = g711.ulaw_to_linear(payload)
        return _resample_up(pcm, native_rate).tobytes()

    return CodecInstance("PCMU", 0, n_samples, enc, dec)


def _make_pcma() -> CodecInstance:
    native_rate = 8000
    n_samples = native_rate * FRAME_MS // 1000

    def enc(pcm_bus: bytes) -> bytes:
        arr = np.frombuffer(pcm_bus, dtype=np.int16)
        return g711.linear_to_alaw(_resample_down(arr, native_rate))

    def dec(payload: bytes) -> bytes:
        pcm = g711.alaw_to_linear(payload)
        return _resample_up(pcm, native_rate).tobytes()

    return CodecInstance("PCMA", 8, n_samples, enc, dec)


# ---- Opus factory ----
def _make_opus() -> CodecInstance:
    opus = OpusCodec()
    return CodecInstance(
        name="opus",
        payload_type=111,               # dynamic PT (WebRTC convention)
        samples_per_frame=BUS_SAMPLES,
        encode=opus.encode,
        decode=opus.decode,
    )


# ---- G.729 factory (optional) ----
def _make_g729() -> Optional[CodecInstance]:
    try:
        from .g729 import G729Codec
        c = G729Codec()
    except Exception:
        return None
    native_rate = 8000
    n_samples = native_rate * FRAME_MS // 1000

    return CodecInstance(
        name="G729",
        payload_type=18,
        samples_per_frame=n_samples,
        encode=c.encode,
        decode=c.decode,
    )


# --------------------------------------------------------------------------- #
_FACTORIES = {
    "PCMU": _make_pcmu,
    "PCMA": _make_pcma,
    "opus": _make_opus,
    "G729": _make_g729,
}


def make_codec(name: str) -> Optional[CodecInstance]:
    fac = _FACTORIES.get(name)
    if not fac:
        return None
    try:
        return fac()
    except Exception:
        return None
