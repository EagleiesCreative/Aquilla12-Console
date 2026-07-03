"""Opus codec via PyAV (libavcodec).

We use PyAV because it is the most stable Python binding to libopus and
already ships wheels for Linux/macOS/Windows.  Everything is wide-band 16
kHz mono — matches the internal bus rate exactly, so no resampling.
"""
from __future__ import annotations

from typing import Optional

import numpy as np

try:
    import av                                   # PyAV
    _HAS_AV = True
except ImportError:                             # pragma: no cover
    _HAS_AV = False


class OpusCodec:
    SAMPLE_RATE = 16000
    FRAME_MS = 20
    SAMPLES_PER_FRAME = SAMPLE_RATE * FRAME_MS // 1000

    def __init__(self):
        if not _HAS_AV:
            raise RuntimeError("PyAV not installed — pip install av")
        self._encoder = av.CodecContext.create("libopus", "w")
        self._encoder.sample_rate = self.SAMPLE_RATE
        self._encoder.layout = "mono"
        self._encoder.format = "s16"
        self._encoder.bit_rate = 24000
        self._encoder.open()
        self._decoder = av.CodecContext.create("libopus", "r")
        self._decoder.sample_rate = self.SAMPLE_RATE
        self._decoder.layout = "mono"
        self._decoder.format = "s16"
        self._decoder.open()

    def encode(self, pcm: bytes) -> bytes:
        samples = np.frombuffer(pcm, dtype=np.int16)
        if samples.size != self.SAMPLES_PER_FRAME:
            return b""
        frame = av.AudioFrame.from_ndarray(
            samples.reshape(1, -1), format="s16", layout="mono"
        )
        frame.sample_rate = self.SAMPLE_RATE
        packets = self._encoder.encode(frame)
        return b"".join(bytes(p) for p in packets) if packets else b""

    def decode(self, payload: bytes) -> bytes:
        if not payload:
            return b""
        pkt = av.Packet(payload)
        try:
            frames = self._decoder.decode(pkt)
        except Exception:
            return b""
        out = bytearray()
        for f in frames:
            arr = f.to_ndarray().astype(np.int16).flatten()
            out.extend(arr.tobytes())
        return bytes(out)
