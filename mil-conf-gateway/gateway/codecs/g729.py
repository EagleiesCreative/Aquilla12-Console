"""G.729 wrapper.

G.729 is patented (though most patents expired in 2017).  We *do not* ship
a reference implementation — instead we look for ``bcg729`` (or the
``g729`` python binding) at runtime.  If unavailable, the codec is marked
unsupported and negotiation skips it gracefully.
"""
from __future__ import annotations

import ctypes
import ctypes.util
from typing import Optional

import numpy as np


_lib: Optional[ctypes.CDLL] = None


def _load() -> Optional[ctypes.CDLL]:
    global _lib
    if _lib is not None:
        return _lib
    for name in ("bcg729", "g729"):
        path = ctypes.util.find_library(name)
        if path:
            try:
                _lib = ctypes.CDLL(path)
                return _lib
            except OSError:
                continue
    return None


class G729Codec:
    """Narrow-band 8 kHz, 10 ms frames, 10 bytes/frame (8 kbps).

    We upsample the 8 kHz decoded PCM to the 16 kHz bus using a simple
    linear interpolation (cheap; good enough for tactical intelligibility).
    """
    SAMPLE_RATE_NATIVE = 8000
    BUS_RATE = 16000
    FRAME_MS = 10
    NATIVE_SAMPLES_PER_FRAME = SAMPLE_RATE_NATIVE * FRAME_MS // 1000    # 80
    ENCODED_BYTES = 10

    def __init__(self):
        lib = _load()
        if lib is None:
            raise RuntimeError("libbcg729 not found — G.729 unavailable")
        self.lib = lib
        # bcg729 API:
        #   bcg729Encoder_t initBcg729EncoderChannel(uint8_t enableVAD)
        #   void bcg729Encoder(bcg729Encoder_t, int16_t*, uint8_t*, uint8_t*)
        #   void closeBcg729EncoderChannel(bcg729Encoder_t)
        #   bcg729Decoder_t initBcg729DecoderChannel(void)
        #   void bcg729Decoder(bcg729Decoder_t, uint8_t*, uint8_t, uint8_t,
        #                      uint8_t, uint8_t, int16_t*)
        lib.initBcg729EncoderChannel.restype = ctypes.c_void_p
        lib.initBcg729EncoderChannel.argtypes = [ctypes.c_uint8]
        lib.initBcg729DecoderChannel.restype = ctypes.c_void_p
        self.enc = lib.initBcg729EncoderChannel(0)
        self.dec = lib.initBcg729DecoderChannel()

    def encode(self, pcm_16k: bytes) -> bytes:
        # downsample 16k -> 8k by decimation of 2 with pre-filter
        samples = np.frombuffer(pcm_16k, dtype=np.int16)
        # simple averaging pre-filter to combat aliasing
        pre = ((samples[::2].astype(np.int32) + samples[1::2].astype(np.int32)) // 2
               ).astype(np.int16)
        out = bytearray()
        for i in range(0, pre.size, self.NATIVE_SAMPLES_PER_FRAME):
            chunk = pre[i:i + self.NATIVE_SAMPLES_PER_FRAME]
            if chunk.size < self.NATIVE_SAMPLES_PER_FRAME:
                break
            in_buf = (ctypes.c_int16 * chunk.size)(*chunk.tolist())
            out_buf = (ctypes.c_uint8 * self.ENCODED_BYTES)()
            frame_size = ctypes.c_uint8(0)
            self.lib.bcg729Encoder(self.enc, in_buf, out_buf, ctypes.byref(frame_size))
            out.extend(bytes(out_buf[:self.ENCODED_BYTES]))
        return bytes(out)

    def decode(self, payload: bytes) -> bytes:
        out = np.empty(0, dtype=np.int16)
        for i in range(0, len(payload), self.ENCODED_BYTES):
            frm = payload[i:i + self.ENCODED_BYTES]
            if len(frm) < self.ENCODED_BYTES:
                break
            in_buf = (ctypes.c_uint8 * self.ENCODED_BYTES)(*frm)
            out_buf = (ctypes.c_int16 * self.NATIVE_SAMPLES_PER_FRAME)()
            self.lib.bcg729Decoder(self.dec, in_buf, 0, 0, 0, 0, out_buf)
            out = np.concatenate([out, np.frombuffer(bytes(out_buf), dtype=np.int16)])
        # upsample 8k -> 16k by linear interpolation
        if out.size == 0:
            return b""
        up = np.empty(out.size * 2, dtype=np.int16)
        up[0::2] = out
        up[1:-1:2] = ((out[:-1].astype(np.int32) + out[1:].astype(np.int32)) // 2).astype(np.int16)
        up[-1] = out[-1]
        return up.tobytes()
