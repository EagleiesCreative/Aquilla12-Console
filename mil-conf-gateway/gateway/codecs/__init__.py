"""Codec transcoders (all normalise to 16 kHz signed 16-bit mono PCM)."""
from .transcoder import CodecInstance, make_codec

__all__ = ["CodecInstance", "make_codec"]
