"""RFC 3550 RTP packet encode / decode.

Fixed 12-byte header; CSRC list, header extension and padding are supported
but rarely needed for narrow-band tactical audio.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field


_HEADER = struct.Struct("!BBHII")   # V/P/X/CC | M/PT | seq | ts | ssrc


@dataclass
class RtpPacket:
    payload_type: int
    sequence_number: int
    timestamp: int
    ssrc: int
    payload: bytes = b""
    marker: bool = False
    csrc: list[int] = field(default_factory=list)
    padding: bool = False
    extension: bool = False

    # ---------------------------------------------------------------- pack
    def pack(self) -> bytes:
        cc = len(self.csrc) & 0x0F
        b0 = (2 << 6) | (int(self.padding) << 5) | (int(self.extension) << 4) | cc
        b1 = (int(self.marker) << 7) | (self.payload_type & 0x7F)
        header = _HEADER.pack(b0, b1, self.sequence_number & 0xFFFF,
                              self.timestamp & 0xFFFFFFFF,
                              self.ssrc & 0xFFFFFFFF)
        csrc_blob = b"".join(struct.pack("!I", c) for c in self.csrc)
        return header + csrc_blob + self.payload

    # -------------------------------------------------------------- unpack
    @classmethod
    def unpack(cls, buf: bytes) -> "RtpPacket":
        if len(buf) < 12:
            raise ValueError("short RTP packet")
        b0, b1, seq, ts, ssrc = _HEADER.unpack_from(buf, 0)
        version = (b0 >> 6) & 0x03
        if version != 2:
            raise ValueError(f"unsupported RTP version {version}")
        padding = bool(b0 & 0x20)
        extension = bool(b0 & 0x10)
        cc = b0 & 0x0F
        marker = bool(b1 & 0x80)
        pt = b1 & 0x7F
        offset = 12
        csrc = []
        for _ in range(cc):
            (c,) = struct.unpack_from("!I", buf, offset)
            csrc.append(c)
            offset += 4
        if extension:
            # skip: 2-byte profile, 2-byte length in 32-bit words
            _prof, ext_len = struct.unpack_from("!HH", buf, offset)
            offset += 4 + ext_len * 4
        payload = buf[offset:]
        if padding and payload:
            pad_len = payload[-1]
            payload = payload[:-pad_len]
        return cls(payload_type=pt, sequence_number=seq, timestamp=ts,
                   ssrc=ssrc, payload=payload, marker=marker,
                   csrc=csrc, padding=False, extension=False)
