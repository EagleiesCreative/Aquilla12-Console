"""Per-endpoint RTP session.

Owns one UDP socket pair (RTP + RTCP), an SSRC, a jitter buffer, and a
codec instance. The mixer pulls PCM frames from ``session.read_pcm()`` and
pushes PCM frames back via ``session.write_pcm()``.
"""
from __future__ import annotations

import asyncio
import os
import random
import socket
from typing import Callable, Optional

from .packet import RtpPacket
from .jitter import JitterBuffer
from ..codecs.transcoder import CodecInstance


class RtpSession(asyncio.DatagramProtocol):
    def __init__(
        self,
        endpoint_id: str,
        codec: CodecInstance,
        remote_addr: Optional[tuple[str, int]] = None,
        ptime_ms: int = 20,
        jitter_target_ms: int = 60,
        on_pcm: Optional[Callable[[str, bytes], None]] = None,
    ):
        self.endpoint_id = endpoint_id
        self.codec = codec
        self.remote_addr = remote_addr
        self.ptime_ms = ptime_ms
        self.ssrc = random.randint(1, 2**31 - 1)
        self.seq = random.randint(0, 65535)
        self.ts = random.randint(0, 2**31 - 1)
        self._jitter = JitterBuffer(jitter_target_ms, ptime_ms)
        self._on_pcm = on_pcm
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._active = True

    # ---------- DatagramProtocol ----------
    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if not self._active:
            return
        try:
            pkt = RtpPacket.unpack(data)
        except ValueError:
            return
        # Adopt discovered remote address (symmetric RTP).
        if self.remote_addr is None:
            self.remote_addr = addr
        self._jitter.push(pkt)
        pkt2 = self._jitter.pop()
        if pkt2 is None:
            return
        try:
            pcm = self.codec.decode(pkt2.payload)
        except Exception:
            return
        if self._on_pcm and pcm:
            self._on_pcm(self.endpoint_id, pcm)

    def connection_lost(self, exc):
        self._active = False

    # ---------- egress ----------
    def send_pcm(self, pcm: bytes) -> None:
        """Encode PCM and transmit as one RTP packet."""
        if not self._active or self._transport is None or self.remote_addr is None:
            return
        payload = self.codec.encode(pcm)
        if not payload:
            return
        pkt = RtpPacket(
            payload_type=self.codec.payload_type,
            sequence_number=self.seq,
            timestamp=self.ts,
            ssrc=self.ssrc,
            payload=payload,
        )
        self.seq = (self.seq + 1) & 0xFFFF
        # timestamp increments by frame size in samples
        self.ts = (self.ts + self.codec.samples_per_frame) & 0xFFFFFFFF
        try:
            self._transport.sendto(pkt.pack(), self.remote_addr)
        except OSError:
            pass

    def close(self) -> None:
        self._active = False
        if self._transport:
            self._transport.close()


# --------------------------------------------------------------------------- #
async def bind_udp(
    session: RtpSession,
    loop: asyncio.AbstractEventLoop,
    port_range: tuple[int, int],
    host: str = "0.0.0.0",
) -> int:
    """Try ports in the range until one binds.  Returns the chosen port."""
    lo, hi = port_range
    tried = list(range(lo, hi + 1, 2))    # even ports only (RTP convention)
    random.shuffle(tried)
    for p in tried:
        try:
            await loop.create_datagram_endpoint(
                lambda: session,
                local_addr=(host, p),
                reuse_port=hasattr(socket, "SO_REUSEPORT"),
            )
            return p
        except OSError:
            continue
    raise RuntimeError("no free RTP port in configured range")
