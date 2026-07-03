"""JPS ACU-Z static-peer bridge.

The JPS ACU-Z (a.k.a. Raytheon ACU-Z / RIU-Z) has no SIP stack.  You
configure a fixed remote IP + UDP port and it just streams G.711 RTP
there.  We mirror that: bind a UDP socket on ``local_port`` and treat
whatever address first sends a valid RTP packet as the peer.

A JPS peer that comes up joins its ``default_talkgroup`` immediately and
its floor is *always granted* — a radio is a full-duplex tap, and PTT
arbitration is done on the radio net itself.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from ..codecs.transcoder import make_codec
from ..config import Endpoint
from ..rtp.session import RtpSession


log = logging.getLogger("mccg.jps")


class AcuStaticPeer:
    """Bind + wire one JPS ACU-Z endpoint to its talkgroup."""

    def __init__(self, endpoint: Endpoint, on_pcm):
        self.ep = endpoint
        self.session: Optional[RtpSession] = None
        self._on_pcm = on_pcm

    async def start(self, loop: asyncio.AbstractEventLoop) -> None:
        codec = make_codec(self.ep.codec or "PCMU")
        if codec is None:
            raise RuntimeError(f"JPS peer {self.ep.id}: codec {self.ep.codec} unsupported")
        remote = None
        if self.ep.peer_host and self.ep.peer_port:
            remote = (self.ep.peer_host, self.ep.peer_port)
        sess = RtpSession(
            endpoint_id=self.ep.id,
            codec=codec,
            remote_addr=remote,
            on_pcm=self._on_pcm,
        )
        local_port = self.ep.local_port or 40000
        await loop.create_datagram_endpoint(
            lambda: sess, local_addr=("0.0.0.0", local_port),
        )
        self.session = sess
        log.info("JPS ACU peer %s bound on :%d, remote=%s",
                 self.ep.id, local_port, remote)

    def close(self) -> None:
        if self.session:
            self.session.close()
