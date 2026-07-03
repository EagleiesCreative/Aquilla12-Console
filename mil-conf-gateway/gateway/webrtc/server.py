"""WebRTC signaling + media bridge.

Runs a plain WSS endpoint that accepts JSON messages:

  { "type": "offer",  "sdp": "..." }
  { "type": "answer", "sdp": "..." }
  { "type": "ice",    "candidate": {...} }
  { "type": "ptt",    "pressed": true, "endpoint_id": "..." }

Each new peer is treated as its own endpoint (id derived from a signed
JWT or from the browser-supplied login).  The audio track is decoded to
PCM by aiortc and pushed to the talkgroup mixer; the mixer's outbound
frames are wrapped in an ``AudioStreamTrack`` and sent back.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Optional

try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, MediaStreamTrack
    from aiortc.mediastreams import AudioStreamTrack
    import av
    _HAS_AIORTC = True
except ImportError:                             # pragma: no cover
    _HAS_AIORTC = False


log = logging.getLogger("mccg.webrtc")


class _MixerTrack:
    """Wraps outbound PCM frames from the mixer as an aiortc audio track."""

    kind = "audio"

    def __init__(self):
        self._q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=50)

    def put(self, pcm16k_mono: bytes) -> None:
        try:
            self._q.put_nowait(pcm16k_mono)
        except asyncio.QueueFull:
            pass

    async def recv(self):
        pcm = await self._q.get()
        frame = av.AudioFrame(format="s16", layout="mono", samples=len(pcm) // 2)
        frame.planes[0].update(pcm)
        frame.sample_rate = 16000
        return frame


class WebRtcServer:
    """Minimal signaling handler; wire it into your HTTPS/WSS front."""

    def __init__(
        self,
        on_join: Callable[[str], None],
        on_leave: Callable[[str], None],
        on_pcm: Callable[[str, bytes], None],
        on_ptt: Callable[[str, bool], None],
    ):
        if not _HAS_AIORTC:
            raise RuntimeError("aiortc not installed — pip install aiortc")
        self._pcs: dict[str, RTCPeerConnection] = {}
        self._mixer_tracks: dict[str, _MixerTrack] = {}
        self._on_join = on_join
        self._on_leave = on_leave
        self._on_pcm = on_pcm
        self._on_ptt = on_ptt

    # --------------------------------------------------------------- API
    def outbound_track(self, endpoint_id: str) -> Optional[_MixerTrack]:
        return self._mixer_tracks.get(endpoint_id)

    async def handle_signaling(self, endpoint_id: str, recv, send) -> None:
        """
        Args:
          recv: async callable returning next JSON message from client
          send: async callable that takes a dict to serialize + send
        """
        pc = RTCPeerConnection()
        self._pcs[endpoint_id] = pc
        mtrack = _MixerTrack()
        self._mixer_tracks[endpoint_id] = mtrack
        pc.addTrack(AudioStreamTrack.__new__(AudioStreamTrack)) if False else None
        pc.addTrack(mtrack)                     # sic — aiortc duck-types

        @pc.on("track")
        def _on_track(track):
            if track.kind != "audio":
                return
            asyncio.create_task(self._consume_audio(endpoint_id, track))

        @pc.on("connectionstatechange")
        async def _on_state():
            log.info("webrtc %s state=%s", endpoint_id, pc.connectionState)
            if pc.connectionState in ("failed", "closed", "disconnected"):
                await self._teardown(endpoint_id)

        self._on_join(endpoint_id)

        while True:
            try:
                msg = await recv()
            except Exception:
                break
            if msg is None:
                break
            t = msg.get("type")
            if t == "offer":
                await pc.setRemoteDescription(RTCSessionDescription(
                    sdp=msg["sdp"], type="offer"))
                answer = await pc.createAnswer()
                await pc.setLocalDescription(answer)
                await send({"type": "answer", "sdp": pc.localDescription.sdp})
            elif t == "ice":
                # aiortc handles trickle ICE via addIceCandidate on newer versions
                try:
                    await pc.addIceCandidate(msg["candidate"])
                except Exception:
                    pass
            elif t == "ptt":
                self._on_ptt(endpoint_id, bool(msg.get("pressed")))
            elif t == "bye":
                break

        await self._teardown(endpoint_id)

    async def _consume_audio(self, ep: str, track) -> None:
        try:
            while True:
                frame = await track.recv()
                # frame is 16-bit signed at frame.sample_rate
                arr = frame.to_ndarray().astype("<i2").tobytes()
                self._on_pcm(ep, arr)
        except Exception:
            pass

    async def _teardown(self, ep: str) -> None:
        pc = self._pcs.pop(ep, None)
        self._mixer_tracks.pop(ep, None)
        if pc:
            try:
                await pc.close()
            except Exception:
                pass
        self._on_leave(ep)
