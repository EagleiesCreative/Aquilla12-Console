"""Conference mixer.

The mixer runs one 20 ms tick per talkgroup.  Each tick it:

1.  Collects the latest PCM frame from every active talker.
2.  Sums them (saturating) into a common bus.
3.  Applies N-1 subtraction so each listener hears everyone *except*
    themselves (prevents echo).
4.  Pushes the resulting frame to each member's RTP session, which
    re-encodes into that endpoint's negotiated codec.

Sample rate on the bus is always 16 kHz signed 16-bit mono; codec
modules resample to/from their native rate.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Optional

import numpy as np


FRAME_MS = 20
BUS_RATE = 16000
SAMPLES_PER_FRAME = BUS_RATE * FRAME_MS // 1000     # 320


class ConferenceMixer:
    def __init__(self, talkgroup_id: str):
        self.tg_id = talkgroup_id
        # endpoint_id -> deque[np.int16 frame]
        self._inbox: dict[str, deque[np.ndarray]] = defaultdict(
            lambda: deque(maxlen=4)
        )
        # endpoint_id -> RtpSession
        self._members: dict[str, object] = {}
        # endpoint_id -> is currently transmitting? (PTT floor holder)
        self._floor: set[str] = set()
        self._running = False
        self._task: Optional[asyncio.Task] = None

    # ---------- membership ----------
    def add_member(self, endpoint_id: str, session) -> None:
        self._members[endpoint_id] = session

    def remove_member(self, endpoint_id: str) -> None:
        self._members.pop(endpoint_id, None)
        self._inbox.pop(endpoint_id, None)
        self._floor.discard(endpoint_id)

    # ---------- floor (push-to-talk) ----------
    def grant_floor(self, endpoint_id: str) -> None:
        self._floor.add(endpoint_id)

    def revoke_floor(self, endpoint_id: str) -> None:
        self._floor.discard(endpoint_id)

    # ---------- audio ingress ----------
    def push_pcm(self, endpoint_id: str, pcm: bytes) -> None:
        """PCM is 16-bit signed little-endian at BUS_RATE."""
        if endpoint_id not in self._floor:
            return                              # not transmitting → drop
        frame = np.frombuffer(pcm, dtype=np.int16)
        if frame.size == 0:
            return
        # split / pad into SAMPLES_PER_FRAME chunks
        for start in range(0, frame.size, SAMPLES_PER_FRAME):
            chunk = frame[start:start + SAMPLES_PER_FRAME]
            if chunk.size < SAMPLES_PER_FRAME:
                chunk = np.pad(chunk, (0, SAMPLES_PER_FRAME - chunk.size))
            self._inbox[endpoint_id].append(chunk)

    # ---------- lifecycle ----------
    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name=f"mix-{self.tg_id}")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ---------- inner loop ----------
    async def _loop(self) -> None:
        period = FRAME_MS / 1000.0
        next_tick = time.monotonic()
        while self._running:
            next_tick += period
            self._tick()
            sleep_for = next_tick - time.monotonic()
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            else:
                # falling behind — resync
                next_tick = time.monotonic()

    def _tick(self) -> None:
        # 1. pull one frame from each talker
        talker_frames: dict[str, np.ndarray] = {}
        for ep, q in self._inbox.items():
            if q:
                talker_frames[ep] = q.popleft()

        if not talker_frames:
            return          # silence — don't waste CPU

        # 2. sum into common bus (int32 to avoid overflow)
        bus = np.zeros(SAMPLES_PER_FRAME, dtype=np.int32)
        for frm in talker_frames.values():
            bus += frm.astype(np.int32)

        # 3. distribute N-1
        for ep, sess in self._members.items():
            listener = bus.copy()
            if ep in talker_frames:
                listener -= talker_frames[ep].astype(np.int32)
            # saturate to int16
            np.clip(listener, -32768, 32767, out=listener)
            frame16 = listener.astype(np.int16)
            try:
                sess.send_pcm(frame16.tobytes())
            except Exception:
                # log & continue — one bad session must not stall the tick
                continue
