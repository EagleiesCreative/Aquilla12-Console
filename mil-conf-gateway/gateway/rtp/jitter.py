"""Adaptive jitter buffer.

Simple play-out buffer that reorders packets by sequence number and drops
duplicates.  Sized in ms; converts to slot count using the negotiated
ptime.  This is intentionally straightforward — production tactical
deployments usually override with a PLC-aware buffer.
"""
from __future__ import annotations

import heapq
from collections import deque
from typing import Optional

from .packet import RtpPacket


class JitterBuffer:
    def __init__(self, target_ms: int = 60, ptime_ms: int = 20):
        self.target_ms = target_ms
        self.ptime_ms = ptime_ms
        self.depth = max(2, target_ms // ptime_ms)
        self._heap: list[tuple[int, int, RtpPacket]] = []
        self._seen: set[int] = set()
        self._last_out_seq: Optional[int] = None
        self._insert_counter = 0

    def push(self, pkt: RtpPacket) -> None:
        if pkt.sequence_number in self._seen:
            return                        # duplicate
        self._seen.add(pkt.sequence_number)
        # timestamp is the ordering key; use insert counter as tiebreak.
        heapq.heappush(self._heap, (pkt.timestamp, self._insert_counter, pkt))
        self._insert_counter += 1
        # trim very old
        while len(self._seen) > self.depth * 4:
            self._seen.pop()

    def pop(self) -> Optional[RtpPacket]:
        """Return the next packet if the buffer has warmed up."""
        if len(self._heap) < self.depth:
            return None
        _, _, pkt = heapq.heappop(self._heap)
        self._last_out_seq = pkt.sequence_number
        return pkt

    def flush(self) -> list[RtpPacket]:
        out = [item[2] for item in sorted(self._heap)]
        self._heap.clear()
        self._seen.clear()
        return out
