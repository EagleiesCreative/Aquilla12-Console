"""In-process event bus.

The gateway subsystems (talkgroup, floor, registrar) fire events into
this bus; the WebSocket handler subscribes and forwards to browsers.
Keeps the web layer decoupled from the audio/signal path.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any


class EventBus:
    def __init__(self, history: int = 200):
        self._subscribers: set[asyncio.Queue] = set()
        self._recent: deque[dict] = deque(maxlen=history)

    def publish(self, event_type: str, **fields: Any) -> None:
        record = {"ts": time.time(), "type": event_type, **fields}
        self._recent.append(record)
        dead = []
        for q in self._subscribers:
            try:
                q.put_nowait(record)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        # replay recent so a fresh client sees context
        for r in self._recent:
            try:
                q.put_nowait(r)
            except asyncio.QueueFull:
                break
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)
