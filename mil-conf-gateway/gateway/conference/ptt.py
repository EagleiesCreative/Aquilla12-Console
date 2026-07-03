"""Push-to-talk floor controller.

Rules (military voice conferencing convention):

* At most ``max_talkers`` may hold the floor at once.
* A request is denied if the floor is full and the requester's priority
  is not strictly higher (lower numeric value) than the *lowest-priority*
  current talker.
* Higher priority preempts: the losing talker is revoked and gets a
  "floor-revoked" event so its handset can beep.
* If the talkgroup is not ``preemptable``, priority is ignored and the
  floor is strictly first-come first-served.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

log = logging.getLogger("mccg.ptt")


@dataclass
class FloorHolder:
    endpoint_id: str
    priority: int
    acquired_at: float = field(default_factory=time.monotonic)


class FloorController:
    def __init__(
        self,
        talkgroup_id: str,
        max_talkers: int = 3,
        preemptable: bool = True,
        on_grant: Optional[Callable[[str], None]] = None,
        on_revoke: Optional[Callable[[str, str], None]] = None,   # (ep, reason)
    ):
        self.tg_id = talkgroup_id
        self.max_talkers = max_talkers
        self.preemptable = preemptable
        self._holders: dict[str, FloorHolder] = {}
        self._on_grant = on_grant
        self._on_revoke = on_revoke

    # ------------------------------------------------------------- request
    def request(self, endpoint_id: str, priority: int) -> bool:
        if endpoint_id in self._holders:
            return True                     # already holding
        if len(self._holders) < self.max_talkers:
            self._grant(endpoint_id, priority)
            return True
        if not self.preemptable:
            log.debug("PTT deny on %s (non-preemptable, floor full)", self.tg_id)
            return False
        # find weakest current holder
        weakest = max(self._holders.values(), key=lambda h: h.priority)
        if priority < weakest.priority:
            self._revoke(weakest.endpoint_id, reason="preempted")
            self._grant(endpoint_id, priority)
            return True
        log.debug("PTT deny on %s (priority %d ≥ weakest %d)",
                  self.tg_id, priority, weakest.priority)
        return False

    # ------------------------------------------------------------- release
    def release(self, endpoint_id: str) -> None:
        if endpoint_id in self._holders:
            self._revoke(endpoint_id, reason="released")

    # ------------------------------------------------------------- members
    def holders(self) -> list[str]:
        return list(self._holders.keys())

    # ------------------------------------------------------------- internal
    def _grant(self, ep: str, prio: int) -> None:
        self._holders[ep] = FloorHolder(endpoint_id=ep, priority=prio)
        log.info("floor grant tg=%s ep=%s prio=%d", self.tg_id, ep, prio)
        if self._on_grant:
            try:
                self._on_grant(ep)
            except Exception:
                log.exception("on_grant callback failed")

    def _revoke(self, ep: str, reason: str) -> None:
        self._holders.pop(ep, None)
        log.info("floor revoke tg=%s ep=%s reason=%s", self.tg_id, ep, reason)
        if self._on_revoke:
            try:
                self._on_revoke(ep, reason)
            except Exception:
                log.exception("on_revoke callback failed")
