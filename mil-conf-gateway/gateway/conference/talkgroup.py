"""Talkgroup manager.

Owns one ``ConferenceMixer`` and one ``FloorController`` per talkgroup,
and knows the mapping ``endpoint_id -> RtpSession``.  Business logic that
crosses the mixer/floor boundary lives here.
"""
from __future__ import annotations

import logging
from typing import Optional

from ..config import Talkgroup, Endpoint
from ..rtp.mixer import ConferenceMixer
from .ptt import FloorController


log = logging.getLogger("mccg.tg")


class TalkgroupState:
    def __init__(self, tg: Talkgroup, endpoints: dict[str, Endpoint], max_talkers: int):
        self.tg = tg
        self.mixer = ConferenceMixer(tg.id)
        self.floor = FloorController(
            talkgroup_id=tg.id,
            max_talkers=max_talkers,
            preemptable=tg.preemptable,
            on_grant=self.mixer.grant_floor,
            on_revoke=lambda ep, reason: self.mixer.revoke_floor(ep),
        )
        self._endpoints = endpoints
        self._sessions: dict[str, object] = {}       # ep_id -> RtpSession

    # ------------------------------------------------------------ join
    def join(self, endpoint_id: str, session) -> None:
        if endpoint_id not in self._endpoints:
            log.warning("join denied — unknown endpoint %s", endpoint_id)
            return
        self._sessions[endpoint_id] = session
        self.mixer.add_member(endpoint_id, session)
        log.info("endpoint %s joined talkgroup %s", endpoint_id, self.tg.id)

    def leave(self, endpoint_id: str) -> None:
        self._sessions.pop(endpoint_id, None)
        self.mixer.remove_member(endpoint_id)
        self.floor.release(endpoint_id)
        log.info("endpoint %s left talkgroup %s", endpoint_id, self.tg.id)

    # ------------------------------------------------------------ PTT
    def ptt(self, endpoint_id: str, pressed: bool) -> bool:
        ep = self._endpoints.get(endpoint_id)
        if ep is None:
            return False
        if pressed:
            return self.floor.request(endpoint_id, ep.priority)
        self.floor.release(endpoint_id)
        return True

    # ------------------------------------------------------------ audio
    def audio_in(self, endpoint_id: str, pcm: bytes) -> None:
        """Called by an RtpSession's on_pcm hook."""
        self.mixer.push_pcm(endpoint_id, pcm)


# --------------------------------------------------------------------------- #
class TalkgroupManager:
    def __init__(self, talkgroups: list[Talkgroup], endpoints: list[Endpoint],
                 max_talkers: int):
        self._eps = {e.id: e for e in endpoints}
        self._tgs: dict[str, TalkgroupState] = {
            t.id: TalkgroupState(t, self._eps, max_talkers) for t in talkgroups
        }

    def get(self, tg_id: str) -> Optional[TalkgroupState]:
        return self._tgs.get(tg_id)

    def all(self) -> list[TalkgroupState]:
        return list(self._tgs.values())

    async def start(self) -> None:
        for tg in self._tgs.values():
            await tg.mixer.start()

    async def stop(self) -> None:
        for tg in self._tgs.values():
            await tg.mixer.stop()

    # convenient dispatcher used by ingress paths
    def route_audio(self, endpoint_id: str, pcm: bytes) -> None:
        ep = self._eps.get(endpoint_id)
        if ep is None or ep.default_talkgroup is None:
            return
        tg = self._tgs.get(ep.default_talkgroup)
        if tg:
            tg.audio_in(endpoint_id, pcm)
