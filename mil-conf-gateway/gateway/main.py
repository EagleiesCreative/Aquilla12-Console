"""Gateway entry point.

Wires all subsystems together:

  config → talkgroups → RTP mixer → codecs
                     ↑
                     ├── SIP registrar (SIP consoles / MCPTT)
                     ├── JPS ACU static peers
                     └── WebRTC signaling (via external WSS handler)
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from .config import load, Endpoint, Talkgroup
from .codecs.transcoder import make_codec
from .conference.talkgroup import TalkgroupManager, TalkgroupState
from .jps.acu_bridge import AcuStaticPeer
from .rtp.session import RtpSession, bind_udp
from .security.audit import AuditLogger
from .sip.registrar import SipRegistrar
from .web.server import WebServer


log = logging.getLogger("mccg")


class Gateway:
    def __init__(self, config_dir: str, local_ip: str):
        self.gw_cfg, self.talkgroups, self.endpoints = load(config_dir)
        self.local_ip = local_ip
        self.audit = AuditLogger(self.gw_cfg.audit_log)
        self.tgm = TalkgroupManager(
            talkgroups=self.talkgroups,
            endpoints=self.endpoints,
            max_talkers=self.gw_cfg.media.max_talkers_per_group,
        )
        self._sip_registrar: Optional[SipRegistrar] = None
        self._jps_peers: list[AcuStaticPeer] = []
        self._web: Optional[WebServer] = None
        # Populated by WebServer.start() — used to fire live events for the UI.
        self.event_bus = None

    # -------------------------------------------------------------- run
    async def start(self, loop: asyncio.AbstractEventLoop,
                    web_host: str = "0.0.0.0", web_port: int = 8080) -> None:
        await self.tgm.start()

        # ---- Web console (must start early so it can subscribe to events) ----
        self._web = WebServer(self, host=web_host, port=web_port)
        await self._web.start()

        # ---- SIP registrar ----
        ep_by_user = {e.sip_user: e for e in self.endpoints
                      if e.sip_user and e.kind in ("sip", "poc")}
        host, port_s = self.gw_cfg.bind.sip_udp.rsplit(":", 1)
        self._sip_registrar = SipRegistrar(
            realm=self.gw_cfg.realm,
            endpoint_by_user=ep_by_user,
            on_invite=self._on_sip_invite,
            on_ptt=self._on_sip_ptt,
            on_bye=self._on_sip_bye,
            local_ip=self.local_ip,
        )
        await loop.create_datagram_endpoint(
            lambda: self._sip_registrar, local_addr=(host, int(port_s))
        )
        log.info("SIP registrar bound on %s:%s", host, port_s)
        self.audit.log("start", subsystem="sip", addr=self.gw_cfg.bind.sip_udp)

        # ---- JPS ACU static peers ----
        for ep in self.endpoints:
            if ep.kind != "jps":
                continue
            peer = AcuStaticPeer(ep, on_pcm=self._route_ingress_pcm)
            await peer.start(loop)
            self._jps_peers.append(peer)
            tg = self.tgm.get(ep.default_talkgroup or "")
            if tg and peer.session is not None:
                tg.join(ep.id, peer.session)
                # radios always hold the floor (net-side arbitration)
                tg.floor.request(ep.id, ep.priority)
            self.audit.log("start", subsystem="jps", endpoint=ep.id,
                           talkgroup=ep.default_talkgroup)

        log.info("gateway ready: %d talkgroups, %d endpoints",
                 len(self.talkgroups), len(self.endpoints))

    # -------------------------------------------------------------- SIP callbacks
    async def _on_sip_invite(self, dialog, sdp_offer) -> int:
        """Allocate an RTP session for a newly-arrived SIP INVITE."""
        ep = next((e for e in self.endpoints if e.id == dialog.endpoint_id), None)
        if ep is None:
            raise RuntimeError(f"no endpoint for {dialog.endpoint_id}")
        codec = make_codec(ep.codec) or make_codec("PCMU")
        if codec is None:
            raise RuntimeError("no codec available")
        session = RtpSession(
            endpoint_id=ep.id, codec=codec,
            remote_addr=(sdp_offer.ip, sdp_offer.port),
            ptime_ms=self.gw_cfg.media.ptime_ms,
            jitter_target_ms=self.gw_cfg.media.jitter_target_ms,
            on_pcm=self._route_ingress_pcm,
        )
        loop = asyncio.get_running_loop()
        port = await bind_udp(session, loop, self.gw_cfg.bind.rtp_range,
                              host=self.local_ip if self.local_ip != "0.0.0.0" else "0.0.0.0")
        tg = self.tgm.get(dialog.talkgroup_id)
        if tg:
            tg.join(ep.id, session)
        self.audit.log("invite", endpoint=ep.id, call_id=dialog.call_id,
                       talkgroup=dialog.talkgroup_id, rtp_port=port)
        return port

    def _on_sip_ptt(self, dialog, pressed: bool) -> None:
        tg = self.tgm.get(dialog.talkgroup_id)
        if not tg:
            return
        granted = tg.ptt(dialog.endpoint_id, pressed)
        self.audit.log("ptt", endpoint=dialog.endpoint_id,
                       talkgroup=dialog.talkgroup_id,
                       pressed=pressed, granted=granted)

    def _on_sip_bye(self, dialog) -> None:
        tg = self.tgm.get(dialog.talkgroup_id)
        if tg:
            tg.leave(dialog.endpoint_id)
        self.audit.log("bye", endpoint=dialog.endpoint_id,
                       call_id=dialog.call_id)

    # -------------------------------------------------------------- ingress fan-in
    def _route_ingress_pcm(self, endpoint_id: str, pcm: bytes) -> None:
        self.tgm.route_audio(endpoint_id, pcm)

    # -------------------------------------------------------------- admin CRUD (called by web/api.py)
    def add_talkgroup(self, tg: Talkgroup) -> None:
        self.talkgroups.append(tg)
        state = TalkgroupState(tg, {e.id: e for e in self.endpoints},
                               self.gw_cfg.media.max_talkers_per_group)
        self.tgm._tgs[tg.id] = state
        asyncio.create_task(state.mixer.start())
        self.audit.log("tg_create", talkgroup=tg.id)

    def remove_talkgroup(self, tg_id: str) -> bool:
        state = self.tgm._tgs.pop(tg_id, None)
        if not state:
            return False
        asyncio.create_task(state.mixer.stop())
        self.talkgroups = [t for t in self.talkgroups if t.id != tg_id]
        self.audit.log("tg_delete", talkgroup=tg_id)
        return True

    def add_endpoint(self, ep: Endpoint) -> None:
        self.endpoints.append(ep)
        # SIP endpoints become auto-discoverable via the registrar's dict.
        if self._sip_registrar and ep.sip_user and ep.kind in ("sip", "poc"):
            self._sip_registrar.endpoint_by_user[ep.sip_user] = ep
        self.audit.log("ep_create", endpoint=ep.id, kind=ep.kind)

    def remove_endpoint(self, ep_id: str) -> bool:
        ep = next((e for e in self.endpoints if e.id == ep_id), None)
        if ep is None:
            return False
        # remove from any talkgroup
        for tg_state in self.tgm._tgs.values():
            tg_state.leave(ep_id)
        if self._sip_registrar and ep.sip_user:
            self._sip_registrar.endpoint_by_user.pop(ep.sip_user, None)
        self.endpoints = [e for e in self.endpoints if e.id != ep_id]
        self.audit.log("ep_delete", endpoint=ep_id)
        return True

    # -------------------------------------------------------------- shutdown
    async def stop(self) -> None:
        if self._web:
            await self._web.stop()
        await self.tgm.stop()
        for p in self._jps_peers:
            p.close()
        self.audit.log("stop")
        self.audit.close()


# --------------------------------------------------------------------------- #
def _parse_args():
    ap = argparse.ArgumentParser("mccg")
    ap.add_argument("--config", default="./config", help="config directory")
    ap.add_argument("--local-ip", default="0.0.0.0",
                    help="advertised local IP for SDP / SIP contact")
    ap.add_argument("--web-host", default="0.0.0.0",
                    help="bind host for the web console")
    ap.add_argument("--web-port", default=8080, type=int,
                    help="bind port for the web console")
    ap.add_argument("--log-level", default="INFO")
    return ap.parse_args()


async def _async_main():
    args = _parse_args()
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if not Path(args.config).is_dir():
        log.error("config directory not found: %s", args.config)
        sys.exit(2)

    gw = Gateway(args.config, args.local_ip)
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_sig():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            pass

    await gw.start(loop, web_host=args.web_host, web_port=args.web_port)
    log.info("gateway running — web console: http://%s:%d/  — Ctrl-C to stop",
             args.web_host, args.web_port)
    await stop_event.wait()
    log.info("shutting down")
    await gw.stop()


def main():
    try:
        import uvloop                            # type: ignore
        uvloop.install()
    except ImportError:
        pass
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
