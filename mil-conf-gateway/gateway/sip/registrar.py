"""SIP registrar + minimal B2BUA.

Behaviour:

* ``REGISTER``  → digest auth against ``endpoints.yaml``; store contact.
* ``INVITE``    → we are the callee.  Answer with SDP pointing at a fresh
                  RTP session; add the caller to their default talkgroup.
* ``BYE``       → remove from talkgroup, tear down RTP.
* ``INFO``      → PTT floor control ("Signal=PTT-Press" / "PTT-Release").
* ``OPTIONS``   → 200 OK (keep-alive).

This is not a full RFC 3261 UAS — but it is enough for tactical consoles,
JPS ACU auto-answer legs, and PoC handsets to join a conference bridge.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .parser import SipMessage
from . import sdp as sdp_mod


log = logging.getLogger("mccg.sip")


# --------------------------------------------------------------------------- #
@dataclass
class Registration:
    aor: str                        # e.g. "sip:alpha@mccg.mil"
    contact: str                    # e.g. "sip:alpha@10.0.0.7:5060"
    expires_at: float               # monotonic epoch
    endpoint_id: str


@dataclass
class Dialog:
    call_id: str
    local_tag: str
    remote_tag: str
    aor: str
    endpoint_id: str
    rtp_port: int
    talkgroup_id: str


# --------------------------------------------------------------------------- #
class SipRegistrar(asyncio.DatagramProtocol):
    def __init__(
        self,
        realm: str,
        endpoint_by_user: dict[str, "gateway.config.Endpoint"],  # noqa: F821
        on_invite: Callable[[Dialog, sdp_mod.SdpAudio], asyncio.Future],
        on_ptt: Callable[[Dialog, bool], None],
        on_bye: Callable[[Dialog], None],
        local_ip: str,
    ):
        self.realm = realm
        self.endpoint_by_user = endpoint_by_user
        self.on_invite = on_invite
        self.on_ptt = on_ptt
        self.on_bye = on_bye
        self.local_ip = local_ip
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._regs: dict[str, Registration] = {}       # aor -> reg
        self._dialogs: dict[str, Dialog] = {}          # call_id -> dialog
        self._nonces: dict[str, float] = {}

    # ----------------- asyncio hooks -----------------
    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            msg = SipMessage.decode(data)
        except ValueError as e:
            log.warning("bad SIP from %s: %s", addr, e)
            return
        if not msg.is_request:
            return                        # responses to our own requests
        asyncio.create_task(self._handle(msg, addr))

    # ----------------- main dispatch -----------------
    async def _handle(self, msg: SipMessage, addr) -> None:
        method = (msg.method or "").upper()
        if method == "REGISTER":
            await self._handle_register(msg, addr)
        elif method == "INVITE":
            await self._handle_invite(msg, addr)
        elif method == "ACK":
            pass                        # nothing to do; call is up
        elif method == "BYE":
            await self._handle_bye(msg, addr)
        elif method == "CANCEL":
            self._respond(msg, addr, 200, "OK")
        elif method == "OPTIONS":
            self._respond(msg, addr, 200, "OK")
        elif method == "INFO":
            await self._handle_info(msg, addr)
        else:
            self._respond(msg, addr, 501, "Not Implemented")

    # ----------------- REGISTER -----------------
    async def _handle_register(self, msg: SipMessage, addr) -> None:
        auth = msg.header("Authorization")
        aor = self._extract_aor(msg.header("To") or "")
        user = aor.split(":", 1)[1].split("@", 1)[0] if ":" in aor else aor
        ep = self.endpoint_by_user.get(user)
        if ep is None:
            self._respond(msg, addr, 404, "Not Found")
            return
        if auth is None or not self._check_digest(auth, "REGISTER", msg.request_uri,
                                                  ep.sip_password or ""):
            nonce = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()
            self._nonces[nonce] = time.monotonic()
            self._respond(
                msg, addr, 401, "Unauthorized",
                extra_headers=[(
                    "WWW-Authenticate",
                    f'Digest realm="{self.realm}", nonce="{nonce}", algorithm=MD5',
                )],
            )
            return
        contact = msg.header("Contact") or f"<sip:{user}@{addr[0]}:{addr[1]}>"
        expires = int(msg.header("Expires") or "3600")
        self._regs[aor] = Registration(
            aor=aor, contact=contact, endpoint_id=ep.id,
            expires_at=time.monotonic() + expires,
        )
        log.info("registered %s -> %s (endpoint %s)", aor, contact, ep.id)
        self._respond(msg, addr, 200, "OK",
                      extra_headers=[("Contact", f"{contact};expires={expires}")])

    # ----------------- INVITE -----------------
    async def _handle_invite(self, msg: SipMessage, addr) -> None:
        aor = self._extract_aor(msg.header("From") or "")
        reg = self._regs.get(aor)
        if reg is None:
            self._respond(msg, addr, 403, "Not Registered")
            return
        ep = self.endpoint_by_user.get(reg.endpoint_id) or \
             next((e for e in self.endpoint_by_user.values() if e.id == reg.endpoint_id), None)
        if ep is None or ep.default_talkgroup is None:
            self._respond(msg, addr, 403, "No Talkgroup")
            return
        # provisional
        self._respond(msg, addr, 100, "Trying")
        self._respond(msg, addr, 180, "Ringing")

        # parse SDP offer
        sdp_offer = sdp_mod.parse(msg.body.decode("utf-8", errors="replace"))
        call_id = msg.header("Call-ID") or f"{random.randint(1, 1<<32)}"
        local_tag = hashlib.md5(call_id.encode()).hexdigest()[:8]
        remote_tag = self._tag_of(msg.header("From") or "")

        dialog = Dialog(
            call_id=call_id, local_tag=local_tag, remote_tag=remote_tag,
            aor=aor, endpoint_id=ep.id, rtp_port=0,
            talkgroup_id=ep.default_talkgroup,
        )

        try:
            rtp_port = await self.on_invite(dialog, sdp_offer)
        except Exception as exc:
            log.exception("on_invite failed: %s", exc)
            self._respond(msg, addr, 500, "Server Error")
            return
        dialog.rtp_port = rtp_port
        self._dialogs[call_id] = dialog

        # build 200 OK with our SDP answer
        codec_name = ep.codec
        if codec_name == "PCMU":
            pt, rate = 0, 8000
        elif codec_name == "PCMA":
            pt, rate = 8, 8000
        elif codec_name == "opus":
            pt, rate = 111, 48000
        elif codec_name == "G729":
            pt, rate = 18, 8000
        else:
            pt, rate = 0, 8000

        body = sdp_mod.build_answer(self.local_ip, rtp_port, codec_name,
                                    pt, rate).encode("utf-8")
        self._respond(msg, addr, 200, "OK",
                      extra_headers=[
                          ("Contact", f"<sip:mccg@{self.local_ip}>"),
                          ("Content-Type", "application/sdp"),
                      ], body=body,
                      to_tag=local_tag)

    # ----------------- BYE -----------------
    async def _handle_bye(self, msg: SipMessage, addr) -> None:
        call_id = msg.header("Call-ID") or ""
        dialog = self._dialogs.pop(call_id, None)
        if dialog:
            try:
                self.on_bye(dialog)
            except Exception:
                log.exception("on_bye failed")
        self._respond(msg, addr, 200, "OK")

    # ----------------- INFO (PTT floor) -----------------
    async def _handle_info(self, msg: SipMessage, addr) -> None:
        call_id = msg.header("Call-ID") or ""
        dialog = self._dialogs.get(call_id)
        if not dialog:
            self._respond(msg, addr, 481, "Call/Transaction Does Not Exist")
            return
        body = msg.body.decode("utf-8", errors="replace").upper()
        if "PTT-PRESS" in body or "SIGNAL=PTT" in body:
            self.on_ptt(dialog, True)
        elif "PTT-RELEASE" in body or "SIGNAL=RLS" in body:
            self.on_ptt(dialog, False)
        self._respond(msg, addr, 200, "OK")

    # ----------------- helpers -----------------
    def _respond(self, req: SipMessage, addr, code: int, reason: str,
                 extra_headers: Optional[list[tuple[str, str]]] = None,
                 body: bytes = b"", to_tag: Optional[str] = None) -> None:
        resp = SipMessage(is_request=False, status_code=code, reason=reason)
        # echo mandatory headers
        for name in ("Via", "From", "Call-ID", "CSeq"):
            v = req.header(name)
            if v is not None:
                if name == "To" or name == "From":
                    resp.set_header(name, v)
                else:
                    resp.set_header(name, v)
        to = req.header("To") or ""
        if to_tag and ";tag=" not in to:
            to = f"{to};tag={to_tag}"
        resp.set_header("To", to)
        resp.set_header("User-Agent", "MCCG/1.0")
        if extra_headers:
            for k, v in extra_headers:
                resp.set_header(k, v)
        resp.body = body
        if self._transport:
            self._transport.sendto(resp.encode(), addr)

    def _check_digest(self, auth_header: str, method: str, uri: str,
                      password: str) -> bool:
        params = {}
        for part in auth_header.split(",", 200):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            params[k.strip().lower().replace("digest ", "")] = v.strip().strip('"')
        username = params.get("username", "")
        nonce = params.get("nonce", "")
        realm = params.get("realm", self.realm)
        response = params.get("response", "")
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        return response.lower() == expected.lower() and nonce in self._nonces

    @staticmethod
    def _extract_aor(header: str) -> str:
        if "<" in header:
            return header.split("<", 1)[1].split(">", 1)[0]
        return header.split(";", 1)[0].strip()

    @staticmethod
    def _tag_of(header: str) -> str:
        for part in header.split(";"):
            if part.strip().startswith("tag="):
                return part.strip()[4:]
        return ""
