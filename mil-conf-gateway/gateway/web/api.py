"""REST + WebSocket handlers.

Endpoints:
    GET  /api/status                     — gateway health
    GET  /api/talkgroups                 — list, with member + floor state
    POST /api/talkgroups                 — create
    DEL  /api/talkgroups/{id}            — remove
    GET  /api/endpoints                  — list all endpoints
    POST /api/endpoints                  — create
    DEL  /api/endpoints/{id}             — remove
    POST /api/talkgroups/{id}/ptt        — dispatcher PTT
                                          body: {endpoint_id, pressed}
    WS   /ws/events                      — live event stream
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import TYPE_CHECKING

from aiohttp import web, WSMsgType

from ..config import Endpoint, Talkgroup

if TYPE_CHECKING:                                       # pragma: no cover
    from ..main import Gateway

log = logging.getLogger("mccg.web.api")


# --------------------------------------------------------------------------- #
def build_routes(gateway: "Gateway", bus) -> list[web.RouteDef]:

    # ---------- status ----------
    async def status(request: web.Request) -> web.Response:
        return web.json_response({
            "version": "1.0.0",
            "realm": gateway.gw_cfg.realm,
            "talkgroups": len(gateway.talkgroups),
            "endpoints": len(gateway.endpoints),
            "jps_peers": len(gateway._jps_peers),
        })

    # ---------- talkgroups ----------
    async def list_tgs(request: web.Request) -> web.Response:
        out = []
        for tg in gateway.talkgroups:
            state = gateway.tgm.get(tg.id)
            holders = state.floor.holders() if state else []
            members = list(state._sessions.keys()) if state else []
            out.append({
                **asdict(tg),
                "active_members": members,
                "floor_holders": holders,
            })
        return web.json_response(out)

    async def create_tg(request: web.Request) -> web.Response:
        data = await request.json()
        try:
            tg = Talkgroup(
                id=data["id"],
                name=data.get("name", data["id"]),
                priority=int(data.get("priority", 5)),
                preemptable=bool(data.get("preemptable", True)),
                members=data.get("members", []),
                encryption=data.get("encryption", "srtp"),
            )
        except (KeyError, ValueError) as e:
            return web.json_response({"error": str(e)}, status=400)
        if any(t.id == tg.id for t in gateway.talkgroups):
            return web.json_response({"error": "already exists"}, status=409)
        gateway.add_talkgroup(tg)
        bus.publish("tg_create", talkgroup=tg.id)
        return web.json_response(asdict(tg), status=201)

    async def delete_tg(request: web.Request) -> web.Response:
        tg_id = request.match_info["id"]
        if not gateway.remove_talkgroup(tg_id):
            return web.json_response({"error": "not found"}, status=404)
        bus.publish("tg_delete", talkgroup=tg_id)
        return web.Response(status=204)

    # ---------- endpoints ----------
    async def list_eps(request: web.Request) -> web.Response:
        return web.json_response([asdict(e) for e in gateway.endpoints])

    async def create_ep(request: web.Request) -> web.Response:
        data = await request.json()
        try:
            ep = Endpoint(
                id=data["id"],
                kind=data["kind"],
                display_name=data.get("display_name", ""),
                sip_user=data.get("sip_user"),
                sip_password=data.get("sip_password"),
                peer_host=data.get("peer_host"),
                peer_port=data.get("peer_port"),
                local_port=data.get("local_port"),
                codec=data.get("codec", "PCMU"),
                default_talkgroup=data.get("default_talkgroup"),
                priority=int(data.get("priority", 5)),
            )
        except (KeyError, ValueError) as e:
            return web.json_response({"error": str(e)}, status=400)
        if any(x.id == ep.id for x in gateway.endpoints):
            return web.json_response({"error": "already exists"}, status=409)
        gateway.add_endpoint(ep)
        bus.publish("ep_create", endpoint=ep.id)
        return web.json_response(asdict(ep), status=201)

    async def delete_ep(request: web.Request) -> web.Response:
        ep_id = request.match_info["id"]
        if not gateway.remove_endpoint(ep_id):
            return web.json_response({"error": "not found"}, status=404)
        bus.publish("ep_delete", endpoint=ep_id)
        return web.Response(status=204)

    # ---------- PTT (dispatcher) ----------
    async def ptt(request: web.Request) -> web.Response:
        tg_id = request.match_info["id"]
        data = await request.json()
        ep_id = data.get("endpoint_id")
        pressed = bool(data.get("pressed"))
        tg = gateway.tgm.get(tg_id)
        if tg is None:
            return web.json_response({"error": "unknown talkgroup"}, status=404)
        granted = tg.ptt(ep_id, pressed)
        bus.publish("ptt", talkgroup=tg_id, endpoint=ep_id,
                    pressed=pressed, granted=granted)
        return web.json_response({"granted": granted,
                                  "holders": tg.floor.holders()})

    # ---------- audit tail ----------
    async def audit_tail(request: web.Request) -> web.Response:
        n = int(request.query.get("n", "50"))
        try:
            with open(gateway.gw_cfg.audit_log, "r", encoding="utf-8") as fp:
                lines = fp.readlines()[-n:]
        except FileNotFoundError:
            lines = []
        events = []
        for ln in lines:
            try:
                events.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        return web.json_response(events)

    # ---------- WebSocket ----------
    async def ws_events(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=20)
        await ws.prepare(request)
        q = bus.subscribe()
        try:
            async def sender():
                while True:
                    ev = await q.get()
                    await ws.send_json(ev)

            import asyncio
            send_task = asyncio.create_task(sender())
            async for msg in ws:
                if msg.type == WSMsgType.CLOSE:
                    break
            send_task.cancel()
        finally:
            bus.unsubscribe(q)
        return ws

    return [
        web.get("/api/status",                     status),
        web.get("/api/talkgroups",                 list_tgs),
        web.post("/api/talkgroups",                create_tg),
        web.delete("/api/talkgroups/{id}",         delete_tg),
        web.get("/api/endpoints",                  list_eps),
        web.post("/api/endpoints",                 create_ep),
        web.delete("/api/endpoints/{id}",          delete_ep),
        web.post("/api/talkgroups/{id}/ptt",       ptt),
        web.get("/api/audit",                      audit_tail),
        web.get("/ws/events",                      ws_events),
    ]
