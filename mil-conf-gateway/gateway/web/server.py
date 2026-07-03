"""HTTP + WebSocket + static file server (aiohttp).

Mounted at ``http://<host>:8080/`` (dev) or terminates TLS in production.
Serves the SPA from ``gateway/web/static/`` and the JSON APIs from
``/api/``.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from aiohttp import web

from .api import build_routes
from .events import EventBus

if TYPE_CHECKING:                                       # pragma: no cover
    from ..main import Gateway

log = logging.getLogger("mccg.web")


class WebServer:
    def __init__(self, gateway: "Gateway", host: str = "0.0.0.0", port: int = 8080):
        self.gateway = gateway
        self.host = host
        self.port = port
        self.bus = EventBus()
        self._runner: Optional[web.AppRunner] = None
        # Expose the bus so the rest of the gateway can publish events.
        gateway.event_bus = self.bus                    # type: ignore[attr-defined]

    async def start(self) -> None:
        app = web.Application(client_max_size=1024 * 1024)
        app.add_routes(build_routes(self.gateway, self.bus))

        # static SPA
        static_dir = Path(__file__).parent / "static"
        if static_dir.is_dir():
            app.router.add_static("/static/", static_dir, show_index=False)

            async def index(_: web.Request) -> web.FileResponse:
                return web.FileResponse(static_dir / "index.html")

            app.router.add_get("/", index)
            app.router.add_get("/{tail:.*}", index)     # SPA fallback

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        log.info("web console listening on http://%s:%d/", self.host, self.port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
