"""TLS context helpers for SIP-TLS and WSS."""
from __future__ import annotations

import ssl
from pathlib import Path


def make_server_context(
    cert_path: str,
    key_path: str,
    ca_path: str | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    if ca_path and Path(ca_path).is_file():
        ctx.load_verify_locations(cafile=ca_path)
        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS")
    return ctx
