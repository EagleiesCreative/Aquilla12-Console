"""Typed configuration loader.

All runtime knobs live in three YAML files under ``config/``.  We validate
them at start-up and expose dataclasses to the rest of the codebase — no
string keys or dict lookups leak outside this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# --------------------------------------------------------------------------- #
#  gateway.yaml
# --------------------------------------------------------------------------- #
@dataclass
class BindConfig:
    sip_udp: str = "0.0.0.0:5060"
    sip_tls: str = "0.0.0.0:5061"
    rtp_range: tuple[int, int] = (16384, 32767)
    webrtc_https: str = "0.0.0.0:8443"
    web_console: str = "0.0.0.0:8080"
    metrics: str = "0.0.0.0:9100"


@dataclass
class TlsConfig:
    cert: str = "/etc/mccg/tls/server.crt"
    key: str = "/etc/mccg/tls/server.key"
    ca: str = "/etc/mccg/tls/ca.crt"
    require_client_cert: bool = False


@dataclass
class MediaConfig:
    # Codec preference on the common PCM bus (in negotiation order).
    preferred_codecs: list[str] = field(
        default_factory=lambda: ["opus", "PCMU", "PCMA", "G729"]
    )
    ptime_ms: int = 20                 # packet time on egress
    jitter_target_ms: int = 60         # target jitter buffer depth
    mix_sample_rate: int = 16000       # internal bus rate (Hz)
    max_talkers_per_group: int = 3     # PTT concurrent floor limit


@dataclass
class GatewayConfig:
    bind: BindConfig = field(default_factory=BindConfig)
    tls: TlsConfig = field(default_factory=TlsConfig)
    media: MediaConfig = field(default_factory=MediaConfig)
    realm: str = "mccg.mil"
    audit_log: str = "/var/log/mccg/audit.jsonl"


# --------------------------------------------------------------------------- #
#  talkgroups.yaml
# --------------------------------------------------------------------------- #
@dataclass
class Talkgroup:
    id: str                        # e.g. "TG1"
    name: str                      # human label
    priority: int = 5              # 1 = highest, 9 = lowest
    preemptable: bool = True       # higher-priority PTT can steal floor
    members: list[str] = field(default_factory=list)  # endpoint IDs
    encryption: str = "srtp"       # "srtp" | "none"


# --------------------------------------------------------------------------- #
#  endpoints.yaml
# --------------------------------------------------------------------------- #
@dataclass
class Endpoint:
    id: str                        # unique
    kind: str                      # "sip" | "jps" | "poc" | "webrtc"
    display_name: str = ""
    # SIP / PoC
    sip_user: Optional[str] = None
    sip_password: Optional[str] = None
    # JPS ACU static peer
    peer_host: Optional[str] = None
    peer_port: Optional[int] = None
    local_port: Optional[int] = None
    codec: str = "PCMU"
    # Common
    default_talkgroup: Optional[str] = None
    priority: int = 5


# --------------------------------------------------------------------------- #
#  loader
# --------------------------------------------------------------------------- #
def _load_yaml(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"config not found: {path}")
    with path.open("r", encoding="utf-8") as fp:
        return yaml.safe_load(fp) or {}


def load(config_dir: str | Path) -> tuple[GatewayConfig, list[Talkgroup], list[Endpoint]]:
    """Load all three YAML files and return validated objects."""
    cdir = Path(config_dir)

    g = _load_yaml(cdir / "gateway.yaml")
    bind = BindConfig(**g.get("bind", {}))
    if isinstance(bind.rtp_range, list):
        bind.rtp_range = tuple(bind.rtp_range)  # type: ignore[assignment]
    tls = TlsConfig(**g.get("tls", {}))
    media = MediaConfig(**g.get("media", {}))
    gw = GatewayConfig(
        bind=bind, tls=tls, media=media,
        realm=g.get("realm", "mccg.mil"),
        audit_log=g.get("audit_log", "/var/log/mccg/audit.jsonl"),
    )

    tgs_raw = _load_yaml(cdir / "talkgroups.yaml").get("talkgroups", [])
    tgs = [Talkgroup(**t) for t in tgs_raw]

    eps_raw = _load_yaml(cdir / "endpoints.yaml").get("endpoints", [])
    eps = [Endpoint(**e) for e in eps_raw]

    # cross-validation
    tg_ids = {t.id for t in tgs}
    for e in eps:
        if e.default_talkgroup and e.default_talkgroup not in tg_ids:
            raise ValueError(
                f"endpoint {e.id} references unknown talkgroup "
                f"{e.default_talkgroup}"
            )

    return gw, tgs, eps
