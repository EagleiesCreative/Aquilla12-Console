"""Very small SDP (RFC 4566) helper.

Only what we need: parse m=audio line to learn the peer's RTP port and
codec list, and build our own audio SDP response with selected codec.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SdpAudio:
    ip: str = "0.0.0.0"
    port: int = 0
    payload_types: list[int] = field(default_factory=list)
    rtpmap: dict[int, str] = field(default_factory=dict)   # PT -> "PCMU/8000"


def parse(sdp_text: str) -> SdpAudio:
    a = SdpAudio()
    for ln in sdp_text.splitlines():
        if ln.startswith("c="):                     # c=IN IP4 <ip>
            parts = ln.split(" ")
            if len(parts) >= 3:
                a.ip = parts[2].strip()
        elif ln.startswith("m=audio"):
            parts = ln.split(" ")
            if len(parts) >= 4:
                a.port = int(parts[1])
                a.payload_types = [int(p) for p in parts[3:]]
        elif ln.startswith("a=rtpmap:"):
            rest = ln[len("a=rtpmap:"):]
            pt_str, mapping = rest.split(" ", 1)
            a.rtpmap[int(pt_str)] = mapping.strip()
    return a


def build_answer(local_ip: str, local_rtp_port: int,
                 codec_name: str, payload_type: int,
                 clock_rate: int, session_id: int = 0) -> str:
    lines = [
        "v=0",
        f"o=- {session_id} 1 IN IP4 {local_ip}",
        "s=MCCG-Conference",
        f"c=IN IP4 {local_ip}",
        "t=0 0",
        f"m=audio {local_rtp_port} RTP/AVP {payload_type}",
        f"a=rtpmap:{payload_type} {codec_name}/{clock_rate}",
        "a=sendrecv",
        "a=ptime:20",
    ]
    return "\r\n".join(lines) + "\r\n"
