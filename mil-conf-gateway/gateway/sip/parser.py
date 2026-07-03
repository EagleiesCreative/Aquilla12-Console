"""Minimal RFC 3261 message parser / serializer.

We deliberately avoid a full SIP stack — the gateway only speaks a small
subset: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS, plus INFO for
push-to-talk floor control on legacy handsets that don't do MBCP.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


CRLF = "\r\n"


@dataclass
class SipMessage:
    is_request: bool
    method: Optional[str] = None
    request_uri: Optional[str] = None
    status_code: Optional[int] = None
    reason: Optional[str] = None
    version: str = "SIP/2.0"
    headers: list[tuple[str, str]] = field(default_factory=list)   # keep order
    body: bytes = b""

    # ----------------------- helpers -----------------------
    def header(self, name: str) -> Optional[str]:
        name_l = name.lower()
        for k, v in self.headers:
            if k.lower() == name_l:
                return v
        return None

    def headers_all(self, name: str) -> list[str]:
        name_l = name.lower()
        return [v for k, v in self.headers if k.lower() == name_l]

    def set_header(self, name: str, value: str) -> None:
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == name.lower():
                self.headers[i] = (name, value)
                return
        self.headers.append((name, value))

    # ------------------- encode / decode -------------------
    def encode(self) -> bytes:
        if self.is_request:
            start = f"{self.method} {self.request_uri} {self.version}"
        else:
            start = f"{self.version} {self.status_code} {self.reason}"
        lines = [start]
        # Ensure Content-Length is honest.
        cl = str(len(self.body))
        found_cl = False
        for k, v in self.headers:
            if k.lower() == "content-length":
                v = cl
                found_cl = True
            lines.append(f"{k}: {v}")
        if not found_cl:
            lines.append(f"Content-Length: {cl}")
        head = CRLF.join(lines) + CRLF + CRLF
        return head.encode("utf-8") + self.body

    @classmethod
    def decode(cls, raw: bytes) -> "SipMessage":
        try:
            head_bytes, _, body = raw.partition(b"\r\n\r\n")
            head = head_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            raise ValueError(f"bad SIP framing: {exc}")
        lines = head.split(CRLF)
        if not lines:
            raise ValueError("empty SIP message")
        first = lines[0]
        headers: list[tuple[str, str]] = []
        for ln in lines[1:]:
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            headers.append((k.strip(), v.strip()))
        if first.startswith("SIP/"):
            parts = first.split(" ", 2)
            return cls(
                is_request=False, version=parts[0],
                status_code=int(parts[1]),
                reason=parts[2] if len(parts) > 2 else "",
                headers=headers, body=body,
            )
        parts = first.split(" ", 2)
        return cls(
            is_request=True, method=parts[0],
            request_uri=parts[1],
            version=parts[2] if len(parts) > 2 else "SIP/2.0",
            headers=headers, body=body,
        )
