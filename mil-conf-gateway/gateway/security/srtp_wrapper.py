"""SRTP wrapper around ``pylibsrtp`` (libsrtp2).

Profile: AES-128-CM / HMAC-SHA1-80 (RFC 3711).  Key material is 30 bytes
(16 key + 14 salt).  We negotiate keys via SDES for SIP endpoints and
via DTLS for WebRTC (aiortc handles the DTLS case internally, so this
class is only used on SIP legs).
"""
from __future__ import annotations

import os
from typing import Optional

try:
    from pylibsrtp import Policy, Session
    _HAS_SRTP = True
except ImportError:                             # pragma: no cover
    _HAS_SRTP = False


class SrtpSession:
    KEY_LEN = 30

    def __init__(self, tx_key: bytes, rx_key: bytes):
        if not _HAS_SRTP:
            raise RuntimeError("pylibsrtp not installed — pip install pylibsrtp")
        if len(tx_key) != self.KEY_LEN or len(rx_key) != self.KEY_LEN:
            raise ValueError("SRTP keys must be 30 bytes")
        self._tx = Session(policy=Policy(key=tx_key, ssrc_type=Policy.SSRC_ANY_OUTBOUND))
        self._rx = Session(policy=Policy(key=rx_key, ssrc_type=Policy.SSRC_ANY_INBOUND))

    def encrypt(self, rtp: bytes) -> bytes:
        return self._tx.protect(rtp)

    def decrypt(self, srtp: bytes) -> bytes:
        return self._rx.unprotect(srtp)

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(SrtpSession.KEY_LEN)
