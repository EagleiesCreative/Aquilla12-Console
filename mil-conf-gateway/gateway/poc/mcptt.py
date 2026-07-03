"""MCPTT (3GPP TS 24.379) floor-control adapter.

Handsets negotiate SIP as usual (handled by ``sip.registrar``).  Once
the call is up, floor control runs as an in-band **MBCP** (Media Burst
Control Protocol, TS 24.380) stream on the RTCP-mux port.  For each
group call the client sends:

  * Floor Request       (msg type 1)  — "I want to talk"
  * Floor Granted       (msg type 3)  — server → client, floor is yours
  * Floor Deny          (msg type 4)  — server → client, denied
  * Floor Release       (msg type 5)  — "I'm done"
  * Floor Taken         (msg type 2)  — server → all others

This module builds/parses those messages.  It does not implement the
full state machine — only what is needed to gate our talkgroup floor
controller from the handset side.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


# ---------- MBCP field IDs -------------------------------------- #
class MbcpMsg(IntEnum):
    FLOOR_REQUEST = 0x01
    FLOOR_TAKEN   = 0x02
    FLOOR_GRANTED = 0x03
    FLOOR_DENY    = 0x04
    FLOOR_RELEASE = 0x05
    FLOOR_IDLE    = 0x06


# ---------- codec ---------------------------------------------- #
@dataclass
class MbcpMessage:
    msg_type: int
    priority: int = 0
    user_id: str = ""
    ssrc: int = 0

    def pack(self) -> bytes:
        """
        Simplified MBCP packet:
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |V=1|P|X|M|  PT=204   |     Length (32-bit words)             |
         +---------------------------------------------------------------+
         |                          SSRC                                 |
         +---------------------------------------------------------------+
         | msg_type| prio |    reserved   |    user_id_len              |
         +---------------------------------------------------------------+
         |  user_id ... (padded to 4-byte multiple)                     |
         +---------------------------------------------------------------+
        """
        uid = self.user_id.encode("utf-8")
        pad = (-len(uid)) % 4
        uid_padded = uid + b"\x00" * pad
        length_words = 1 + 1 + (len(uid_padded) // 4)         # SSRC + fields + uid
        b0 = (2 << 6) | 0x00                                   # V=2, PT=204 (APP)
        b1 = 204
        header = struct.pack("!BBH", b0, b1, length_words)
        ssrc = struct.pack("!I", self.ssrc & 0xFFFFFFFF)
        fields = struct.pack("!BBBB", self.msg_type & 0xFF,
                             self.priority & 0xFF, 0, len(uid))
        return header + ssrc + fields + uid_padded

    @classmethod
    def unpack(cls, buf: bytes) -> Optional["MbcpMessage"]:
        if len(buf) < 12:
            return None
        b0, b1, _length = struct.unpack("!BBH", buf[:4])
        if (b0 >> 6) != 2 or b1 != 204:
            return None
        ssrc, = struct.unpack("!I", buf[4:8])
        msg_type, prio, _res, uid_len = struct.unpack("!BBBB", buf[8:12])
        uid = buf[12:12 + uid_len].decode("utf-8", errors="replace")
        return cls(msg_type=msg_type, priority=prio, user_id=uid, ssrc=ssrc)


# ---------- bridge --------------------------------------------- #
class McpttBridge:
    """Thin adapter — the SIP registrar forwards INFO/RTCP-APP here.

    The registrar handles UDP transport; this class only decides what
    reply to build after the talkgroup floor controller answers.
    """

    def build_granted(self, ssrc: int, user_id: str) -> bytes:
        return MbcpMessage(MbcpMsg.FLOOR_GRANTED, 0, user_id, ssrc).pack()

    def build_deny(self, ssrc: int, user_id: str) -> bytes:
        return MbcpMessage(MbcpMsg.FLOOR_DENY, 0, user_id, ssrc).pack()

    def build_taken(self, ssrc: int, user_id: str) -> bytes:
        return MbcpMessage(MbcpMsg.FLOOR_TAKEN, 0, user_id, ssrc).pack()

    def build_idle(self, ssrc: int) -> bytes:
        return MbcpMessage(MbcpMsg.FLOOR_IDLE, 0, "", ssrc).pack()

    def parse(self, buf: bytes) -> Optional[MbcpMessage]:
        return MbcpMessage.unpack(buf)
