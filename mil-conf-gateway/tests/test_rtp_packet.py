"""Basic round-trip tests for RTP packet + G.711 codecs + PTT floor."""
import numpy as np

from gateway.rtp.packet import RtpPacket
from gateway.codecs import g711
from gateway.conference.ptt import FloorController


def test_rtp_pack_unpack():
    pkt = RtpPacket(payload_type=0, sequence_number=42, timestamp=100,
                    ssrc=0xDEADBEEF, payload=b"\x00\x01\x02\x03", marker=True)
    wire = pkt.pack()
    got = RtpPacket.unpack(wire)
    assert got.payload_type == 0
    assert got.sequence_number == 42
    assert got.timestamp == 100
    assert got.ssrc == 0xDEADBEEF
    assert got.payload == b"\x00\x01\x02\x03"
    assert got.marker is True


def test_g711_ulaw_roundtrip():
    src = (np.random.default_rng(0).integers(-16000, 16000, 160)).astype(np.int16)
    enc = g711.linear_to_ulaw(src)
    dec = g711.ulaw_to_linear(enc)
    assert dec.shape == src.shape
    # G.711 is lossy, error should be bounded
    err = np.abs(dec.astype(np.int32) - src.astype(np.int32)).max()
    assert err < 4096, f"decoded error too large: {err}"


def test_ptt_floor_preemption():
    granted, revoked = [], []
    fc = FloorController(
        talkgroup_id="TG-test",
        max_talkers=1,
        preemptable=True,
        on_grant=granted.append,
        on_revoke=lambda ep, r: revoked.append((ep, r)),
    )
    assert fc.request("bob", priority=5) is True
    # same-priority — deny
    assert fc.request("carol", priority=5) is False
    # higher priority — preempt bob
    assert fc.request("alice", priority=2) is True
    assert "bob" not in fc.holders()
    assert "alice" in fc.holders()
    assert ("bob", "preempted") in revoked
    fc.release("alice")
    assert fc.holders() == []
