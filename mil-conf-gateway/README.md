# Military Conference Call Gateway (MCCG)

A stable, containerized RTP-based conference gateway that bridges heterogeneous
tactical voice endpoints into a single "group call" (talkgroup) fabric.

## Supported endpoints

| Endpoint class            | Signaling            | Media (RTP payload)                  |
|---------------------------|----------------------|--------------------------------------|
| SIP consoles / softphones | SIP (RFC 3261 / TLS) | G.711 u/A-law, Opus, G.729           |
| JPS ACU-Z / VoIP radios   | Static peer (no sig) | G.711 u/A-law over fixed UDP ports   |
| PoC handsets (3GPP MCPTT) | SIP + MBCP floor     | AMR-WB / Opus                        |
| WebRTC dispatchers        | HTTPS/WSS + SDP      | Opus / DTLS-SRTP                     |

## Architecture

```
   ┌──────────┐  ┌────────┐  ┌────────┐  ┌────────┐
   │ SIP      │  │ WebRTC │  │ MCPTT  │  │ JPS    │
   │ consoles │  │ dispatch│ │ PoC    │  │ ACU-Z  │
   └────┬─────┘  └────┬───┘  └────┬───┘  └────┬───┘
        │             │           │           │
   ┌────▼─────────────▼───────────▼───────────▼────┐
   │              Signaling / floor control       │
   │  (sip.registrar · webrtc.server · mcptt      │
   │   floor · jps.static_peer)                   │
   └────────────────────┬─────────────────────────┘
                        │  PCM 16 kHz common bus
   ┌────────────────────▼─────────────────────────┐
   │  codecs.transcoder  (G.711 · Opus · G.729)   │
   └────────────────────┬─────────────────────────┘
                        │
   ┌────────────────────▼─────────────────────────┐
   │  rtp.mixer     (N-1 sum · jitter · SSRC)     │
   │  conference.talkgroup (PTT arbitration)      │
   └────────────────────┬─────────────────────────┘
                        │  SRTP out (per endpoint codec)
                        ▼
                   Endpoints receive
```

## Quick start (Docker)

```
cd docker
docker compose up -d
docker compose logs -f gateway
```

Point endpoints at:

- SIP:     `sip:<host>:5060` (UDP), `sips:<host>:5061` (TLS)
- WebRTC:  `wss://<host>:8443/rtc`
- JPS ACU: configure static peer to `<host>:40000` (talkgroup TG1)
- MCPTT:   `sip:mcptt@<host>:5060` with MBCP over RTCP-APP

## Configuration

- `config/gateway.yaml`     — bind addresses, TLS, codecs, jitter buffer
- `config/talkgroups.yaml`  — group definitions, priorities, member lists
- `config/endpoints.yaml`   — static peers (JPS), SIP users, PoC users

## Directory layout

```
gateway/
  main.py               entry point (asyncio orchestrator)
  config.py             YAML loader + typed dataclasses
  sip/                  SIP parser, registrar, B2BUA
  rtp/                  RTP packet, session, jitter buffer, mixer
  codecs/               G.711 / Opus / G.729 transcoders
  conference/           talkgroup, PTT floor arbitration
  webrtc/               aiortc-based WebRTC bridge
  poc/                  MCPTT / MBCP adapter
  jps/                  JPS ACU-Z static peer bridge
  security/             SRTP, TLS, digest auth, audit
config/                 YAML config files
docker/                 Dockerfile + compose
systemd/                gateway.service unit
tests/                  unit tests
```

## Security

- SIP over TLS 1.2+ (RFC 3261 §26)
- SRTP AES-128-CM / HMAC-SHA1-80 (RFC 3711)
- Digest MD5 auth (SIP), mTLS optional for consoles
- Every floor grant/PTT event is written to the audit log

## License / classification

Design is COTS-only; no ITAR-controlled cryptography ships in this repo.
Operators are responsible for site-specific accreditation.
