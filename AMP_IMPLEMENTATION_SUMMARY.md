# A-MP (Aquilla Mirror Protocol) — Implementation Summary

**Scope:** Implement the CTO's `implementation_plan.md` — turn the initial call-recording tap into a
configurable, per-channel **A-MP stream** to the NP-C4I Recorder, with a global on/off toggle, a tabbed
Web Config UI, live streaming indicators in the console, and a fix for the PTT audio-corruption issue.

**Result:** All items in the plan were implemented. One design change was made for correctness (deadlock
safety) and is described under *Deviations*. TypeScript type-checks clean; the Rust backend was reviewed
in depth but could not be compiled in this environment (see *Problems / caveats*).

---

## What changed, by area

### 1. Database & state (`src-tauri/src/lib.rs`)
- New global setting `amp_enabled` (default `true`) stored in the `settings` table.
- New per-channel columns `amp_ip` (TEXT, default `127.0.0.1`) and `amp_port` (INTEGER).
- Migration in `init_db` adds the columns and, **only on first creation of `amp_port`**, seeds each
  channel with `5004 + (id - 1) * 2`. (The plan ran this `UPDATE` on every start; I gated it to the
  first migration so a user who later sets a port to `0` to disable a channel isn't reset on restart.)
- `ChannelConfig`, `Channel`, `GatewayConfig`, and `AppState` gained the corresponding fields
  (`amp_ip`, `amp_port`, `amp_streaming`, `amp_enabled`). `load_config`, `save_config`,
  `save_config_to_conn`, `default_config`, `save_state_to_file`, and the `Channel` builder in `run()`
  were all updated to read/write/seed them.

### 2. A-MP mirroring & the PTT fix (`src-tauri/src/lib.rs`)
- `build_recording_tap` now uses **live A-MP settings** (IP/port/enabled) instead of the old
  `recorder_config.json` file. The `RecorderConfig` / `load_recorder_config` / `recorder_port_for`
  helpers were removed; `recorder_config.json` is now obsolete.
- **PTT corruption fix:** in `start_audio_playback`, incoming (RX) audio is no longer mirrored while PTT
  is active. TX and RX share one RTP/PCMU stream to a single recorder port; interleaving both directions
  during simultaneous talk caused the stutter/distortion. Since PTT comms are half-duplex, skipping RX
  during transmit removes the corruption without losing anything the operator would hear. The RX task now
  receives the channel's PTT `AtomicBool` (the same flag `ptt_toggle_handler` flips).
- `amp_streaming` is set `true` when a call starts (if a tap was created) and `false` on every call-teardown
  path (hangup, reject, remote BYE, call-failed, SIP BYE listener). Each transition is broadcast to the
  console over the existing WebSocket `channel_update` message.

### 3. Web Config UI (`/config` page in `src-tauri/src/lib.rs`)
- Added a **tabbed layout**: *Channel Mapping* (the existing table) and *A-MP Stream Mapping* (new).
- The A-MP tab has the global **enable checkbox** plus a 12-row table to edit destination **IP** and
  **UDP port** per channel, with a live **Mirror State** indicator (pulsing red dot = streaming).
- `/config/save` (`save_config_handler`) now parses and persists `amp_enabled` and per-channel
  `amp_ip_*` / `amp_port_*`. A-MP fields are editable even mid-call (they only affect the next call's
  mirror, never the live audio path). `ampEnabled` is included in the `config_update` broadcast and in
  `GET /api/config`.

### 4. Console UI (Next.js)
- `src/lib/types.ts`: added `ampIp` / `ampPort` / `ampStreaming` to `ChannelState` and `ampEnabled` to
  `GlobalSettings`.
- `src/app/page.tsx`: initial state for the new fields; syncs `ampEnabled` from `/api/config` and from
  `config_update`; simulator call/hangup flows set/clear `ampStreaming`.
- `src/components/ChannelCard.tsx`: a small pulsing red dot renders top-left when `ampStreaming` is
  active (tooltip: "A-MP Mirror Stream Active").

---

## How the pieces fit together

```
 Aquilla channel (call active)                       NP-C4I Recorder
 ┌───────────────────────────┐                       ┌──────────────────┐
 │ TX mic ─(while PTT held)─┐ │   RTP/PCMU (µ-law)    │ UDP :5004 (CH01) │
 │                          ├─┼──────────────────────►│ UDP :5006 (CH02) │
 │ RX peer ─(while PTT idle)┘ │   one shared stream   │ UDP :5008 (CH03) │
 └───────────────────────────┘   per channel          │ UDP :5010 (CH04) │
        amp_ip : amp_port  ◄── configurable per channel in the A-MP tab
        amp_enabled        ◄── global master switch
```

---

## Deviations from the plan (and why)

1. **`build_recording_tap` takes resolved params, not `&AppState`.** The plan's snippet had the tap
   builder lock `AppState` internally. Two of the three call sites already hold the state lock, and
   `tokio::sync::Mutex` is **not** re-entrant — locking again there would deadlock at runtime. The builder
   now takes `(enabled, ip, port)`; sites holding the lock read those from the held guard, and a small
   `amp_settings_for` helper covers the one site that doesn't hold the lock. Behaviour is identical, minus
   the deadlock risk.

2. **Migration seeding gated to first run** (see Database section) to respect a user setting `port = 0`
   to disable a channel.

3. **Recording model kept as one combined file per channel** (both directions on one stream). This matches
   the recorder's per-port model and "both sides in one recording," and the new PTT-skip is exactly what
   makes that single stream clean. Dual-file (separate TX/RX ports) was not adopted.

---

## Problems / caveats

- **Rust was not compiled here.** This environment has no Rust toolchain and no network to install one
  (and a full Tauri + cpal build needs the macOS build environment anyway). I verified the backend by
  close review: all call sites match the new function signatures, `format!` placeholder/arg counts match
  (config page 6/6, A-MP rows 8/8), the `/config` HTML `<div>` tags balance (17/17), serde defaults cover
  old configs, and the SQL column/param counts line up. **Please run `cargo build` (or your normal Tauri
  build) on your Mac to confirm** — the changes are additive and localized.
- **TypeScript passed:** `tsc --noEmit` is clean.
- **`recorder_config.json` is now obsolete** (settings live in the DB, editable in the A-MP tab). I could
  not delete it from this environment — safe to remove manually.
- **Full-duplex note:** if both parties truly talk at once, RX is briefly not mirrored while you transmit.
  This is intentional (half-duplex PTT assumption) and the reason the audio corruption is gone.
- **Channels 5–12:** default seeded ports continue the pattern (5012, 5014, …). To actually record them,
  add matching listening ports on the NP-C4I Recorder side.

---

## Suggested verification once building locally

1. `cargo build` in `src-tauri/` (confirm clean compile).
2. Launch app → open `http://localhost:8085/config` → verify the two tabs and that A-MP IP/port edits save.
3. Toggle the global A-MP switch off → confirm no mirror stream on the next call.
4. Place a call → confirm the console shows the pulsing red dot and the recorder receives audio.
5. Hold PTT while the far side talks → confirm the recording is clean (no stutter) and the dot stays on.
6. Hang up → confirm the dot clears.
