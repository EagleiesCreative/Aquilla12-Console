//! USB HID driver for the "Aquilla 12" control surface.
//!
//! The device has 12 rotary encoders (per-channel gain), 12 encoder
//! push-switches, and 4 dedicated PTT buttons. It reports over a 14-byte HID
//! IN report at a 1 ms interval: 12 signed encoder deltas, then a 16-bit
//! button bitmap (LE). Deltas are relative/stateless by design — a dropped
//! report loses at most one detent, it never desyncs an absolute position.
//!
//! # Why PTT here never touches the webview
//!
//! `EngineControl::set_ptt` is called synchronously, in-process, directly
//! from the blocking read loop on this module's dedicated OS thread. It never
//! goes through Tauri IPC or JS. Webview event-loop scheduling has unbounded
//! jitter under load, which is unacceptable for a safety-critical transmit
//! key. The webview only ever *hears about* PTT state afterwards, via
//! `PanelEventSink`, purely for indicator UI — it is never part of the
//! control loop.
//!
//! The device I/O (this file) is kept deliberately separate from report
//! interpretation (`PanelDispatcher`) so the latter — parsing, edge
//! detection, engine dispatch, and the disconnect fail-safe — can be unit
//! tested without any real hardware or `hidapi` involved.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// pid.codes shared vendor id (https://pid.codes) used by open-source hardware
/// projects that don't want to buy a dedicated USB VID.
pub const VENDOR_ID: u16 = 0x1209;

/// Placeholder pid.codes product id for Aquilla 12. Replace with the actual
/// PID once registered at https://pid.codes/1209/ — override via
/// `HidPanelConfig::product_id` in the meantime (e.g. for a prototype using a
/// generic dev PID).
pub const DEFAULT_PRODUCT_ID: u16 = 0xA612;

pub const REPORT_LEN: usize = 14;
pub const NUM_ENCODERS: usize = 12;
pub const NUM_PTT_BUTTONS: usize = 4;

/// Bit offset of the first encoder push-switch (E0) in the button bitmap.
const ENCODER_SWITCH_BASE_BIT: u32 = 0;
/// Bit offset of the first dedicated PTT button (SW0) in the button bitmap.
const PTT_BUTTON_BASE_BIT: u32 = 12;

// ---------------------------------------------------------------------------
// Report parsing
// ---------------------------------------------------------------------------

/// One parsed 14-byte IN report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HidReport {
    /// Signed encoder delta since the last report, channel 0..11. Relative,
    /// not an absolute position — apply, don't assign.
    pub deltas: [i8; NUM_ENCODERS],
    /// Raw button bitmap: bits 0..11 = encoder switches E0..E11, bits 12..15
    /// = dedicated PTT buttons SW0..SW3. 1 = pressed.
    pub buttons: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportParseError {
    pub got_len: usize,
}

/// Parse a raw HID report buffer. `buf` may be longer than `REPORT_LEN` (some
/// backends prefix a report-id byte) but must contain at least `REPORT_LEN`
/// bytes of payload starting at index 0.
pub fn parse_report(buf: &[u8]) -> Result<HidReport, ReportParseError> {
    if buf.len() < REPORT_LEN {
        return Err(ReportParseError { got_len: buf.len() });
    }
    let mut deltas = [0i8; NUM_ENCODERS];
    for (i, d) in deltas.iter_mut().enumerate() {
        *d = buf[i] as i8;
    }
    let buttons = u16::from_le_bytes([buf[12], buf[13]]);
    Ok(HidReport { deltas, buttons })
}

// ---------------------------------------------------------------------------
// Edge detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    /// Encoder push-switch, index 0..11.
    EncoderSwitch(u8),
    /// Dedicated PTT button, index 0..3.
    Ptt(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonEdge {
    pub kind: ButtonKind,
    /// true = press (0->1), false = release (1->0).
    pub pressed: bool,
}

fn bit_to_kind(bit: u32) -> ButtonKind {
    if bit < PTT_BUTTON_BASE_BIT {
        ButtonKind::EncoderSwitch((bit - ENCODER_SWITCH_BASE_BIT) as u8)
    } else {
        ButtonKind::Ptt((bit - PTT_BUTTON_BASE_BIT) as u8)
    }
}

/// Tracks the previous button bitmap and turns level state into discrete
/// press/release transitions, so a steady-held button at 1kHz doesn't
/// re-trigger every poll.
#[derive(Debug, Default)]
pub struct EdgeDetector {
    prev: u16,
}

impl EdgeDetector {
    pub fn new() -> Self {
        Self { prev: 0 }
    }

    /// Snap back to "everything released" without emitting edges. Used after
    /// a reconnect so a stale bitmap from before the drop can't fabricate a
    /// release for a button that was never pressed in the new session.
    pub fn reset(&mut self) {
        self.prev = 0;
    }

    pub fn update(&mut self, buttons: u16) -> Vec<ButtonEdge> {
        let changed = self.prev ^ buttons;
        let mut edges = Vec::new();
        if changed != 0 {
            for bit in 0..16u32 {
                let mask = 1u16 << bit;
                if changed & mask != 0 {
                    edges.push(ButtonEdge {
                        kind: bit_to_kind(bit),
                        pressed: buttons & mask != 0,
                    });
                }
            }
        }
        self.prev = buttons;
        edges
    }
}

// ---------------------------------------------------------------------------
// Engine interface (mockable)
// ---------------------------------------------------------------------------

/// The engine calls this module drives directly. Implementations must be
/// cheap/safe to call from a plain (non-async, non-Tauri-runtime) OS thread —
/// that guarantee is what lets PTT skip the webview entirely.
pub trait EngineControl: Send + Sync {
    /// Key or unkey transmit on `channel` immediately.
    fn set_ptt(&self, channel: u32, active: bool);

    /// Apply a relative gain change (`delta_db`, in dB) to `channel`, clamped
    /// to the engine's per-channel gain range, and return the resulting
    /// gain in dB so the caller can notify the UI of true engine state.
    fn adjust_gain(&self, channel: u32, delta_db: f32) -> f32;
}

/// Notification-only events for the UI. Never part of the control loop —
/// PTT has already been applied via `EngineControl` by the time these fire.
#[derive(Debug, Clone, PartialEq)]
pub enum PanelEvent {
    Connected,
    Disconnected,
    Ptt { channel: u32, active: bool },
    EncoderSwitch { index: u8, pressed: bool },
    GainChanged { channel: u32, gain_db: f32 },
}

pub trait PanelEventSink: Send + Sync {
    fn emit(&self, event: PanelEvent);
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HidPanelConfig {
    pub vendor_id: u16,
    pub product_id: u16,
    /// SW0..SW3 -> engine channel id. `None` = that button is unmapped and
    /// is ignored (no engine call, no event).
    pub ptt_channel_map: [Option<u32>; NUM_PTT_BUTTONS],
    /// Encoder 0..11 -> engine channel id. Defaults to the natural 1:1
    /// wiring (encoder i -> channel i+1) since the hardware has exactly one
    /// encoder per channel; override only for non-standard panel wiring.
    pub encoder_channel_map: [Option<u32>; NUM_ENCODERS],
    /// dB applied per encoder detent.
    pub gain_step_db: f32,
    pub gain_min_db: f32,
    pub gain_max_db: f32,
    pub reconnect_initial_backoff: Duration,
    pub reconnect_max_backoff: Duration,
    /// Blocking read timeout — bounds how long the device thread can be
    /// stuck in a read before it re-checks the shutdown flag. Not polling:
    /// the read still returns as soon as a report arrives.
    pub read_timeout: Duration,
}

impl Default for HidPanelConfig {
    fn default() -> Self {
        let mut encoder_channel_map = [None; NUM_ENCODERS];
        for (i, slot) in encoder_channel_map.iter_mut().enumerate() {
            *slot = Some((i + 1) as u32);
        }
        Self {
            vendor_id: VENDOR_ID,
            product_id: DEFAULT_PRODUCT_ID,
            ptt_channel_map: [None; NUM_PTT_BUTTONS],
            encoder_channel_map,
            gain_step_db: 0.5,
            gain_min_db: -60.0,
            gain_max_db: 0.0,
            reconnect_initial_backoff: Duration::from_millis(250),
            reconnect_max_backoff: Duration::from_secs(10),
            read_timeout: Duration::from_millis(250),
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatcher — pure report -> engine-call logic, no device I/O
// ---------------------------------------------------------------------------

/// Interprets parsed reports and drives `EngineControl`/`PanelEventSink`.
/// Kept free of any `hidapi` dependency so it can be exercised in tests with
/// mock engine/sink implementations.
pub struct PanelDispatcher<E: EngineControl, S: PanelEventSink> {
    engine: Arc<E>,
    sink: Arc<S>,
    config: HidPanelConfig,
    edges: EdgeDetector,
    /// Channels this panel currently holds PTT active on, per the last known
    /// button state. This — not "every channel" — is exactly what a
    /// disconnect fail-safe must release.
    active_ptt: HashSet<u32>,
}

impl<E: EngineControl, S: PanelEventSink> PanelDispatcher<E, S> {
    pub fn new(engine: Arc<E>, sink: Arc<S>, config: HidPanelConfig) -> Self {
        Self {
            engine,
            sink,
            config,
            edges: EdgeDetector::new(),
            active_ptt: HashSet::new(),
        }
    }

    pub fn handle_report(&mut self, report: HidReport) {
        for (i, &delta) in report.deltas.iter().enumerate() {
            if delta == 0 {
                continue;
            }
            if let Some(channel) = self.config.encoder_channel_map[i] {
                let delta_db = self.config.gain_step_db * delta as f32;
                let gain_db = self.engine.adjust_gain(channel, delta_db);
                self.sink.emit(PanelEvent::GainChanged { channel, gain_db });
            }
        }

        for edge in self.edges.update(report.buttons) {
            match edge.kind {
                ButtonKind::Ptt(idx) => {
                    let Some(channel) = self.config.ptt_channel_map[idx as usize] else {
                        continue;
                    };
                    self.engine.set_ptt(channel, edge.pressed);
                    if edge.pressed {
                        self.active_ptt.insert(channel);
                    } else {
                        self.active_ptt.remove(&channel);
                    }
                    self.sink.emit(PanelEvent::Ptt { channel, active: edge.pressed });
                }
                ButtonKind::EncoderSwitch(idx) => {
                    self.sink.emit(PanelEvent::EncoderSwitch { index: idx, pressed: edge.pressed });
                }
            }
        }
    }

    /// Fail-safe: force-release every channel this panel currently holds PTT
    /// on. Call on disconnect (and defensively before shutdown) so a device
    /// unplugged mid-hold can never leave a stuck transmit.
    pub fn force_release_all_ptt(&mut self) {
        let channels: Vec<u32> = self.active_ptt.drain().collect();
        for channel in channels {
            self.engine.set_ptt(channel, false);
            self.sink.emit(PanelEvent::Ptt { channel, active: false });
        }
        // A stale bitmap must not fabricate a phantom release/press pair on
        // the next successful reconnect.
        self.edges.reset();
    }
}

// ---------------------------------------------------------------------------
// Device thread — hidapi I/O, reconnect/backoff
// ---------------------------------------------------------------------------

/// Spawn the dedicated OS thread that owns the physical device: opens it,
/// blocks on reads, dispatches reports, and on disconnect force-releases PTT
/// and retries with backoff. Returns immediately; the thread runs until
/// `shutdown` is set.
pub fn spawn<E, S>(
    engine: Arc<E>,
    sink: Arc<S>,
    config: HidPanelConfig,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()>
where
    E: EngineControl + 'static,
    S: PanelEventSink + 'static,
{
    std::thread::spawn(move || run_device_loop(engine, sink, config, shutdown))
}

fn run_device_loop<E, S>(
    engine: Arc<E>,
    sink: Arc<S>,
    config: HidPanelConfig,
    shutdown: Arc<AtomicBool>,
) where
    E: EngineControl,
    S: PanelEventSink,
{
    let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config.clone());

    let mut api = match hidapi::HidApi::new() {
        Ok(api) => api,
        Err(e) => {
            eprintln!("[HID Panel] Failed to initialize HID subsystem: {e}. Aquilla 12 support disabled.");
            return;
        }
    };

    let mut backoff = config.reconnect_initial_backoff;

    while !shutdown.load(Ordering::SeqCst) {
        match api.open(config.vendor_id, config.product_id) {
            Ok(device) => {
                println!(
                    "[HID Panel] Aquilla 12 connected (VID {:#06x} PID {:#06x}).",
                    config.vendor_id, config.product_id
                );
                sink.emit(PanelEvent::Connected);
                backoff = config.reconnect_initial_backoff;

                let mut buf = [0u8; REPORT_LEN];
                loop {
                    if shutdown.load(Ordering::SeqCst) {
                        dispatcher.force_release_all_ptt();
                        return;
                    }
                    match device.read_timeout(&mut buf, config.read_timeout.as_millis() as i32) {
                        Ok(0) => continue, // timeout, no report yet — not a busy-poll, read blocked for the timeout
                        Ok(n) if n >= REPORT_LEN => {
                            if let Ok(report) = parse_report(&buf[..n]) {
                                dispatcher.handle_report(report);
                            }
                        }
                        Ok(_) => { /* short/garbled report — ignore, wait for the next one */ }
                        Err(e) => {
                            eprintln!("[HID Panel] Aquilla 12 disconnected: {e}");
                            dispatcher.force_release_all_ptt();
                            sink.emit(PanelEvent::Disconnected);
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                // Not present yet / still unplugged — expected during normal
                // operation, stay quiet and keep retrying with backoff.
            }
        }

        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(backoff);
        backoff = std::cmp::min(backoff * 2, config.reconnect_max_backoff);
        let _ = api.refresh_devices();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct MockEngine {
        ptt_calls: StdMutex<Vec<(u32, bool)>>,
        gain_db: StdMutex<HashMap<u32, f32>>,
    }

    impl EngineControl for MockEngine {
        fn set_ptt(&self, channel: u32, active: bool) {
            self.ptt_calls.lock().unwrap().push((channel, active));
        }

        fn adjust_gain(&self, channel: u32, delta_db: f32) -> f32 {
            let mut map = self.gain_db.lock().unwrap();
            let entry = map.entry(channel).or_insert(0.0);
            *entry = (*entry + delta_db).clamp(-60.0, 0.0);
            *entry
        }
    }

    #[derive(Default)]
    struct MockSink {
        events: StdMutex<Vec<PanelEvent>>,
    }

    impl PanelEventSink for MockSink {
        fn emit(&self, event: PanelEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn report_with_buttons(buttons: u16) -> HidReport {
        HidReport { deltas: [0; NUM_ENCODERS], buttons }
    }

    // -- report parsing ------------------------------------------------

    #[test]
    fn parses_deltas_and_button_bitmap() {
        let mut buf = [0u8; REPORT_LEN];
        buf[0] = 3;
        buf[1] = (-2i8) as u8;
        buf[11] = (-1i8) as u8;
        buf[12..14].copy_from_slice(&0b0001_0000_0000_0001u16.to_le_bytes());

        let report = parse_report(&buf).unwrap();
        assert_eq!(report.deltas[0], 3);
        assert_eq!(report.deltas[1], -2);
        assert_eq!(report.deltas[11], -1);
        assert_eq!(report.buttons, 0b0001_0000_0000_0001);
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = [0u8; REPORT_LEN - 1];
        let err = parse_report(&buf).unwrap_err();
        assert_eq!(err.got_len, REPORT_LEN - 1);
    }

    #[test]
    fn accepts_longer_buffer_using_first_report_len_bytes() {
        // Some backends prefix a report-id byte; parsing must not choke on
        // trailing bytes beyond REPORT_LEN.
        let mut buf = [0u8; REPORT_LEN + 1];
        buf[0] = 5;
        assert!(parse_report(&buf).is_ok());
    }

    // -- edge detection --------------------------------------------------

    #[test]
    fn edge_detector_emits_only_on_transition() {
        let mut ed = EdgeDetector::new();
        assert!(ed.update(0).is_empty());

        let pressed = ed.update(1 << PTT_BUTTON_BASE_BIT);
        assert_eq!(pressed, vec![ButtonEdge { kind: ButtonKind::Ptt(0), pressed: true }]);

        // Holding steady at 1kHz must not re-trigger.
        assert!(ed.update(1 << PTT_BUTTON_BASE_BIT).is_empty());
        assert!(ed.update(1 << PTT_BUTTON_BASE_BIT).is_empty());

        let released = ed.update(0);
        assert_eq!(released, vec![ButtonEdge { kind: ButtonKind::Ptt(0), pressed: false }]);
    }

    #[test]
    fn edge_detector_reports_multiple_simultaneous_transitions() {
        let mut ed = EdgeDetector::new();
        let edges = ed.update((1 << 0) | (1 << PTT_BUTTON_BASE_BIT));
        assert_eq!(edges.len(), 2);
        assert!(edges.contains(&ButtonEdge { kind: ButtonKind::EncoderSwitch(0), pressed: true }));
        assert!(edges.contains(&ButtonEdge { kind: ButtonKind::Ptt(0), pressed: true }));
    }

    #[test]
    fn edge_detector_reset_clears_history_without_emitting() {
        let mut ed = EdgeDetector::new();
        ed.update(1 << PTT_BUTTON_BASE_BIT);
        ed.reset();
        // A fresh bitmap of 0 must not read as a release edge after reset.
        assert!(ed.update(0).is_empty());
    }

    // -- dispatcher: PTT mapping & edge-triggering ------------------------

    #[test]
    fn dispatcher_maps_ptt_button_to_configured_channel() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let mut config = HidPanelConfig::default();
        config.ptt_channel_map[2] = Some(7);
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        dispatcher.handle_report(report_with_buttons(1 << (PTT_BUTTON_BASE_BIT + 2)));

        assert_eq!(*engine.ptt_calls.lock().unwrap(), vec![(7, true)]);
    }

    #[test]
    fn dispatcher_ignores_unmapped_ptt_button() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let config = HidPanelConfig::default(); // no ptt buttons mapped
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        dispatcher.handle_report(report_with_buttons(1 << PTT_BUTTON_BASE_BIT));

        assert!(engine.ptt_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatcher_does_not_retrigger_ptt_while_held() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let mut config = HidPanelConfig::default();
        config.ptt_channel_map[0] = Some(1);
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        let held = report_with_buttons(1 << PTT_BUTTON_BASE_BIT);
        for _ in 0..5 {
            dispatcher.handle_report(held);
        }

        assert_eq!(*engine.ptt_calls.lock().unwrap(), vec![(1, true)]);
    }

    // -- dispatcher: gain -------------------------------------------------

    #[test]
    fn dispatcher_applies_gain_step_scaled_by_delta() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let config = HidPanelConfig::default(); // encoder 0 -> channel 1, 0.5dB/step
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        let mut report = HidReport::default();
        report.deltas[0] = -2; // two detents CCW in one report (a coalesced/dropped-frame case)
        dispatcher.handle_report(report);

        let gain = *engine.gain_db.lock().unwrap().get(&1).unwrap();
        assert_eq!(gain, -1.0); // 2 * 0.5dB step, attenuating from the 0dB start
        assert_eq!(
            *sink.events.lock().unwrap(),
            vec![PanelEvent::GainChanged { channel: 1, gain_db: -1.0 }]
        );
    }

    #[test]
    fn dispatcher_skips_zero_delta_encoders() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let config = HidPanelConfig::default();
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        dispatcher.handle_report(HidReport::default());

        assert!(engine.gain_db.lock().unwrap().is_empty());
        assert!(sink.events.lock().unwrap().is_empty());
    }

    // -- disconnect fail-safe ---------------------------------------------

    #[test]
    fn disconnect_force_releases_only_channels_actually_held() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let mut config = HidPanelConfig::default();
        config.ptt_channel_map = [Some(1), Some(2), Some(3), Some(4)];
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        // Hold SW0 (channel 1) and SW2 (channel 3); SW1/SW3 stay released.
        let held = (1 << PTT_BUTTON_BASE_BIT) | (1 << (PTT_BUTTON_BASE_BIT + 2));
        dispatcher.handle_report(report_with_buttons(held));
        assert_eq!(engine.ptt_calls.lock().unwrap().len(), 2);

        // Simulate a USB drop mid-hold.
        dispatcher.force_release_all_ptt();

        let calls = engine.ptt_calls.lock().unwrap().clone();
        assert!(calls.contains(&(1, false)));
        assert!(calls.contains(&(3, false)));
        assert!(!calls.iter().any(|(ch, active)| (*ch == 2 || *ch == 4) && *active));
        assert!(!calls.iter().any(|(ch, _)| *ch == 2 || *ch == 4));
    }

    #[test]
    fn disconnect_with_nothing_held_is_a_no_op() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let config = HidPanelConfig::default();
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        dispatcher.force_release_all_ptt();

        assert!(engine.ptt_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn reconnect_after_disconnect_does_not_replay_stale_release() {
        let engine = Arc::new(MockEngine::default());
        let sink = Arc::new(MockSink::default());
        let mut config = HidPanelConfig::default();
        config.ptt_channel_map[0] = Some(1);
        let mut dispatcher = PanelDispatcher::new(Arc::clone(&engine), Arc::clone(&sink), config);

        dispatcher.handle_report(report_with_buttons(1 << PTT_BUTTON_BASE_BIT));
        dispatcher.force_release_all_ptt();
        let count_after_disconnect = engine.ptt_calls.lock().unwrap().len();

        // Device reconnects; first report happens to be all-zero (nothing
        // held). Must not fabricate another release for channel 1.
        dispatcher.handle_report(report_with_buttons(0));

        assert_eq!(engine.ptt_calls.lock().unwrap().len(), count_after_disconnect);
    }
}
