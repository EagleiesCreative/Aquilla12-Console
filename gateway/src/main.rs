use axum::{
    extract::{Path, State, WebSocketUpgrade, Form, Query, ws::{Message, WebSocket}},
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response, Html, Redirect},
    routing::{get, post},
    Json, Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tower_http::cors::CorsLayer;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

use std::sync::OnceLock;
use std::sync::Mutex as StdMutex;

static SIP_NONCES: OnceLock<StdMutex<HashMap<String, String>>> = OnceLock::new();

fn get_sip_nonces() -> &'static StdMutex<HashMap<String, String>> {
    SIP_NONCES.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn parse_digest_auth(auth_header: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let parts: Vec<&str> = auth_header.split(',').collect();
    for part in parts {
        let subparts: Vec<&str> = part.split('=').collect();
        if subparts.len() >= 2 {
            let key = subparts[0].trim().trim_start_matches("Digest ").trim_start_matches("Digest").to_string();
            let val = subparts[1].trim().trim_matches('"').to_string();
            map.insert(key, val);
        }
    }
    map
}

fn get_input_devices() -> Vec<String> {
    let host = cpal::default_host();
    let mut devices = Vec::new();
    if let Ok(input_devices) = host.input_devices() {
        for device in input_devices {
            if let Ok(name) = device.name() {
                devices.push(name);
            }
        }
    }
    devices.dedup();
    if devices.is_empty() {
        devices.push("Default System Audio Input".to_string());
    }
    devices
}

async fn get_audio_devices_handler() -> impl IntoResponse {
    let devices = get_input_devices();
    (StatusCode::OK, Json(devices))
}

// Embed the Next.js SPA static export files
#[derive(RustEmbed)]
#[folder = "../out"]
struct Asset;

mod crypto;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelConfig {
    id: u32,
    label: String,
    protocol: String, // "SIP" | "RTP"
    #[serde(rename = "targetIp")]
    target_ip: String,
    #[serde(rename = "targetPort")]
    target_port: u16,
    #[serde(rename = "sipUser")]
    sip_user: Option<String>,
    codec: String,
    #[serde(rename = "localPort")]
    local_port: Option<u16>,
    volume: u32,
    #[serde(rename = "srtpEnabled")]
    srtp_enabled: bool,
    #[serde(rename = "sipAuthRequired")]
    sip_auth_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayConfig {
    #[serde(rename = "sipPort")]
    sip_port: u16,
    #[serde(rename = "selectedDevice")]
    selected_device: Option<String>,
    channels: Vec<ChannelConfig>,
}

fn load_config() -> GatewayConfig {
    if let Ok(mut file) = File::open("gateway_config.json") {
        let mut content = String::new();
        if file.read_to_string(&mut content).is_ok() {
            if let Ok(config) = serde_json::from_str::<GatewayConfig>(&content) {
                return config;
            }
        }
    }
    // Return default config
    let channels = (1..=12)
        .map(|id| ChannelConfig {
            id,
            label: format!("CH {:02}", id),
            protocol: "RTP".to_string(), // Default destination to RTP format
            target_ip: format!("192.168.1.10{}", id),
            target_port: 5004,
            sip_user: Some(format!("receiver{}", id)),
            codec: if id % 3 == 0 { "Opus" } else if id % 3 == 1 { "G.711µ" } else { "G.722" }.to_string(),
            local_port: None,
            volume: 100,
            srtp_enabled: true,
            sip_auth_required: true,
        })
        .collect();
    
    let default_config = GatewayConfig {
        sip_port: 5060,
        selected_device: None,
        channels,
    };
    
    save_config(&default_config);
    default_config
}

fn save_config(config: &GatewayConfig) {
    if let Ok(content) = serde_json::to_string_pretty(config) {
        if let Ok(mut file) = File::create("gateway_config.json") {
            let _ = file.write_all(content.as_bytes());
        }
    }
}

// Channel telemetry model matching the frontend expectation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Channel {
    id: u32,
    label: String,
    protocol: String,
    status: String, // "IDLE" | "RINGING" | "CONNECTED" | "FAILED"
    duration: u32,
    #[serde(rename = "audioLevel")]
    audio_level: u32,
    latency: u32,
    jitter: u32,
    #[serde(rename = "packetLoss")]
    packet_loss: f32,
    #[serde(rename = "rxKbps")]
    rx_kbps: u32,
    #[serde(rename = "txKbps")]
    tx_kbps: u32,
    #[serde(rename = "targetUri")]
    target_uri: String,
    #[serde(rename = "targetIp")]
    target_ip: String,
    #[serde(rename = "targetPort")]
    target_port: u16,
    #[serde(rename = "sipUser")]
    sip_user: Option<String>,
    codec: String,
    #[serde(rename = "localPort")]
    local_port: Option<u16>,
    #[serde(rename = "pttActive")]
    ptt_active: bool,
    volume: u32,
    #[serde(rename = "srtpEnabled")]
    srtp_enabled: bool,
    #[serde(rename = "sipAuthRequired")]
    sip_auth_required: bool,
    #[serde(skip)]
    secure_context: Arc<tokio::sync::Mutex<crypto::SecureChannelContext>>,
}

struct ActiveCall {
    channel_id: u32,
    target_ip: String,
    target_port: u16,
    local_ip: String,
    local_sip_port: u16,
    local_rtp_port: u16,
    call_id: String,
    from_tag: String,
    to_tag: Option<String>,
    audio_stop_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ptt_active: Option<Arc<std::sync::atomic::AtomicBool>>,
    rtp_abort_handle: Option<tokio::task::AbortHandle>,
    rtp_rx_abort_handle: Option<tokio::task::AbortHandle>,
    sip_abort_handle: Option<tokio::task::AbortHandle>,
}

// Request payloads
#[derive(Debug, Deserialize)]
struct CallRequest {
    #[serde(rename = "targetUri")]
    target_uri: String,
    codec: String,
}

#[derive(Debug, Deserialize)]
struct SelectAudioDeviceRequest {
    device: String,
}

// Shared application state
struct AppState {
    channels: Vec<Channel>,
    tx: broadcast::Sender<String>,
    active_calls: Vec<ActiveCall>,
    selected_device: Option<String>,
    sip_port: u16,
}

fn save_state_to_file(state: &AppState) {
    let channel_configs = state.channels.iter().map(|ch| ChannelConfig {
        id: ch.id,
        label: ch.label.clone(),
        protocol: ch.protocol.clone(),
        target_ip: ch.target_ip.clone(),
        target_port: ch.target_port,
        sip_user: ch.sip_user.clone(),
        codec: ch.codec.clone(),
        local_port: ch.local_port,
        volume: ch.volume,
        srtp_enabled: ch.srtp_enabled,
        sip_auth_required: ch.sip_auth_required,
    }).collect();

    let config = GatewayConfig {
        sip_port: state.sip_port,
        selected_device: state.selected_device.clone(),
        channels: channel_configs,
    };
    
    save_config(&config);
}

#[tokio::main]
async fn main() {
    println!("[Rust SBC] Initializing native VoIP signaling gateway...");

    // Create the broadcast channel for WebSocket updates
    let (tx, _) = broadcast::channel(100);

    // Load persisted configuration or write defaults
    let config = load_config();

    // Initialize 12 channel states from loaded config
    let channels = config.channels.iter().map(|ch_cfg| {
        let computed_uri = if ch_cfg.protocol == "RTP" {
            format!("rtp://{}:{}", ch_cfg.target_ip, ch_cfg.target_port)
        } else {
            let user = ch_cfg.sip_user.as_deref().unwrap_or("receiver");
            format!("sip:{}@{}:{}", user, ch_cfg.target_ip, ch_cfg.target_port)
        };

        Channel {
            id: ch_cfg.id,
            label: ch_cfg.label.clone(),
            protocol: ch_cfg.protocol.clone(),
            status: "IDLE".to_string(),
            duration: 0,
            audio_level: 0,
            latency: 0,
            jitter: 0,
            packet_loss: 0.0,
            rx_kbps: 0,
            tx_kbps: 0,
            target_uri: computed_uri,
            target_ip: ch_cfg.target_ip.clone(),
            target_port: ch_cfg.target_port,
            sip_user: ch_cfg.sip_user.clone(),
            codec: ch_cfg.codec.clone(),
            local_port: ch_cfg.local_port,
            ptt_active: false,
            volume: ch_cfg.volume,
            srtp_enabled: ch_cfg.srtp_enabled,
            sip_auth_required: ch_cfg.sip_auth_required,
            secure_context: Arc::new(tokio::sync::Mutex::new(crypto::SecureChannelContext::new())),
        }
    }).collect::<Vec<_>>();

    let state = Arc::new(Mutex::new(AppState {
        channels,
        tx: tx.clone(),
        active_calls: Vec::new(),
        selected_device: config.selected_device,
        sip_port: config.sip_port,
    }));

    // Spawn background task to simulate real-time VoIP telemetry and audio VU levels
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        let mut second_timer = tokio::time::interval(Duration::from_secs(1));
        let mut fast_timer = tokio::time::interval(Duration::from_millis(100));

        loop {
            tokio::select! {
                // Every 100ms: Fluctuate voice levels for connected channels
                _ = fast_timer.tick() => {
                    let mut lock = state_clone.lock().await;
                    let tx_chan = lock.tx.clone();
                    for ch in lock.channels.iter_mut() {
                        if ch.status == "CONNECTED" {
                            let r: f64 = rand_f64();
                            if r > 0.85 {
                                ch.audio_level = ch.audio_level.saturating_sub(20);
                            } else if r > 0.75 {
                                ch.audio_level = (r * 15.0 + 83.0) as u32;
                            } else {
                                let delta = (r * 30.0 - 15.0) as i32;
                                ch.audio_level = ((ch.audio_level as i32 + delta).max(20).min(80)) as u32;
                            }

                            // Broadcast audio level
                            let level_msg = serde_json::json!({
                                "type": "audio_level",
                                "data": { "id": ch.id, "level": ch.audio_level }
                            }).to_string();
                            let _ = tx_chan.send(level_msg);
                        }
                    }
                }
                // Every 1s: Update call timers, network stats, and SBC resource usage
                _ = second_timer.tick() => {
                    let mut lock = state_clone.lock().await;
                    let tx_chan = lock.tx.clone();
                    let active_calls = lock.channels.iter().filter(|c| c.status == "CONNECTED").count();

                    // Simulate CPU and RAM usage depending on active SIP streams
                    let cpu = ((15.0 + active_calls as f64 * 4.5 + rand_f64() * 4.0 - 2.0).max(5.0).min(99.0)) as u32;
                    let ram = ((38.0 + active_calls as f64 * 0.8 + rand_f64() * 2.0 - 1.0).max(20.0).min(95.0)) as u32;

                    let telemetry_msg = serde_json::json!({
                        "type": "telemetry",
                        "data": { "cpu": cpu, "ram": ram }
                    }).to_string();
                    let _ = tx_chan.send(telemetry_msg);

                    for ch in lock.channels.iter_mut() {
                        if ch.status == "CONNECTED" {
                            ch.duration += 1;
                            
                            // Simulate network jitter and latency fluctuations
                            let lat_delta = if rand_f64() > 0.7 { if rand_f64() > 0.5 { 1 } else { -1 } } else { 0 };
                            ch.latency = ((ch.latency as i32 + lat_delta).max(10).min(120)) as u32;

                            let jit_delta = if rand_f64() > 0.8 { if rand_f64() > 0.5 { 1 } else { -1 } } else { 0 };
                            ch.jitter = ((ch.jitter as i32 + jit_delta).max(1).min(20)) as u32;

                            let loss_delta = if rand_f64() > 0.95 { 0.15 } else if rand_f64() > 0.95 { -0.15 } else { 0.0 };
                            ch.packet_loss = (ch.packet_loss + loss_delta).max(0.0).min(10.0);

                            ch.tx_kbps = if ch.ptt_active { 80 } else { 0 };

                            let update_msg = serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": ch.id,
                                    "duration": ch.duration,
                                    "latency": ch.latency,
                                    "jitter": ch.jitter,
                                    "packetLoss": ch.packet_loss,
                                    "txKbps": ch.tx_kbps
                                }
                            }).to_string();
                            let _ = tx_chan.send(update_msg);
                        }
                    }
                }
            }
        }
    });

    // Build the Axum server router
    let app = Router::new()
        // API routes
        .route("/api/channels/:id/call", post(initiate_call_handler))
        .route("/api/channels/:id/hangup", post(hangup_handler))
        .route("/api/channels/:id/ptt", post(ptt_toggle_handler))
        .route("/api/audio-devices", get(get_audio_devices_handler))
        .route("/api/audio-devices/select", post(select_audio_device_handler))
        .route("/api/config", get(get_config_handler))
        // Web Config interface
        .route("/config", get(show_config_handler))
        .route("/config/save", post(save_config_handler))
        // WebSocket telemetry route
        .route("/events", get(ws_handler))
        .with_state(Arc::clone(&state))
        // CORS configuration
        .layer(CorsLayer::permissive())
        // Static website assets served as fallback route
        .fallback(serve_static_assets);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8085").await.unwrap();
    println!("\n======================================================");
    println!("🚀 RUST NATIVE SBC GATEWAY ACTIVE ON PORT 8085");
    println!("👉 Open in browser: http://localhost:8085/");
    println!("======================================================\n");
    axum::serve(listener, app).await.unwrap();
}

// Simple deterministic float generator for simulated random states
fn rand_f64() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    ((nanos % 1000) as f64) / 1000.0
}

// WebSocket handler
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_websocket_session(socket, state))
}

async fn handle_websocket_session(socket: WebSocket, state: Arc<Mutex<AppState>>) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    
    // Subscribe to backend event broadcasts
    let mut rx = {
        let lock = state.lock().await;
        // Seed client with initial states of all 12 channels
        for ch in &lock.channels {
            let msg = serde_json::json!({
                "type": "channel_update",
                "data": ch
            }).to_string();
            let _ = ws_sender.send(Message::Text(msg)).await;
        }

        // Send a greeting log
        let greeting = serde_json::json!({
            "type": "log",
            "data": {
                "level": "success",
                "message": "[Rust Engine] Session established. Physical multi-channel I2S mapper synced."
            }
        }).to_string();
        let _ = ws_sender.send(Message::Text(greeting)).await;

        lock.tx.subscribe()
    };

    // Spawn a dedicated forwarder task
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg)).await.is_err() {
                break; // Client disconnected
            }
        }
    });

    // Spawn a client receiver task (for listening to client requests if needed)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(_)) = ws_receiver.next().await {
            // No client commands expected on WS yet, just keep connection open
        }
    });

    // Cleanup when either task fails
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
    println!("[SBC WS] Dashboard client connection closed.");
}

// Helper function to convert 16-bit PCM to 8-bit G.711 u-law
fn linear_to_ulaw(sample: i16) -> u8 {
    const BIAS: i16 = 0x84;
    const CLIP: i16 = 32635;
    let mut sign = 0;
    let mut sample_val = sample;
    if sample_val < 0 {
        sample_val = -sample_val;
        sign = 0x80;
    }
    if sample_val > CLIP {
        sample_val = CLIP;
    }
    sample_val += BIAS;
    
    let mut exponent = 7;
    let mut mask = 0x4000;
    while (sample_val & mask) == 0 && exponent > 0 {
        exponent -= 1;
        mask >>= 1;
    }
    let mantissa = (sample_val >> (exponent + 3)) & 0x0F;
    let ulaw_val = sign | (exponent << 4) | mantissa;
    !(ulaw_val as u8)
}

// 2nd-order IIR biquad section (RBJ cookbook), Direct Form II Transposed
struct Biquad {
    b0: f64, b1: f64, b2: f64,
    a1: f64, a2: f64,
    z1: f64, z2: f64,
}

impl Biquad {
    fn lowpass(sample_rate: f64, cutoff: f64, q: f64) -> Self {
        let omega = 2.0 * std::f64::consts::PI * cutoff / sample_rate;
        let sin_w = omega.sin();
        let cos_w = omega.cos();
        let alpha = sin_w / (2.0 * q);
        let a0 = 1.0 + alpha;
        Self {
            b0: ((1.0 - cos_w) / 2.0) / a0,
            b1: (1.0 - cos_w) / a0,
            b2: ((1.0 - cos_w) / 2.0) / a0,
            a1: (-2.0 * cos_w) / a0,
            a2: (1.0 - alpha) / a0,
            z1: 0.0, z2: 0.0,
        }
    }

    fn highpass(sample_rate: f64, cutoff: f64, q: f64) -> Self {
        let omega = 2.0 * std::f64::consts::PI * cutoff / sample_rate;
        let sin_w = omega.sin();
        let cos_w = omega.cos();
        let alpha = sin_w / (2.0 * q);
        let a0 = 1.0 + alpha;
        Self {
            b0: ((1.0 + cos_w) / 2.0) / a0,
            b1: (-(1.0 + cos_w)) / a0,
            b2: ((1.0 + cos_w) / 2.0) / a0,
            a1: (-2.0 * cos_w) / a0,
            a2: (1.0 - alpha) / a0,
            z1: 0.0, z2: 0.0,
        }
    }

    #[inline]
    fn process(&mut self, x: f64) -> f64 {
        let y = self.b0 * x + self.z1;
        self.z1 = self.b1 * x - self.a1 * y + self.z2;
        self.z2 = self.b2 * x - self.a2 * y;
        y
    }
}

// Resampler to convert input sample rate to 8000 Hz.
// Applies a 4th-order Butterworth anti-alias low-pass before decimation and
// uses linear interpolation instead of nearest-neighbor sample dropping.
// Without the anti-alias stage, everything above 4 kHz folds back into the
// voice band as harsh distortion when capturing at 44.1/48 kHz.
struct Resampler {
    source_rate: u32,
    target_rate: u32,
    fractional_index: f64,
    anti_alias: Option<[Biquad; 2]>,
}

impl Resampler {
    fn new(source_rate: u32, target_rate: u32) -> Self {
        // 4th-order Butterworth = cascade of two biquads (Q = 0.5412, 1.3066).
        // Cutoff at 0.42 × target rate (~3.36 kHz for 8 kHz output) leaves
        // headroom below Nyquist so the stopband is actually attenuated.
        let anti_alias = if source_rate > target_rate {
            let cutoff = target_rate as f64 * 0.42;
            Some([
                Biquad::lowpass(source_rate as f64, cutoff, 0.54119610),
                Biquad::lowpass(source_rate as f64, cutoff, 1.30656296),
            ])
        } else {
            None
        };
        Self {
            source_rate,
            target_rate,
            fractional_index: 0.0,
            anti_alias,
        }
    }

    fn process(&mut self, input: &[f32], output: &mut Vec<i16>) {
        if input.is_empty() {
            return;
        }

        if self.source_rate == self.target_rate {
            for &sample in input {
                output.push((sample.clamp(-1.0, 1.0) * 32767.0) as i16);
            }
            return;
        }

        // Step 1: Anti-alias low-pass over every input sample
        let filtered: Vec<f32> = if let Some(ref mut stages) = self.anti_alias {
            input.iter().map(|&s| {
                let mut v = s as f64;
                for st in stages.iter_mut() {
                    v = st.process(v);
                }
                v as f32
            }).collect()
        } else {
            input.to_vec()
        };

        // Step 2: Downsample with linear interpolation
        let step = self.source_rate as f64 / self.target_rate as f64;
        let mut idx = self.fractional_index;
        while (idx as usize) < filtered.len() {
            let i = idx as usize;
            let frac = (idx - i as f64) as f32;
            let sample_f32 = if i + 1 < filtered.len() {
                let s0 = filtered[i];
                let s1 = filtered[i + 1];
                s0 + frac * (s1 - s0)
            } else {
                filtered[i]
            };
            output.push((sample_f32.clamp(-1.0, 1.0) * 32767.0) as i16);
            idx += step;
        }
        // Clamp fractional_index to prevent unbounded float drift
        self.fractional_index = (idx - filtered.len() as f64).max(0.0);
        if self.fractional_index >= 1.0 {
            self.fractional_index = self.fractional_index.fract();
        }
    }
}

// Helper function to convert 8-bit G.711 u-law back to 16-bit signed linear PCM
fn ulaw_to_linear(ulaw_byte: u8) -> i16 {
    let raw = !ulaw_byte;
    let sign = raw & 0x80;
    let exponent = (raw >> 4) & 0x07;
    let mantissa = raw & 0x0F;
    
    let mut sample = ((mantissa as i16) << 3) + 132;
    sample <<= exponent;
    sample -= 132;
    
    if sign != 0 {
        -sample
    } else {
        sample
    }
}

// Helper to dynamically parse RTP headers (handling CSRC count and extension headers)
fn parse_rtp_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 12 {
        return None;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return None;
    }
    let cc = (data[0] & 0x0F) as usize;
    let has_extension = ((data[0] >> 4) & 0x01) == 1;
    
    let mut header_len = 12 + cc * 4;
    if has_extension {
        if data.len() < header_len + 4 {
            return None;
        }
        let ext_len = ((data[header_len + 2] as usize) << 8) | (data[header_len + 3] as usize);
        header_len += 4 + ext_len * 4;
    }
    
    if data.len() < header_len {
        return None;
    }
    
    Some(&data[header_len..])
}

// ============================================================================
// AUDIO PROCESSING PIPELINE
// Ported from JPS_Recorder/limiter.go with enhancements for real-time playback
// ============================================================================

/// Automatic Gain Control (AGC) + Peak Limiter
/// Normalizes incoming audio volume and prevents clipping/distortion.
/// Algorithm ported from JPS_Recorder limiter.go with Rust optimizations.
struct AudioLimiter {
    target_volume: f64,  // Target peak amplitude (e.g. 15000 out of 32767)
    max_gain: f64,       // Maximum gain multiplier to prevent amplifying background hiss
    current_gain: f64,   // Smoothly interpolated current gain
    threshold: i16,      // Hard safety threshold ceiling
}

impl AudioLimiter {
    fn new() -> Self {
        Self {
            target_volume: 15000.0,
            max_gain: 2.5,
            current_gain: 1.0,
            threshold: 28000,
        }
    }

    /// Process a frame of i16 PCM samples in-place.
    /// Applies: AGC gain normalization → soft-knee peak ceiling limiter
    fn process(&mut self, samples: &mut [i16]) {
        if samples.is_empty() {
            return;
        }

        // 1. Calculate the peak value of the current frame
        let mut peak: i16 = 0;
        for &s in samples.iter() {
            let abs_val = if s == i16::MIN { i16::MAX } else { s.abs() };
            if abs_val > peak {
                peak = abs_val;
            }
        }

        // 2. Determine target gain for this frame
        let target_gain = if peak > 100 {
            // Only scale if there is actual signal activity, not noise floor
            let g = self.target_volume / peak as f64;
            if g > self.max_gain { self.max_gain } else { g }
        } else {
            1.0
        };

        // 3. Attack/release coefficients for smooth transitions
        // Attack: 0.03 (moderate response to volume spikes to avoid sudden waveform clipping)
        // Release: 0.0005 (slow release to prevent pumping artifacts between words)
        let coeff = if target_gain < self.current_gain {
            0.03 // Softer attack
        } else {
            0.0005 // Softer release
        };

        // 4. Smoothly scale samples and apply soft-knee limiter
        let threshold_f = self.threshold as f64;
        let limit_start = 20000.0;
        let range = threshold_f - limit_start;

        for s in samples.iter_mut() {
            // Single-pole low-pass filter to interpolate gain sample-by-sample
            self.current_gain += coeff * (target_gain - self.current_gain);

            let val = *s as f64 * self.current_gain;

            // Soft-Knee Peak Limiter using a rational mapping
            let clamped = if val > limit_start {
                limit_start + range * ((val - limit_start) / (range + (val - limit_start)))
            } else if val < -limit_start {
                -limit_start - range * ((-val - limit_start) / (range + (-val - limit_start)))
            } else {
                val
            };

            *s = clamped as i16;
        }
    }
}

/// Adaptive Jitter Buffer for smooth real-time audio playback.
/// Manages buffering state with crossfade transitions to eliminate clicks/pops
/// when the buffer runs dry or needs to catch up.
struct AdaptiveJitterBuffer {
    /// Minimum samples to buffer before starting playback (prevents stuttering)
    min_buffer_samples: usize,
    /// Maximum samples to allow in buffer (prevents latency buildup)
    max_buffer_samples: usize,
    /// Whether we are currently in buffering/accumulation mode
    buffering: bool,
    /// Crossfade length in samples for smooth transitions
    crossfade_len: usize,
    /// Current position in a crossfade (0 = not fading)
    fade_position: usize,
    /// Whether we are fading in (true) or fading out (false)
    fading_in: bool,
    /// Previous sample for interpolation during underruns
    last_sample: f32,
}

impl AdaptiveJitterBuffer {
    fn new(output_sample_rate: u32) -> Self {
        // 80ms initial buffer = good balance between latency and smoothness for VoIP
        let min_buf = (output_sample_rate as usize) * 80 / 1000;
        // 500ms max buffer to cap latency
        let max_buf = (output_sample_rate as usize) * 500 / 1000;
        // 5ms crossfade for click-free transitions
        let crossfade = (output_sample_rate as usize) * 5 / 1000;

        Self {
            min_buffer_samples: min_buf,
            max_buffer_samples: max_buf,
            buffering: true,
            crossfade_len: crossfade.max(1),
            fade_position: 0,
            fading_in: false,
            last_sample: 0.0,
        }
    }

    /// Pull samples from the queue into the output buffer with adaptive jitter management.
    /// Returns smoothly-transitioned audio even during buffer underruns.
    fn fill_output(&mut self, queue: &mut std::collections::VecDeque<f32>, output: &mut [f32], channels: usize) {
        for frame in output.chunks_mut(channels) {
            let sample = self.next_sample(queue);
            for out in frame.iter_mut() {
                *out = sample;
            }
        }
    }

    fn next_sample(&mut self, queue: &mut std::collections::VecDeque<f32>) -> f32 {
        let q_len = queue.len();

        // State machine: buffering → playing → (underrun) → buffering
        if self.buffering {
            if q_len >= self.min_buffer_samples {
                // Buffer is full enough, start playing with fade-in
                self.buffering = false;
                self.fade_position = 0;
                self.fading_in = true;
            } else {
                // Still accumulating — output silence, smoothly fading from last known sample
                let sample = if self.fade_position < self.crossfade_len {
                    let t = 1.0 - (self.fade_position as f32 / self.crossfade_len as f32);
                    self.fade_position += 1;
                    self.last_sample * t
                } else {
                    0.0
                };
                return sample;
            }
        }

        // Trim excess latency: if buffer grows too large, discard oldest samples
        if q_len > self.max_buffer_samples {
            let to_drain = q_len - self.max_buffer_samples;
            queue.drain(..to_drain);
        }

        // Try to get next sample
        if let Some(raw_sample) = queue.pop_front() {
            let sample = if self.fading_in && self.fade_position < self.crossfade_len {
                // Crossfade from silence/last_sample into live audio
                let t = self.fade_position as f32 / self.crossfade_len as f32;
                self.fade_position += 1;
                self.last_sample * (1.0 - t) + raw_sample * t
            } else {
                self.fading_in = false;
                raw_sample
            };
            self.last_sample = sample;
            sample
        } else {
            // Buffer underrun — go back to buffering mode with fade-out
            self.buffering = true;
            self.fade_position = 0;
            self.last_sample
        }
    }
}

// Upsampler to convert incoming 8000 Hz audio to the speaker output sample rate
// Uses cubic Hermite interpolation for smoother audio than linear interpolation
struct PlaybackResampler {
    source_rate: u32,
    target_rate: u32,
    fractional_index: f64,
}

impl PlaybackResampler {
    fn new(source_rate: u32, target_rate: u32) -> Self {
        Self {
            source_rate,
            target_rate,
            fractional_index: 0.0,
        }
    }

    /// Cubic Hermite spline interpolation between 4 points
    /// Produces smoother results than linear interpolation, reducing aliasing artifacts
    fn cubic_interpolate(y0: f32, y1: f32, y2: f32, y3: f32, t: f32) -> f32 {
        let a = -0.5 * y0 + 1.5 * y1 - 1.5 * y2 + 0.5 * y3;
        let b = y0 - 2.5 * y1 + 2.0 * y2 - 0.5 * y3;
        let c = -0.5 * y0 + 0.5 * y2;
        let d = y1;
        ((a * t + b) * t + c) * t + d
    }

    fn process(&mut self, input: &[i16], output: &mut Vec<f32>) {
        if input.is_empty() {
            return;
        }

        if self.source_rate == self.target_rate {
            for &sample in input {
                output.push(sample as f32 / 32768.0);
            }
            return;
        }
        
        let step = self.source_rate as f64 / self.target_rate as f64;
        let input_f: Vec<f32> = input.iter().map(|&s| s as f32 / 32768.0).collect();
        let mut idx = self.fractional_index;
        
        while (idx as usize) < input_f.len() {
            let i = idx as usize;
            let frac = (idx - i as f64) as f32;

            let sample = if i >= 1 && i + 2 < input_f.len() {
                // Full cubic interpolation with 4 surrounding points
                Self::cubic_interpolate(
                    input_f[i - 1],
                    input_f[i],
                    input_f[i + 1],
                    input_f[i + 2],
                    frac,
                )
            } else if i + 1 < input_f.len() {
                // Fallback to linear interpolation at boundaries
                let s0 = input_f[i];
                let s1 = input_f[i + 1];
                s0 + frac * (s1 - s0)
            } else {
                input_f[i]
            };

            output.push(sample);
            idx += step;
        }
        self.fractional_index = idx - input_f.len() as f64;
    }
}

// ============================================================================
// END AUDIO PROCESSING PIPELINE
// ============================================================================

// SIP URI Parser: extracts extension/username, host, and port
fn parse_sip_uri(uri: &str) -> Option<(String, String, u16)> {
    let clean = uri.trim().strip_prefix("sip:").unwrap_or(uri.trim());
    let parts: Vec<&str> = clean.split('@').collect();
    if parts.len() != 2 {
        return None;
    }
    let username = parts[0].to_string();
    let host_part = parts[1];
    
    let (host, port) = if host_part.contains(']') {
        if let Some(bracket_idx) = host_part.rfind(']') {
            if bracket_idx + 1 < host_part.len() && host_part.as_bytes()[bracket_idx + 1] == b':' {
                let host = host_part[..=bracket_idx].to_string();
                let port_str = &host_part[bracket_idx + 2..];
                if let Ok(p) = port_str.parse::<u16>() {
                    (host, p)
                } else {
                    (host_part.to_string(), 5060)
                }
            } else {
                (host_part.to_string(), 5060)
            }
        } else {
            (host_part.to_string(), 5060)
        }
    } else if let Some(colon_idx) = host_part.rfind(':') {
        let host = host_part[..colon_idx].to_string();
        let port_str = &host_part[colon_idx + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            (host, port)
        } else {
            (host_part.to_string(), 5060)
        }
    } else {
        (host_part.to_string(), 5060)
    };
    
    Some((username, host, port))
}

// Random numbers generator using system time
fn rand_u32() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    (nanos & 0xFFFFFFFF) as u32
}

fn rand_u64() -> u64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos as u64
}

// Background RTP streaming from local microphone
fn start_microphone_rtp(
    channel_id: u32,
    rtp_socket: Arc<tokio::net::UdpSocket>,
    rtp_destination: String,
    state: Arc<Mutex<AppState>>,
    device_name: Option<String>,
    ptt_active: Arc<std::sync::atomic::AtomicBool>,
) -> (Arc<std::sync::atomic::AtomicBool>, tokio::task::AbortHandle) {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    use std::sync::atomic::{AtomicBool, Ordering};
    
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = Arc::clone(&stop_flag);
    
    let (tx_audio, mut rx_audio) = tokio::sync::mpsc::channel::<Vec<f32>>(100);
    
    let rtp_socket_clone = Arc::clone(&rtp_socket);
    let rtp_dest_clone = rtp_destination.clone();
    let state_clone = Arc::clone(&state);
    let device_name_clone = device_name.clone();
    
    let ptt_active_clone = Arc::clone(&ptt_active);
    // Spawn async network sender task
    let sender_task = tokio::spawn(async move {
        let state_sender = Arc::clone(&state_clone);
        let (srtp_enabled, secure_context) = {
            let app_state = state_sender.lock().await;
            let ch = app_state.channels.iter().find(|c| c.id == channel_id);
            let srtp = ch.map(|c| c.srtp_enabled).unwrap_or(false);
            let s_ctx = ch.map(|c| Arc::clone(&c.secure_context)).unwrap();
            (srtp, s_ctx)
        };

        let sample_rate = {
            let host = cpal::default_host();
            let dev = device_name_clone.and_then(|name| {
                host.input_devices().ok().and_then(|mut devs| {
                    devs.find(|d| d.name().ok().map(|n| n == name).unwrap_or(false))
                })
            }).or_else(|| host.default_input_device());
            
            dev.and_then(|d| d.default_input_config().ok())
               .map(|c| c.sample_rate().0)
               .unwrap_or(44100)
        };
        
        let mut resampler = Resampler::new(sample_rate, 8000);
        // TX intake chain: rumble/DC high-pass → AGC + soft-knee limiter.
        // Same AudioLimiter algorithm (JPS_Recorder port) as the RX path, so
        // outgoing mic audio is normalized instead of raw.
        let mut tx_highpass = Biquad::highpass(8000.0, 100.0, 0.7071);
        let mut tx_limiter = AudioLimiter::new();
        let mut pcm_buffer = Vec::new();
        let mut sequence_number: u16 = rand_u32() as u16;
        let mut timestamp: u32 = rand_u32();
        let ssrc: u32 = rand_u32();
        
        println!("[RTP TX Task] Audio pipeline: Mic → AGC/Limiter → Resample → µ-law encode → RTP");
        let rtp_socket_tx = Arc::clone(&rtp_socket_clone);
        let rtp_dest_tx = rtp_dest_clone.clone();
        
        // Spawn key exchange handshake loop if SRTP is enabled
        if srtp_enabled {
            {
                let mut ctx = secure_context.lock().await;
                if ctx.local_public.is_none() {
                    ctx.initialize_keypair();
                }
            }
            
            let secure_context_handshake = Arc::clone(&secure_context);
            let rtp_socket_handshake = Arc::clone(&rtp_socket_tx);
            let rtp_dest_handshake = rtp_dest_tx.clone();
            tokio::spawn(async move {
                for _ in 0..15 {
                    let (fingerprint, pub_hex, keys_exist) = {
                        let ctx = secure_context_handshake.lock().await;
                        (
                            ctx.get_local_fingerprint(),
                            ctx.local_public.map(|p| hex::encode(p.as_bytes())).unwrap_or_default(),
                            ctx.keys.is_some()
                        )
                    };
                    if keys_exist {
                        break;
                    }
                    if !pub_hex.is_empty() {
                        let handshake_msg = format!("AQUILLA12_KEY_EXCHANGE:{}:{}", fingerprint, pub_hex);
                        let _ = rtp_socket_handshake.send_to(handshake_msg.as_bytes(), &rtp_dest_handshake).await;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            });
        }
        
        {
            // Standard point-to-point PTT logic
            let mut interval = tokio::time::interval(Duration::from_millis(20));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            while let Some(audio_chunk) = rx_audio.recv().await {
                resampler.process(&audio_chunk, &mut pcm_buffer);
                
                while pcm_buffer.len() >= 160 {
                    let mut chunk_160: Vec<i16> = pcm_buffer.drain(..160).collect();

                    // Mic intake processing: high-pass (cut rumble/DC below 100 Hz),
                    // then AGC + peak limiter to normalize level before µ-law encode
                    for s in chunk_160.iter_mut() {
                        *s = (tx_highpass.process(*s as f64)).clamp(-32768.0, 32767.0) as i16;
                    }
                    tx_limiter.process(&mut chunk_160);

                    let sum_squares: f64 = chunk_160.iter().map(|&s| {
                        let normalized = s as f64 / 32768.0;
                        normalized * normalized
                    }).sum();
                    let rms = (sum_squares / 160.0).sqrt();
                    let audio_level = (rms * 500.0).clamp(0.0, 100.0) as u32;
                    
                    let mut packet = vec![0u8; 12 + 160];
                    packet[0] = 0x80;
                    packet[1] = 0x00;
                    
                    packet[2] = (sequence_number >> 8) as u8;
                    packet[3] = (sequence_number & 0xFF) as u8;
                    
                    packet[4] = (timestamp >> 24) as u8;
                    packet[5] = ((timestamp >> 16) & 0xFF) as u8;
                    packet[6] = ((timestamp >> 8) & 0xFF) as u8;
                    packet[7] = (timestamp & 0xFF) as u8;
                    
                    packet[8] = (ssrc >> 24) as u8;
                    packet[9] = ((ssrc >> 16) & 0xFF) as u8;
                    packet[10] = ((ssrc >> 8) & 0xFF) as u8;
                    packet[11] = (ssrc & 0xFF) as u8;
                    
                    for i in 0..160 {
                        packet[12 + i] = linear_to_ulaw(chunk_160[i]);
                    }
                    
                    if ptt_active_clone.load(Ordering::SeqCst) {
                        if srtp_enabled {
                            let ctx = secure_context.lock().await;
                            if let Some(ref keys) = ctx.keys {
                                let mut payload = packet[12..].to_vec();
                                if let Ok(tag) = crypto::encrypt_rtp_gcm(keys, sequence_number, timestamp, ssrc, &mut payload) {
                                    let mut srtp_packet = packet[0..12].to_vec();
                                    srtp_packet.extend_from_slice(&payload);
                                    srtp_packet.extend_from_slice(&tag);
                                    let _ = rtp_socket_clone.send_to(&srtp_packet, &rtp_dest_clone).await;
                                }
                            }
                        } else {
                            let _ = rtp_socket_clone.send_to(&packet, &rtp_dest_clone).await;
                        }
                    }
                    
                    sequence_number = sequence_number.wrapping_add(1);
                    timestamp = timestamp.wrapping_add(160);
                    
                    let tx_ws = {
                        let mut lock_state = state_clone.lock().await;
                        if let Some(ch) = lock_state.channels.iter_mut().find(|c| c.id == channel_id) {
                            ch.audio_level = audio_level;
                        }
                        lock_state.tx.clone()
                    };
                    let level_msg = serde_json::json!({
                        "type": "audio_level",
                        "data": { "id": channel_id, "level": audio_level }
                    }).to_string();
                    let _ = tx_ws.send(level_msg);
                    
                    interval.tick().await;
                }
            }
        }
    });
    
    // Spawn OS thread to build and run cpal input stream (keeping it thread-bound)
    let selected_device_name = {
        let host = cpal::default_host();
        let dev = device_name.and_then(|name| {
            host.input_devices().ok().and_then(|mut devs| {
                devs.find(|d| d.name().ok().map(|n| n == name).unwrap_or(false))
            })
        }).or_else(|| host.default_input_device());
        
        dev.and_then(|d| d.name().ok())
    };

    std::thread::spawn(move || {
        println!("[RTP Stream Thread] OS audio thread active.");
        
        let host = cpal::default_host();
        let device = match selected_device_name {
            Some(name) => {
                let mut found_device = None;
                if let Ok(devices) = host.input_devices() {
                    for dev in devices {
                        if let Ok(n) = dev.name() {
                            if n == name {
                                found_device = Some(dev);
                                break;
                            }
                        }
                    }
                }
                found_device.or_else(|| host.default_input_device())
            }
            None => host.default_input_device(),
        };
        
        let device = match device {
            Some(d) => d,
            None => {
                eprintln!("[RTP Stream Thread] No audio input device found!");
                return;
            }
        };
        
        let config = match device.default_input_config() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[RTP Stream Thread] Failed to get default input config: {}", e);
                return;
            }
        };
        
        let channels = config.channels();
        let tx_audio_clone = tx_audio.clone();
        let err_fn = |err| eprintln!("[RTP Stream Thread] an error occurred on stream: {}", err);
        
        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => {
                device.build_input_stream(
                    &config.into(),
                    move |data: &[f32], _: &_| {
                        let mut mono = Vec::new();
                        if channels > 1 {
                            for chunk in data.chunks(channels as usize) {
                                if !chunk.is_empty() {
                                    // Average all channels instead of dropping everything but ch 0
                                    let sum: f32 = chunk.iter().sum();
                                    mono.push(sum / chunk.len() as f32);
                                }
                            }
                        } else {
                            mono = data.to_vec();
                        }
                        let _ = tx_audio_clone.try_send(mono);
                    },
                    err_fn,
                    None
                )
            }
            cpal::SampleFormat::I16 => {
                device.build_input_stream(
                    &config.into(),
                    move |data: &[i16], _: &_| {
                        let mut mono = Vec::new();
                        if channels > 1 {
                            for chunk in data.chunks(channels as usize) {
                                if !chunk.is_empty() {
                                    let sum: f32 = chunk.iter().map(|&s| s as f32 / 32768.0).sum();
                                    mono.push(sum / chunk.len() as f32);
                                }
                            }
                        } else {
                            mono = data.iter().map(|&s| s as f32 / 32768.0).collect();
                        }
                        let _ = tx_audio_clone.try_send(mono);
                    },
                    err_fn,
                    None
                )
            }
            cpal::SampleFormat::U16 => {
                device.build_input_stream(
                    &config.into(),
                    move |data: &[u16], _: &_| {
                        let mut mono = Vec::new();
                        if channels > 1 {
                            for chunk in data.chunks(channels as usize) {
                                if !chunk.is_empty() {
                                    let sum: f32 = chunk.iter().map(|&s| (s as f32 - 32768.0) / 32768.0).sum();
                                    mono.push(sum / chunk.len() as f32);
                                }
                            }
                        } else {
                            mono = data.iter().map(|&s| {
                                let signed = s as f32 - 32768.0;
                                signed / 32768.0
                            }).collect();
                        }
                        let _ = tx_audio_clone.try_send(mono);
                    },
                    err_fn,
                    None
                )
            }
            _ => {
                eprintln!("[RTP Stream Thread] Unsupported sample format!");
                return;
            }
        };
        
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[RTP Stream Thread] Failed to build input stream: {}", e);
                return;
            }
        };
        
        if let Err(e) = stream.play() {
            eprintln!("[RTP Stream Thread] Failed to play stream: {}", e);
            return;
        }
        
        while !stop_flag_clone.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
        }
        
        println!("[RTP Stream Thread] Terminating cpal stream.");
    });

    (stop_flag, sender_task.abort_handle())
}

// Background RTP receiving and playback to local speaker
fn start_audio_playback(
    channel_id: u32,
    rtp_socket: Arc<tokio::net::UdpSocket>,
    state: Arc<Mutex<AppState>>,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::AbortHandle {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::Ordering;

    let (srtp_enabled, secure_context) = {
        let app_state = state.blocking_lock();
        let ch = app_state.channels.iter().find(|c| c.id == channel_id);
        let srtp = ch.map(|c| c.srtp_enabled).unwrap_or(false);
        let s_ctx = ch.map(|c| Arc::clone(&c.secure_context)).unwrap();
        (srtp, s_ctx)
    };

    // Query output device and sample rate ONCE on the calling thread to prevent mismatches
    let host = cpal::default_host();
    let device = host.default_output_device();
    
    let (config, sample_rate) = if let Some(ref d) = device {
        if let Ok(c) = d.default_output_config() {
            let sr = c.sample_rate().0;
            (Some(c), sr)
        } else {
            (None, 48000)
        }
    } else {
        (None, 48000)
    };

    println!("[RTP Playback] Initializing playback. Sample rate: {} Hz", sample_rate);

    let queue = Arc::new(Mutex::new(VecDeque::<f32>::new()));
    let queue_clone = Arc::clone(&queue);
    let stop_flag_clone = Arc::clone(&stop_flag);
    
    let device_clone = device.clone();
    let config_clone = config.clone();

    {
        // 1. Spawn the CPAL output stream thread with AdaptiveJitterBuffer
        std::thread::spawn(move || {
            println!("[RTP Playback Thread] OS audio output thread active.");
            
            let device = match device_clone {
                Some(d) => d,
                None => {
                    eprintln!("[RTP Playback Thread] No default output device found!");
                    return;
                }
            };
            
            let config = match config_clone {
                Some(c) => c,
                None => {
                    eprintln!("[RTP Playback Thread] Failed to get default output config!");
                    return;
                }
            };
            
            let channels = config.channels() as usize;
            let out_rate = config.sample_rate().0;
            let err_fn = |err| eprintln!("[RTP Playback Thread] an error occurred on output stream: {}", err);
            
            let stream = match config.sample_format() {
                cpal::SampleFormat::F32 => {
                    let q_c = Arc::clone(&queue_clone);
                    let mut jitter_buf = AdaptiveJitterBuffer::new(out_rate);
                    device.build_output_stream(
                        &config.into(),
                        move |data: &mut [f32], _: &_| {
                            let mut q = q_c.lock().unwrap();
                            jitter_buf.fill_output(&mut q, data, channels);
                        },
                        err_fn,
                        None
                    )
                }
                cpal::SampleFormat::I16 => {
                    let q_c = Arc::clone(&queue_clone);
                    let mut jitter_buf = AdaptiveJitterBuffer::new(out_rate);
                    let mut float_buf = Vec::new();
                    device.build_output_stream(
                        &config.into(),
                        move |data: &mut [i16], _: &_| {
                            float_buf.resize(data.len(), 0.0f32);
                            {
                                let mut q = q_c.lock().unwrap();
                                jitter_buf.fill_output(&mut q, &mut float_buf, channels);
                            }
                            for (out, &f) in data.iter_mut().zip(float_buf.iter()) {
                                *out = (f.clamp(-1.0, 1.0) * 32767.0) as i16;
                            }
                        },
                        err_fn,
                        None
                    )
                }
                cpal::SampleFormat::U16 => {
                    let q_c = Arc::clone(&queue_clone);
                    let mut jitter_buf = AdaptiveJitterBuffer::new(out_rate);
                    let mut float_buf = Vec::new();
                    device.build_output_stream(
                        &config.into(),
                        move |data: &mut [u16], _: &_| {
                            float_buf.resize(data.len(), 0.0f32);
                            {
                                let mut q = q_c.lock().unwrap();
                                jitter_buf.fill_output(&mut q, &mut float_buf, channels);
                            }
                            for (out, &f) in data.iter_mut().zip(float_buf.iter()) {
                                *out = ((f.clamp(-1.0, 1.0) * 32767.0) + 32768.0) as u16;
                            }
                        },
                        err_fn,
                        None
                    )
                }
                _ => {
                    eprintln!("[RTP Playback Thread] Unsupported sample format!");
                    return;
                }
            };
            
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[RTP Playback Thread] Failed to build output stream: {}", e);
                    return;
                }
            };
            
            if let Err(e) = stream.play() {
                eprintln!("[RTP Playback Thread] Failed to play stream: {}", e);
                return;
            }
            
            while !stop_flag_clone.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }
            
            println!("[RTP Playback Thread] Terminating cpal output stream.");
        });
    }

    // 2. Spawn the tokio task to receive incoming RTP UDP packets, decode, and route accordingly
    let rtp_socket_clone = Arc::clone(&rtp_socket);
    let queue_write = Arc::clone(&queue);

    let rx_task = tokio::spawn(async move {
        let mut resampler = PlaybackResampler::new(8000, sample_rate);
        let mut limiter = AudioLimiter::new();
        let mut buf = [0u8; 2048];
        
        println!("[RTP RX Task] Audio pipeline active");
        
        loop {
            match rtp_socket_clone.recv_from(&mut buf).await {
                Ok((len, _src)) => {
                    if len >= 12 {
                        let version = (buf[0] >> 6) & 0x03;
                        let payload_type = buf[1] & 0x7F;
                        
                        // Handle In-Band Key Exchange Handshake
                        if srtp_enabled && buf[..len].starts_with(b"AQUILLA12_KEY_EXCHANGE:") {
                            if let Some(peer_key) = crypto::parse_key_exchange(&buf[..len]) {
                                let mut ctx = secure_context.lock().await;
                                if ctx.keys.is_none() {
                                    let is_server = channel_id % 2 == 0;
                                    if let Err(e) = ctx.derive_keys(peer_key, is_server) {
                                        eprintln!("[SRTP Key Exchange] Key derivation failed: {}", e);
                                    } else if let Some(ref keys) = ctx.keys {
                                        println!("[SRTP Key Exchange] Derived keys: Tx={:02x?}... Rx={:02x?}...", &keys.tx_key[..4], &keys.rx_key[..4]);
                                    }
                                }
                            }
                            continue;
                        }
                        
                        if version == 2 && payload_type == 0 {
                            let payload_opt = if srtp_enabled {
                                let ctx = secure_context.lock().await;
                                if let Some(ref keys) = ctx.keys {
                                    let seq = ((buf[2] as u16) << 8) | (buf[3] as u16);
                                    let ts = ((buf[4] as u32) << 24) | ((buf[5] as u32) << 16) | ((buf[6] as u32) << 8) | (buf[7] as u32);
                                    let ssrc = ((buf[8] as u32) << 24) | ((buf[9] as u32) << 16) | ((buf[10] as u32) << 8) | (buf[11] as u32);
                                    let mut payload_cipher = buf[12..len].to_vec();
                                    if payload_cipher.len() > 16 {
                                        let tag_start = payload_cipher.len() - 16;
                                        let tag_vec = payload_cipher.split_off(tag_start);
                                        let mut tag = [0u8; 16];
                                        tag.copy_from_slice(&tag_vec);
                                        if crypto::decrypt_rtp_gcm(keys, seq, ts, ssrc, &mut payload_cipher, &tag).is_ok() {
                                            Some(payload_cipher)
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                parse_rtp_payload(&buf[..len]).map(|p| p.to_vec())
                            };
                            
                            if let Some(payload) = payload_opt {
                                // Decode µ-law to linear i16
                                let mut pcm: Vec<i16> = payload.iter().map(|&b| ulaw_to_linear(b)).collect();
                                
                                // Apply AGC and limiter to incoming audio
                                limiter.process(&mut pcm);

                                // Standard playback path
                                let mut upsampled = Vec::new();
                                resampler.process(&pcm, &mut upsampled);

                                if !upsampled.is_empty() {
                                    let mut q = queue_write.lock().unwrap();
                                    q.extend(upsampled);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("[RTP RX Task] Socket read ending (or error): {}", e);
                    break;
                }
            }
        }
    });

    rx_task.abort_handle()
}

#[derive(Debug, Deserialize)]
struct PttRequest {
    active: bool,
}

// REST: Toggle PTT Transmit state
async fn ptt_toggle_handler(
    Path(id): Path<u32>,
    State(state): State<Arc<Mutex<AppState>>>,
    Json(payload): Json<PttRequest>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    let tx = lock.tx.clone();

    if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
        ch.ptt_active = payload.active;
        ch.tx_kbps = if payload.active { 80 } else { 0 };

        println!("[Rust Engine] [CH {}] PTT set to {}", id, payload.active);

        let _ = tx.send(serde_json::json!({
            "type": "channel_update",
            "data": {
                "id": id,
                "pttActive": ch.ptt_active,
                "txKbps": ch.tx_kbps
            }
        }).to_string());

        let _ = tx.send(serde_json::json!({
            "type": "log",
            "data": {
                "level": "info",
                "channelId": id,
                "message": format!("[PTT] Channel {} PTT {}", id, if payload.active { "pressed (Transmitting)" } else { "released (Muted)" })
            }
        }).to_string());
    }

    if let Some(active) = lock.active_calls.iter_mut().find(|c| c.channel_id == id) {
        if let Some(ref ptt_flag) = active.ptt_active {
            ptt_flag.store(payload.active, std::sync::atomic::Ordering::SeqCst);
        }
    }

    (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
}

// REST: Initiate Outbound SIP Call
async fn initiate_call_handler(
    Path(id): Path<u32>,
    State(state): State<Arc<Mutex<AppState>>>,
    Json(payload): Json<CallRequest>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    
    // Check if there is already an active call on this channel. If so, hang it up first.
    if let Some(pos) = lock.active_calls.iter().position(|c| c.channel_id == id) {
        let active = lock.active_calls.remove(pos);
        if let Some(flag) = active.audio_stop_flag {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(h) = active.rtp_abort_handle {
            h.abort();
        }
        if let Some(h) = active.rtp_rx_abort_handle {
            h.abort();
        }
        if let Some(h) = active.sip_abort_handle {
            h.abort();
        }
        
        let local_ip = active.local_ip.clone();
        let local_sip_port = active.local_sip_port;
        let target_ip = active.target_ip.clone();
        let target_port = active.target_port;
        let call_id = active.call_id.clone();
        let from_tag = active.from_tag.clone();
        let to_tag = active.to_tag.clone();
        let target_user = parse_sip_uri(&active.target_ip).map(|(u, _, _)| u).unwrap_or_else(|| "113".to_string());
        
        tokio::spawn(async move {
            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                let to_tag_str = match to_tag {
                    Some(t) => format!(";tag={}", t),
                    None => "".to_string(),
                };
                let branch_bye = format!("z9hG4bK{:x}", rand_u32());
                let bye = format!(
                    "BYE sip:{}@{}:{} SIP/2.0\r\n\
                     Via: SIP/2.0/UDP {}:{};branch={}\r\n\
                     Max-Forwards: 70\r\n\
                     To: <sip:{}@{}:{}>{}\r\n\
                     From: <sip:caller@{}:{}>;tag={}\r\n\
                     Call-ID: {}\r\n\
                     CSeq: 2 BYE\r\n\
                     Content-Length: 0\r\n\
                     \r\n",
                    target_user, target_ip, target_port,
                    local_ip, local_sip_port, branch_bye,
                    target_user, target_ip, target_port, to_tag_str,
                    local_ip, local_sip_port, from_tag,
                    call_id
                );
                let dest = format!("{}:{}", target_ip, target_port);
                let _ = socket.send_to(bye.as_bytes(), dest).await;
            }
        });
    }

    let tx = lock.tx.clone();

    // Check if channel protocol is RTP
    let is_rtp = if let Some(ch) = lock.channels.iter().find(|c| c.id == id) {
        ch.protocol == "RTP"
    } else {
        false
    };

    if is_rtp {
        // Direct RTP path
        let target = payload.target_uri.trim_start_matches("rtp://").to_string();
        let parts: Vec<&str> = target.split(':').collect();
        let (dest_ip, dest_port) = if parts.len() == 2 {
            let ip = parts[0].to_string();
            let port = parts[1].parse::<u16>().unwrap_or(5004);
            (ip, port)
        } else {
            (target.clone(), 5004)
        };

        let local_port = if let Some(ch) = lock.channels.iter().find(|c| c.id == id) {
            ch.local_port.unwrap_or((6000 + id * 2) as u16)
        } else {
            (6000 + id * 2) as u16
        };

        let dest_addr = format!("{}:{}", dest_ip, dest_port);
        let local_ip = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(sock) => {
                if sock.connect(&dest_addr).await.is_ok() {
                    sock.local_addr().map(|a| a.ip().to_string()).unwrap_or_else(|_| "127.0.0.1".to_string())
                } else {
                    "127.0.0.1".to_string()
                }
            }
            Err(_) => "127.0.0.1".to_string(),
        };

        let rtp_socket = match tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Failed to bind RTP socket: {}", e) }))).into_response();
            }
        };

        if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
            ch.target_uri = payload.target_uri.clone();
            ch.codec = payload.codec.clone();
            ch.status = "CONNECTED".to_string();
            ch.duration = 0;
            ch.latency = 5;
            ch.jitter = 1;
            ch.packet_loss = 0.0;
            ch.rx_kbps = 80;
            ch.tx_kbps = 0;
            ch.ptt_active = false;
        }

        let _ = tx.send(serde_json::json!({
            "type": "channel_update",
            "data": {
                "id": id,
                "status": "CONNECTED",
                "duration": 0,
                "targetUri": payload.target_uri.clone(),
                "codec": payload.codec.clone(),
                "latency": 5,
                "jitter": 1,
                "packetLoss": 0.0,
                "rxKbps": 80,
                "txKbps": 0,
                "pttActive": false
            }
        }).to_string());

        let _ = tx.send(serde_json::json!({
            "type": "log",
            "data": {
                "level": "info",
                "channelId": id,
                "message": format!("[RTP Stack] Direct RTP audio session starting. Local Port: {}, Target: {}", local_port, dest_addr)
            }
        }).to_string());

        let rtp_dest = dest_addr;
        let rtp_sock_task = Arc::clone(&rtp_socket);
        let state_audio = Arc::clone(&state);
        let selected_device = lock.selected_device.clone();

        let ptt_active_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ptt_active_flag_clone = Arc::clone(&ptt_active_flag);

        let (audio_flag, rtp_task) = start_microphone_rtp(
            id, Arc::clone(&rtp_sock_task), rtp_dest, Arc::clone(&state_audio), selected_device, ptt_active_flag
        );

        let audio_flag_playback = Arc::clone(&audio_flag);
        let rtp_rx_task = start_audio_playback(
            id, Arc::clone(&rtp_sock_task), Arc::clone(&state_audio), audio_flag_playback
        );

        let active_call = ActiveCall {
            channel_id: id,
            target_ip: dest_ip,
            target_port: dest_port,
            local_ip,
            local_sip_port: 0,
            local_rtp_port: local_port,
            call_id: format!("rtp-{}", id),
            from_tag: "".to_string(),
            to_tag: None,
            audio_stop_flag: Some(audio_flag),
            ptt_active: Some(ptt_active_flag_clone),
            rtp_abort_handle: Some(rtp_task),
            rtp_rx_abort_handle: Some(rtp_rx_task),
            sip_abort_handle: None,
        };
        lock.active_calls.push(active_call);

        return (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response();
    }

    let parsed_uri = parse_sip_uri(&payload.target_uri);
    if parsed_uri.is_none() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid SIP URI format" }))).into_response();
    }
    let (target_user, target_ip, target_port) = parsed_uri.unwrap();

    let dest_addr = format!("{}:{}", target_ip, target_port);
    let local_ip = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => {
            if sock.connect(&dest_addr).await.is_ok() {
                sock.local_addr().map(|a| a.ip().to_string()).unwrap_or_else(|_| "127.0.0.1".to_string())
            } else {
                "127.0.0.1".to_string()
            }
        }
        Err(_) => "127.0.0.1".to_string(),
    };

    let sip_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Failed to bind SIP socket: {}", e) }))).into_response();
        }
    };
    let local_sip_port = sip_socket.local_addr().unwrap().port();

    let rtp_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Failed to bind RTP socket: {}", e) }))).into_response();
        }
    };
    let local_rtp_port = rtp_socket.local_addr().unwrap().port();

    if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
        ch.target_uri = payload.target_uri.clone();
        ch.codec = payload.codec.clone();
        ch.status = "RINGING".to_string();
        ch.duration = 0;
        
        let call_id = format!("{:016x}", rand_u64());
        let from_tag = format!("{:08x}", rand_u32());
        let branch = format!("z9hG4bK{:x}", rand_u32());

        println!("[Rust Engine] [CH {}] Real Outbound Direct SIP INVITE to {} from local {}:{}", id, dest_addr, local_ip, local_sip_port);

        let _ = tx.send(serde_json::json!({
            "type": "channel_update",
            "data": {
                "id": id,
                "status": "RINGING",
                "duration": 0,
                "targetUri": ch.target_uri,
                "codec": ch.codec
            }
        }).to_string());

        let _ = tx.send(serde_json::json!({
            "type": "log",
            "data": {
                "level": "sip_tx",
                "channelId": id,
                "message": format!("[rsipstack] SIP INVITE sent over UDP to {}:{}", target_ip, target_port)
            }
        }).to_string());

        let sdp = format!(
            "v=0\r\n\
             o=sip-controller 123456 123456 IN IP4 {local_ip}\r\n\
             s=Talk\r\n\
             c=IN IP4 {local_ip}\r\n\
             t=0 0\r\n\
             m=audio {local_rtp_port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n"
        );
        let invite = format!(
            "INVITE sip:{}@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {}:{};branch={}\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:{}@{}>\r\n\
             From: <sip:caller@{}:{}>;tag={}\r\n\
             Call-ID: {}\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:caller@{}:{}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {sdp}",
            target_user, dest_addr,
            local_ip, local_sip_port, branch,
            target_user, dest_addr,
            local_ip, local_sip_port, from_tag,
            call_id,
            local_ip, local_sip_port,
            sdp.len()
        );

        let socket_clone = Arc::clone(&sip_socket);
        let dest_addr_clone = dest_addr.clone();
        tokio::spawn(async move {
            let _ = socket_clone.send_to(invite.as_bytes(), &dest_addr_clone).await;
        });

        let mut active_call = ActiveCall {
            channel_id: id,
            target_ip: target_ip.clone(),
            target_port,
            local_ip: local_ip.clone(),
            local_sip_port,
            local_rtp_port,
            call_id: call_id.clone(),
            from_tag: from_tag.clone(),
            to_tag: None,
            audio_stop_flag: None,
            ptt_active: None,
            rtp_abort_handle: None,
            rtp_rx_abort_handle: None,
            sip_abort_handle: None,
        };

        let state_clone = Arc::clone(&state);
        let sip_socket_clone = Arc::clone(&sip_socket);
        let rtp_socket_clone = Arc::clone(&rtp_socket);
        let target_user_clone = target_user.clone();
        let target_ip_clone = target_ip.clone();
        let from_tag_clone = from_tag.clone();
        let call_id_clone = call_id.clone();
        let dest_addr_clone = dest_addr.clone();
        let selected_device = lock.selected_device.clone();
        
        let sip_listen_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut remote_to_tag = None;
            
            loop {
                match sip_socket_clone.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let msg = String::from_utf8_lossy(&buf[..len]);
                        println!("[SIP RX from {}]:\n{}", src, msg);
                        
                        let tx_cb = {
                            let l = state_clone.lock().await;
                            l.tx.clone()
                        };

                        if msg.contains("SIP/2.0 100") {
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "log",
                                "data": {
                                    "level": "sip_rx",
                                    "channelId": id,
                                    "message": "[rsipstack] SIP/2.0 100 Trying received"
                                }
                            }).to_string());
                        } else if msg.contains("SIP/2.0 180") {
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "log",
                                "data": {
                                    "level": "sip_rx",
                                    "channelId": id,
                                    "message": "[rsipstack] SIP/2.0 180 Ringing received"
                                }
                            }).to_string());
                        } else if msg.contains("SIP/2.0 200") {
                            if let Some(tag_idx) = msg.find("To:") {
                                if let Some(tag_param) = msg[tag_idx..].split('\n').next() {
                                    if let Some(tag_pos) = tag_param.find(";tag=") {
                                        let tag = tag_param[tag_pos + 5..].trim().to_string();
                                        remote_to_tag = Some(tag.clone());
                                        let mut lock_cb = state_clone.lock().await;
                                        if let Some(ac) = lock_cb.active_calls.iter_mut().find(|c| c.channel_id == id) {
                                            ac.to_tag = Some(tag);
                                        }
                                    }
                                }
                            }
                            
                            let mut remote_rtp_port = 5004;
                            if let Some(m_audio_idx) = msg.find("m=audio ") {
                                if let Some(line) = msg[m_audio_idx..].split('\n').next() {
                                    let tokens: Vec<&str> = line.split_whitespace().collect();
                                    if tokens.len() >= 2 {
                                        if let Ok(p) = tokens[1].parse::<u16>() {
                                            remote_rtp_port = p;
                                        }
                                    }
                                }
                            }

                            let _ = tx_cb.send(serde_json::json!({
                                "type": "log",
                                "data": {
                                    "level": "sip_rx",
                                    "channelId": id,
                                    "message": format!("[rsipstack] SIP/2.0 200 OK received. Negotiated remote RTP port {}", remote_rtp_port)
                                }
                            }).to_string());

                            let branch_ack = format!("z9hG4bK{:x}", rand_u32());
                            let to_tag_str = match &remote_to_tag {
                                Some(t) => format!(";tag={}", t),
                                None => "".to_string(),
                            };
                            let ack = format!(
                                "ACK sip:{}@{} SIP/2.0\r\n\
                                 Via: SIP/2.0/UDP {}:{};branch={}\r\n\
                                 Max-Forwards: 70\r\n\
                                 To: <sip:{}@{}>{}\r\n\
                                 From: <sip:caller@{}:{}>;tag={}\r\n\
                                 Call-ID: {}\r\n\
                                 CSeq: 1 ACK\r\n\
                                 Content-Length: 0\r\n\
                                 \r\n",
                                target_user_clone, dest_addr_clone,
                                local_ip, local_sip_port, branch_ack,
                                target_user_clone, dest_addr_clone, to_tag_str,
                                local_ip, local_sip_port, from_tag_clone,
                                call_id_clone
                            );

                            let _ = sip_socket_clone.send_to(ack.as_bytes(), &dest_addr_clone).await;

                            let _ = tx_cb.send(serde_json::json!({
                                "type": "log",
                                "data": {
                                    "level": "sip_tx",
                                    "channelId": id,
                                    "message": "[rsipstack] ACK sent. Audio session starting..."
                                }
                            }).to_string());

                            {
                                let mut lock_conn = state_clone.lock().await;
                                if let Some(ch_conn) = lock_conn.channels.iter_mut().find(|c| c.id == id) {
                                    ch_conn.status = "CONNECTED".to_string();
                                    ch_conn.latency = 12;
                                    ch_conn.jitter = 1;
                                    ch_conn.packet_loss = 0.0;
                                    ch_conn.rx_kbps = 80;
                                    ch_conn.tx_kbps = 0;
                                    ch_conn.ptt_active = false;
                                }
                            }
                            
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": id,
                                    "status": "CONNECTED",
                                    "latency": 12,
                                    "jitter": 1,
                                    "packetLoss": 0.0,
                                    "rxKbps": 80,
                                    "txKbps": 0,
                                    "pttActive": false
                                }
                            }).to_string());

                            let rtp_dest = format!("{}:{}", target_ip_clone, remote_rtp_port);
                            let rtp_sock_task = Arc::clone(&rtp_socket_clone);
                            let state_audio = Arc::clone(&state_clone);
                            
                            let ptt_active_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
                            let ptt_active_flag_clone = Arc::clone(&ptt_active_flag);

                            let (audio_flag, rtp_task) = start_microphone_rtp(
                                id, Arc::clone(&rtp_sock_task), rtp_dest, Arc::clone(&state_audio), selected_device.clone(), ptt_active_flag
                            );

                            let audio_flag_playback = Arc::clone(&audio_flag);
                            let rtp_rx_task = start_audio_playback(
                                id, Arc::clone(&rtp_sock_task), Arc::clone(&state_audio), audio_flag_playback
                            );

                            let mut lock_rtp = state_clone.lock().await;
                            if let Some(ac) = lock_rtp.active_calls.iter_mut().find(|c| c.channel_id == id) {
                                ac.audio_stop_flag = Some(audio_flag);
                                ac.ptt_active = Some(ptt_active_flag_clone);
                                ac.rtp_abort_handle = Some(rtp_task);
                                ac.rtp_rx_abort_handle = Some(rtp_rx_task);
                            }
                        } else if msg.contains("BYE") {
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "log",
                                "data": {
                                    "level": "sip_rx",
                                    "channelId": id,
                                    "message": "[rsipstack] SIP BYE received from target"
                                }
                            }).to_string());

                            let mut lock_bye = state_clone.lock().await;
                            if let Some(pos) = lock_bye.active_calls.iter().position(|c| c.channel_id == id) {
                                let active = lock_bye.active_calls.remove(pos);
                                if let Some(flag) = active.audio_stop_flag {
                                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                                }
                                if let Some(h) = active.rtp_abort_handle {
                                    h.abort();
                                }
                                if let Some(h) = active.rtp_rx_abort_handle {
                                    h.abort();
                                }
                                if let Some(ch_bye) = lock_bye.channels.iter_mut().find(|c| c.id == id) {
                                    ch_bye.status = "IDLE".to_string();
                                    ch_bye.ptt_active = false;
                                    ch_bye.tx_kbps = 0;
                                }
                                let _ = tx_cb.send(serde_json::json!({
                                    "type": "channel_update",
                                    "data": {
                                        "id": id,
                                        "status": "IDLE",
                                        "pttActive": false,
                                        "txKbps": 0
                                    }
                                }).to_string());
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        println!("[SIP listen error]: {}", e);
                        break;
                    }
                }
            }
        });

        active_call.sip_abort_handle = Some(sip_listen_task.abort_handle());
        lock.active_calls.push(active_call);

        (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Not Found" }))).into_response()
    }
}

// REST: Terminate Call (SIP or RTP)
async fn hangup_handler(
    Path(id): Path<u32>,
    State(state): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    let tx = lock.tx.clone();

    let is_rtp = if let Some(ch) = lock.channels.iter().find(|c| c.id == id) {
        ch.protocol == "RTP"
    } else {
        false
    };

    if let Some(pos) = lock.active_calls.iter().position(|c| c.channel_id == id) {
        let active = lock.active_calls.remove(pos);
        if let Some(flag) = active.audio_stop_flag {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(h) = active.rtp_abort_handle {
            h.abort();
        }
        if let Some(h) = active.rtp_rx_abort_handle {
            h.abort();
        }
        if let Some(h) = active.sip_abort_handle {
            h.abort();
        }
        
        if !is_rtp {
            let local_ip = active.local_ip.clone();
            let local_sip_port = active.local_sip_port;
            let target_ip = active.target_ip.clone();
            let target_port = active.target_port;
            let call_id = active.call_id.clone();
            let from_tag = active.from_tag.clone();
            let to_tag = active.to_tag.clone();
            let target_user = parse_sip_uri(&active.target_ip).map(|(u, _, _)| u).unwrap_or_else(|| "113".to_string());

            tokio::spawn(async move {
                if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                    let to_tag_str = match to_tag {
                        Some(t) => format!(";tag={}", t),
                        None => "".to_string(),
                    };
                    let branch_bye = format!("z9hG4bK{:x}", rand_u32());
                    let bye = format!(
                        "BYE sip:{}@{}:{} SIP/2.0\r\n\
                         Via: SIP/2.0/UDP {}:{};branch={}\r\n\
                         Max-Forwards: 70\r\n\
                         To: <sip:{}@{}:{}>{}\r\n\
                         From: <sip:caller@{}:{}>;tag={}\r\n\
                         Call-ID: {}\r\n\
                         CSeq: 2 BYE\r\n\
                         Content-Length: 0\r\n\
                         \r\n",
                        target_user, target_ip, target_port,
                        local_ip, local_sip_port, branch_bye,
                        target_user, target_ip, target_port, to_tag_str,
                        local_ip, local_sip_port, from_tag,
                        call_id
                    );
                    let dest = format!("{}:{}", target_ip, target_port);
                    let _ = socket.send_to(bye.as_bytes(), dest).await;
                }
            });
        }
    }

    if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
        ch.status = "IDLE".to_string();
        ch.audio_level = 0;
        ch.duration = 0;
        ch.ptt_active = false;

        println!("[Rust Engine] [CH {}] Call/Session terminated.", id);

        let _ = tx.send(serde_json::json!({
            "type": "channel_update",
            "data": {
                "id": id,
                "status": "IDLE",
                "audioLevel": 0,
                "duration": 0,
                "latency": 0,
                "jitter": 0,
                "packetLoss": 0.0,
                "rxKbps": 0,
                "txKbps": 0,
                "pttActive": false
            }
        }).to_string());

        if is_rtp {
            let _ = tx.send(serde_json::json!({
                "type": "log",
                "data": {
                    "level": "info",
                    "channelId": id,
                    "message": "[RTP Stack] Direct RTP audio session closed."
                }
            }).to_string());
        } else {
            let _ = tx.send(serde_json::json!({
                "type": "log",
                "data": {
                    "level": "sip_tx",
                    "channelId": id,
                    "message": "[rsipstack] Transmitting BYE message."
                }
            }).to_string());

            let _ = tx.send(serde_json::json!({
                "type": "log",
                "data": {
                    "level": "info",
                    "channelId": id,
                    "message": "[rsipstack] Call hung up."
                }
            }).to_string());
        }

        let _ = tx.send(serde_json::json!({
            "type": "log",
            "data": {
                "level": "info",
                "channelId": id,
                "message": format!("[rvoip] Channel mapping released. Audio slot I2S Slot {} unlinked.", id - 1)
            }
        }).to_string());

        (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Not Found" }))).into_response()
    }
}

// REST: Bind selected audio input device
async fn select_audio_device_handler(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(payload): Json<SelectAudioDeviceRequest>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    lock.selected_device = Some(payload.device.clone());
    println!("[Rust Engine] Hardware capture interface bound to: {}", payload.device);
    save_state_to_file(&lock);

    // Broadcast config update to all connected frontend clients
    let config_msg = serde_json::json!({
        "type": "config_update",
        "data": {
            "sipPort": lock.sip_port.to_string(),
            "selectedDevice": lock.selected_device.clone().unwrap_or_default()
        }
    }).to_string();
    let _ = lock.tx.send(config_msg);

    (StatusCode::OK, Json(serde_json::json!({ "success": true })))
}

// Serve static assets embedded in binary
async fn serve_static_assets(uri: Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/').to_string();

    if path.is_empty() {
        path = "index.html".to_string();
    }

    match Asset::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(axum::body::Body::from(content.data.into_owned()))
                .unwrap()
        }
        None => {
            // Falling back to 404.html if path is not found
            match Asset::get("404.html") {
                Some(content) => {
                    let mime = mime_guess::from_path("404.html").first_or_octet_stream();
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(header::CONTENT_TYPE, mime.as_ref())
                        .body(axum::body::Body::from(content.data.into_owned()))
                        .unwrap()
                }
                None => {
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(axum::body::Body::from("Not Found"))
                        .unwrap()
                }
            }
        }
    }
}

// GET: Serve simple configuration interface
async fn show_config_handler(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let lock = state.lock().await;
    let saved = params.contains_key("saved");
    
    // Get audio devices
    let devices = get_input_devices();
    
    let mut devices_options = String::new();
    let current_device = lock.selected_device.clone().unwrap_or_default();
    
    devices_options.push_str("<option value=\"\" ");
    if current_device.is_empty() {
        devices_options.push_str("selected");
    }
    devices_options.push_str(">None (Default System Audio)</option>");

    for dev in &devices {
        let selected = if dev == &current_device { "selected" } else { "" };
        devices_options.push_str(&format!(
            "<option value=\"{}\" {}>{}</option>",
            html_escape(dev),
            selected,
            html_escape(dev)
        ));
    }

    let mut channels_rows = String::new();
    for ch in &lock.channels {
        let status_class = match ch.status.as_str() {
            "CONNECTED" => "status-connected",
            "RINGING" | "INCOMING" => "status-ringing",
            "FAILED" => "status-failed",
            _ => "status-idle",
        };
        
        let status_text = match ch.status.as_str() {
            "CONNECTED" => "ROUTING",
            "RINGING" => "DIALING",
            "INCOMING" => "INCOMING",
            "FAILED" => "FAILED",
            _ => "STANDBY",
        };

        let is_routing_or_dialing = ch.status == "CONNECTED" || ch.status == "RINGING" || ch.status == "INCOMING";
        let disabled_attr = if is_routing_or_dialing { "disabled" } else { "" };

        let opus_selected = if ch.codec == "Opus" { "selected" } else { "" };
        let g722_selected = if ch.codec == "G.722" { "selected" } else { "" };
        let g711_selected = if ch.codec == "G.711µ" { "selected" } else { "" };

        let sip_selected = if ch.protocol == "SIP" { "selected" } else { "" };
        let rtp_selected = if ch.protocol == "RTP" { "selected" } else { "" };

        let local_port_val = match ch.local_port {
            Some(p) => p.to_string(),
            None => "".to_string(),
        };

        let sip_user_val = ch.sip_user.clone().unwrap_or_default();
        let target_ip_val = ch.target_ip.clone();
        let target_port_val = ch.target_port.to_string();

        let srtp_checked = if ch.srtp_enabled { "checked" } else { "" };
        let sip_auth_checked = if ch.sip_auth_required { "checked" } else { "" };

        channels_rows.push_str(&format!(
            r#"
            <tr>
                <td style="font-weight: bold; text-align: center;">{:02}</td>
                <td>
                    <select name="protocol_{}" {} style="width: 70px;">
                        <option value="SIP" {}>SIP</option>
                        <option value="RTP" {}>RTP</option>
                    </select>
                </td>
                <td>
                    <span class="status-badge {}">{}</span>
                </td>
                <td>
                    <input type="text" name="label_{}" value="{}" {} style="width: 100px;" required />
                </td>
                <td style="text-align: center;">
                    <input type="checkbox" name="srtp_enabled_{}" {} {} style="width: 20px; height: 20px; cursor: pointer;" />
                </td>
                <td style="text-align: center;">
                    <input type="checkbox" name="sip_auth_required_{}" {} {} style="width: 20px; height: 20px; cursor: pointer;" />
                </td>
                <td>
                    <input type="text" name="sip_user_{}" value="{}" {} style="width: 90px;" placeholder="receiver" />
                </td>
                <td>
                    <input type="text" name="target_ip_{}" value="{}" {} style="width: 125px;" placeholder="192.168.1.1" required />
                </td>
                <td>
                    <input type="number" name="target_port_{}" value="{}" {} style="width: 90px;" min="1" max="65535" required />
                </td>
                <td>
                    <input type="number" name="local_port_{}" value="{}" {} style="width: 90px;" placeholder="Auto" min="1024" max="65535" />
                </td>
                <td>
                    <select name="codec_{}" {}>
                        <option value="Opus" {}>Opus</option>
                        <option value="G.722" {}>G.722</option>
                        <option value="G.711µ" {}>G.711µ</option>
                    </select>
                </td>
                <td style="font-size: 11px; font-family: monospace; color: #9ca3af;">
                    Dur: {}s | Rx: {}kbps | Tx: {}kbps | PL: {:.1}% | Jit: {}ms | Lat: {}ms
                </td>
            </tr>
            "#,
            ch.id,
            ch.id,
            disabled_attr,
            sip_selected,
            rtp_selected,
            status_class,
            status_text,
            ch.id,
            html_escape(&ch.label),
            disabled_attr,
            ch.id,
            srtp_checked,
            disabled_attr,
            ch.id,
            sip_auth_checked,
            disabled_attr,
            ch.id,
            html_escape(&sip_user_val),
            disabled_attr,
            ch.id,
            html_escape(&target_ip_val),
            disabled_attr,
            ch.id,
            target_port_val,
            disabled_attr,
            ch.id,
            local_port_val,
            disabled_attr,
            ch.id,
            disabled_attr,
            opus_selected,
            g722_selected,
            g711_selected,
            ch.duration,
            ch.rx_kbps,
            ch.tx_kbps,
            ch.packet_loss,
            ch.jitter,
            ch.latency
        ));
    }

    let success_banner = if saved {
        r#"<div class="alert-success">Configuration saved successfully and synced to console panel.</div>"#
    } else {
        ""
    };

    let html_content = format!(
        r##"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AQUILLA-12 GATEWAY CONFIGURATION</title>
            <style>
                body {{
                    background-color: #f3f4f6;
                    color: #1f2937;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    font-size: 14px;
                    line-height: 1.5;
                }}
                h1, h2 {{
                    color: #111827;
                    border-bottom: 1px solid #e5e7eb;
                    padding-bottom: 8px;
                    margin-top: 0;
                    font-weight: 600;
                }}
                h1 {{
                    font-size: 20px;
                }}
                h2 {{
                    font-size: 16px;
                }}
                .container {{
                    max-width: 98%;
                    width: 98%;
                    margin: 0 auto;
                    border: 1px solid #e5e7eb;
                    background: #ffffff;
                    padding: 24px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
                    border-radius: 6px;
                }}
                .header-meta {{
                    display: flex;
                    justify-content: space-between;
                    background: #f9fafb;
                    padding: 12px 16px;
                    border: 1px solid #e5e7eb;
                    margin-bottom: 24px;
                    border-radius: 4px;
                }}
                .meta-item {{
                    font-size: 12px;
                    color: #4b5563;
                }}
                .meta-item span {{
                    color: #111827;
                    font-weight: 600;
                }}
                .section {{
                    background: #ffffff;
                    border: 1px solid #e5e7eb;
                    padding: 20px;
                    margin-bottom: 24px;
                    border-radius: 4px;
                }}
                .grid-settings {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                }}
                .form-group {{
                    display: flex;
                    flex-direction: column;
                    gap: 6px;
                }}
                label {{
                    color: #4b5563;
                    font-size: 12px;
                    font-weight: 600;
                }}
                input, select {{
                    background: #ffffff;
                    border: 1px solid #d1d5db;
                    color: #111827;
                    padding: 8px 12px;
                    font-family: inherit;
                    font-size: 14px;
                    border-radius: 4px;
                    box-sizing: border-box;
                    width: 100%;
                }}
                input:focus, select:focus {{
                    border-color: #3b82f6;
                    outline: none;
                    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
                }}
                .channels-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 12px;
                }}
                .channels-table th, .channels-table td {{
                    border: 1px solid #e5e7eb;
                    padding: 10px 12px;
                    text-align: left;
                    vertical-align: middle;
                }}
                .channels-table th {{
                    background: #f9fafb;
                    color: #4b5563;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .channels-table tr:nth-child(even) {{
                    background: #fcfdfe;
                }}
                .status-badge {{
                    display: inline-block;
                    padding: 3px 8px;
                    font-size: 11px;
                    font-weight: 600;
                    text-align: center;
                    width: 75px;
                    border-radius: 4px;
                    border: 1px solid #d1d5db;
                }}
                .status-idle {{ color: #4b5563; border-color: #d1d5db; background: #f3f4f6; }}
                .status-ringing {{ color: #b45309; border-color: #fcd34d; background: #fef3c7; }}
                .status-connected {{ color: #047857; border-color: #6ee7b7; background: #d1fae5; }}
                .status-failed {{ color: #b91c1c; border-color: #fca5a5; background: #fee2e2; }}
                
                .btn-submit {{
                    background: #2563eb;
                    color: #ffffff;
                    border: none;
                    padding: 10px 24px;
                    font-family: inherit;
                    font-weight: 600;
                    font-size: 14px;
                    cursor: pointer;
                    border-radius: 4px;
                    transition: background 0.15s;
                }}
                .btn-submit:hover {{
                    background: #1d4ed8;
                }}
                .alert-success {{
                    border: 1px solid #6ee7b7;
                    background: #d1fae5;
                    color: #065f46;
                    padding: 12px 16px;
                    margin-bottom: 24px;
                    font-weight: 600;
                    border-radius: 4px;
                }}
                .info-note {{
                    font-size: 12px;
                    color: #6b7280;
                    margin-top: 15px;
                    line-height: 1.4;
                }}
                .refresh-link {{
                    color: #2563eb;
                    text-decoration: none;
                }}
                .refresh-link:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>AQUILLA-12 :: Web Config Gateway</h1>
                
                <div class="header-meta">
                    <div class="meta-item">STATE: <span>ACTIVE</span></div>
                    <div class="meta-item"><a href="/config" class="refresh-link">Refresh Diagnostics</a></div>
                </div>

                {}

                <form method="POST" action="/config/save">
                    <div class="section">
                        <h2>General Interface Configuration</h2>
                        <div class="grid-settings">
                            <div class="form-group">
                                <label for="sip_port">Local SIP Listening Port</label>
                                <input type="number" id="sip_port" name="sip_port" value="{}" min="1" max="65535" required />
                            </div>
                            <div class="form-group">
                                <label for="selected_device">Active Audio Input Interface</label>
                                <select id="selected_device" name="selected_device">
                                    {}
                                </select>
                            </div>
                        </div>
                    </div>

                    <div class="section">
                        <h2>Hardware Audio Channel Mapping</h2>
                        <table class="channels-table">
                            <thead>
                                <tr>
                                    <th style="width: 4%; text-align: center;">Slot</th>
                                    <th style="width: 8%;">Protocol</th>
                                    <th style="width: 8%;">Status</th>
                                    <th style="width: 12%;">Channel Alias</th>
                                    <th style="width: 6%; text-align: center;">SRTP</th>
                                    <th style="width: 6%; text-align: center;">SIP Auth</th>
                                    <th style="width: 10%;">SIP User</th>
                                    <th style="width: 14%;">Destination IP</th>
                                    <th style="width: 8%;">Dest Port</th>
                                    <th style="width: 8%;">Local Port</th>
                                    <th style="width: 8%;">Codec</th>
                                    <th style="width: 14%;">Live Telemetry Stream</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                        <div class="info-note">
                            * Note: Channel parameters (Alias, Destination, Codec) cannot be modified while the respective channel is active (Routing or Dialing).
                        </div>
                    </div>

                    <div style="text-align: right;">
                        <button type="submit" class="btn-submit">Apply Configuration</button>
                    </div>
                </form>
            </div>
            <script>
            function updateSipUserState(id) {{
                const protoSelect = document.getElementsByName("protocol_" + id)[0];
                const sipUserInput = document.getElementsByName("sip_user_" + id)[0];
                const targetPortInput = document.getElementsByName("target_port_" + id)[0];
                if (protoSelect && sipUserInput) {{
                    if (protoSelect.value === "RTP") {{
                        sipUserInput.disabled = true;
                        sipUserInput.style.backgroundColor = "#f3f4f6";
                        sipUserInput.style.cursor = "not-allowed";
                        sipUserInput.value = "";
                        if (targetPortInput && (targetPortInput.value === "5060" || targetPortInput.value === "")) {{
                            targetPortInput.value = "5004";
                        }}
                    }} else {{
                        sipUserInput.disabled = false;
                        sipUserInput.style.backgroundColor = "#ffffff";
                        sipUserInput.style.cursor = "text";
                        if (targetPortInput && (targetPortInput.value === "5004" || targetPortInput.value === "")) {{
                            targetPortInput.value = "5060";
                        }}
                    }}
                }}
            }}
            window.addEventListener("DOMContentLoaded", () => {{
                for (let id = 1; id <= 12; id++) {{
                    const protoSelect = document.getElementsByName("protocol_" + id)[0];
                    if (protoSelect) {{
                        protoSelect.addEventListener("change", () => updateSipUserState(id));
                        updateSipUserState(id);
                    }}
                }}
            }});
            </script>
        </body>
        </html>
        "##,
        success_banner,
        lock.sip_port,
        devices_options,
        channels_rows
    );

    Html(html_content)
}

// POST: Save configurations from web form
async fn save_config_handler(
    State(state): State<Arc<Mutex<AppState>>>,
    Form(form_data): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    
    // Parse general settings
    if let Some(port_str) = form_data.get("sip_port") {
        if let Ok(port) = port_str.parse::<u16>() {
            lock.sip_port = port;
        }
    }
    if let Some(device) = form_data.get("selected_device") {
        if device == "none" || device.is_empty() {
            lock.selected_device = None;
        } else {
            lock.selected_device = Some(device.clone());
        }
    }

    // Parse channel settings
    for id in 1..=12 {
        let label_key = format!("label_{}", id);
        let protocol_key = format!("protocol_{}", id);
        let sip_user_key = format!("sip_user_{}", id);
        let target_ip_key = format!("target_ip_{}", id);
        let target_port_key = format!("target_port_{}", id);
        let local_port_key = format!("local_port_{}", id);
        let codec_key = format!("codec_{}", id);

        if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
            // Only update channels that are IDLE or FAILED
            if ch.status == "IDLE" || ch.status == "FAILED" {
                if let Some(label) = form_data.get(&label_key) {
                    ch.label = label.clone();
                }
                if let Some(protocol) = form_data.get(&protocol_key) {
                    ch.protocol = protocol.clone();
                }
                if let Some(ip) = form_data.get(&target_ip_key) {
                    ch.target_ip = ip.clone();
                }
                if let Some(port_str) = form_data.get(&target_port_key) {
                    if let Ok(port) = port_str.parse::<u16>() {
                        ch.target_port = port;
                    }
                }
                if let Some(user) = form_data.get(&sip_user_key) {
                    ch.sip_user = if user.is_empty() { None } else { Some(user.clone()) };
                }

                // Checkbox: if present in form payload, it is checked ("on"), otherwise false
                ch.srtp_enabled = form_data.contains_key(&format!("srtp_enabled_{}", id));
                ch.sip_auth_required = form_data.contains_key(&format!("sip_auth_required_{}", id));

                // Recompute computed target_uri for frontend / telemetry
                ch.target_uri = if ch.protocol == "RTP" {
                    format!("rtp://{}:{}", ch.target_ip, ch.target_port)
                } else {
                    let user = ch.sip_user.as_deref().unwrap_or("receiver");
                    format!("sip:{}@{}:{}", user, ch.target_ip, ch.target_port)
                };

                if let Some(port_str) = form_data.get(&local_port_key) {
                    if port_str.is_empty() {
                        ch.local_port = None;
                    } else if let Ok(port) = port_str.parse::<u16>() {
                        ch.local_port = Some(port);
                    }
                }
                if let Some(codec) = form_data.get(&codec_key) {
                    ch.codec = codec.clone();
                }
            }

            // Broadcast the channel update to all connected frontend clients
            let update_msg = serde_json::json!({
                "type": "channel_update",
                "data": ch
            }).to_string();
            let _ = lock.tx.send(update_msg);
        }
    }

    // Broadcast config update to all connected frontend clients
    let config_msg = serde_json::json!({
        "type": "config_update",
        "data": {
            "sipPort": lock.sip_port.to_string(),
            "selectedDevice": lock.selected_device.clone().unwrap_or_default(),
            "localIp": get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string())
        }
    }).to_string();
    let _ = lock.tx.send(config_msg);

    // Persist configuration to disk
    save_state_to_file(&lock);

    // Redirect to /config with success query
    Redirect::to("/config?saved=true")
}

fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

// GET: Fetch config settings for client synchronization
async fn get_config_handler(
    State(state): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let lock = state.lock().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "sipPort": lock.sip_port.to_string(),
            "selectedDevice": lock.selected_device.clone().unwrap_or_default(),
            "localIp": get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string())
        })),
    )
}

fn html_escape(input: &str) -> String {
    let mut escaped = String::new();
    for c in input.chars() {
        match c {
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            '&' => escaped.push_str("&amp;"),
            _ => escaped.push(c),
        }
    }
    escaped
}
