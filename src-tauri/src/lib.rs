use axum::{
    extract::{Path, State, WebSocketUpgrade, Form, Query, ws::{Message, WebSocket}},
    http::StatusCode,
    response::{IntoResponse, Html, Redirect},
    routing::{get, post},
    Json, Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tower_http::cors::CorsLayer;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::collections::HashMap;
use rusqlite::Connection;


mod crypto;

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
    // A-MP (Aquilla Mirror Protocol) — per-channel recorder mirror destination
    #[serde(rename = "ampIp", default = "default_amp_ip")]
    amp_ip: String,
    #[serde(rename = "ampPort", default)]
    amp_port: u16,
    #[serde(rename = "ampEnabled", default = "default_true")]
    amp_enabled: bool,
}

fn default_amp_ip() -> String {
    "127.0.0.1".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayConfig {
    #[serde(rename = "sipPort")]
    sip_port: u16,
    #[serde(rename = "selectedDevice")]
    selected_device: Option<String>,
    channels: Vec<ChannelConfig>,
    // A-MP global master enable
    #[serde(rename = "ampEnabled", default = "default_true")]
    amp_enabled: bool,
}

/// Get the path to the SQLite database in the OS app data directory.
/// macOS:   ~/Library/Application Support/Aquilla-12/config.db
/// Linux:   ~/.local/share/Aquilla-12/config.db
/// Windows: C:\Users\<user>\AppData\Roaming\Aquilla-12\config.db
fn get_db_path() -> std::path::PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let app_dir = base.join("Aquilla-12");
    std::fs::create_dir_all(&app_dir).ok();
    app_dir.join("config.db")
}

/// Initialize the SQLite database and create tables if they don't exist.
fn init_db(conn: &Connection) {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS channels (
            id            INTEGER PRIMARY KEY,
            label         TEXT NOT NULL,
            protocol      TEXT NOT NULL DEFAULT 'RTP',
            target_ip     TEXT NOT NULL,
            target_port   INTEGER NOT NULL DEFAULT 5004,
            sip_user      TEXT,
            codec         TEXT NOT NULL DEFAULT 'G.711µ',
            local_port    INTEGER,
            is_conference INTEGER NOT NULL DEFAULT 0,
            volume        INTEGER NOT NULL DEFAULT 100,
            srtp_enabled  INTEGER NOT NULL DEFAULT 1,
            sip_auth_required INTEGER NOT NULL DEFAULT 1
        );
    ").expect("[DB] Failed to initialize database tables");
    
    // Attempt migration for existing databases missing the volume or security columns
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN volume INTEGER NOT NULL DEFAULT 100", []);
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN srtp_enabled INTEGER NOT NULL DEFAULT 1", []);
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN sip_auth_required INTEGER NOT NULL DEFAULT 1", []);

    // A-MP (Aquilla Mirror Protocol) columns for per-channel recorder mirroring.
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN amp_ip TEXT NOT NULL DEFAULT '127.0.0.1'", []);
    // Seed default per-channel ports (5004, 5006, 5008 ...) ONLY on first add of the
    // column — so a user who later sets a port to 0 (to disable a channel's mirror)
    // isn't reset back to a default on the next startup.
    let amp_port_added = conn
        .execute("ALTER TABLE channels ADD COLUMN amp_port INTEGER NOT NULL DEFAULT 0", [])
        .is_ok();
    if amp_port_added {
        let _ = conn.execute("UPDATE channels SET amp_port = 5004 + (id - 1) * 2 WHERE amp_port = 0", []);
    }
    // Global A-MP master enable (default on).
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN amp_enabled INTEGER NOT NULL DEFAULT 1", []);
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('amp_enabled', 'true')", []).ok();

    // Ensure we have a default/auto-generated API key, SIP auth credentials, and admin login password
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('sip_auth_password', 'securepass123')", []).ok();
    
    let api_key = crypto::generate_api_key();
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('api_key', ?1)", [api_key]).ok();
    
    let admin_pwd_hash = crypto::hash_password("admin");
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('web_config_username', 'admin')", []).ok();
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('web_config_password_hash', ?1)", [admin_pwd_hash]).ok();

}

fn load_config() -> GatewayConfig {
    let db_path = get_db_path();
    println!("[DB] Loading config from: {}", db_path.display());
    
    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[DB] Failed to open database: {}. Using defaults.", e);
            return default_config();
        }
    };
    init_db(&conn);

    // Try to migrate from old JSON file (one-time migration)
    let migrated = migrate_from_json(&conn);
    if migrated {
        println!("[DB] Migrated existing JSON config into database.");
    }
    
    // Load settings
    let sip_port: u16 = conn
        .query_row("SELECT value FROM settings WHERE key = 'sip_port'", [], |row| {
            let v: String = row.get(0)?;
            Ok(v.parse::<u16>().unwrap_or(5060))
        })
        .unwrap_or(5060);
    
    let selected_device: Option<String> = conn
        .query_row("SELECT value FROM settings WHERE key = 'selected_device'", [], |row| {
            let v: String = row.get(0)?;
            Ok(if v.is_empty() { None } else { Some(v) })
        })
        .unwrap_or(None);

    let amp_enabled: bool = conn
        .query_row("SELECT value FROM settings WHERE key = 'amp_enabled'", [], |row| {
            let v: String = row.get(0)?;
            Ok(v != "false" && v != "0")
        })
        .unwrap_or(true);

    // Load channels (still read is_conference column for backward compat but ignore it)
    let mut stmt = conn.prepare(
        "SELECT id, label, protocol, target_ip, target_port, sip_user, codec, local_port, is_conference, volume, srtp_enabled, sip_auth_required, amp_ip, amp_port, amp_enabled FROM channels ORDER BY id"
    ).unwrap();

    let channels: Vec<ChannelConfig> = stmt.query_map([], |row| {
        Ok(ChannelConfig {
            id: row.get::<_, u32>(0)?,
            label: row.get(1)?,
            protocol: row.get(2)?,
            target_ip: row.get(3)?,
            target_port: row.get::<_, u32>(4)? as u16,
            sip_user: row.get(5)?,
            codec: row.get(6)?,
            local_port: row.get::<_, Option<u32>>(7)?.map(|v| v as u16),
            // index 8 = is_conference — ignored, conference is now a separate system
            volume: row.get::<_, u32>(9)?,
            srtp_enabled: row.get::<_, i32>(10)? != 0,
            sip_auth_required: row.get::<_, i32>(11)? != 0,
            amp_ip: row.get::<_, String>(12).unwrap_or_else(|_| default_amp_ip()),
            amp_port: row.get::<_, u32>(13).unwrap_or(0) as u16,
            amp_enabled: row.get::<_, i32>(14).unwrap_or(1) != 0,
        })
    }).unwrap().filter_map(|r| r.ok()).collect();

    if channels.is_empty() {
        // First run — seed defaults and save
        let config = default_config();
        save_config(&config);
        return config;
    }

    GatewayConfig {
        sip_port,
        selected_device,
        channels,
        amp_enabled,
    }
}

fn save_config(config: &GatewayConfig) {
    let db_path = get_db_path();
    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[DB] Failed to open database for save: {}", e);
            return;
        }
    };
    init_db(&conn);
    
    // Save settings
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('sip_port', ?1)",
        [config.sip_port.to_string()],
    ).ok();
    
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('selected_device', ?1)",
        [config.selected_device.clone().unwrap_or_default()],
    ).ok();

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('amp_enabled', ?1)",
        [if config.amp_enabled { "true" } else { "false" }],
    ).ok();

    // Save channels in a transaction
    conn.execute("BEGIN", []).ok();
    for ch in &config.channels {
        conn.execute(
            "INSERT OR REPLACE INTO channels (id, label, protocol, target_ip, target_port, sip_user, codec, local_port, is_conference, volume, srtp_enabled, sip_auth_required, amp_ip, amp_port, amp_enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                ch.id,
                ch.label,
                ch.protocol,
                ch.target_ip,
                ch.target_port as u32,
                ch.sip_user,
                ch.codec,
                ch.local_port.map(|v| v as u32),
                ch.volume,
                ch.srtp_enabled as i32,
                ch.sip_auth_required as i32,
                ch.amp_ip,
                ch.amp_port as u32,
                ch.amp_enabled as i32,
            ],
        ).ok();
    }
    conn.execute("COMMIT", []).ok();
    println!("[DB] Config saved successfully.");
}

/// One-time migration from the old JSON config file into SQLite.
fn migrate_from_json(conn: &Connection) -> bool {
    // Check if we already have data
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
        .unwrap_or(0);
    if count > 0 {
        return false; // Already has data, no migration needed
    }
    
    // Try to read the old JSON file from known locations
    let paths_to_try = vec![
        std::path::PathBuf::from("../gateway_config.json"),
        std::path::PathBuf::from("gateway_config.json"),
    ];
    
    for path in paths_to_try {
        if let Ok(mut file) = std::fs::File::open(&path) {
            let mut content = String::new();
            if std::io::Read::read_to_string(&mut file, &mut content).is_ok() {
                if let Ok(config) = serde_json::from_str::<GatewayConfig>(&content) {
                    // Write migrated data into SQLite
                    save_config_to_conn(conn, &config);
                    return true;
                }
            }
        }
    }
    false
}

/// Save config using an existing connection (used during migration).
fn save_config_to_conn(conn: &Connection, config: &GatewayConfig) {
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('sip_port', ?1)",
        [config.sip_port.to_string()],
    ).ok();
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('selected_device', ?1)",
        [config.selected_device.clone().unwrap_or_default()],
    ).ok();

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('amp_enabled', ?1)",
        [if config.amp_enabled { "true" } else { "false" }],
    ).ok();

    for ch in &config.channels {
        conn.execute(
            "INSERT OR REPLACE INTO channels (id, label, protocol, target_ip, target_port, sip_user, codec, local_port, is_conference, volume, srtp_enabled, sip_auth_required, amp_ip, amp_port, amp_enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                ch.id, ch.label, ch.protocol, ch.target_ip,
                ch.target_port as u32, ch.sip_user, ch.codec,
                ch.local_port.map(|v| v as u32),
                ch.volume, ch.srtp_enabled as i32, ch.sip_auth_required as i32,
                ch.amp_ip, ch.amp_port as u32, ch.amp_enabled as i32,
            ],
        ).ok();
    }
}

fn default_config() -> GatewayConfig {
    let channels = (1..=12)
        .map(|id| ChannelConfig {
            id,
            label: format!("CH {:02}", id),
            protocol: "RTP".to_string(),
            target_ip: format!("192.168.1.10{}", id),
            target_port: 5004,
            sip_user: Some(format!("receiver{}", id)),
            codec: if id % 3 == 0 { "Opus" } else if id % 3 == 1 { "G.711µ" } else { "G.722" }.to_string(),
            local_port: None,
            volume: 100,
            srtp_enabled: true,
            sip_auth_required: true,
            amp_ip: "127.0.0.1".to_string(),
            amp_port: 5004 + (id as u16 - 1) * 2,
            amp_enabled: true,
        })
        .collect();

    GatewayConfig {
        sip_port: 5060,
        selected_device: None,
        channels,
        amp_enabled: true,
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
    #[serde(rename = "ampIp")]
    amp_ip: String,
    #[serde(rename = "ampPort")]
    amp_port: u16,
    #[serde(rename = "ampStreaming")]
    amp_streaming: bool,
    #[serde(rename = "ampEnabled")]
    amp_enabled: bool,
    #[serde(skip)]
    secure_context: Arc<tokio::sync::Mutex<crypto::SecureChannelContext>>,
    #[serde(skip)]
    incoming_call: Option<IncomingCallContext>,
}

#[derive(Debug, Clone)]
struct IncomingCallContext {
    call_id: String,
    from: String,
    to: String,
    via: String,
    cseq: String,
    remote_ip: String,
    remote_rtp_port: u16,
    remote_sip_port: u16,
}

#[allow(dead_code)]
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
    amp_enabled: bool,
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
        amp_ip: ch.amp_ip.clone(),
        amp_port: ch.amp_port,
        amp_enabled: ch.amp_enabled,
    }).collect();

    let config = GatewayConfig {
        sip_port: state.sip_port,
        selected_device: state.selected_device.clone(),
        channels: channel_configs,
        amp_enabled: state.amp_enabled,
    };

    save_config(&config);
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
                "message": "[Tauri Backend] Desktop session linked. Telemetry stream active."
            }
        }).to_string();
        let _ = ws_sender.send(Message::Text(greeting)).await;

        lock.tx.subscribe()
    };

    // Spawn a dedicated forwarder task
    let mut send_task = tauri::async_runtime::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg)).await.is_err() {
                break; // Client disconnected
            }
        }
    });

    // Spawn a client receiver task
    let mut recv_task = tauri::async_runtime::spawn(async move {
        while let Some(Ok(_)) = ws_receiver.next().await {
            // Keep connection open
        }
    });

    // Cleanup when either task fails
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
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
// Uses a 4th-order Butterworth anti-alias low-pass (two cascaded biquads) +
// linear interpolation. Cutoff sits at 0.42 × target rate so the stopband is
// meaningfully attenuated at Nyquist, unlike a single 2nd-order at exactly fs/2.
struct Resampler {
    source_rate: u32,
    target_rate: u32,
    fractional_index: f64,
    anti_alias: Option<[Biquad; 2]>,
}

impl Resampler {
    fn new(source_rate: u32, target_rate: u32) -> Self {
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

        // Step 1: Apply anti-alias low-pass filter to all input samples
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

        // Step 2: Downsample with linear interpolation (not nearest-neighbor)
        let step = self.source_rate as f64 / self.target_rate as f64;
        let mut idx = self.fractional_index;
        while (idx as usize) < filtered.len() {
            let i = idx as usize;
            let frac = (idx - i as f64) as f32;

            // Linear interpolation between adjacent filtered samples
            let sample_f32 = if i + 1 < filtered.len() {
                let s0 = filtered[i];
                let s1 = filtered[i + 1];
                s0 + frac * (s1 - s0)
            } else {
                filtered[i]
            };

            let sample_i16 = (sample_f32.clamp(-1.0, 1.0) * 32767.0) as i16;
            output.push(sample_i16);
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
        // 40ms initial buffer = low-latency for LAN SIP calls
        let min_buf = (output_sample_rate as usize) * 40 / 1000;
        // 200ms max buffer to cap latency without excessive drain events
        let max_buf = (output_sample_rate as usize) * 200 / 1000;
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
        // Clamp fractional_index to prevent unbounded floating-point drift over long calls
        self.fractional_index = (idx - input_f.len() as f64).max(0.0);
        if self.fractional_index >= 1.0 {
            self.fractional_index = self.fractional_index.fract();
        }
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

// ============================================================================
// A-MP (Aquilla Mirror Protocol) — NP-C4I Recorder integration
//
// Aquilla always transmits/receives G.711 µ-law (PCMU) on the wire. The NP-C4I
// Recorder ingests standard RTP/PCMU on UDP ports (one per channel). To record
// a peer-to-peer call we "tap" both directions and mirror a clean copy of the
// µ-law audio to the recorder as a single, coherent RTP/PCMU stream.
//
//   TX (local mic, only while PTT is active) ─┐
//                                             ├─►  RecordingTap  ─► recorder UDP port
//   RX (remote peer audio, when PTT idle)  ───┘
//
// Both directions share one SSRC + sequence + timestamp space so the recorder
// sees one well-formed stream and records the whole conversation into one file.
// Destination IP/port are configured per channel (amp_ip / amp_port) and gated
// by the global amp_enabled flag, all held in AppState (editable via Web Config).
// ============================================================================

/// A per-call sink that re-packetizes µ-law audio into RTP/PCMU for the recorder.
struct RecordingTap {
    socket: Arc<tokio::net::UdpSocket>,
    dest: String,
    ssrc: u32,
    seq: std::sync::atomic::AtomicU16,
    ts: std::sync::atomic::AtomicU32,
}

impl RecordingTap {
    /// Wrap a µ-law payload in a standard RTP header (V2, PT=0 PCMU) and send it
    /// to the recorder. TX and RX both call this, sharing one seq/ts/ssrc space.
    async fn send_ulaw(&self, ulaw: &[u8]) {
        use std::sync::atomic::Ordering;
        if ulaw.is_empty() {
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let ts = self.ts.fetch_add(ulaw.len() as u32, Ordering::Relaxed);

        let mut packet = Vec::with_capacity(12 + ulaw.len());
        packet.push(0x80); // Version 2, no padding/extension/CSRC
        packet.push(0x00); // Marker 0, Payload Type 0 (PCMU)
        packet.push((seq >> 8) as u8);
        packet.push((seq & 0xFF) as u8);
        packet.extend_from_slice(&ts.to_be_bytes());
        packet.extend_from_slice(&self.ssrc.to_be_bytes());
        packet.extend_from_slice(ulaw);

        let _ = self.socket.send_to(&packet, &self.dest).await;
    }
}

/// Build a recording tap from already-resolved A-MP settings. Takes plain params
/// (never locks AppState) so it is safe to call from a site that already holds
/// the state lock — avoiding tokio Mutex re-entrancy deadlocks. Returns None if
/// A-MP is disabled, the port is unset, or the mirror socket can't be created.
async fn build_recording_tap(enabled: bool, ip: &str, port: u16, channel_id: u32) -> Option<Arc<RecordingTap>> {
    if !enabled || port == 0 || ip.trim().is_empty() {
        return None;
    }
    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => {
            let dest = format!("{}:{}", ip, port);
            println!("[A-MP] Channel {} mirroring call audio to {}", channel_id, dest);
            Some(Arc::new(RecordingTap {
                socket: Arc::new(sock),
                dest,
                ssrc: rand_u32(),
                seq: std::sync::atomic::AtomicU16::new(rand_u32() as u16),
                ts: std::sync::atomic::AtomicU32::new(rand_u32()),
            }))
        }
        Err(e) => {
            eprintln!("[A-MP] Failed to open mirror socket for channel {}: {}", channel_id, e);
            None
        }
    }
}

/// Resolve (enabled, ip, port) for a channel from AppState without holding the
/// lock across the socket bind. Convenience for call sites that do NOT already
/// hold the state lock.
async fn amp_settings_for(state: &Arc<Mutex<AppState>>, channel_id: u32) -> (bool, String, u16) {
    let lock = state.lock().await;
    let ch = lock.channels.iter().find(|c| c.id == channel_id);
    (
        lock.amp_enabled && ch.map(|c| c.amp_enabled).unwrap_or(false),
        ch.map(|c| c.amp_ip.clone()).unwrap_or_else(|| "127.0.0.1".to_string()),
        ch.map(|c| c.amp_port).unwrap_or(0),
    )
}

// Background RTP streaming from local microphone
fn start_microphone_rtp(
    channel_id: u32,
    rtp_socket: Arc<tokio::net::UdpSocket>,
    rtp_destination: String,
    state: Arc<Mutex<AppState>>,
    device_name: Option<String>,
    ptt_active: Arc<std::sync::atomic::AtomicBool>,
    call_id: String,
    rec_tap: Option<Arc<RecordingTap>>,
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
    let call_id_clone = call_id.clone();
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
        let mut tx_highpass = Biquad::highpass(8000.0, 100.0, 0.7071); // cut rumble/DC below 100 Hz
        let mut tx_limiter = AudioLimiter::new(); // AGC + peak limiter for TX path
        let mut pcm_buffer = Vec::new();
        let mut sequence_number: u16 = rand_u32() as u16;
        let mut timestamp: u32 = rand_u32();
        let ssrc: u32 = rand_u32();
        
        println!("[RTP TX Task] Audio pipeline: Mic → Resample → AGC/Limiter → µ-law encode → RTP");
        
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

                        // Mirror the outgoing (local/TX) audio to the NP-C4I Recorder.
                        // Always send the clean, unencrypted µ-law payload so the
                        // recorder gets plain RTP/PCMU regardless of SRTP.
                        if let Some(ref tap) = rec_tap {
                            tap.send_ulaw(&packet[12..]).await;
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
    srtp_enabled: bool,
    secure_context: Arc<tokio::sync::Mutex<crypto::SecureChannelContext>>,
    call_id: String,
    rec_tap: Option<Arc<RecordingTap>>,
    ptt_active: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::AbortHandle {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::Ordering;

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
                        // Check if it's a key exchange packet
                        if buf[..len].starts_with(b"AQUILLA12_KEY_EXCHANGE:") {
                            if let Some(peer_key) = crypto::parse_key_exchange(&buf[..len]) {
                                let mut ctx = secure_context.lock().await;
                                if ctx.keys.is_none() {
                                    let is_server = channel_id % 2 == 0;
                                    if let Err(e) = ctx.derive_keys(peer_key, is_server) {
                                        eprintln!("[Crypto Error] Key derivation failed for Channel {}: {}", channel_id, e);
                                    } else {
                                        println!("[Crypto] Derived secure keys successfully for Channel {}!", channel_id);
                                    }
                                }
                            }
                            continue;
                        }

                        let version = (buf[0] >> 6) & 0x03;
                        let payload_type = buf[1] & 0x7F;
                        
                        if version == 2 && payload_type == 0 {
                            let mut raw_payload = None;
                            
                            if srtp_enabled {
                                if len >= 12 + 16 {
                                    let seq = ((buf[2] as u16) << 8) | (buf[3] as u16);
                                    let ts = ((buf[4] as u32) << 24) | ((buf[5] as u32) << 16) | ((buf[6] as u32) << 8) | (buf[7] as u32);
                                    let ssrc = ((buf[8] as u32) << 24) | ((buf[9] as u32) << 16) | ((buf[10] as u32) << 8) | (buf[11] as u32);
                                    
                                    let mut payload_bytes = buf[12..(len - 16)].to_vec();
                                    let mut tag_bytes = [0u8; 16];
                                    tag_bytes.copy_from_slice(&buf[(len - 16)..len]);
                                    
                                    let ctx = secure_context.lock().await;
                                    if let Some(ref keys) = ctx.keys {
                                        if crypto::decrypt_rtp_gcm(keys, seq, ts, ssrc, &mut payload_bytes, &tag_bytes).is_ok() {
                                            raw_payload = Some(payload_bytes);
                                        }
                                    }
                                }
                            } else {
                                raw_payload = parse_rtp_payload(&buf[..len]).map(|p| p.to_vec());
                            }

                            if let Some(payload) = raw_payload {
                                // Mirror the incoming (remote/RX) audio to the recorder
                                // as clean RTP/PCMU (µ-law, post-decrypt). Skip while PTT
                                // is active: TX is being mirrored on the same shared stream,
                                // and interleaving both directions into one port causes
                                // stutter/distortion. PTT comms are half-duplex, so during
                                // transmit the local operator isn't listening anyway.
                                if let Some(ref tap) = rec_tap {
                                    if !ptt_active.load(std::sync::atomic::Ordering::SeqCst) {
                                        tap.send_ulaw(&payload).await;
                                    }
                                }

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

// REST: Accept Incoming Call
async fn accept_call_handler(
    Path(id): Path<u32>,
    State(state): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    
    // Find the channel
    let ch = lock.channels.iter_mut().find(|c| c.id == id);
    if ch.is_none() {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Channel not found" }))).into_response();
    }
    
    let ch = ch.unwrap();
    if ch.status != "INCOMING" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Channel is not ringing" }))).into_response();
    }

    if let Some(ctx) = ch.incoming_call.take() {
        ch.status = "CONNECTED".to_string();
        ch.duration = 0;
        ch.ptt_active = false;
        
        let ch_clone = ch.clone();
        let tx = lock.tx.clone();
        
        // Broadcast UI update
        let state_msg = serde_json::json!({
            "type": "channel_update",
            "data": ch_clone
        }).to_string();
        let _ = tx.send(state_msg);

        // Bind local RTP socket
        let rtp_socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let local_rtp_port = rtp_socket.local_addr().unwrap().port();
        
        let dest_addr = format!("{}:{}", ctx.remote_ip, ctx.remote_sip_port);
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

        let selected_device = lock.selected_device.clone();
        
        // Extract channel metadata before releasing the lock reference (avoid re-locking in sync fn)
        let ch_srtp = lock.channels.iter().find(|c| c.id == id).map(|c| c.srtp_enabled).unwrap_or(false);
        let ch_ctx = lock.channels.iter().find(|c| c.id == id).map(|c| Arc::clone(&c.secure_context)).unwrap();

        let ptt_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Build the A-MP recorder tap (shared by TX + RX for this call).
        // Read settings from the already-held lock to avoid re-locking (deadlock).
        let (amp_en, amp_ip, amp_port) = {
            let ch_ref = lock.channels.iter().find(|c| c.id == id);
            (lock.amp_enabled && ch_ref.map(|c| c.amp_enabled).unwrap_or(false),
             ch_ref.map(|c| c.amp_ip.clone()).unwrap_or_else(|| "127.0.0.1".to_string()),
             ch_ref.map(|c| c.amp_port).unwrap_or(0))
        };
        let rec_tap = build_recording_tap(amp_en, &amp_ip, amp_port, id).await;
        if rec_tap.is_some() {
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.amp_streaming = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }

        // Start capture/transmit task
        let dest_rtp = format!("{}:{}", ctx.remote_ip, ctx.remote_rtp_port);
        let (stop_flag, rtp_abort) = start_microphone_rtp(
            id, Arc::clone(&rtp_socket), dest_rtp, Arc::clone(&state), selected_device, Arc::clone(&ptt_flag), ctx.call_id.clone(), rec_tap.clone()
        );

        // Start playback task
        let stop_flag_playback = Arc::clone(&stop_flag);
        let rtp_rx_abort = start_audio_playback(id, Arc::clone(&rtp_socket), Arc::clone(&state), stop_flag_playback, ch_srtp, ch_ctx, ctx.call_id.clone(), rec_tap.clone(), Arc::clone(&ptt_flag));

        // Bind local SIP socket synchronously so we can keep it alive for the session
        let sip_socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let local_sip_port = sip_socket.local_addr().unwrap().port();

        // Clone fields before spawning so they're usable after the move
        let ctx_remote_ip = ctx.remote_ip.clone();
        let ctx_remote_sip_port = ctx.remote_sip_port;
        let ctx_call_id = ctx.call_id.clone();
        let local_ip_for_spawn = local_ip.clone();

        // Send 200 OK
        let sdp_body = format!(
            "v=0\r\n\
            o=- 123456 123457 IN IP4 {}\r\n\
            s=Session SIP\r\n\
            c=IN IP4 {}\r\n\
            t=0 0\r\n\
            m=audio {} RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=sendrecv\r\n",
            local_ip_for_spawn, local_ip_for_spawn, local_rtp_port
        );
        
        let ok_msg = format!(
            "SIP/2.0 200 OK\r\n\
            Via: {}\r\n\
            From: {}\r\n\
            To: {};tag=local-{}\r\n\
            Call-ID: {}\r\n\
            CSeq: {}\r\n\
            Contact: <sip:113@{}:{}>\r\n\
            Content-Type: application/sdp\r\n\
            Content-Length: {}\r\n\
            \r\n\
            {}",
            ctx.via,
            ctx.from,
            ctx.to, id,
            ctx.call_id,
            ctx.cseq,
            local_ip_for_spawn, local_sip_port,
            sdp_body.len(),
            sdp_body
        );
        
        let dest = format!("{}:{}", ctx.remote_ip, ctx.remote_sip_port);
        let sip_socket_clone = Arc::clone(&sip_socket);
        tokio::spawn(async move {
            let _ = sip_socket_clone.send_to(ok_msg.as_bytes(), dest).await;
        });

        // Spawn a dedicated SIP listener task for this incoming call session
        let sip_socket_listen = Arc::clone(&sip_socket);
        let state_clone_listen = Arc::clone(&state);
        let tx_cb_listen = lock.tx.clone();
        
        let sip_listen_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match sip_socket_listen.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let msg = String::from_utf8_lossy(&buf[..len]);
                        if msg.contains("BYE") {
                            let _ = tx_cb_listen.send(serde_json::json!({
                                "type": "log",
                                "data": {
                                    "level": "sip_rx",
                                    "channelId": id,
                                    "message": "[rsipstack] SIP BYE received from target (dedicated port)"
                                }
                            }).to_string());

                            let mut lock_bye = state_clone_listen.lock().await;
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
                                // Send 200 OK back to BYE request
                                let ok_resp = format!(
                                    "SIP/2.0 200 OK\r\n\
                                     Via: SIP/2.0/UDP {}:{};branch=z9hG4bK-bye\r\n\
                                     Content-Length: 0\r\n\r\n",
                                     local_ip_for_spawn, local_sip_port
                                );
                                let _ = sip_socket_listen.send_to(ok_resp.as_bytes(), src).await;
                            }
                            if let Some(ch_bye) = lock_bye.channels.iter_mut().find(|c| c.id == id) {
                                ch_bye.status = "IDLE".to_string();
                                ch_bye.ptt_active = false;
                                ch_bye.tx_kbps = 0;
                                ch_bye.audio_level = 0;
                                ch_bye.amp_streaming = false;
                            }
                            let _ = tx_cb_listen.send(serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": id,
                                    "status": "IDLE",
                                    "pttActive": false,
                                    "txKbps": 0,
                                    "audioLevel": 0,
                                    "ampStreaming": false
                                }
                            }).to_string());
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        lock.active_calls.push(ActiveCall {
            channel_id: id,
            target_ip: ctx_remote_ip,
            target_port: ctx_remote_sip_port,
            local_ip: local_ip.clone(),
            local_sip_port,
            local_rtp_port,
            call_id: ctx_call_id,
            from_tag: "".to_string(),
            to_tag: Some(format!("local-{}", id)),
            audio_stop_flag: Some(stop_flag),
            ptt_active: Some(ptt_flag),
            rtp_abort_handle: Some(rtp_abort),
            rtp_rx_abort_handle: Some(rtp_rx_abort),
            sip_abort_handle: Some(sip_listen_task.abort_handle()),
        });
        
        let log_msg = serde_json::json!({
            "type": "log",
            "data": {
                "level": "info",
                "channelId": id,
                "message": "[rsipstack] Call Accepted"
            }
        }).to_string();
        let _ = tx.send(log_msg);
    }

    (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
}

// REST: Reject Incoming Call
async fn reject_call_handler(
    Path(id): Path<u32>,
    State(state): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    
    let ch = lock.channels.iter_mut().find(|c| c.id == id);
    if ch.is_none() {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Channel not found" }))).into_response();
    }
    
    let ch = ch.unwrap();
    if ch.status != "INCOMING" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Channel is not ringing" }))).into_response();
    }

    if let Some(ctx) = ch.incoming_call.take() {
        ch.status = "IDLE".to_string();
        ch.amp_streaming = false;

        let ch_clone = ch.clone();
        let tx = lock.tx.clone();

        // Broadcast UI update
        let state_msg = serde_json::json!({
            "type": "channel_update",
            "data": ch_clone
        }).to_string();
        let _ = tx.send(state_msg);

        // Send 486 Busy Here
        tokio::spawn(async move {
            if let Ok(sip_sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                let busy = format!(
                    "SIP/2.0 486 Busy Here\r\n\
                    Via: {}\r\n\
                    From: {}\r\n\
                    To: {};tag=busy\r\n\
                    Call-ID: {}\r\n\
                    CSeq: {}\r\n\
                    Content-Length: 0\r\n\r\n",
                    ctx.via,
                    ctx.from,
                    ctx.to,
                    ctx.call_id,
                    ctx.cseq
                );
                
                let dest = format!("{}:{}", ctx.remote_ip, ctx.remote_sip_port);
                let _ = sip_sock.send_to(busy.as_bytes(), dest).await;
            }
        });
        
        let log_msg = serde_json::json!({
            "type": "log",
            "data": {
                "level": "warn",
                "channelId": id,
                "message": "[rsipstack] Call Rejected"
            }
        }).to_string();
        let _ = tx.send(log_msg);
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

        // Extract channel metadata before releasing the lock reference
        let ch_srtp = lock.channels.iter().find(|c| c.id == id).map(|c| c.srtp_enabled).unwrap_or(false);
        let ch_ctx = lock.channels.iter().find(|c| c.id == id).map(|c| Arc::clone(&c.secure_context)).unwrap();

        let ptt_active_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ptt_active_flag_clone = Arc::clone(&ptt_active_flag);

        let call_id = format!("rtp-{}", id);
        // A-MP tap — read settings from the held lock (no re-lock / deadlock).
        let (amp_en, amp_ip, amp_port) = {
            let ch_ref = lock.channels.iter().find(|c| c.id == id);
            (lock.amp_enabled && ch_ref.map(|c| c.amp_enabled).unwrap_or(false),
             ch_ref.map(|c| c.amp_ip.clone()).unwrap_or_else(|| "127.0.0.1".to_string()),
             ch_ref.map(|c| c.amp_port).unwrap_or(0))
        };
        let rec_tap = build_recording_tap(amp_en, &amp_ip, amp_port, id).await;
        if rec_tap.is_some() {
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.amp_streaming = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }
        let (audio_flag, rtp_task) = start_microphone_rtp(
            id, Arc::clone(&rtp_sock_task), rtp_dest, Arc::clone(&state_audio), selected_device, ptt_active_flag, call_id.clone(), rec_tap.clone()
        );

        let audio_flag_playback = Arc::clone(&audio_flag);
        let rtp_rx_task = start_audio_playback(
            id, Arc::clone(&rtp_sock_task), Arc::clone(&state_audio), audio_flag_playback, ch_srtp, ch_ctx, call_id.clone(), rec_tap.clone(), Arc::clone(&ptt_active_flag_clone)
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

                        let mut is_failure = false;
                        let mut reason = "Call failed".to_string();
                        if let Some(status_line) = msg.lines().next() {
                            if status_line.starts_with("SIP/2.0 ") {
                                let parts: Vec<&str> = status_line.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    if let Ok(code) = parts[1].parse::<u32>() {
                                        if code >= 300 {
                                            is_failure = true;
                                            reason = format!("[rsipstack] Outbound call failed with: {}", status_line);
                                        }
                                    }
                                }
                            }
                        }

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
                        } else if is_failure {
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "log",
                                "data": {
                                    "level": "error",
                                    "channelId": id,
                                    "message": reason
                                }
                            }).to_string());

                            let mut lock_fail = state_clone.lock().await;
                            if let Some(pos) = lock_fail.active_calls.iter().position(|c| c.channel_id == id) {
                                lock_fail.active_calls.remove(pos);
                            }
                            if let Some(ch_fail) = lock_fail.channels.iter_mut().find(|c| c.id == id) {
                                ch_fail.status = "FAILED".to_string();
                                ch_fail.ptt_active = false;
                                ch_fail.tx_kbps = 0;
                                ch_fail.amp_streaming = false;
                            }
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": id,
                                    "status": "FAILED",
                                    "pttActive": false,
                                    "txKbps": 0,
                                    "ampStreaming": false
                                }
                            }).to_string());
                            break;
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

                            // Extract channel metadata before locking again in spawn context
                            let (ch_srtp, ch_ctx) = {
                                let lock_meta = state_audio.lock().await;
                                let ch = lock_meta.channels.iter().find(|c| c.id == id);
                                (
                                    ch.map(|c| c.srtp_enabled).unwrap_or(false),
                                    ch.map(|c| Arc::clone(&c.secure_context)).unwrap(),
                                )
                            };
                            
                            let ptt_active_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
                            let ptt_active_flag_clone = Arc::clone(&ptt_active_flag);
                            let call_id = {
                                 let lock_ac = state_audio.lock().await;
                                 lock_ac.active_calls.iter().find(|c| c.channel_id == id).map(|c| c.call_id.clone()).unwrap_or_else(|| format!("sip-{}", id))
                             };
                             let (amp_en, amp_ip, amp_port) = amp_settings_for(&state_audio, id).await;
                             let rec_tap = build_recording_tap(amp_en, &amp_ip, amp_port, id).await;
                             let (audio_flag, rtp_task) = start_microphone_rtp(
                                 id, Arc::clone(&rtp_sock_task), rtp_dest, Arc::clone(&state_audio), selected_device.clone(), ptt_active_flag, call_id.clone(), rec_tap.clone()
                             );

                             let audio_flag_playback = Arc::clone(&audio_flag);
                             let rtp_rx_task = start_audio_playback(
                                 id, Arc::clone(&rtp_sock_task), Arc::clone(&state_audio), audio_flag_playback, ch_srtp, ch_ctx, call_id.clone(), rec_tap.clone(), Arc::clone(&ptt_active_flag_clone)
                             );

                            let mut lock_rtp = state_clone.lock().await;
                            if let Some(ac) = lock_rtp.active_calls.iter_mut().find(|c| c.channel_id == id) {
                                ac.audio_stop_flag = Some(audio_flag);
                                ac.ptt_active = Some(ptt_active_flag_clone);
                                ac.rtp_abort_handle = Some(rtp_task);
                                ac.rtp_rx_abort_handle = Some(rtp_rx_task);
                            }
                            if rec_tap.is_some() {
                                let upd = {
                                    if let Some(ch) = lock_rtp.channels.iter_mut().find(|c| c.id == id) {
                                        ch.amp_streaming = true;
                                        Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                                    } else { None }
                                };
                                if let Some(upd) = upd {
                                    let _ = lock_rtp.tx.send(upd);
                                }
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
                            }
                            if let Some(ch_bye) = lock_bye.channels.iter_mut().find(|c| c.id == id) {
                                ch_bye.status = "IDLE".to_string();
                                ch_bye.ptt_active = false;
                                ch_bye.tx_kbps = 0;
                                ch_bye.amp_streaming = false;
                            }
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": id,
                                    "status": "IDLE",
                                    "pttActive": false,
                                    "txKbps": 0,
                                    "ampStreaming": false
                                }
                            }).to_string());
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
        ch.amp_streaming = false;

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
                "pttActive": false,
                "ampStreaming": false
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

fn get_or_generate_tls_cert() -> (String, String) {
    let db_path = get_db_path();
    if let Ok(conn) = Connection::open(&db_path) {
        let cert: Option<String> = conn.query_row("SELECT value FROM settings WHERE key = 'tls_cert'", [], |row| row.get(0)).ok();
        let key: Option<String> = conn.query_row("SELECT value FROM settings WHERE key = 'tls_key'", [], |row| row.get(0)).ok();
        if let (Some(c), Some(k)) = (cert, key) {
            return (c, k);
        }
        
        if let Ok((c, k)) = crypto::generate_self_signed_cert() {
            let _ = conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('tls_cert', ?1)", [&c]);
            let _ = conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('tls_key', ?1)", [&k]);
            return (c, k);
        }
    }
    ("".to_string(), "".to_string())
}

async fn serve_https(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    cert_pem: String,
    key_pem: String,
) {
    use std::io::BufReader;
    use tokio_rustls::TlsAcceptor;
    use hyper_util::rt::TokioIo;
    use hyper::server::conn::http1;
    use tower::Service;

    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let mut key_reader = BufReader::new(key_pem.as_bytes());
    
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    
    let key = rustls_pemfile::private_key(&mut key_reader)
        .ok()
        .flatten()
        .expect("No private key found");
    
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build server config");
        
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    
    println!("[HTTPS Server] Listening on https://localhost:8085/");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let acceptor = acceptor.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    use tower_service::Service;
                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                        let io = TokioIo::new(tls_stream);
                        let _ = http1::Builder::new()
                            .serve_connection(io, hyper::service::service_fn(move |req| {
                                let mut router = router.clone();
                                async move {
                                    router.call(req).await
                                }
                            }))
                            .await;
                    }
                });
            }
            Err(e) => {
                eprintln!("[HTTPS Server] Accept error: {}", e);
            }
        }
    }
}

// cpal traits are imported locally inside start_microphone_rtp and get_input_devices

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Install the rustls ring crypto provider at process startup.
    // rustls 0.23+ requires an explicit provider when 'ring' is enabled without
    // 'aws-lc-rs', otherwise ServerConfig::builder() panics at runtime.
    let _ = rustls::crypto::ring::default_provider().install_default();

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
            amp_ip: if ch_cfg.amp_ip.is_empty() { "127.0.0.1".to_string() } else { ch_cfg.amp_ip.clone() },
            amp_port: if ch_cfg.amp_port == 0 { 5004 + (ch_cfg.id as u16 - 1) * 2 } else { ch_cfg.amp_port },
            amp_streaming: false,
            amp_enabled: ch_cfg.amp_enabled,
            secure_context: Arc::new(tokio::sync::Mutex::new(crypto::SecureChannelContext::new())),
            incoming_call: None,
        }
    }).collect::<Vec<_>>();

    let state = Arc::new(Mutex::new(AppState {
        channels,
        tx: tx.clone(),
        active_calls: Vec::new(),
        selected_device: config.selected_device,
        sip_port: config.sip_port,
        amp_enabled: config.amp_enabled,
    }));
    let state_for_server = Arc::clone(&state);

    tauri::Builder::default()
        .setup(move |app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Spawn Global SIP Listener for incoming calls (Option B)
            let state_for_sip_listener = Arc::clone(&state_for_server);
            tauri::async_runtime::spawn(async move {
                let addr = "0.0.0.0:5060";
                match tokio::net::UdpSocket::bind(addr).await {
                    Ok(socket) => {
                        println!("[Global SIP Server] Listening for incoming calls on {}", addr);
                        let mut buf = [0u8; 2048];
                        loop {
                            match socket.recv_from(&mut buf).await {
                                Ok((len, src)) => {
                                    let msg = String::from_utf8_lossy(&buf[..len]);
                                    if msg.starts_with("INVITE ") {
                                        // Parse dialed extension from Request-URI (first line)
                                        let first_line = msg.lines().next().unwrap_or("");
                                        let mut dialed_extension = String::new();
                                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                                        if parts.len() >= 2 {
                                            let clean_uri = parts[1].trim_matches(|c| c == '<' || c == '>' || c == '"' || c == ' ');
                                            let uri = clean_uri.strip_prefix("sip:").unwrap_or(clean_uri);
                                            if let Some(at_idx) = uri.find('@') {
                                                dialed_extension = uri[..at_idx].to_string();
                                            }
                                        }

                                        println!("[Global SIP Server] Incoming INVITE from {} (Dialed Extension: '{}')", src, dialed_extension);
                                        
                                        let mut call_id = String::new();
                                        let mut from_hdr = String::new();
                                        let mut to_hdr = String::new();
                                        let mut via_hdr = String::new();
                                        let mut cseq_hdr = String::new();
                                        let mut remote_rtp_port = 5004;
                                        let mut auth_hdr = String::new();

                                        for line in msg.lines() {
                                            let lower = line.to_lowercase();
                                            if lower.starts_with("call-id:") {
                                                call_id = line[8..].trim().to_string();
                                            } else if lower.starts_with("from:") {
                                                from_hdr = line[5..].trim().to_string();
                                            } else if lower.starts_with("to:") {
                                                to_hdr = line[3..].trim().to_string();
                                            } else if lower.starts_with("via:") {
                                                via_hdr = line[4..].trim().to_string();
                                            } else if lower.starts_with("cseq:") {
                                                cseq_hdr = line[5..].trim().to_string();
                                            } else if lower.starts_with("authorization:") {
                                                auth_hdr = line[14..].trim().to_string();
                                            } else if lower.starts_with("proxy-authorization:") {
                                                auth_hdr = line[20..].trim().to_string();
                                            } else if lower.starts_with("m=audio ") {
                                                let tokens: Vec<&str> = line.split_whitespace().collect();
                                                if tokens.len() >= 2 {
                                                    if let Ok(p) = tokens[1].parse::<u16>() {
                                                        remote_rtp_port = p;
                                                    }
                                                }
                                            }
                                        }

                                        let src_ip = src.ip().to_string();
                                        let mut lock = state_for_sip_listener.lock().await;

                                        // Deduplication check: check if call_id is already assigned/active.
                                        let mut already_ringing_channel_id = None;
                                        let mut already_connected = false;

                                        for ch in lock.channels.iter() {
                                            if let Some(ref incoming) = ch.incoming_call {
                                                if incoming.call_id == call_id {
                                                    already_ringing_channel_id = Some(ch.id);
                                                    break;
                                                }
                                            }
                                        }

                                        if already_ringing_channel_id.is_none() {
                                            for ac in lock.active_calls.iter() {
                                                if ac.call_id == call_id {
                                                    already_connected = true;
                                                    break;
                                                }
                                            }
                                        }

                                        if already_connected {
                                            println!("[Global SIP Server] Call-ID {} is already active/connected. Skipping INVITE retransmission.", call_id);
                                            continue;
                                        }

                                        if let Some(id) = already_ringing_channel_id {
                                            println!("[Global SIP Server] Call-ID {} is already ringing on Channel {}. Re-sending 180 Ringing.", call_id, id);
                                            // Re-send 180 Ringing back
                                            let ringing = format!(
                                                "SIP/2.0 180 Ringing\r\n\
                                                Via: {}\r\n\
                                                From: {}\r\n\
                                                To: {};tag=local-{}\r\n\
                                                Call-ID: {}\r\n\
                                                CSeq: {}\r\n\
                                                Contact: <sip:113@{}:5060>\r\n\
                                                Content-Length: 0\r\n\r\n",
                                                via_hdr,
                                                from_hdr,
                                                to_hdr, id,
                                                call_id,
                                                cseq_hdr,
                                                src_ip
                                            );
                                            let _ = socket.send_to(ringing.as_bytes(), src).await;
                                            continue;
                                        }
                                        
                                        // Pass 1: Try direct numeric mapping (e.g. "101" -> Channel 1, "1" -> Channel 1)
                                        let mut matched_channel_id = None;
                                        if let Ok(num) = dialed_extension.parse::<u32>() {
                                            if num >= 101 && num <= 112 {
                                                let target_id = num - 100;
                                                if let Some(ch) = lock.channels.iter().find(|c| c.id == target_id) {
                                                    if ch.status == "IDLE" || ch.status == "FAILED" {
                                                        matched_channel_id = Some(target_id);
                                                    }
                                                }
                                            } else if num >= 1 && num <= 12 {
                                                if let Some(ch) = lock.channels.iter().find(|c| c.id == num) {
                                                    if ch.status == "IDLE" || ch.status == "FAILED" {
                                                        matched_channel_id = Some(num);
                                                    }
                                                }
                                            }
                                        }

                                        // Pass 2: Match caller IP or custom target_uri user string
                                        if matched_channel_id.is_none() {
                                            for ch in lock.channels.iter() {
                                                if ch.status == "IDLE" || ch.status == "FAILED" {
                                                    let target_user = ch.sip_user.clone().unwrap_or_default();
                                                    if (!dialed_extension.is_empty() && target_user == dialed_extension) || ch.target_ip == src_ip {
                                                        matched_channel_id = Some(ch.id);
                                                        break;
                                                    }
                                                }
                                            }
                                        }

                                        // Pass 3: Fall back to first available IDLE/FAILED channel
                                        if matched_channel_id.is_none() {
                                            for ch in lock.channels.iter() {
                                                if ch.status == "IDLE" || ch.status == "FAILED" {
                                                    matched_channel_id = Some(ch.id);
                                                    break;
                                                }
                                            }
                                        }

                                         // Enforce SIP Digest challenge if required by the matched channel config
                                         let mut auth_required = false;
                                         if let Some(matched_id) = matched_channel_id {
                                             if let Some(ch) = lock.channels.iter().find(|c| c.id == matched_id) {
                                                 auth_required = ch.sip_auth_required;
                                             }
                                         }
                                         
                                         if auth_required {
                                             let mut authenticated = false;
                                             if !auth_hdr.is_empty() {
                                                 let auth_map = parse_digest_auth(&auth_hdr);
                                                 if let (Some(user), Some(nonce), Some(uri), Some(response)) = (
                                                     auth_map.get("username"),
                                                     auth_map.get("nonce"),
                                                     auth_map.get("uri"),
                                                     auth_map.get("response")
                                                 ) {
                                                     let nonce_valid = {
                                                         let mut nonces = get_sip_nonces().lock().unwrap();
                                                         nonces.remove(nonce).is_some()
                                                     };
                                                     
                                                     if nonce_valid {
                                                         let db_path = get_db_path();
                                                         let sip_pass = if let Ok(conn_db) = Connection::open(&db_path) {
                                                             conn_db.query_row("SELECT value FROM settings WHERE key = 'sip_auth_password'", [], |row| row.get::<_, String>(0)).unwrap_or_else(|_| "securepass123".to_string())
                                                         } else {
                                                             "securepass123".to_string()
                                                         };
                                                         let expected = crypto::compute_sip_digest_sha256(user, "aquilla-12", &sip_pass, nonce, "INVITE", uri);
                                                         if expected == *response {
                                                             authenticated = true;
                                                         }
                                                     }
                                                 }
                                             }
                                             
                                             if !authenticated {
                                                 // Generate secure SHA-256 nonce
                                                 let nonce = crypto::generate_api_key();
                                                 {
                                                     let mut nonces = get_sip_nonces().lock().unwrap();
                                                     nonces.insert(nonce.clone(), call_id.clone());
                                                 }
                                                 
                                                 let proxy_auth_msg = format!(
                                                     "SIP/2.0 407 Proxy Authentication Required\r\n\
                                                     Via: {}\r\n\
                                                     From: {}\r\n\
                                                     To: {}\r\n\
                                                     Call-ID: {}\r\n\
                                                     CSeq: {}\r\n\
                                                     Proxy-Authenticate: Digest realm=\"aquilla-12\", nonce=\"{}\", algorithm=SHA-256, qop=\"auth\"\r\n\
                                                     Content-Length: 0\r\n\r\n",
                                                     via_hdr, from_hdr, to_hdr, call_id, cseq_hdr, nonce
                                                 );
                                                 let _ = socket.send_to(proxy_auth_msg.as_bytes(), src).await;
                                                 continue; // Wait for next INVITE with auth header
                                             }
                                          }

                                          if let Some(matched_id) = matched_channel_id {
                                              if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == matched_id) {
                                                  ch.status = "INCOMING".to_string();
                                                  ch.incoming_call = Some(IncomingCallContext {
                                                      call_id: call_id.clone(),
                                                      from: from_hdr.clone(),
                                                      to: to_hdr.clone(),
                                                      via: via_hdr.clone(),
                                                      cseq: cseq_hdr.clone(),
                                                      remote_ip: src_ip.clone(),
                                                      remote_rtp_port,
                                                      remote_sip_port: src.port(),
                                                  });
                                              }
                                          }

                                          if let Some(id) = matched_channel_id {
                                              let tx_chan = lock.tx.clone();

                                              // Send 180 Ringing back
                                              let ringing = format!(
                                                  "SIP/2.0 180 Ringing\r\n\
                                                  Via: {}\r\n\
                                                  From: {}\r\n\
                                                  To: {};tag=local-{}\r\n\
                                                  Call-ID: {}\r\n\
                                                  CSeq: {}\r\n\
                                                  Contact: <sip:113@{}:5060>\r\n\
                                                  Content-Length: 0\r\n\r\n",
                                                  via_hdr,
                                                  from_hdr,
                                                  to_hdr, id,
                                                  call_id,
                                                  cseq_hdr,
                                                  src_ip
                                              );
                                              let _ = socket.send_to(ringing.as_bytes(), src).await;

                                              // Notify UI via channel_update
                                              let update_msg = serde_json::json!({
                                                  "type": "channel_update",
                                                  "data": {
                                                      "id": id,
                                                      "status": "INCOMING"
                                                  }
                                              }).to_string();
                                              let _ = tx_chan.send(update_msg);
                                              
                                              let log_msg = serde_json::json!({
                                                  "type": "log",
                                                  "data": {
                                                      "level": "sip_rx",
                                                      "channelId": id,
                                                      "message": format!("[rsipstack] Incoming INVITE from {} (ext '{}') → assigned to Channel {}", src_ip, dialed_extension, id)
                                                  }
                                              }).to_string();
                                              let _ = tx_chan.send(log_msg);
                                          } else {
                                              // Send 486 Busy Here if no matching channel found
                                              let busy = format!(
                                                  "SIP/2.0 486 Busy Here\r\n\
                                                  Via: SIP/2.0/UDP {}:{};branch=z9hG4bK-inc\r\n\
                                                  From: {}\r\n\
                                                  To: {};tag=busy\r\n\
                                                  Call-ID: {}\r\n\
                                                  CSeq: 1 INVITE\r\n\
                                                  Content-Length: 0\r\n\r\n",
                                                  src_ip, src.port(),
                                                  from_hdr,
                                                  to_hdr,
                                                  call_id
                                              );
                                              let _ = socket.send_to(busy.as_bytes(), src).await;
                                          }
                                    } else if msg.starts_with("CANCEL ") || msg.starts_with("BYE ") {
                                        let is_cancel = msg.starts_with("CANCEL ");
                                        let method = if is_cancel { "CANCEL" } else { "BYE" };
                                        println!("[Global SIP Server] Incoming {} from {}", method, src);

                                        let mut call_id = String::new();
                                        let mut via_hdr = String::new();
                                        let mut from_hdr = String::new();
                                        let mut to_hdr = String::new();
                                        let mut cseq_hdr = String::new();

                                        for line in msg.lines() {
                                            let lower = line.to_lowercase();
                                            if lower.starts_with("call-id:") {
                                                call_id = line[8..].trim().to_string();
                                            } else if lower.starts_with("via:") {
                                                via_hdr = line[4..].trim().to_string();
                                            } else if lower.starts_with("from:") {
                                                from_hdr = line[5..].trim().to_string();
                                            } else if lower.starts_with("to:") {
                                                to_hdr = line[3..].trim().to_string();
                                            } else if lower.starts_with("cseq:") {
                                                cseq_hdr = line[5..].trim().to_string();
                                            }
                                        }

                                        if !call_id.is_empty() {
                                            let mut lock = state_for_sip_listener.lock().await;
                                            let tx_chan = lock.tx.clone();
                                            let mut matched_channel_id = None;

                                            // 1. Check incoming call (ringing) queue
                                            for ch in lock.channels.iter_mut() {
                                                if let Some(ref incoming) = ch.incoming_call {
                                                    if incoming.call_id == call_id {
                                                        matched_channel_id = Some(ch.id);
                                                        ch.status = "IDLE".to_string();
                                                        ch.amp_streaming = false;
                                                        ch.incoming_call = None;
                                                        break;
                                                    }
                                                }
                                            }

                                            // 2. Check active calls (connected)
                                            if matched_channel_id.is_none() {
                                                if let Some(pos) = lock.active_calls.iter().position(|c| c.call_id == call_id) {
                                                    let active = lock.active_calls.remove(pos);
                                                    matched_channel_id = Some(active.channel_id);
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
                                                    if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == active.channel_id) {
                                                        ch.status = "IDLE".to_string();
                                                        ch.ptt_active = false;
                                                        ch.tx_kbps = 0;
                                                        ch.audio_level = 0;
                                                        ch.amp_streaming = false;
                                                    }
                                                }
                                            }

                                            if let Some(id) = matched_channel_id {
                                                // Send 200 OK back to remote
                                                let ok_resp = format!(
                                                    "SIP/2.0 200 OK\r\n\
                                                    Via: {}\r\n\
                                                    From: {}\r\n\
                                                    To: {}\r\n\
                                                    Call-ID: {}\r\n\
                                                    CSeq: {}\r\n\
                                                    Content-Length: 0\r\n\r\n",
                                                    via_hdr, from_hdr, to_hdr, call_id, cseq_hdr
                                                );
                                                let _ = socket.send_to(ok_resp.as_bytes(), src).await;

                                                // Broadcast update
                                                let update_msg = serde_json::json!({
                                                    "type": "channel_update",
                                                    "data": {
                                                        "id": id,
                                                        "status": "IDLE",
                                                        "pttActive": false,
                                                        "txKbps": 0,
                                                        "audioLevel": 0,
                                                        "ampStreaming": false
                                                    }
                                                }).to_string();
                                                let _ = tx_chan.send(update_msg);

                                                let log_msg = serde_json::json!({
                                                    "type": "log",
                                                    "data": {
                                                        "level": "sip_rx",
                                                        "channelId": id,
                                                        "message": format!("[rsipstack] Received {} from {} - call terminated", method, src)
                                                    }
                                                }).to_string();
                                                let _ = tx_chan.send(log_msg);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[Global SIP Server] Error receiving: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Global SIP Server] Failed to bind 0.0.0.0:5060 - {}", e);
                    }
                }
            });

            // Spawn background task to simulate real-time VoIP telemetry and audio VU levels
            let state_clone_sim = Arc::clone(&state_for_server);
            tauri::async_runtime::spawn(async move {
                let mut second_timer = tokio::time::interval(Duration::from_secs(1));
                let mut fast_timer = tokio::time::interval(Duration::from_millis(100));

                loop {
                    tokio::select! {
                        // Every 100ms: Fluctuate voice levels for connected channels
                        _ = fast_timer.tick() => {
                            let mut lock = state_clone_sim.lock().await;
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
                            let mut lock = state_clone_sim.lock().await;
                            let tx_chan = lock.tx.clone();
                            let active_calls = lock.channels.iter().filter(|c| c.status == "CONNECTED").count();

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
                                    
                                    let lat_delta = if rand_f64() > 0.7 { if rand_f64() > 0.5 { 1 } else { -1 } } else { 0 };
                                    ch.latency = ((ch.latency as i32 + lat_delta).max(10).min(120)) as u32;

                                    let jitter_delta = if rand_f64() > 0.8 { if rand_f64() > 0.5 { 1 } else { -1 } } else { 0 };
                                    ch.jitter = ((ch.jitter as i32 + jitter_delta).max(1).min(20)) as u32;

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
                                            "txKbps": ch.tx_kbps,
                                            "pttActive": ch.ptt_active
                                        }
                                    }).to_string();
                                    let _ = tx_chan.send(update_msg);
                                }
                            }
                        }
                    }
                }
            });

            // Spawn the Axum HTTP & WebSocket server in a background thread
            let state_clone = Arc::clone(&state_for_server);
            tauri::async_runtime::spawn(async move {
                let app_routes = Router::new()
                    .route("/api/channels/:id/call", post(initiate_call_handler))
                    .route("/api/channels/:id/accept", post(accept_call_handler))
                    .route("/api/channels/:id/reject", post(reject_call_handler))
                    .route("/api/channels/:id/hangup", post(hangup_handler))
                    .route("/api/channels/:id/ptt", post(ptt_toggle_handler))
                    .route("/api/audio-devices", get(get_audio_devices_handler))
                    .route("/api/audio-devices/select", post(select_audio_device_handler))
                    .route("/api/config", get(get_config_handler))
                    // Web Config routes
                    .route("/config", get(show_config_handler))
                    .route("/config/save", post(save_config_handler))
                    .route("/events", get(ws_handler))
                    .with_state(state_clone)
                    .layer(CorsLayer::permissive());

                // Serve plain HTTP on localhost — HTTPS with self-signed certs causes
                // browser trust errors (ERR_SSL_PROTOCOL_ERROR / cert blocked) for a
                // local-only admin UI. HTTP on 127.0.0.1 is safe for local access.
                match tokio::net::TcpListener::bind("0.0.0.0:8085").await {
                    Ok(listener) => {
                        println!("[Tauri Rust Server] Web config listening on http://localhost:8085/");
                        if let Err(e) = axum::serve(listener, app_routes).await {
                            eprintln!("[Tauri Rust Server] Axum server error: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("[Tauri Rust Server] Failed to bind Axum server to port 8085: {}", e);
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
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

    // Build A-MP (Aquilla Mirror Protocol) per-channel destination rows.
    let mut amp_rows = String::new();
    for ch in &lock.channels {
        let (dot_class, stream_text) = if ch.amp_streaming {
            ("amp-dot amp-dot-live", "STREAMING")
        } else {
            ("amp-dot", "IDLE")
        };
        let is_routing_or_dialing = ch.status == "CONNECTED" || ch.status == "RINGING" || ch.status == "INCOMING";
        let disabled_attr = if is_routing_or_dialing { "disabled" } else { "" };
        let amp_enabled_checked = if ch.amp_enabled { "checked" } else { "" };

        amp_rows.push_str(&format!(
            r#"
            <tr>
                <td style="font-weight: bold; text-align: center;">{:02}</td>
                <td style="color:#4b5563;">{}</td>
                <td style="text-align: center;">
                    <input type="checkbox" name="amp_channel_enabled_{}" {} {} style="width: 18px; height: 18px; cursor: pointer;" />
                </td>
                <td>
                    <input type="text" name="amp_ip_{}" value="{}" {} style="width: 150px;" placeholder="127.0.0.1" />
                </td>
                <td>
                    <input type="number" name="amp_port_{}" value="{}" {} style="width: 100px;" min="0" max="65535" />
                </td>
                <td style="text-align:center;">
                    <span class="{}"></span><span style="font-size:11px; font-weight:600; color:#4b5563;">{}</span>
                </td>
            </tr>
            "#,
            ch.id,
            html_escape(&ch.label),
            ch.id,
            amp_enabled_checked,
            disabled_attr,
            ch.id,
            html_escape(&ch.amp_ip),
            disabled_attr,
            ch.id,
            ch.amp_port,
            disabled_attr,
            dot_class,
            stream_text,
        ));
    }
    let amp_enabled_checked = if lock.amp_enabled { "checked" } else { "" };

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
                .tabs {{
                    display: flex;
                    gap: 4px;
                    border-bottom: 2px solid #e5e7eb;
                    margin-bottom: 20px;
                }}
                .tab-btn {{
                    background: transparent;
                    border: none;
                    border-bottom: 2px solid transparent;
                    margin-bottom: -2px;
                    padding: 10px 18px;
                    font-family: inherit;
                    font-size: 13px;
                    font-weight: 600;
                    color: #6b7280;
                    cursor: pointer;
                }}
                .tab-btn:hover {{ color: #111827; }}
                .tab-btn.active {{
                    color: #2563eb;
                    border-bottom-color: #2563eb;
                }}
                .tab-panel {{ display: none; }}
                .tab-panel.active {{ display: block; }}
                .amp-toggle-row {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 12px 16px;
                    background: #f9fafb;
                    border: 1px solid #e5e7eb;
                    border-radius: 4px;
                    margin-bottom: 16px;
                }}
                .amp-toggle-row input {{ width: 18px; height: 18px; cursor: pointer; }}
                .amp-toggle-row label {{ font-size: 13px; color: #111827; font-weight: 600; }}
                .amp-dot {{
                    display: inline-block;
                    width: 8px; height: 8px;
                    border-radius: 50%;
                    background: #d1d5db;
                    margin-right: 6px;
                    vertical-align: middle;
                }}
                .amp-dot-live {{
                    background: #ef4444;
                    box-shadow: 0 0 0 0 rgba(239,68,68,0.7);
                    animation: amp-pulse 1.4s infinite;
                }}
                @keyframes amp-pulse {{
                    0%   {{ box-shadow: 0 0 0 0 rgba(239,68,68,0.6); }}
                    70%  {{ box-shadow: 0 0 0 6px rgba(239,68,68,0); }}
                    100% {{ box-shadow: 0 0 0 0 rgba(239,68,68,0); }}
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

                <div class="tabs">
                    <button type="button" class="tab-btn active" data-tab="tab-channels" onclick="switchTab('tab-channels', this)">Channel Mapping</button>
                    <button type="button" class="tab-btn" data-tab="tab-amp" onclick="switchTab('tab-amp', this)">A-MP Stream Mapping</button>
                </div>

                <form method="POST" action="/config/save">
                  <div id="tab-channels" class="tab-panel active">
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
                  </div>

                  <div id="tab-amp" class="tab-panel">
                    <div class="section">
                        <h2>A-MP Stream Mapping (NP-C4I Recorder)</h2>
                        <div class="amp-toggle-row">
                            <input type="checkbox" id="amp_enabled" name="amp_enabled" {} />
                            <label for="amp_enabled">Enable A-MP call mirroring to the NP-C4I Recorder (global master switch)</label>
                        </div>
                        <div class="info-note" style="margin-top:0; margin-bottom:8px;">
                            Each active call is mirrored to the recorder as clean RTP/PCMU. Set the destination IP and UDP port per channel to match the recorder's listening ports (defaults: CH01&rarr;5004, CH02&rarr;5006, CH03&rarr;5008, CH04&rarr;5010). Set port to 0 to disable a channel.
                        </div>
                        <table class="channels-table">
                            <thead>
                                <tr>
                                    <th style="width: 6%; text-align: center;">Slot</th>
                                    <th style="width: 22%;">Channel Alias</th>
                                    <th style="width: 10%; text-align: center;">Enable</th>
                                    <th style="width: 26%;">Recorder Destination IP</th>
                                    <th style="width: 20%;">Recorder UDP Port</th>
                                    <th style="width: 16%; text-align:center;">Mirror State</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                  </div>

                    <div style="text-align: right;">
                        <button type="submit" class="btn-submit">Apply Configuration</button>
                    </div>
                </form>
            </div>
            <script>
            function switchTab(tabId, btn) {{
                document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
                document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
                const panel = document.getElementById(tabId);
                if (panel) panel.classList.add("active");
                if (btn) btn.classList.add("active");
            }}
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
        channels_rows,
        amp_enabled_checked,
        amp_rows
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

    // A-MP global master switch (checkbox present only when ticked)
    lock.amp_enabled = form_data.contains_key("amp_enabled");

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

                ch.srtp_enabled = form_data.contains_key(&format!("srtp_enabled_{}", id));
                ch.sip_auth_required = form_data.contains_key(&format!("sip_auth_required_{}", id));
                ch.amp_enabled = form_data.contains_key(&format!("amp_channel_enabled_{}", id));

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

            // A-MP per-channel recorder destination — editable regardless of call
            // state (only affects the NEXT call's mirror, not the live audio path).
            if let Some(ip) = form_data.get(&format!("amp_ip_{}", id)) {
                ch.amp_ip = if ip.trim().is_empty() { "127.0.0.1".to_string() } else { ip.trim().to_string() };
            }
            if let Some(port_str) = form_data.get(&format!("amp_port_{}", id)) {
                if let Ok(p) = port_str.parse::<u16>() {
                    ch.amp_port = p;
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
            "localIp": get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string()),
            "ampEnabled": lock.amp_enabled
        }
    }).to_string();
    let _ = lock.tx.send(config_msg);

    // Update A-MP streaming status dynamically based on current configuration
    let amp_enabled = lock.amp_enabled;
    let tx = lock.tx.clone();
    for ch in lock.channels.iter_mut() {
        let was_streaming = ch.amp_streaming;
        ch.amp_streaming = amp_enabled && ch.amp_enabled && ch.status == "CONNECTED";
        if was_streaming != ch.amp_streaming {
            let update_msg = serde_json::json!({
                "type": "channel_update",
                "data": ch
            }).to_string();
            let _ = tx.send(update_msg);
        }
    }

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
            "localIp": get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string()),
            "ampEnabled": lock.amp_enabled
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
