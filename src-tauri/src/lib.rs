use axum::{
    extract::{Path, State, WebSocketUpgrade, Form, Query, ws::{Message, WebSocket}},
    http::StatusCode,
    response::{IntoResponse, Html},
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
mod ed137;

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
    // ACU Bridge — per-channel two-way interop leg (e.g. JPS ACU/RSP-Z2) that is
    // mixed into the primary call, not just a passive recorder mirror like A-MP.
    #[serde(rename = "bridgeIp", default = "default_amp_ip")]
    bridge_ip: String,
    #[serde(rename = "bridgePort", default)]
    bridge_port: u16,
    #[serde(rename = "bridgeEnabled", default)]
    bridge_enabled: bool,
    // Fixed local UDP port the ACU peer should be configured to send its RTP to.
    // None = ephemeral (auto-assigned each call, won't be stable across calls).
    #[serde(rename = "bridgeLocalPort", default)]
    bridge_local_port: Option<u16>,
    // ED-137 (EUROCAE VoIP-ATM Radio interoperability standard) — when enabled,
    // this channel's RTP carries the ED-137A/B/C PTT/SQU header extension so it
    // can key/receive a real radio or VCS instead of plain unsignalled RTP.
    // Opt-in per channel since most legs (other consoles, ACU/A-MP, dispatcher
    // patches) are not talking to ED-137 equipment.
    #[serde(rename = "ed137Enabled", default)]
    ed137_enabled: bool,
    // PTT source id (0-63) this channel identifies itself as in the ED-137
    // extension word — corresponds to the radio port/operator id the far-end
    // VCS/radio expects.
    #[serde(rename = "ed137PttId", default)]
    ed137_ptt_id: u8,
}

fn default_amp_ip() -> String {
    "127.0.0.1".to_string()
}

fn default_true() -> bool {
    true
}

/// Dispatcher — an internal N-way patch group. Members are Aquilla channels
/// that already each have their own live call (SIP or RTP); while patched,
/// every member hears + can talk to every other active member, on top of
/// their own primary call. Optionally, the whole group's audio can also be
/// mirrored out over RTP to an external destination (same idea as A-MP/ACU
/// Bridge, but at the group level — see DISPATCHER_IMPLEMENTATION_SUMMARY.md).
///
/// v1 supports a fixed number of group slots (`DISPATCH_GROUP_COUNT`) rather
/// than a dynamically growable list, to keep the /config UI and form parsing
/// simple. Raise the constant to add more slots.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DispatchGroup {
    id: u32,
    #[serde(default)]
    name: String,
    #[serde(rename = "memberIds", default)]
    member_ids: Vec<u32>,
    #[serde(rename = "mirrorEnabled", default)]
    mirror_enabled: bool,
    #[serde(rename = "mirrorIp", default = "default_amp_ip")]
    mirror_ip: String,
    #[serde(rename = "mirrorPort", default)]
    mirror_port: u16,
    // Fixed local UDP port the external party (e.g. an ACU Z2 headset resource)
    // should be configured to send its RTP to, so it can talk back into the
    // whole patch — same idea as Channel.bridge_local_port for the ACU Bridge.
    // None = ephemeral (auto-assigned, not stable, external party can't be told
    // a fixed destination). See `get_or_create_dispatch_mirror`.
    #[serde(rename = "mirrorLocalPort", default)]
    mirror_local_port: Option<u16>,
}

const DISPATCH_GROUP_COUNT: u32 = 4;

fn default_dispatch_groups() -> Vec<DispatchGroup> {
    (1..=DISPATCH_GROUP_COUNT)
        .map(|id| DispatchGroup {
            id,
            name: format!("Patch {}", ((b'A' + (id as u8 - 1)) as char)),
            member_ids: Vec::new(),
            mirror_enabled: false,
            mirror_ip: "127.0.0.1".to_string(),
            mirror_port: 9004 + (id as u16 - 1) * 2,
            mirror_local_port: None,
        })
        .collect()
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
    // ACU Bridge global master enable
    #[serde(rename = "bridgeEnabled", default = "default_true")]
    bridge_enabled: bool,
    // Dispatcher patch groups
    #[serde(rename = "dispatchGroups", default = "default_dispatch_groups")]
    dispatch_groups: Vec<DispatchGroup>,
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

    // ACU Bridge columns — a two-way interop leg (e.g. JPS ACU/RSP-Z2) mixed into
    // the live call, distinct from the one-way A-MP recorder mirror above.
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN bridge_ip TEXT NOT NULL DEFAULT '127.0.0.1'", []);
    let bridge_port_added = conn
        .execute("ALTER TABLE channels ADD COLUMN bridge_port INTEGER NOT NULL DEFAULT 0", [])
        .is_ok();
    if bridge_port_added {
        // Seed a range that doesn't collide with the A-MP default ports (5004, 5006, ...).
        let _ = conn.execute("UPDATE channels SET bridge_port = 6004 + (id - 1) * 2 WHERE bridge_port = 0", []);
    }
    // Per-channel bridge is opt-in (default off) since, unlike A-MP, it's a live
    // two-way leg mixed into the call rather than a passive recording tap.
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN bridge_enabled INTEGER NOT NULL DEFAULT 0", []);
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('bridge_enabled', 'true')", []).ok();
    // Fixed local UDP port to bind the bridge socket to, so the ACU peer can be
    // configured with a stable destination (nullable = ephemeral/auto).
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN bridge_local_port INTEGER", []);

    // ED-137 (EUROCAE Radio interop standard) — per-channel opt-in, default off.
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN ed137_enabled INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE channels ADD COLUMN ed137_ptt_id INTEGER NOT NULL DEFAULT 0", []);

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

    let bridge_enabled: bool = conn
        .query_row("SELECT value FROM settings WHERE key = 'bridge_enabled'", [], |row| {
            let v: String = row.get(0)?;
            Ok(v != "false" && v != "0")
        })
        .unwrap_or(true);

    // Dispatcher patch groups are stored as a single JSON blob (a fixed-size list,
    // not per-channel, so a settings row is simpler than a new relational table).
    let dispatch_groups: Vec<DispatchGroup> = conn
        .query_row("SELECT value FROM settings WHERE key = 'dispatch_groups'", [], |row| {
            let v: String = row.get(0)?;
            Ok(serde_json::from_str::<Vec<DispatchGroup>>(&v).unwrap_or_else(|_| default_dispatch_groups()))
        })
        .unwrap_or_else(|_| default_dispatch_groups());

    // Load channels (still read is_conference column for backward compat but ignore it)
    let mut stmt = conn.prepare(
        "SELECT id, label, protocol, target_ip, target_port, sip_user, codec, local_port, is_conference, volume, srtp_enabled, sip_auth_required, amp_ip, amp_port, amp_enabled, bridge_ip, bridge_port, bridge_enabled, bridge_local_port, ed137_enabled, ed137_ptt_id FROM channels ORDER BY id"
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
            bridge_ip: row.get::<_, String>(15).unwrap_or_else(|_| default_amp_ip()),
            bridge_port: row.get::<_, u32>(16).unwrap_or(0) as u16,
            bridge_enabled: row.get::<_, i32>(17).unwrap_or(0) != 0,
            bridge_local_port: row.get::<_, Option<u32>>(18).unwrap_or(None).map(|v| v as u16),
            ed137_enabled: row.get::<_, i32>(19).unwrap_or(0) != 0,
            ed137_ptt_id: row.get::<_, u32>(20).unwrap_or(0) as u8,
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
        bridge_enabled,
        dispatch_groups,
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

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('bridge_enabled', ?1)",
        [if config.bridge_enabled { "true" } else { "false" }],
    ).ok();

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('dispatch_groups', ?1)",
        [serde_json::to_string(&config.dispatch_groups).unwrap_or_else(|_| "[]".to_string())],
    ).ok();

    // Save channels in a transaction
    conn.execute("BEGIN", []).ok();
    for ch in &config.channels {
        conn.execute(
            "INSERT OR REPLACE INTO channels (id, label, protocol, target_ip, target_port, sip_user, codec, local_port, is_conference, volume, srtp_enabled, sip_auth_required, amp_ip, amp_port, amp_enabled, bridge_ip, bridge_port, bridge_enabled, bridge_local_port, ed137_enabled, ed137_ptt_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
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
                ch.bridge_ip,
                ch.bridge_port as u32,
                ch.bridge_enabled as i32,
                ch.bridge_local_port.map(|v| v as u32),
                ch.ed137_enabled as i32,
                ch.ed137_ptt_id as u32,
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

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('bridge_enabled', ?1)",
        [if config.bridge_enabled { "true" } else { "false" }],
    ).ok();

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('dispatch_groups', ?1)",
        [serde_json::to_string(&config.dispatch_groups).unwrap_or_else(|_| "[]".to_string())],
    ).ok();

    for ch in &config.channels {
        conn.execute(
            "INSERT OR REPLACE INTO channels (id, label, protocol, target_ip, target_port, sip_user, codec, local_port, is_conference, volume, srtp_enabled, sip_auth_required, amp_ip, amp_port, amp_enabled, bridge_ip, bridge_port, bridge_enabled, bridge_local_port, ed137_enabled, ed137_ptt_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            rusqlite::params![
                ch.id, ch.label, ch.protocol, ch.target_ip,
                ch.target_port as u32, ch.sip_user, ch.codec,
                ch.local_port.map(|v| v as u32),
                ch.volume, ch.srtp_enabled as i32, ch.sip_auth_required as i32,
                ch.amp_ip, ch.amp_port as u32, ch.amp_enabled as i32,
                ch.bridge_ip, ch.bridge_port as u32, ch.bridge_enabled as i32,
                ch.bridge_local_port.map(|v| v as u32),
                ch.ed137_enabled as i32, ch.ed137_ptt_id as u32,
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
            bridge_ip: "127.0.0.1".to_string(),
            bridge_port: 6004 + (id as u16 - 1) * 2,
            bridge_enabled: false,
            bridge_local_port: None,
            ed137_enabled: false,
            ed137_ptt_id: 0,
        })
        .collect();

    GatewayConfig {
        sip_port: 5060,
        selected_device: None,
        channels,
        amp_enabled: true,
        bridge_enabled: true,
        dispatch_groups: default_dispatch_groups(),
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
    #[serde(rename = "bridgeIp")]
    bridge_ip: String,
    #[serde(rename = "bridgePort")]
    bridge_port: u16,
    #[serde(rename = "bridgeEnabled")]
    bridge_enabled: bool,
    #[serde(rename = "bridgeLocalPort")]
    bridge_local_port: Option<u16>,
    #[serde(rename = "ed137Enabled")]
    ed137_enabled: bool,
    #[serde(rename = "ed137PttId")]
    ed137_ptt_id: u8,
    /// Runtime status: true while the most recent inbound ED-137 extension on
    /// this channel reported squelch (carrier/signal present) from the radio.
    #[serde(rename = "ed137RemoteSquelch")]
    ed137_remote_squelch: bool,
    /// Runtime status: true while the most recent inbound ED-137 extension on
    /// this channel reported a keyed PTT type (i.e. the far end is talking).
    #[serde(rename = "ed137RemotePtt")]
    ed137_remote_ptt: bool,
    /// Runtime status: true while a live two-way ACU bridge leg is up for this call.
    #[serde(rename = "bridgeConnected")]
    bridge_connected: bool,
    /// Runtime status: true while the ACU Bridge keepalive has confirmed the RTP
    /// link is live — i.e. valid RTP from the ACU Z has arrived within the last
    /// few seconds. Distinct from `bridge_connected` (which only means a bridge
    /// leg/task exists for this call): this reflects the actual health of the
    /// ACU Z's 5-second keepalive link, and clears to false when it goes stale.
    #[serde(rename = "bridgeLinkAlive")]
    bridge_link_alive: bool,
    /// Runtime status: true while this channel is an active Dispatcher patch member
    /// (i.e. it's on a live call AND at least one other member of one of its
    /// Dispatcher groups is also on a live call).
    #[serde(rename = "dispatchConnected")]
    dispatch_connected: bool,
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
    bridge_abort_handle: Option<tokio::task::AbortHandle>,
    dispatch_abort_handles: Vec<tokio::task::AbortHandle>,
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
    bridge_enabled: bool,
    dispatch_groups: Vec<DispatchGroup>,
    /// Runtime-only fan-out buses for active Dispatcher groups, keyed by group id.
    /// Created lazily the first time a member of that group needs it.
    dispatch_buses: HashMap<u32, broadcast::Sender<DispatchFrame>>,
    /// The ONE shared two-way mirror tap per Dispatcher group (not one per
    /// member — every member's outgoing audio goes through the same tap so the
    /// external party hears one combined patch feed, and whatever it sends back
    /// is republished onto the group's bus for every member to pick up). Created
    /// lazily on first use; invalidated (cleared) whenever config is saved so a
    /// changed ip/port/local-port takes effect on the next connecting member.
    dispatch_mirror_taps: HashMap<u32, Arc<RecordingTap>>,
    /// Abort handle for each group's mirror RX listener task, paired 1:1 with
    /// `dispatch_mirror_taps`.
    dispatch_mirror_listeners: HashMap<u32, tokio::task::AbortHandle>,
    /// Live, instantly-toggleable membership flags for every currently
    /// connected (channel_id, group_id) pair — see `DispatchOut`. The matrix
    /// toggle endpoint flips these directly so a patch change takes effect on
    /// the very next audio frame, with no reconnect/respawn needed. Entries
    /// are (re)created fresh at connect time and removed at teardown.
    dispatch_membership_flags: HashMap<(u32, u32), Arc<std::sync::atomic::AtomicBool>>,
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
        bridge_ip: ch.bridge_ip.clone(),
        bridge_port: ch.bridge_port,
        bridge_enabled: ch.bridge_enabled,
        bridge_local_port: ch.bridge_local_port,
        ed137_enabled: ch.ed137_enabled,
        ed137_ptt_id: ch.ed137_ptt_id,
    }).collect();

    let config = GatewayConfig {
        sip_port: state.sip_port,
        selected_device: state.selected_device.clone(),
        channels: channel_configs,
        amp_enabled: state.amp_enabled,
        bridge_enabled: state.bridge_enabled,
        dispatch_groups: state.dispatch_groups.clone(),
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

/// Milliseconds since the Unix epoch. Used for coarse idle/staleness timing on
/// the ACU Bridge keepalive + link-status monitor (not for precise scheduling).
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deterministic per-channel RTP SSRC for the channel's *primary operator stream*
/// to its primary target (the ACU Z / RSP-Z2 or other radio/console it calls).
///
/// The keyed PTT-ON establishment burst, live mic/PTT audio, and the idle
/// keep-alive — all emitted by the one mic TX task — share this single SSRC so
/// the far end sees one continuous stream: the burst keys/establishes the link,
/// and the keep-alive holds it. The ACU Z tracks its link per-SSRC, so these
/// must not drift onto separate SSRCs. (The cosmetic connect tone and the
/// concurrent Dispatcher/ACU-Bridge forwards deliberately use their own SSRCs —
/// they are independent senders and must not collide with this stream.)
fn channel_rtp_ssrc(channel_id: u32) -> u32 {
    0xAC00_0000 | (channel_id & 0x00FF_FFFF)
}

/// Aborts the wrapped task when this guard is dropped. Lets a child task's
/// lifetime piggyback on a parent task: when the parent future is dropped
/// (e.g. the ACU Bridge listener task is aborted at call teardown), the guard's
/// Drop aborts the child too — so the keepalive/link-monitor task never needs a
/// separate AbortHandle threaded through every `ActiveCall` literal / teardown
/// site.
struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A per-call sink that re-packetizes µ-law audio into RTP/PCMU for the recorder.
struct RecordingTap {
    socket: Arc<tokio::net::UdpSocket>,
    dest: String,
    ssrc: u32,
    seq: std::sync::atomic::AtomicU16,
    ts: std::sync::atomic::AtomicU32,
    /// Unix-millis of the last real audio frame sent through this tap. The ACU
    /// Bridge keepalive reads this to detect idle gaps and inject a silence
    /// frame before the ACU Z's 5-second link-establishment window elapses.
    last_activity_ms: std::sync::atomic::AtomicU64,
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

        // Stamp activity so the keepalive monitor knows the leg isn't idle.
        self.last_activity_ms.store(now_millis(), Ordering::Relaxed);
    }

    /// Send one 20 ms µ-law *silence* frame (160 bytes of 0xFF = digital zero)
    /// as a well-formed RTP/PCMU packet — the ACU Bridge keepalive. To the ACU Z
    /// this is indistinguishable from a real (quiet) audio frame, so it holds the
    /// RTP link "established" during call silence without being audible. Shares
    /// this tap's seq/ts/ssrc space via `send_ulaw`, keeping the stream contiguous
    /// (and refreshing `last_activity_ms` so the next keepalive is ~4 s later).
    async fn send_keepalive_silence(&self) {
        const ULAW_SILENCE: u8 = 0xFF; // linear 0 encoded as µ-law
        let frame = [ULAW_SILENCE; 160];
        self.send_ulaw(&frame).await;
    }
}

// ============================================================================
// Connected tone — a short audible confirmation burst sent as real RTP/PCMU
// payload the instant a link (main leg or ACU Bridge/RSP-Z2 leg) is opened.
//
// A bare empty-payload RTP packet turned out not to be enough: some far-end
// gear only marks its RTP link "established" once it has actually received
// an audio payload, not just a header. So instead we generate a brief tone
// and packetize/send it exactly like live TX audio (same 20ms/160-sample
// µ-law framing), which both proves the link is live to the far end and
// gives the operator on that end an audible "connected" cue.
// ============================================================================

/// Duration (ms) of the connected tone sent when a leg opens. Also serves as the
/// ACU Z / RSP-Z2 stream-establishment burst: it must be long enough for the far
/// end to lock onto the RTP SSRC before the stream drops to the (empty) idle
/// keep-alive. Bumped from 300 ms → 1000 ms so a full second of continuous audio
/// establishes the link. Must be a multiple of 20 ms.
const CONNECTED_TONE_MS: u32 = 1000;

/// Generate a short tone as 20ms (160-sample) µ-law frames at 8kHz — the same
/// framing as the live TX audio path. `duration_ms` should be a multiple of
/// 20 for a clean frame count.
fn generate_connected_tone_frames(freq_hz: f64, duration_ms: u32) -> Vec<[u8; 160]> {
    const SAMPLE_RATE: f64 = 8000.0;
    const FRAME_SAMPLES: usize = 160;
    let total_samples = ((duration_ms as f64 / 1000.0) * SAMPLE_RATE) as usize;
    let amplitude: f64 = 8000.0; // moderate level — audible cue, not a full-scale blast

    let mut frames = Vec::new();
    let mut sample_idx = 0usize;
    while sample_idx < total_samples {
        let mut frame = [0u8; FRAME_SAMPLES];
        for (i, slot) in frame.iter_mut().enumerate() {
            let n = sample_idx + i;
            let t = n as f64 / SAMPLE_RATE;
            let s = (amplitude * (2.0 * std::f64::consts::PI * freq_hz * t).sin()) as i16;
            *slot = linear_to_ulaw(s);
        }
        frames.push(frame);
        sample_idx += FRAME_SAMPLES;
    }
    frames
}

/// Send the connected tone as real RTP/PCMU packets directly on a raw socket
/// (used for the main leg), paced at 20ms/frame like live audio, with its own
/// header/seq/ts/ssrc and the marker bit set on the first frame.
async fn send_connected_tone(socket: &tokio::net::UdpSocket, dest: &str) {
    let frames = generate_connected_tone_frames(1000.0, CONNECTED_TONE_MS);
    let mut seq: u16 = rand_u32() as u16;
    let mut ts: u32 = rand_u32();
    // Cosmetic connect beep only — NOT the ACU Z link-establishment signal (that
    // is the keyed PTT-ON burst at the start of the mic TX task, which the far end
    // requires before it will honour keep-alives). Uses its own SSRC so it never
    // collides with that keyed stream.
    let ssrc: u32 = rand_u32();

    for (i, frame) in frames.iter().enumerate() {
        let mut packet = vec![0u8; 12 + frame.len()];
        packet[0] = 0x80;
        packet[1] = if i == 0 { 0x80 } else { 0x00 }; // marker bit on first frame (talkspurt start)
        packet[2] = (seq >> 8) as u8;
        packet[3] = (seq & 0xFF) as u8;
        packet[4] = (ts >> 24) as u8;
        packet[5] = ((ts >> 16) & 0xFF) as u8;
        packet[6] = ((ts >> 8) & 0xFF) as u8;
        packet[7] = (ts & 0xFF) as u8;
        packet[8] = (ssrc >> 24) as u8;
        packet[9] = ((ssrc >> 16) & 0xFF) as u8;
        packet[10] = ((ssrc >> 8) & 0xFF) as u8;
        packet[11] = (ssrc & 0xFF) as u8;
        packet[12..].copy_from_slice(frame);

        let _ = socket.send_to(&packet, dest).await;

        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(frame.len() as u32);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Same tone, sent through a RecordingTap (ACU Bridge/RSP-Z2 or A-MP leg),
/// reusing its own shared seq/ts/ssrc space via `send_ulaw`.
async fn send_connected_tone_via_tap(tap: &RecordingTap) {
    let frames = generate_connected_tone_frames(1000.0, CONNECTED_TONE_MS);
    for frame in &frames {
        tap.send_ulaw(frame).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Fire the connected tone on the main leg as a detached background task, so
/// call setup never blocks on the ~300ms send while holding the state lock.
fn spawn_connected_tone(socket: Arc<tokio::net::UdpSocket>, dest: String) {
    tokio::spawn(async move {
        send_connected_tone(&socket, &dest).await;
    });
}

/// Fire the connected tone on a RecordingTap (ACU Bridge/RSP-Z2 leg) as a
/// detached background task, same rationale as `spawn_connected_tone`.
fn spawn_connected_tone_tap(tap: Arc<RecordingTap>) {
    tokio::spawn(async move {
        send_connected_tone_via_tap(&tap).await;
    });
}

/// Build a recording tap from already-resolved A-MP (or ACU Bridge) settings.
/// Takes plain params (never locks AppState) so it is safe to call from a site
/// that already holds the state lock — avoiding tokio Mutex re-entrancy
/// deadlocks. Returns None if disabled, the port is unset, or the socket can't
/// be created.
///
/// `local_port`: None binds an ephemeral port (fine for A-MP, which is a
/// receive-only recorder that never needs to be dialed back). Some(p) binds a
/// fixed local port instead — required for the ACU Bridge leg, since the ACU
/// peer needs a stable, known destination port on this console to send its
/// own RTP to (see ACU_BRIDGE_IMPLEMENTATION_SUMMARY.md).
async fn build_recording_tap(enabled: bool, ip: &str, port: u16, channel_id: u32, local_port: Option<u16>) -> Option<Arc<RecordingTap>> {
    if !enabled || port == 0 || ip.trim().is_empty() {
        return None;
    }
    let bind_addr = match local_port {
        Some(p) => format!("0.0.0.0:{}", p),
        None => "0.0.0.0:0".to_string(),
    };
    match tokio::net::UdpSocket::bind(&bind_addr).await {
        Ok(sock) => {
            let dest = format!("{}:{}", ip, port);
            let actual_local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
            println!("[A-MP/Bridge] Channel {} mirroring call audio to {} (local port {})", channel_id, dest, actual_local_port);
            Some(Arc::new(RecordingTap {
                socket: Arc::new(sock),
                dest,
                ssrc: rand_u32(),
                seq: std::sync::atomic::AtomicU16::new(rand_u32() as u16),
                ts: std::sync::atomic::AtomicU32::new(rand_u32()),
                last_activity_ms: std::sync::atomic::AtomicU64::new(now_millis()),
            }))
        }
        Err(e) => {
            eprintln!("[A-MP/Bridge] Failed to open mirror socket for channel {} (bind {}): {}", channel_id, bind_addr, e);
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

/// Same as `amp_settings_for` but for the ACU Bridge leg. Also resolves the
/// fixed local bind port (falling back to `8004 + (id-1)*2` if unset) so the
/// ACU peer can be given a stable destination. Convenience for call sites that
/// do NOT already hold the state lock.
async fn bridge_settings_for(state: &Arc<Mutex<AppState>>, channel_id: u32) -> (bool, String, u16, u16) {
    let lock = state.lock().await;
    let ch = lock.channels.iter().find(|c| c.id == channel_id);
    (
        lock.bridge_enabled && ch.map(|c| c.bridge_enabled).unwrap_or(false),
        ch.map(|c| c.bridge_ip.clone()).unwrap_or_else(|| "127.0.0.1".to_string()),
        ch.map(|c| c.bridge_port).unwrap_or(0),
        ch.and_then(|c| c.bridge_local_port).unwrap_or(8004 + (channel_id as u16 - 1) * 2),
    )
}

/// Overlay a secondary mono audio source onto an already primary-filled output
/// buffer (interleaved by `channels`). Used to mix the ACU Bridge leg's decoded
/// audio into local speaker output alongside the primary (jitter-buffered) call
/// audio. Best-effort: pops silence when the secondary queue is empty instead of
/// stalling — only the primary path gets full adaptive jitter-buffer/underrun
/// handling; the bridge leg is a secondary, lower-priority audio source.
fn overlay_secondary_mono(buf: &mut [f32], secondary: &std::sync::Mutex<std::collections::VecDeque<f32>>, channels: usize) {
    if channels == 0 {
        return;
    }
    let mut q = secondary.lock().unwrap();
    for frame in buf.chunks_mut(channels) {
        let s = q.pop_front().unwrap_or(0.0);
        if s == 0.0 {
            continue;
        }
        for out in frame.iter_mut() {
            *out = (*out + s).clamp(-1.0, 1.0);
        }
    }
}

/// Two-way ACU Bridge leg: receives RTP/PCMU from a secondary interop endpoint
/// (e.g. a JPS ACU/RSP-Z2 attached to another radio/console), and:
///   1. mixes the decoded audio into the local speaker output via `acu_queue`
///      (overlaid on top of the primary jitter-buffered audio in
///      `start_audio_playback`'s cpal output callback), and
///   2. re-encodes it as an independent RTP/PCMU stream (its own SSRC) and
///      forwards it to the primary call's target (e.g. JPS MCC), so the ACU
///      party is heard on both ends of the primary call — a real 3-way patch,
///      not just a passive recording tap.
///
/// Caveat (see ACU_BRIDGE_IMPLEMENTATION_SUMMARY.md): step 2 sends a *second*
/// RTP SSRC to the primary target rather than sample-mixing into the operator's
/// own encoded TX stream. This keeps the existing, safety-critical PTT-gated
/// mic path completely untouched. Most interop gateways (including JPS
/// hardware) handle multiple inbound SSRCs natively; if the far end strictly
/// expects a single SSRC, only the most recently active source may be audible.
fn start_bridge_listener(
    channel_id: u32,
    bridge_socket: Arc<tokio::net::UdpSocket>,
    primary_rtp_socket: Arc<tokio::net::UdpSocket>,
    primary_rtp_dest: String,
    acu_queue: Arc<std::sync::Mutex<std::collections::VecDeque<f32>>>,
    out_sample_rate: u32,
    bridge_tap: Arc<RecordingTap>,
    state: Arc<Mutex<AppState>>,
) -> tokio::task::AbortHandle {
    let task = tokio::spawn(async move {
        use std::sync::atomic::Ordering;
        let mut resampler_out = PlaybackResampler::new(8000, out_sample_rate);
        let mut limiter = AudioLimiter::new();
        let mut buf = [0u8; 2048];
        // Independent SSRC: the ACU-Bridge forward runs as its own task and can
        // send to the primary target concurrently with the mic/keep-alive stream,
        // so it must NOT share that stream's SSRC (two senders on one SSRC with
        // independent seq/ts would corrupt the stream). A distinct SSRC is a
        // legal second RTP source the far end mixes/plays alongside the primary.
        let fwd_ssrc = rand_u32();
        let mut fwd_seq: u16 = rand_u32() as u16;
        let mut fwd_ts: u32 = rand_u32();
        let max_queue_samples = (out_sample_rate as usize) * 500 / 1000; // cap at 500ms, matches primary jitter buffer ceiling

        // Unix-millis of the last valid RTP/PCMU packet received FROM the ACU peer
        // (0 = never heard yet). Read by the keepalive/link-status monitor below.
        let last_rx_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // ── ACU Bridge keepalive + link-status monitor ──────────────────────────
        // A single 1 Hz task that does two jobs, both driven by the ACU Z's hard
        // 5-second "link must be (re)established" requirement:
        //   (1) OUTBOUND keepalive — if the bridge tap has sent no real audio for
        //       ~4 s (safely under 5 s), inject one µ-law silence frame so the ACU
        //       Z keeps the RTP link up during call silence.
        //   (2) INBOUND link status — flip this channel's `bridge_link_alive` (and
        //       broadcast a `bridge_status` event) based on whether any RTP has
        //       arrived from the ACU within ~6 s.
        // Guarded by `AbortOnDrop`: when this listener task is aborted at call
        // teardown, the monitor is aborted with it — no extra AbortHandle plumbing.
        let _keepalive_guard = {
            let tap = Arc::clone(&bridge_tap);
            let last_rx = Arc::clone(&last_rx_ms);
            let state = Arc::clone(&state);
            let dest = primary_rtp_dest.clone();
            let handle = tokio::spawn(async move {
                const KEEPALIVE_IDLE_MS: u64 = 4000; // inject silence if idle this long (< 5 s ACU limit)
                const LINK_STALE_MS: u64 = 6000;     // declare link stale after this long with no inbound RTP
                let mut prev_alive: Option<bool> = None;
                let mut tick = tokio::time::interval(Duration::from_millis(1000));
                loop {
                    tick.tick().await;
                    let now = now_millis();

                    // (1) Outbound keepalive during silence.
                    let idle = now.saturating_sub(tap.last_activity_ms.load(Ordering::Relaxed));
                    if idle >= KEEPALIVE_IDLE_MS {
                        tap.send_keepalive_silence().await;
                    }

                    // (2) Inbound link-alive status (edge-triggered broadcast).
                    let last = last_rx.load(Ordering::Relaxed);
                    let alive = last != 0 && now.saturating_sub(last) < LINK_STALE_MS;
                    if prev_alive != Some(alive) {
                        prev_alive = Some(alive);
                        let tx_ws = {
                            let mut app_state = state.lock().await;
                            if let Some(ch) = app_state.channels.iter_mut().find(|c| c.id == channel_id) {
                                ch.bridge_link_alive = alive;
                            }
                            app_state.tx.clone()
                        };
                        let msg = serde_json::json!({
                            "type": "bridge_status",
                            "data": { "id": channel_id, "linkAlive": alive }
                        }).to_string();
                        let _ = tx_ws.send(msg);
                        println!(
                            "[ACU Bridge] Channel {} keepalive link {} (peer {})",
                            channel_id,
                            if alive { "ALIVE — RTP from ACU within 6s" } else { "STALE — no RTP from ACU" },
                            dest
                        );
                    }
                }
            });
            AbortOnDrop(handle.abort_handle())
        };

        println!("[ACU Bridge] Channel {} bridge RX task active (forwarding to {})", channel_id, primary_rtp_dest);

        loop {
            match bridge_socket.recv_from(&mut buf).await {
                Ok((len, _src)) => {
                    if len < 12 {
                        continue;
                    }
                    let version = (buf[0] >> 6) & 0x03;
                    let payload_type = buf[1] & 0x7F;
                    if version != 2 || payload_type != 0 {
                        continue;
                    }
                    // Any valid RTP/PCMU from the ACU (even an empty-payload keepalive
                    // of its own) proves the link is live — stamp before the payload
                    // emptiness check below so silent keepalives still count.
                    last_rx_ms.store(now_millis(), Ordering::Relaxed);
                    let payload = match parse_rtp_payload(&buf[..len]) {
                        Some(p) if !p.is_empty() => p.to_vec(),
                        _ => continue,
                    };

                    // Decode + clean up for local playback
                    let mut pcm: Vec<i16> = payload.iter().map(|&b| ulaw_to_linear(b)).collect();
                    limiter.process(&mut pcm);

                    // 1. Mix into the local speaker (best-effort overlay, see start_audio_playback)
                    let mut upsampled = Vec::new();
                    resampler_out.process(&pcm, &mut upsampled);
                    if !upsampled.is_empty() {
                        let mut q = acu_queue.lock().unwrap();
                        q.extend(upsampled);
                        if q.len() > max_queue_samples {
                            let excess = q.len() - max_queue_samples;
                            q.drain(..excess);
                        }
                    }

                    // 2. Forward to the primary call's target as an independent RTP/PCMU stream
                    let mut packet = vec![0u8; 12 + payload.len()];
                    packet[0] = 0x80;
                    packet[1] = 0x00;
                    packet[2] = (fwd_seq >> 8) as u8;
                    packet[3] = (fwd_seq & 0xFF) as u8;
                    packet[4..8].copy_from_slice(&fwd_ts.to_be_bytes());
                    packet[8..12].copy_from_slice(&fwd_ssrc.to_be_bytes());
                    packet[12..].copy_from_slice(&payload);
                    let _ = primary_rtp_socket.send_to(&packet, &primary_rtp_dest).await;
                    fwd_seq = fwd_seq.wrapping_add(1);
                    fwd_ts = fwd_ts.wrapping_add(payload.len() as u32);
                }
                Err(e) => {
                    println!("[ACU Bridge] Channel {} bridge socket closed: {}", channel_id, e);
                    break;
                }
            }
        }
    });
    task.abort_handle()
}

// ============================================================================
// DISPATCHER — internal N-way patch groups.
// Members are Aquilla channels that already each have their own live call; a
// group's broadcast bus fans out every member's audio (µ-law frames tagged
// with the source channel id) to every other member, in-process (no sockets).
// Each member independently mixes what it receives into its own local speaker
// output and forwards it to its own primary target — the same mixing/forward
// pattern the ACU Bridge uses, just sourced from an in-process bus instead of
// a UDP socket. See DISPATCHER_IMPLEMENTATION_SUMMARY.md for the full design
// and trade-offs.
// ============================================================================

/// One frame published onto a Dispatcher group's bus.
#[derive(Debug, Clone)]
struct DispatchFrame {
    source_channel_id: u32,
    ulaw: Vec<u8>,
}

/// Which group ids (if any) a channel currently belongs to.
fn dispatch_group_ids_for(groups: &[DispatchGroup], channel_id: u32) -> Vec<u32> {
    groups.iter().filter(|g| g.member_ids.contains(&channel_id)).map(|g| g.id).collect()
}

/// Get (or lazily create) the broadcast bus for a Dispatcher group. Takes
/// `&mut AppState` directly (synchronous, no lock re-entry) so it's safe to
/// call from sites that already hold the state lock.
fn get_or_create_dispatch_bus(state: &mut AppState, group_id: u32) -> broadcast::Sender<DispatchFrame> {
    state.dispatch_buses
        .entry(group_id)
        .or_insert_with(|| broadcast::channel::<DispatchFrame>(200).0)
        .clone()
}

/// Get (or lazily create) the ONE shared two-way mirror tap for a Dispatcher
/// group, plus its RX listener task. Unlike per-channel A-MP/ACU Bridge taps
/// (one per call), a group's mirror is a single shared resource: every
/// member's outgoing audio goes through the same tap (so the external party —
/// e.g. an ACU Z2 headset resource — hears one combined patch feed instead of
/// N separate streams), and anything that external party sends back is
/// decoded once by the listener and republished onto the group's bus tagged
/// with a sentinel `source_channel_id: 0` (never a real channel id), so every
/// current member's existing relay task (`start_dispatch_relay`) picks it up
/// exactly like another member's audio. This is what makes the mirror a real
/// two-way leg instead of a passive recording tap — the same idea as the ACU
/// Bridge, just shared across the whole group instead of tied to one call.
///
/// Takes `&mut AppState` and is itself `async` (the tap's socket bind is
/// async); safe to call from sites that already hold the state lock, same as
/// every other tap-building call site in this file (tokio::sync::Mutex is
/// fine to hold across an await).
async fn get_or_create_dispatch_mirror(state: &mut AppState, group_id: u32) -> Option<Arc<RecordingTap>> {
    if let Some(tap) = state.dispatch_mirror_taps.get(&group_id) {
        return Some(Arc::clone(tap));
    }
    let group = state.dispatch_groups.iter().find(|g| g.id == group_id)?.clone();
    if !group.mirror_enabled || group.mirror_port == 0 || group.mirror_ip.trim().is_empty() {
        return None;
    }
    let local_port = group.mirror_local_port.unwrap_or(11004 + (group_id as u16 - 1) * 2);
    let tap = build_recording_tap(true, &group.mirror_ip, group.mirror_port, group_id, Some(local_port)).await?;
    let bus = get_or_create_dispatch_bus(state, group_id);
    let listener = start_dispatch_mirror_listener(group_id, Arc::clone(&tap.socket), bus);
    state.dispatch_mirror_taps.insert(group_id, Arc::clone(&tap));
    state.dispatch_mirror_listeners.insert(group_id, listener);
    Some(tap)
}

/// Listens for RTP/PCMU sent back from the external party on a Dispatcher
/// group's shared mirror tap, decodes it, and republishes it onto the
/// group's bus (sentinel `source_channel_id: 0`) so every current member
/// mixes it into their own speaker and forwards it to their own primary RTP
/// target via their existing relay task. See `get_or_create_dispatch_mirror`.
fn start_dispatch_mirror_listener(
    group_id: u32,
    mirror_socket: Arc<tokio::net::UdpSocket>,
    bus: broadcast::Sender<DispatchFrame>,
) -> tokio::task::AbortHandle {
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        println!("[Dispatcher] Group {} mirror RX task active", group_id);
        loop {
            match mirror_socket.recv_from(&mut buf).await {
                Ok((len, _src)) => {
                    if len < 12 {
                        continue;
                    }
                    let version = (buf[0] >> 6) & 0x03;
                    let payload_type = buf[1] & 0x7F;
                    if version != 2 || payload_type != 0 {
                        continue;
                    }
                    let payload = match parse_rtp_payload(&buf[..len]) {
                        Some(p) if !p.is_empty() => p.to_vec(),
                        _ => continue,
                    };
                    let _ = bus.send(DispatchFrame { source_channel_id: 0, ulaw: payload });
                }
                Err(e) => {
                    println!("[Dispatcher] Group {} mirror socket closed: {}", group_id, e);
                    break;
                }
            }
        }
    });
    task.abort_handle()
}

/// A channel's resolved Dispatcher fan-out for ONE group: the group's bus,
/// that group's ONE shared mirror tap if configured (see
/// `get_or_create_dispatch_mirror`), and a live, instantly-toggleable
/// membership flag.
///
/// For "instant, no save/reload" emergency patching, every connected channel
/// is ALWAYS linked to all `DISPATCH_GROUP_COUNT` groups (a relay task
/// running for each, and TX/RX always able to publish to each bus) — nothing
/// is spawned or torn down when membership changes. Instead, `is_member`
/// (shared via `AppState.dispatch_membership_flags`) is checked on every
/// frame; the matrix toggle endpoint just flips this atomic, so a patch
/// takes effect on the very next audio frame for calls already in progress,
/// with no reconnect needed.
#[derive(Clone)]
struct DispatchOut {
    group_id: u32,
    bus: broadcast::Sender<DispatchFrame>,
    mirror_tap: Option<Arc<RecordingTap>>,
    is_member: Arc<std::sync::atomic::AtomicBool>,
}

/// Get (or create) the live membership flag for (channel_id, group_id),
/// seeded from `initial`, and register it in `AppState.dispatch_membership_flags`
/// so the matrix toggle endpoint can find and flip it instantly for a channel
/// that's currently connected. Always creates a fresh flag at connect time
/// (overwriting any stale leftover from a previous call) so it reflects
/// current config at the moment of connecting.
fn register_dispatch_membership_flag(state: &mut AppState, channel_id: u32, group_id: u32, initial: bool) -> Arc<std::sync::atomic::AtomicBool> {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(initial));
    state.dispatch_membership_flags.insert((channel_id, group_id), Arc::clone(&flag));
    flag
}

/// Resolve all `DISPATCH_GROUP_COUNT` DispatchOuts for a connecting channel
/// (always all groups, not just its current members — see `DispatchOut`).
/// Convenience for call sites that do NOT already hold the state lock
/// (mirrors `bridge_settings_for`).
async fn dispatch_outs_for(state: &Arc<Mutex<AppState>>, channel_id: u32) -> Vec<DispatchOut> {
    let mut lock = state.lock().await;
    dispatch_outs_for_locked(&mut lock, channel_id).await
}

/// Same as `dispatch_outs_for` but for call sites that already hold the state
/// lock (a `tokio::sync::MutexGuard` derefs to `&mut AppState`).
async fn dispatch_outs_for_locked(state: &mut AppState, channel_id: u32) -> Vec<DispatchOut> {
    let mut outs = Vec::new();
    for gid in 1..=DISPATCH_GROUP_COUNT {
        let is_member_now = state.dispatch_groups.iter()
            .find(|g| g.id == gid)
            .map(|g| g.member_ids.contains(&channel_id))
            .unwrap_or(false);
        let is_member = register_dispatch_membership_flag(state, channel_id, gid, is_member_now);
        let bus = get_or_create_dispatch_bus(state, gid);
        let mirror_tap = get_or_create_dispatch_mirror(state, gid).await;
        outs.push(DispatchOut { group_id: gid, bus, mirror_tap, is_member });
    }
    outs
}

/// One relay per Dispatcher group a channel belongs to. Subscribes to that
/// group's bus and, for every frame from a *different* channel:
///   1. mixes it into the local speaker (via `dispatch_queue`, overlaid the
///      same way `acu_queue` is for the ACU Bridge), and
///   2. re-encodes it and forwards it to this channel's own primary target as
///      an independent RTP/PCMU stream (own SSRC — same trade-off as the ACU
///      Bridge's forwarding).
/// Frames this channel itself published are skipped so it never hears/forwards
/// its own audio back to itself.
fn start_dispatch_relay(
    channel_id: u32,
    mut rx: broadcast::Receiver<DispatchFrame>,
    primary_rtp_socket: Arc<tokio::net::UdpSocket>,
    primary_rtp_dest: String,
    dispatch_queue: Arc<std::sync::Mutex<std::collections::VecDeque<f32>>>,
    out_sample_rate: u32,
    is_member: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::AbortHandle {
    let task = tokio::spawn(async move {
        let mut resampler_out = PlaybackResampler::new(8000, out_sample_rate);
        let mut limiter = AudioLimiter::new();
        // Independent SSRC: the Dispatcher forward runs as its own task and can send
        // to the primary target concurrently with the mic/keep-alive stream, so it
        // must NOT share that stream's SSRC (two senders on one SSRC with independent
        // seq/ts would corrupt the stream). A distinct SSRC is a legal second RTP
        // source the far end mixes/plays alongside the primary.
        let fwd_ssrc = rand_u32();
        let mut fwd_seq: u16 = rand_u32() as u16;
        let mut fwd_ts: u32 = rand_u32();
        let max_queue_samples = (out_sample_rate as usize) * 500 / 1000;

        println!("[Dispatcher] Channel {} patch relay active (forwarding to {})", channel_id, primary_rtp_dest);

        loop {
            match rx.recv().await {
                Ok(frame) => {
                    if frame.source_channel_id == channel_id || frame.ulaw.is_empty() {
                        continue;
                    }
                    // Live membership gate: even though this relay is always
                    // running for every group, it only actually mixes/forwards
                    // while this channel is CURRENTLY toggled into the group —
                    // this is what makes matrix clicks take effect instantly on
                    // calls already in progress, with no respawn needed.
                    if !is_member.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }

                    let mut pcm: Vec<i16> = frame.ulaw.iter().map(|&b| ulaw_to_linear(b)).collect();
                    limiter.process(&mut pcm);

                    // 1. Mix into the local speaker (best-effort overlay)
                    let mut upsampled = Vec::new();
                    resampler_out.process(&pcm, &mut upsampled);
                    if !upsampled.is_empty() {
                        let mut q = dispatch_queue.lock().unwrap();
                        q.extend(upsampled);
                        if q.len() > max_queue_samples {
                            let excess = q.len() - max_queue_samples;
                            q.drain(..excess);
                        }
                    }

                    // 2. Forward to this channel's own primary target as an independent RTP/PCMU stream
                    let mut packet = vec![0u8; 12 + frame.ulaw.len()];
                    packet[0] = 0x80;
                    packet[1] = 0x00;
                    packet[2] = (fwd_seq >> 8) as u8;
                    packet[3] = (fwd_seq & 0xFF) as u8;
                    packet[4..8].copy_from_slice(&fwd_ts.to_be_bytes());
                    packet[8..12].copy_from_slice(&fwd_ssrc.to_be_bytes());
                    packet[12..].copy_from_slice(&frame.ulaw);
                    let _ = primary_rtp_socket.send_to(&packet, &primary_rtp_dest).await;
                    fwd_seq = fwd_seq.wrapping_add(1);
                    fwd_ts = fwd_ts.wrapping_add(frame.ulaw.len() as u32);
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    task.abort_handle()
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
    bridge_tap: Option<Arc<RecordingTap>>,
    dispatch_outs: Vec<DispatchOut>,
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
        let (srtp_enabled, secure_context, ed137_enabled, ed137_ptt_id) = {
            let app_state = state_sender.lock().await;
            let ch = app_state.channels.iter().find(|c| c.id == channel_id);
            let srtp = ch.map(|c| c.srtp_enabled).unwrap_or(false);
            let s_ctx = ch.map(|c| Arc::clone(&c.secure_context)).unwrap();
            let ed137 = ch.map(|c| c.ed137_enabled).unwrap_or(false);
            let ed137_id = ch.map(|c| c.ed137_ptt_id).unwrap_or(0);
            (srtp, s_ctx, ed137, ed137_id)
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
        // Shared per-channel SSRC: the connected tone, this mic/PTT audio, and the
        // idle keep-alive all use the SAME SSRC so the ACU Z establishes the link
        // from the connected tone and the keep-alive holds it — without waiting for
        // the first PTT. See channel_rtp_ssrc().
        let ssrc: u32 = channel_rtp_ssrc(channel_id);

        // ACU Z / ED-137 radio (e.g. JPS RSP-Z2) keep-alive: these devices drop
        // the RTP link if they receive no packet for ~5 s. The PTT path below only
        // transmits while keyed, so during idle we would send nothing and the link
        // would time out (talking re-establishes it — the exact symptom reported).
        // `last_tx_ms` tracks the last packet actually sent to the primary target
        // (real TX or keep-alive); the idle branch tops it up every ~3 s.
        const KEEPALIVE_IDLE_MS: u64 = 3000; // send a keep-alive if idle this long (< 5 s ACU limit)
        let mut last_tx_ms: u64 = now_millis();

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

        // ── ACU Z / RSP-Z2 link-establishment burst (keyed PTT-ON) ────────────────
        // The RSP-Z2 only brings its RTP link "up" once it receives a KEYED
        // (PTT-ON) ED-137 header; until then it ignores our PTT-off keep-alives, so
        // the link previously only came up after the operator's first physical PTT
        // (per the reported symptom). To prime it, send a short keyed burst at call
        // start: ED-137 PTT-ON header + µ-law SILENCE payload — this keys the far
        // end briefly to establish the session without transmitting an audible tone
        // over the air. It shares this stream's SSRC and seq/ts counters, so the
        // PTT-off keep-alive that follows is seen as the SAME, already-established
        // stream. Only sent when ED-137 signalling is enabled (the mode the radio
        // needs); plain non-ED-137 links keep the empty keep-alive that worked before.
        if ed137_enabled {
            const ESTABLISH_BURST_MS: u64 = 1000; // keyed priming duration (multiple of 20 ms)
            let ext_bytes = ed137::encode_ed137b(&ed137::Ed137Fields {
                ptt_type: ed137::PttType::Normal, // keyed / PTT-ON
                ptt_id: ed137_ptt_id,
                ..Default::default()
            }).to_vec();
            let payload_start = 12 + ext_bytes.len();
            let frames = (ESTABLISH_BURST_MS / 20).max(1);
            for _ in 0..frames {
                let mut packet = vec![0u8; payload_start + 160];
                packet[0] = 0x90; // version 2 + extension bit
                packet[1] = 0x00; // marker 0, PT 0 (PCMU)
                packet[2] = (sequence_number >> 8) as u8;
                packet[3] = (sequence_number & 0xFF) as u8;
                packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
                packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
                packet[12..payload_start].copy_from_slice(&ext_bytes);
                for i in 0..160 {
                    packet[payload_start + i] = 0xFF; // µ-law silence
                }
                if srtp_enabled {
                    let ctx = secure_context.lock().await;
                    if let Some(ref keys) = ctx.keys {
                        let mut payload = packet[payload_start..].to_vec();
                        if let Ok(tag) = crypto::encrypt_rtp_gcm(keys, sequence_number, timestamp, ssrc, &mut payload) {
                            let mut pkt = packet[0..payload_start].to_vec();
                            pkt.extend_from_slice(&payload);
                            pkt.extend_from_slice(&tag);
                            let _ = rtp_socket_clone.send_to(&pkt, &rtp_dest_clone).await;
                        }
                    }
                } else {
                    let _ = rtp_socket_clone.send_to(&packet, &rtp_dest_clone).await;
                }
                sequence_number = sequence_number.wrapping_add(1);
                timestamp = timestamp.wrapping_add(160);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            last_tx_ms = now_millis();
            println!("[RTP TX Task] ED-137 keyed establishment burst sent to {} ({} ms)", rtp_dest_clone, ESTABLISH_BURST_MS);
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

                    let ptt_on = ptt_active_clone.load(Ordering::SeqCst);

                    // ED-137A/B/C RTP header extension: carries PTT/SQU signalling so
                    // a real radio/VCS on the other end can key/receive properly,
                    // instead of plain unsignalled RTP. Opt-in per channel.
                    let ext_bytes: Vec<u8> = if ed137_enabled {
                        ed137::encode_ed137b(&ed137::Ed137Fields {
                            ptt_type: if ptt_on { ed137::PttType::Normal } else { ed137::PttType::Off },
                            ptt_id: ed137_ptt_id,
                            ..Default::default()
                        }).to_vec()
                    } else {
                        Vec::new()
                    };
                    let ext_len = ext_bytes.len();
                    let payload_start = 12 + ext_len;

                    let mut packet = vec![0u8; payload_start + 160];
                    packet[0] = if ext_len > 0 { 0x90 } else { 0x80 }; // version 2, extension bit if ED-137 is on
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

                    if ext_len > 0 {
                        packet[12..payload_start].copy_from_slice(&ext_bytes);
                    }

                    for i in 0..160 {
                        packet[payload_start + i] = linear_to_ulaw(chunk_160[i]);
                    }

                    if ptt_on {
                        if srtp_enabled {
                            let ctx = secure_context.lock().await;
                            if let Some(ref keys) = ctx.keys {
                                let mut payload = packet[payload_start..].to_vec();
                                if let Ok(tag) = crypto::encrypt_rtp_gcm(keys, sequence_number, timestamp, ssrc, &mut payload) {
                                    let mut srtp_packet = packet[0..payload_start].to_vec();
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
                            tap.send_ulaw(&packet[payload_start..]).await;
                        }

                        // Also mirror to the ACU Bridge leg (e.g. JPS ACU/RSP-Z2), same
                        // half-duplex sharing as the A-MP tap above.
                        if let Some(ref tap) = bridge_tap {
                            tap.send_ulaw(&packet[payload_start..]).await;
                        }

                        // Publish to any Dispatcher patch groups this channel belongs to
                        // (fan-out to other members) and their optional external mirror tap.
                        for d in &dispatch_outs {
                            if !d.is_member.load(Ordering::Relaxed) {
                                continue;
                            }
                            let _ = d.bus.send(DispatchFrame { source_channel_id: channel_id, ulaw: packet[payload_start..].to_vec() });
                            if let Some(ref tap) = d.mirror_tap {
                                tap.send_ulaw(&packet[payload_start..]).await;
                            }
                        }

                        // Real audio just went out — reset the keep-alive idle timer.
                        last_tx_ms = now_millis();
                    } else {
                        // ── Idle keep-alive to the primary target (ACU Z / RSP-Z2) ──
                        // PTT is not keyed, so no audio is being transmitted. The ACU Z /
                        // ED-137 radio tears down the link after ~5 s with no RTP, so every
                        // ~3 s we send an EMPTY-payload RTP keep-alive: the header (+ ED-137
                        // extension when enabled) with NO audio bytes after it.
                        //
                        // `packet[0..payload_start]` = 12-byte RTP header, plus the ED-137
                        // PTT-off extension already built above when ED-137 is on. This is
                        // the important fix over a bare `packet[0..12]`: when ED-137 is
                        // enabled the header's extension bit (0x90) is set, so a 12-byte-only
                        // packet would claim an extension that isn't there and the Z2 would
                        // drop it as malformed — which is why the link only came up AFTER the
                        // first PTT (the first real, valid packet). Including the extension
                        // makes every keep-alive a valid ED-137 PTT-off packet from call
                        // start. No audio payload → no RX "beeping". (When ED-137 is off,
                        // payload_start == 12, so this is exactly the original empty-RTP
                        // keep-alive that worked before.)
                        let now = now_millis();
                        if now.saturating_sub(last_tx_ms) >= KEEPALIVE_IDLE_MS {
                            if srtp_enabled {
                                let ctx = secure_context.lock().await;
                                if let Some(ref keys) = ctx.keys {
                                    // Encrypt an empty payload; append only the GCM tag.
                                    let mut payload: Vec<u8> = Vec::new();
                                    if let Ok(tag) = crypto::encrypt_rtp_gcm(keys, sequence_number, timestamp, ssrc, &mut payload) {
                                        let mut srtp_packet = packet[0..payload_start].to_vec();
                                        srtp_packet.extend_from_slice(&payload);
                                        srtp_packet.extend_from_slice(&tag);
                                        let _ = rtp_socket_clone.send_to(&srtp_packet, &rtp_dest_clone).await;
                                    }
                                }
                            } else {
                                let _ = rtp_socket_clone.send_to(&packet[0..payload_start], &rtp_dest_clone).await;
                            }
                            last_tx_ms = now;
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

/// Abort handles returned by `start_audio_playback` for every secondary audio
/// path it may have started, so callers don't need an ever-growing tuple.
struct PlaybackHandles {
    rx_abort: tokio::task::AbortHandle,
    bridge_abort: Option<tokio::task::AbortHandle>,
    dispatch_aborts: Vec<tokio::task::AbortHandle>,
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
    bridge_tap: Option<Arc<RecordingTap>>,
    primary_rtp_dest: String,
    dispatch_outs: Vec<DispatchOut>,
) -> PlaybackHandles {
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

    // Secondary mono queue fed by the ACU Bridge leg (if enabled), overlaid onto
    // the primary jitter-buffered output in the cpal callback below.
    let acu_queue: Option<Arc<Mutex<VecDeque<f32>>>> = if bridge_tap.is_some() {
        Some(Arc::new(Mutex::new(VecDeque::<f32>::new())))
    } else {
        None
    };

    // Secondary mono queue fed by any Dispatcher patch groups this channel is
    // in (shared across all of them — see the "multiple groups" caveat in
    // DISPATCHER_IMPLEMENTATION_SUMMARY.md), overlaid the same way as acu_queue.
    let dispatch_queue: Option<Arc<Mutex<VecDeque<f32>>>> = if !dispatch_outs.is_empty() {
        Some(Arc::new(Mutex::new(VecDeque::<f32>::new())))
    } else {
        None
    };

    let device_clone = device.clone();
    let config_clone = config.clone();
    let acu_queue_for_thread = acu_queue.clone();
    let dispatch_queue_for_thread = dispatch_queue.clone();

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
                    let acu_q = acu_queue_for_thread.clone();
                    let dispatch_q = dispatch_queue_for_thread.clone();
                    let mut jitter_buf = AdaptiveJitterBuffer::new(out_rate);
                    device.build_output_stream(
                        &config.into(),
                        move |data: &mut [f32], _: &_| {
                            let mut q = q_c.lock().unwrap();
                            jitter_buf.fill_output(&mut q, data, channels);
                            drop(q);
                            if let Some(ref aq) = acu_q {
                                overlay_secondary_mono(data, aq, channels);
                            }
                            if let Some(ref dq) = dispatch_q {
                                overlay_secondary_mono(data, dq, channels);
                            }
                        },
                        err_fn,
                        None
                    )
                }
                cpal::SampleFormat::I16 => {
                    let q_c = Arc::clone(&queue_clone);
                    let acu_q = acu_queue_for_thread.clone();
                    let dispatch_q = dispatch_queue_for_thread.clone();
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
                            if let Some(ref aq) = acu_q {
                                overlay_secondary_mono(&mut float_buf, aq, channels);
                            }
                            if let Some(ref dq) = dispatch_q {
                                overlay_secondary_mono(&mut float_buf, dq, channels);
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
                    let acu_q = acu_queue_for_thread.clone();
                    let dispatch_q = dispatch_queue_for_thread.clone();
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
                            if let Some(ref aq) = acu_q {
                                overlay_secondary_mono(&mut float_buf, aq, channels);
                            }
                            if let Some(ref dq) = dispatch_q {
                                overlay_secondary_mono(&mut float_buf, dq, channels);
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
    // Cloned so `bridge_tap` itself remains available below (after this async block
    // moves its own copy in) to spawn the two-way bridge listener.
    let bridge_tap_rx = bridge_tap.clone();
    // Cloned so `dispatch_outs` itself remains available below to spawn the
    // per-group relay tasks after this async block moves its own copy in.
    let dispatch_outs_rx = dispatch_outs.clone();
    // Cloned so we can update this channel's ED-137 remote PTT/squelch status
    // (and broadcast it) as extensions arrive, without moving the outer `state`.
    let state_rx = Arc::clone(&state);

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

                            // The RTP header + any extension (including an ED-137 PTT/SQU
                            // block) travels in clear even under SRTP — only the payload
                            // itself is encrypted — so this is always safe to inspect.
                            if let Some(fields) = ed137::parse_rtp_ed137(&buf[..len]) {
                                let squ = fields.squ;
                                let remote_ptt = fields.ptt_type.is_keyed();
                                let (changed, tx_ws) = {
                                    let mut app_state = state_rx.lock().await;
                                    let mut changed = false;
                                    if let Some(ch) = app_state.channels.iter_mut().find(|c| c.id == channel_id) {
                                        if ch.ed137_remote_squelch != squ || ch.ed137_remote_ptt != remote_ptt {
                                            ch.ed137_remote_squelch = squ;
                                            ch.ed137_remote_ptt = remote_ptt;
                                            changed = true;
                                        }
                                    }
                                    (changed, app_state.tx.clone())
                                };
                                if changed {
                                    let msg = serde_json::json!({
                                        "type": "ed137_status",
                                        "data": { "id": channel_id, "squelch": squ, "remotePtt": remote_ptt }
                                    }).to_string();
                                    let _ = tx_ws.send(msg);
                                }
                            }

                            if srtp_enabled {
                                if let Some(header_len) = ed137::rtp_header_len(&buf[..len]) {
                                    if len >= header_len + 16 {
                                        let seq = ((buf[2] as u16) << 8) | (buf[3] as u16);
                                        let ts = ((buf[4] as u32) << 24) | ((buf[5] as u32) << 16) | ((buf[6] as u32) << 8) | (buf[7] as u32);
                                        let ssrc = ((buf[8] as u32) << 24) | ((buf[9] as u32) << 16) | ((buf[10] as u32) << 8) | (buf[11] as u32);

                                        let mut payload_bytes = buf[header_len..(len - 16)].to_vec();
                                        let mut tag_bytes = [0u8; 16];
                                        tag_bytes.copy_from_slice(&buf[(len - 16)..len]);

                                        let ctx = secure_context.lock().await;
                                        if let Some(ref keys) = ctx.keys {
                                            if crypto::decrypt_rtp_gcm(keys, seq, ts, ssrc, &mut payload_bytes, &tag_bytes).is_ok() {
                                                raw_payload = Some(payload_bytes);
                                            }
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

                                // Also mirror to the ACU Bridge leg, same half-duplex sharing.
                                if let Some(ref tap) = bridge_tap_rx {
                                    if !ptt_active.load(std::sync::atomic::Ordering::SeqCst) {
                                        tap.send_ulaw(&payload).await;
                                    }
                                }

                                // Publish the incoming (remote/RX) leg to any Dispatcher patch
                                // groups this channel belongs to, so other patched channels hear
                                // this side of the call too. Not gated by PTT: each group member
                                // publishes independent frames onto its own bus (not a shared
                                // wire), so there's no TX/RX interleaving hazard here — only the
                                // optional external mirror tap below reuses the shared-wire
                                // RecordingTap mechanism and needs the same half-duplex gating.
                                for d in &dispatch_outs_rx {
                                    if !d.is_member.load(std::sync::atomic::Ordering::Relaxed) {
                                        continue;
                                    }
                                    let _ = d.bus.send(DispatchFrame { source_channel_id: channel_id, ulaw: payload.clone() });
                                    if let Some(ref tap) = d.mirror_tap {
                                        if !ptt_active.load(std::sync::atomic::Ordering::SeqCst) {
                                            tap.send_ulaw(&payload).await;
                                        }
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

    // 3. If an ACU Bridge tap was built for this call, spawn the two-way bridge
    // listener on the SAME socket the tap uses to send (so replies from the ACU
    // peer arrive symmetrically on the port it just saw traffic from).
    let bridge_abort = if let (Some(tap), Some(aq)) = (bridge_tap.as_ref(), acu_queue.as_ref()) {
        Some(start_bridge_listener(
            channel_id,
            Arc::clone(&tap.socket),
            Arc::clone(&rtp_socket),
            primary_rtp_dest.clone(),
            Arc::clone(aq),
            sample_rate,
            Arc::clone(tap),
            Arc::clone(&state),
        ))
    } else {
        None
    };

    // 4. Spawn one relay task per Dispatcher group this channel belongs to,
    // forwarding what every OTHER member of that group says both into this
    // channel's local speaker (via dispatch_queue) and onward to this call's
    // own primary RTP peer as an independent forwarded stream.
    let dispatch_aborts: Vec<tokio::task::AbortHandle> = if let Some(ref dq) = dispatch_queue {
        dispatch_outs.iter().map(|d| {
            start_dispatch_relay(
                channel_id,
                d.bus.subscribe(),
                Arc::clone(&rtp_socket),
                primary_rtp_dest.clone(),
                Arc::clone(dq),
                sample_rate,
                Arc::clone(&d.is_member),
            )
        }).collect()
    } else {
        Vec::new()
    };

    PlaybackHandles {
        rx_abort: rx_task.abort_handle(),
        bridge_abort,
        dispatch_aborts,
    }
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

#[derive(Debug, Clone, Serialize)]
struct DispatchMatrixGroup {
    id: u32,
    name: String,
    #[serde(rename = "memberIds")]
    member_ids: Vec<u32>,
    #[serde(rename = "mirrorEnabled")]
    mirror_enabled: bool,
    #[serde(rename = "mirrorIp")]
    mirror_ip: String,
    #[serde(rename = "mirrorPort")]
    mirror_port: u16,
    #[serde(rename = "mirrorLocalPort")]
    mirror_local_port: Option<u16>,
}

/// GET: current Dispatcher matrix state (all 4 groups' membership + mirror
/// settings), for any UI (console app or /config page JS) that needs to fetch
/// it without a full page reload.
async fn get_dispatch_matrix_handler(
    State(state): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let lock = state.lock().await;
    let groups: Vec<DispatchMatrixGroup> = lock.dispatch_groups.iter().map(|g| DispatchMatrixGroup {
        id: g.id,
        name: g.name.clone(),
        member_ids: g.member_ids.clone(),
        mirror_enabled: g.mirror_enabled,
        mirror_ip: g.mirror_ip.clone(),
        mirror_port: g.mirror_port,
        mirror_local_port: g.mirror_local_port,
    }).collect();
    (StatusCode::OK, Json(serde_json::json!({ "groups": groups })))
}

#[derive(Debug, Deserialize)]
struct DispatchToggleRequest {
    #[serde(rename = "groupId")]
    group_id: u32,
    #[serde(rename = "channelId")]
    channel_id: u32,
}

/// POST: instantly patch/unpatch a channel into/out of a Dispatcher group —
/// no "Apply Configuration"/reload needed, built for quick action in an
/// emergency. Updates the persisted `member_ids` roster AND, if the channel
/// is currently on a live call, flips its live `is_member` flag directly so
/// the change is audible on the very next audio frame (see `DispatchOut` /
/// `start_dispatch_relay`). Broadcasts a `dispatch_matrix_update` WebSocket
/// message so every open console/admin view stays in sync.
async fn dispatch_toggle_handler(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(payload): Json<DispatchToggleRequest>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;

    if payload.group_id < 1 || payload.group_id > DISPATCH_GROUP_COUNT {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid group id" }))).into_response();
    }
    if payload.channel_id < 1 || payload.channel_id > 12 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid channel id" }))).into_response();
    }

    let now_member = {
        let group = match lock.dispatch_groups.iter_mut().find(|g| g.id == payload.group_id) {
            Some(g) => g,
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Group not found" }))).into_response(),
        };
        if let Some(pos) = group.member_ids.iter().position(|&c| c == payload.channel_id) {
            group.member_ids.remove(pos);
            false
        } else {
            group.member_ids.push(payload.channel_id);
            true
        }
    };

    // If this channel is currently connected, flip its live flag immediately
    // — this is what makes the toggle take effect on a call already in
    // progress, with no reconnect. If it's not currently connected there's no
    // flag to flip yet; the roster change above is what `dispatch_outs_for`
    // will read the next time it connects.
    if let Some(flag) = lock.dispatch_membership_flags.get(&(payload.channel_id, payload.group_id)) {
        flag.store(now_member, std::sync::atomic::Ordering::Relaxed);
    }

    // Recompute this channel's dispatch_connected indicator from its current
    // live flags across all 4 groups (only meaningful if it's connected).
    let any_member_now = (1..=DISPATCH_GROUP_COUNT).any(|gid| {
        lock.dispatch_membership_flags.get(&(payload.channel_id, gid))
            .map(|f| f.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false)
    });
    if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == payload.channel_id) {
        ch.dispatch_connected = any_member_now;
    }

    save_state_to_file(&lock);

    let groups: Vec<DispatchMatrixGroup> = lock.dispatch_groups.iter().map(|g| DispatchMatrixGroup {
        id: g.id,
        name: g.name.clone(),
        member_ids: g.member_ids.clone(),
        mirror_enabled: g.mirror_enabled,
        mirror_ip: g.mirror_ip.clone(),
        mirror_port: g.mirror_port,
        mirror_local_port: g.mirror_local_port,
    }).collect();

    let _ = lock.tx.send(serde_json::json!({
        "type": "dispatch_matrix_update",
        "data": { "groups": groups.clone() }
    }).to_string());

    if let Some(ch) = lock.channels.iter().find(|c| c.id == payload.channel_id) {
        let _ = lock.tx.send(serde_json::json!({
            "type": "channel_update",
            "data": ch
        }).to_string());
    }

    println!("[Dispatcher] Channel {} {} Group {}", payload.channel_id, if now_member { "patched into" } else { "unpatched from" }, payload.group_id);

    (StatusCode::OK, Json(serde_json::json!({ "success": true, "isMember": now_member, "groups": groups }))).into_response()
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
        let rec_tap = build_recording_tap(amp_en, &amp_ip, amp_port, id, None).await;
        if rec_tap.is_some() {
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.amp_streaming = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }

        // Build the ACU Bridge tap (two-way interop leg), same held-lock pattern as A-MP above.
        let (bridge_en, bridge_ip, bridge_port, bridge_local_port) = {
            let ch_ref = lock.channels.iter().find(|c| c.id == id);
            (lock.bridge_enabled && ch_ref.map(|c| c.bridge_enabled).unwrap_or(false),
             ch_ref.map(|c| c.bridge_ip.clone()).unwrap_or_else(|| "127.0.0.1".to_string()),
             ch_ref.map(|c| c.bridge_port).unwrap_or(0),
             ch_ref.and_then(|c| c.bridge_local_port).unwrap_or(8004 + (id as u16 - 1) * 2))
        };
        let bridge_tap = build_recording_tap(bridge_en, &bridge_ip, bridge_port, id, Some(bridge_local_port)).await;
        if let Some(ref tap) = bridge_tap {
            // Connected tone as soon as the bridge leg is built, so the far end
            // (RSP-Z2) gets real audio payload right away instead of the socket
            // just sitting open with nothing sent.
            spawn_connected_tone_tap(Arc::clone(tap));
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.bridge_connected = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }

        // Build Dispatcher patch outputs (in-process bus + optional external mirror
        // tap) for every group this channel belongs to, same held-lock pattern as
        // A-MP/Bridge above.
        let dispatch_outs = dispatch_outs_for_locked(&mut lock, id).await;
        if dispatch_outs.iter().any(|d| d.is_member.load(std::sync::atomic::Ordering::Relaxed)) {
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.dispatch_connected = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }

        // Start capture/transmit task
        let dest_rtp = format!("{}:{}", ctx.remote_ip, ctx.remote_rtp_port);
        let dest_rtp_for_bridge = dest_rtp.clone();

        // Connected tone the instant the media path opens.
        spawn_connected_tone(Arc::clone(&rtp_socket), dest_rtp.clone());

        let (stop_flag, rtp_abort) = start_microphone_rtp(
            id, Arc::clone(&rtp_socket), dest_rtp, Arc::clone(&state), selected_device, Arc::clone(&ptt_flag), ctx.call_id.clone(), rec_tap.clone(), bridge_tap.clone(), dispatch_outs.clone()
        );

        // Start playback task
        let stop_flag_playback = Arc::clone(&stop_flag);
        let playback_handles = start_audio_playback(id, Arc::clone(&rtp_socket), Arc::clone(&state), stop_flag_playback, ch_srtp, ch_ctx, ctx.call_id.clone(), rec_tap.clone(), Arc::clone(&ptt_flag), bridge_tap.clone(), dest_rtp_for_bridge, dispatch_outs);
        let rtp_rx_abort = playback_handles.rx_abort;
        let bridge_abort = playback_handles.bridge_abort;
        let dispatch_aborts = playback_handles.dispatch_aborts;

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
                                if let Some(h) = active.bridge_abort_handle {
                                    h.abort();
                                }
                                for h in active.dispatch_abort_handles {
                                    h.abort();
                                }
                                for gid in 1..=DISPATCH_GROUP_COUNT {
                                    lock_bye.dispatch_membership_flags.remove(&(id, gid));
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
                                ch_bye.bridge_connected = false; ch_bye.bridge_link_alive = false;
                                ch_bye.dispatch_connected = false;
                            }
                            let _ = tx_cb_listen.send(serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": id,
                                    "status": "IDLE",
                                    "pttActive": false,
                                    "txKbps": 0,
                                    "audioLevel": 0,
                                    "ampStreaming": false,
                                    "bridgeConnected": false,
                                    "dispatchConnected": false
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
            bridge_abort_handle: bridge_abort,
            dispatch_abort_handles: dispatch_aborts,
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
        ch.bridge_connected = false; ch.bridge_link_alive = false;
        ch.dispatch_connected = false;

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
        if let Some(h) = active.bridge_abort_handle {
            h.abort();
        }
        for h in active.dispatch_abort_handles {
            h.abort();
        }
        for gid in 1..=DISPATCH_GROUP_COUNT {
            lock.dispatch_membership_flags.remove(&(id, gid));
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

        // Connected tone the instant the session opens (before the channel even
        // flips to CONNECTED/"ROUTING"), so the peer gets real RTP/audio payload
        // right away instead of the link staying silent.
        spawn_connected_tone(Arc::clone(&rtp_socket), dest_addr.clone());

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
        let rec_tap = build_recording_tap(amp_en, &amp_ip, amp_port, id, None).await;
        if rec_tap.is_some() {
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.amp_streaming = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }

        // ACU Bridge tap — same held-lock pattern as A-MP above.
        let (bridge_en, bridge_ip, bridge_port, bridge_local_port) = {
            let ch_ref = lock.channels.iter().find(|c| c.id == id);
            (lock.bridge_enabled && ch_ref.map(|c| c.bridge_enabled).unwrap_or(false),
             ch_ref.map(|c| c.bridge_ip.clone()).unwrap_or_else(|| "127.0.0.1".to_string()),
             ch_ref.map(|c| c.bridge_port).unwrap_or(0),
             ch_ref.and_then(|c| c.bridge_local_port).unwrap_or(8004 + (id as u16 - 1) * 2))
        };
        let bridge_tap = build_recording_tap(bridge_en, &bridge_ip, bridge_port, id, Some(bridge_local_port)).await;
        if let Some(ref tap) = bridge_tap {
            // Connected tone as soon as the bridge leg is built.
            spawn_connected_tone_tap(Arc::clone(tap));
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.bridge_connected = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }

        // Dispatcher patch outputs — same held-lock pattern as A-MP/Bridge above.
        let dispatch_outs = dispatch_outs_for_locked(&mut lock, id).await;
        if dispatch_outs.iter().any(|d| d.is_member.load(std::sync::atomic::Ordering::Relaxed)) {
            let upd = {
                if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == id) {
                    ch.dispatch_connected = true;
                    Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                } else { None }
            };
            if let Some(upd) = upd { let _ = lock.tx.send(upd); }
        }

        let rtp_dest_for_bridge = rtp_dest.clone();
        let (audio_flag, rtp_task) = start_microphone_rtp(
            id, Arc::clone(&rtp_sock_task), rtp_dest, Arc::clone(&state_audio), selected_device, ptt_active_flag, call_id.clone(), rec_tap.clone(), bridge_tap.clone(), dispatch_outs.clone()
        );

        let audio_flag_playback = Arc::clone(&audio_flag);
        let playback_handles = start_audio_playback(
            id, Arc::clone(&rtp_sock_task), Arc::clone(&state_audio), audio_flag_playback, ch_srtp, ch_ctx, call_id.clone(), rec_tap.clone(), Arc::clone(&ptt_active_flag_clone), bridge_tap.clone(), rtp_dest_for_bridge, dispatch_outs
        );
        let rtp_rx_task = playback_handles.rx_abort;
        let bridge_abort = playback_handles.bridge_abort;
        let dispatch_aborts = playback_handles.dispatch_aborts;

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
            bridge_abort_handle: bridge_abort,
            dispatch_abort_handles: dispatch_aborts,
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
            bridge_abort_handle: None,
            dispatch_abort_handles: Vec::new(),
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
                                ch_fail.bridge_connected = false; ch_fail.bridge_link_alive = false;
                                ch_fail.dispatch_connected = false;
                            }
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": id,
                                    "status": "FAILED",
                                    "pttActive": false,
                                    "txKbps": 0,
                                    "ampStreaming": false,
                                    "bridgeConnected": false,
                                    "dispatchConnected": false
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

                            // Connected tone the instant the media path opens.
                            spawn_connected_tone(Arc::clone(&rtp_sock_task), rtp_dest.clone());

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
                             let rec_tap = build_recording_tap(amp_en, &amp_ip, amp_port, id, None).await;
                             let (bridge_en, bridge_ip, bridge_port, bridge_local_port) = bridge_settings_for(&state_audio, id).await;
                             let bridge_tap = build_recording_tap(bridge_en, &bridge_ip, bridge_port, id, Some(bridge_local_port)).await;
                             let dispatch_outs = dispatch_outs_for(&state_audio, id).await;
                             let has_dispatch_membership = dispatch_outs.iter().any(|d| d.is_member.load(std::sync::atomic::Ordering::Relaxed));
                             let rtp_dest_for_bridge = rtp_dest.clone();
                             let (audio_flag, rtp_task) = start_microphone_rtp(
                                 id, Arc::clone(&rtp_sock_task), rtp_dest, Arc::clone(&state_audio), selected_device.clone(), ptt_active_flag, call_id.clone(), rec_tap.clone(), bridge_tap.clone(), dispatch_outs.clone()
                             );

                             let audio_flag_playback = Arc::clone(&audio_flag);
                             let playback_handles = start_audio_playback(
                                 id, Arc::clone(&rtp_sock_task), Arc::clone(&state_audio), audio_flag_playback, ch_srtp, ch_ctx, call_id.clone(), rec_tap.clone(), Arc::clone(&ptt_active_flag_clone), bridge_tap.clone(), rtp_dest_for_bridge, dispatch_outs
                             );
                             let rtp_rx_task = playback_handles.rx_abort;
                             let bridge_abort = playback_handles.bridge_abort;
                             let dispatch_aborts = playback_handles.dispatch_aborts;

                            let mut lock_rtp = state_clone.lock().await;
                            if let Some(ac) = lock_rtp.active_calls.iter_mut().find(|c| c.channel_id == id) {
                                ac.audio_stop_flag = Some(audio_flag);
                                ac.ptt_active = Some(ptt_active_flag_clone);
                                ac.rtp_abort_handle = Some(rtp_task);
                                ac.rtp_rx_abort_handle = Some(rtp_rx_task);
                                ac.bridge_abort_handle = bridge_abort;
                                ac.dispatch_abort_handles = dispatch_aborts;
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
                            if let Some(ref tap) = bridge_tap {
                                // Connected tone as soon as the bridge leg is built.
                                spawn_connected_tone_tap(Arc::clone(tap));
                                let upd = {
                                    if let Some(ch) = lock_rtp.channels.iter_mut().find(|c| c.id == id) {
                                        ch.bridge_connected = true;
                                        Some(serde_json::json!({ "type": "channel_update", "data": ch }).to_string())
                                    } else { None }
                                };
                                if let Some(upd) = upd {
                                    let _ = lock_rtp.tx.send(upd);
                                }
                            }
                            if has_dispatch_membership {
                                let upd = {
                                    if let Some(ch) = lock_rtp.channels.iter_mut().find(|c| c.id == id) {
                                        ch.dispatch_connected = true;
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
                                if let Some(h) = active.bridge_abort_handle {
                                    h.abort();
                                }
                                for h in active.dispatch_abort_handles {
                                    h.abort();
                                }
                                for gid in 1..=DISPATCH_GROUP_COUNT {
                                    lock_bye.dispatch_membership_flags.remove(&(id, gid));
                                }
                            }
                            if let Some(ch_bye) = lock_bye.channels.iter_mut().find(|c| c.id == id) {
                                ch_bye.status = "IDLE".to_string();
                                ch_bye.ptt_active = false;
                                ch_bye.tx_kbps = 0;
                                ch_bye.amp_streaming = false;
                                ch_bye.bridge_connected = false; ch_bye.bridge_link_alive = false;
                                ch_bye.dispatch_connected = false;
                            }
                            let _ = tx_cb.send(serde_json::json!({
                                "type": "channel_update",
                                "data": {
                                    "id": id,
                                    "status": "IDLE",
                                    "pttActive": false,
                                    "txKbps": 0,
                                    "ampStreaming": false,
                                    "bridgeConnected": false,
                                    "dispatchConnected": false
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
        if let Some(h) = active.bridge_abort_handle {
            h.abort();
        }
        for h in active.dispatch_abort_handles.clone() {
            h.abort();
        }
        for gid in 1..=DISPATCH_GROUP_COUNT {
            lock.dispatch_membership_flags.remove(&(id, gid));
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
        ch.bridge_connected = false; ch.bridge_link_alive = false;
        ch.dispatch_connected = false;

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
                "ampStreaming": false,
                "bridgeConnected": false,
                "dispatchConnected": false
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
            bridge_ip: if ch_cfg.bridge_ip.is_empty() { "127.0.0.1".to_string() } else { ch_cfg.bridge_ip.clone() },
            bridge_port: if ch_cfg.bridge_port == 0 { 6004 + (ch_cfg.id as u16 - 1) * 2 } else { ch_cfg.bridge_port },
            bridge_enabled: ch_cfg.bridge_enabled,
            bridge_local_port: ch_cfg.bridge_local_port,
            ed137_enabled: ch_cfg.ed137_enabled,
            ed137_ptt_id: ch_cfg.ed137_ptt_id,
            ed137_remote_squelch: false,
            ed137_remote_ptt: false,
            bridge_connected: false,
            bridge_link_alive: false,
            dispatch_connected: false,
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
        bridge_enabled: config.bridge_enabled,
        dispatch_groups: config.dispatch_groups,
        dispatch_buses: HashMap::new(),
        dispatch_mirror_taps: HashMap::new(),
        dispatch_mirror_listeners: HashMap::new(),
        dispatch_membership_flags: HashMap::new(),
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
                                                        ch.bridge_connected = false; ch.bridge_link_alive = false;
                                                        ch.dispatch_connected = false;
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
                                                    if let Some(h) = active.bridge_abort_handle {
                                                        h.abort();
                                                    }
                                                    for h in active.dispatch_abort_handles {
                                                        h.abort();
                                                    }
                                                    for gid in 1..=DISPATCH_GROUP_COUNT {
                                                        lock.dispatch_membership_flags.remove(&(active.channel_id, gid));
                                                    }
                                                    if let Some(ch) = lock.channels.iter_mut().find(|c| c.id == active.channel_id) {
                                                        ch.status = "IDLE".to_string();
                                                        ch.ptt_active = false;
                                                        ch.tx_kbps = 0;
                                                        ch.audio_level = 0;
                                                        ch.amp_streaming = false;
                                                        ch.bridge_connected = false; ch.bridge_link_alive = false;
                                                        ch.dispatch_connected = false;
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
                                                        "ampStreaming": false,
                                                        "bridgeConnected": false,
                                                        "dispatchConnected": false
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
                    .route("/api/dispatch/matrix", get(get_dispatch_matrix_handler))
                    .route("/api/dispatch/toggle", post(dispatch_toggle_handler))
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
        let ed137_checked = if ch.ed137_enabled { "checked" } else { "" };
        let ed137_ptt_id_val = ch.ed137_ptt_id.to_string();

        channels_rows.push_str(&format!(
            r#"
            <tr>
                <td class="col-c"><span class="slot">{:02}</span></td>
                <td>
                    <select name="protocol_{}" {}>
                        <option value="SIP" {}>SIP</option>
                        <option value="RTP" {}>RTP</option>
                    </select>
                </td>
                <td>
                    <span class="status-badge {}">{}</span>
                </td>
                <td>
                    <input type="text" name="label_{}" value="{}" {} maxlength="7" required />
                </td>
                <td class="col-c">
                    <input type="checkbox" class="chk" name="srtp_enabled_{}" {} {} />
                </td>
                <td class="col-c">
                    <input type="checkbox" class="chk" name="sip_auth_required_{}" {} {} />
                </td>
                <td class="col-c">
                    <input type="checkbox" class="chk" name="ed137_enabled_{}" {} {} title="Tag outgoing RTP with the ED-137A/B/C PTT/SQU header extension for interop with a real radio/VCS" />
                </td>
                <td>
                    <input type="number" name="ed137_ptt_id_{}" value="{}" {} min="0" max="63" style="width:5em;" />
                </td>
                <td>
                    <input type="text" name="sip_user_{}" value="{}" {} placeholder="receiver" />
                </td>
                <td>
                    <input type="text" name="target_ip_{}" value="{}" {} placeholder="192.168.1.1" required />
                </td>
                <td>
                    <input type="number" name="target_port_{}" value="{}" {} min="1" max="65535" required />
                </td>
                <td>
                    <input type="number" name="local_port_{}" value="{}" {} placeholder="Auto" min="1024" max="65535" />
                </td>
                <td>
                    <select name="codec_{}" {}>
                        <option value="Opus" {}>Opus</option>
                        <option value="G.722" {}>G.722</option>
                        <option value="G.711µ" {}>G.711µ</option>
                    </select>
                </td>
                <td>
                    <div class="tel">
                        <div class="m"><span class="k">DUR</span><span class="v">{}s</span></div>
                        <div class="m"><span class="k">RX</span><span class="v">{}k</span></div>
                        <div class="m"><span class="k">TX</span><span class="v">{}k</span></div>
                        <div class="m"><span class="k">PL</span><span class="v">{:.1}%</span></div>
                        <div class="m"><span class="k">JIT</span><span class="v">{}ms</span></div>
                        <div class="m"><span class="k">LAT</span><span class="v">{}ms</span></div>
                    </div>
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
            ed137_checked,
            disabled_attr,
            ch.id,
            ed137_ptt_id_val,
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

    // Build per-channel destination rows for streaming mirror.
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
                <td class="col-c"><span class="slot">{:02}</span></td>
                <td style="color:var(--muted);">{}</td>
                <td class="col-c">
                    <input type="checkbox" class="chk" name="amp_channel_enabled_{}" {} {} />
                </td>
                <td>
                    <input type="text" name="amp_ip_{}" value="{}" {} placeholder="127.0.0.1" />
                </td>
                <td>
                    <input type="number" name="amp_port_{}" value="{}" {} min="0" max="65535" />
                </td>
                <td class="col-c">
                    <span class="{}"></span><span class="amp-txt">{}</span>
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

    let mut bridge_rows = String::new();
    for ch in &lock.channels {
        let (dot_class, stream_text) = if ch.bridge_connected {
            ("amp-dot amp-dot-live", "CONNECTED")
        } else {
            ("amp-dot", "IDLE")
        };
        let is_routing_or_dialing = ch.status == "CONNECTED" || ch.status == "RINGING" || ch.status == "INCOMING";
        let disabled_attr = if is_routing_or_dialing { "disabled" } else { "" };
        let bridge_enabled_checked = if ch.bridge_enabled { "checked" } else { "" };
        let bridge_local_port_val = match ch.bridge_local_port {
            Some(p) => p.to_string(),
            None => "".to_string(),
        };

        bridge_rows.push_str(&format!(
            r#"
            <tr>
                <td class="col-c"><span class="slot">{:02}</span></td>
                <td style="color:var(--muted);">{}</td>
                <td class="col-c">
                    <input type="checkbox" class="chk" name="bridge_channel_enabled_{}" {} {} />
                </td>
                <td>
                    <input type="text" name="bridge_ip_{}" value="{}" placeholder="127.0.0.1" />
                </td>
                <td>
                    <input type="number" name="bridge_port_{}" value="{}" min="0" max="65535" />
                </td>
                <td>
                    <input type="number" name="bridge_local_port_{}" value="{}" {} placeholder="Auto" min="1024" max="65535" />
                </td>
                <td class="col-c">
                    <span class="{}"></span><span class="amp-txt">{}</span>
                </td>
            </tr>
            "#,
            ch.id,
            html_escape(&ch.label),
            ch.id,
            bridge_enabled_checked,
            disabled_attr,
            ch.id,
            html_escape(&ch.bridge_ip),
            ch.id,
            ch.bridge_port,
            ch.id,
            bridge_local_port_val,
            disabled_attr,
            dot_class,
            stream_text,
        ));
    }
    let bridge_enabled_checked = if lock.bridge_enabled { "checked" } else { "" };

    // Build the 12-channel x 4-group patch matrix. Cells are clickable divs
    // (NOT form inputs) that POST to /api/dispatch/toggle via fetch() and
    // update instantly — no "Apply Configuration"/reload, by design, for
    // quick action in an emergency. Group names are read fresh here so the
    // column headers stay in sync with the settings table below.
    let group_names: Vec<String> = (1..=DISPATCH_GROUP_COUNT)
        .map(|gid| lock.dispatch_groups.iter().find(|g| g.id == gid).map(|g| g.name.clone()).unwrap_or_else(|| format!("Patch {}", gid)))
        .collect();

    let mut matrix_header_cells = String::new();
    for (i, gid) in (1..=DISPATCH_GROUP_COUNT).enumerate() {
        matrix_header_cells.push_str(&format!(r#"<th>{}</th>"#, html_escape(&group_names[i])));
        let _ = gid; // header text is all we need here
    }

    let mut matrix_rows = String::new();
    for ch in &lock.channels {
        let mut cells = String::new();
        for gid in 1..=DISPATCH_GROUP_COUNT {
            let is_member = lock.dispatch_groups.iter().find(|g| g.id == gid).map(|g| g.member_ids.contains(&ch.id)).unwrap_or(false);
            let on_class = if is_member { " matrix-on" } else { "" };
            cells.push_str(&format!(
                r#"<td class="matrix-cell-td"><div class="matrix-cell{}" data-channel="{}" data-group="{}" onclick="toggleDispatchCell(this)" title="CH{:02} &lt;-&gt; {}"></div></td>"#,
                on_class, ch.id, gid, ch.id, html_escape(&group_names[(gid - 1) as usize]),
            ));
        }
        matrix_rows.push_str(&format!(
            r#"<tr><td class="matrix-label-col">{:02}</td>{}</tr>"#,
            ch.id, cells,
        ));
    }

    let dispatch_matrix_html = format!(
        r#"
        <div class="card card-flat">
          <div class="card-head">
            <div class="card-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M20 4L8.12 15.88"/><path d="M14.47 14.48L20 20"/><path d="M8.12 8.12L12 12"/></svg></div>
            <div><div class="card-title">Patch Matrix</div><div class="card-desc">Click a cell to instantly patch/unpatch a channel into a group &mdash; takes effect immediately, even on calls already in progress. No Apply/reload needed.</div></div>
          </div>
          <div class="card-body">
            <div class="table-scroll">
              <table class="matrix-grid">
                <thead>
                  <tr><th class="matrix-label-col">CH</th>{}</tr>
                </thead>
                <tbody>
                  {}
                </tbody>
              </table>
            </div>
            <div class="note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg><span>Only channels that are already on a live call actually hear/talk to the rest of a patch. A green cell means that channel is currently patched into that group.</span></div>
          </div>
        </div>
        "#,
        matrix_header_cells,
        matrix_rows,
    );

    // Per-group settings (name + optional external mirror) — these are more
    // "static config" than the matrix above, so they stay in the normal
    // form + Apply Configuration flow.
    let mut dispatch_settings_rows = String::new();
    for gid in 1..=DISPATCH_GROUP_COUNT {
        let group = lock.dispatch_groups.iter().find(|g| g.id == gid);
        let group_name = group.map(|g| g.name.clone()).unwrap_or_else(|| format!("Patch {}", gid));
        let mirror_enabled_checked = if group.map(|g| g.mirror_enabled).unwrap_or(false) { "checked" } else { "" };
        let mirror_ip_val = group.map(|g| g.mirror_ip.clone()).unwrap_or_else(|| "127.0.0.1".to_string());
        let mirror_port_val = group.map(|g| g.mirror_port).unwrap_or(0);
        let mirror_local_port_val = match group.and_then(|g| g.mirror_local_port) {
            Some(p) => p.to_string(),
            None => "".to_string(),
        };

        dispatch_settings_rows.push_str(&format!(
            r#"
            <tr>
                <td class="col-c"><span class="slot">P{}</span></td>
                <td><input type="text" name="dispatch_name_{}" value="{}" maxlength="24" /></td>
                <td class="col-c"><input type="checkbox" class="chk" name="dispatch_mirror_enabled_{}" {} /></td>
                <td><input type="text" name="dispatch_mirror_ip_{}" value="{}" placeholder="127.0.0.1" /></td>
                <td><input type="number" name="dispatch_mirror_port_{}" value="{}" min="0" max="65535" /></td>
                <td><input type="number" name="dispatch_mirror_local_port_{}" value="{}" placeholder="Auto" min="1024" max="65535" /></td>
            </tr>
            "#,
            gid,
            gid, html_escape(&group_name),
            gid, mirror_enabled_checked,
            gid, html_escape(&mirror_ip_val),
            gid, mirror_port_val,
            gid, mirror_local_port_val,
        ));
    }

    let dispatch_settings_html = format!(
        r#"
        <div class="card">
          <div class="card-head">
            <div class="card-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 1l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 23l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg></div>
            <div><div class="card-title">Patch Group Settings</div><div class="card-desc">Rename groups and configure each group's optional external mirror (e.g. a two-way headset resource) &mdash; same idea as AMP Bridge, shared across the whole group</div></div>
          </div>
          <div class="card-body">
            <div class="table-scroll">
              <table class="grid">
                <thead>
                  <tr>
                    <th class="col-c">Group</th>
                    <th>Name</th>
                    <th class="col-c">Mirror Enable</th>
                    <th>Mirror Destination IP</th>
                    <th>Mirror UDP Port</th>
                    <th>Local Port (tell the external party to send here)</th>
                  </tr>
                </thead>
                <tbody>
                  {}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        "#,
        dispatch_settings_rows,
    );

    // Rendered as an inert bootstrap <script> (not a visible banner) so a
    // direct/bookmarked load of /config?saved=true or /config?error=... still
    // surfaces the message as a toast instead of a full-width alert block.
    // The normal Apply Configuration flow no longer navigates here at all —
    // it saves via fetch() and calls showToast() directly.
    let message_banner = if let Some(err) = params.get("error") {
        format!(
            r#"<script>window.__initialToast = {{ message: {}, type: "error" }};</script>"#,
            serde_json::to_string(err).unwrap_or_else(|_| "\"Configuration error\"".to_string())
        )
    } else if saved {
        r#"<script>window.__initialToast = { message: "Configuration saved successfully and synced to console panel.", type: "success" };</script>"#.to_string()
    } else {
        "".to_string()
    };

    let html_content = format!(
        r##"

        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Gateway Configuration</title>
            <style>
                :root{{
                    --primary:#2563eb; --primary-hover:#1d4fd7; --primary-soft:#eff4ff;
                    --page:#eef1f5; --card:#ffffff; --ink:#0f172a; --muted:#5b6472; --faint:#8a94a3;
                    --line:#e4e8ee; --line-soft:#eef1f5; --track:#f5f7fa;
                    --ok:#0f7a4d; --ok-bg:#e9f7ef; --ok-line:#b7e2c8;
                    --warn:#b25e09; --warn-bg:#fdf3e6; --warn-line:#f4d9ac;
                    --err:#c02626; --err-bg:#fdecec; --err-line:#f5c4c4;
                    --mono:"SF Mono",ui-monospace,"Cascadia Mono",Menlo,Consolas,monospace;
                }}
                *{{ box-sizing:border-box; }}
                body{{ margin:0; background:var(--page); color:var(--ink);
                    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
                    font-size:14px; line-height:1.5; -webkit-font-smoothing:antialiased; }}
                a{{ color:inherit; }}
                .topbar{{ position:sticky; top:0; z-index:20; background:var(--card);
                    border-bottom:1px solid var(--line); box-shadow:0 1px 2px rgba(15,23,42,.03); }}
                .topbar-inner{{ max-width:100%; margin:0 auto; padding:14px 28px; display:flex; align-items:center; gap:16px; }}
                .brand{{ display:flex; align-items:center; gap:12px; }}
                .brand-mark{{ width:38px; height:38px; border-radius:0; background:var(--ink); color:#fff;
                    display:flex; align-items:center; justify-content:center; font-weight:700; font-size:13px; letter-spacing:.02em; }}
                .brand-mark span{{ color:#7ab0ff; }}
                .brand-name{{ font-size:15px; font-weight:700; letter-spacing:-.01em; line-height:1.1; }}
                .brand-sub{{ font-size:11.5px; color:var(--faint); font-weight:500; letter-spacing:.02em; }}
                .topbar-spacer{{ flex:1; }}
                .pill{{ display:inline-flex; align-items:center; gap:7px; font-size:12px; font-weight:600;
                    padding:6px 12px; border-radius:0; background:var(--ok-bg); color:var(--ok); border:1px solid var(--ok-line); }}
                .pill .dot{{ width:7px; height:7px; border-radius:0; background:var(--ok); box-shadow:0 0 0 3px rgba(15,122,77,.15); }}
                .btn-ghost{{ display:inline-flex; align-items:center; gap:7px; font-size:13px; font-weight:600; color:var(--muted);
                    background:transparent; border:1px solid var(--line); border-radius:0; padding:8px 14px; cursor:pointer; text-decoration:none; transition:.15s; }}
                .btn-ghost:hover{{ color:var(--ink); border-color:#cfd6e0; background:var(--track); }}
                .wrap{{ max-width:100%; margin:0 auto; padding:28px 28px 100px; }}
                .tabs{{ display:flex; gap:4px; background:var(--card); border:1px solid var(--line); border-radius:0; padding:5px; margin-bottom:24px; width:fit-content; }}
                .tab-btn{{ background:transparent; border:none; padding:9px 20px; font-family:inherit; font-size:13.5px; font-weight:600;
                    color:var(--muted); cursor:pointer; border-radius:0; transition:.15s; }}
                .tab-btn:hover{{ color:var(--ink); }}
                .tab-btn.active{{ color:var(--primary); background:var(--primary-soft); }}
                .tab-panel{{ display:none; }}
                .tab-panel.active{{ display:block; }}
                .card{{ background:var(--card); border:1px solid var(--line); border-radius:0; margin-bottom:20px; overflow:hidden; }}
                .card.card-flat{{ border-radius:0; }}
                .card.card-flat .card-body{{ padding:14px; }}
                .card-head{{ display:flex; align-items:center; gap:12px; padding:18px 22px; border-bottom:1px solid var(--line-soft); }}
                .card-ico{{ width:34px; height:34px; border-radius:0; background:var(--primary-soft); color:var(--primary);
                    display:flex; align-items:center; justify-content:center; flex:0 0 auto; }}
                .card-ico svg{{ width:18px; height:18px; }}
                .card-title{{ font-size:14.5px; font-weight:700; letter-spacing:-.01em; }}
                .card-desc{{ font-size:12px; color:var(--faint); font-weight:500; margin-top:1px; }}
                .card-body{{ padding:22px; }}
                .grid2{{ display:grid; grid-template-columns:1fr 1fr; gap:22px; }}
                .grid3{{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:22px; }}
                .field{{ display:flex; flex-direction:column; gap:7px; }}
                .field label{{ font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }}
                input,select{{ width:100%; height:38px; background:#fff; border:1px solid var(--line); color:var(--ink);
                    padding:0 12px; font-family:inherit; font-size:13.5px; border-radius:0; transition:.15s; }}
                input::placeholder{{ color:var(--faint); }}
                input:focus,select:focus{{ outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(37,99,235,.14); }}
                input:disabled,select:disabled{{ background:var(--track); color:var(--faint); cursor:not-allowed; }}
                .table-scroll{{ width:100%; overflow-x:auto; }}
                table.grid{{ width:100%; border-collapse:separate; border-spacing:0; min-width:1060px; }}
                table.grid th{{ background:var(--track); color:var(--muted); font-size:10.5px; font-weight:700;
                    text-transform:uppercase; letter-spacing:.05em; text-align:left; padding:11px 14px; border-bottom:1px solid var(--line); white-space:nowrap; }}
                table.grid td{{ padding:9px 14px; border-bottom:1px solid var(--line-soft); vertical-align:middle; }}
                table.grid tr:last-child td{{ border-bottom:none; }}
                table.grid tbody tr:hover td{{ background:#fafbfd; }}
                table.grid input,table.grid select{{ height:34px; font-size:13px; }}
                .col-c{{ text-align:center; }}
                .slot{{ font-family:var(--mono); font-weight:700; font-size:12.5px; color:var(--ink);
                    background:var(--track); border:1px solid var(--line); border-radius:0; padding:3px 8px; display:inline-block; }}
                .status-badge{{ display:inline-block; min-width:76px; text-align:center; font-size:10.5px; font-weight:700; letter-spacing:.04em;
                    padding:5px 8px; border-radius:0; border:1px solid var(--line); }}
                .status-idle{{ color:var(--muted); background:var(--track); border-color:var(--line); }}
                .status-connected{{ color:var(--ok); background:var(--ok-bg); border-color:var(--ok-line); }}
                .status-ringing{{ color:var(--warn); background:var(--warn-bg); border-color:var(--warn-line); }}
                .status-failed{{ color:var(--err); background:var(--err-bg); border-color:var(--err-line); }}
                .chk{{ width:18px; height:18px; accent-color:var(--primary); cursor:pointer; }}
                .tel{{ display:grid; grid-template-columns:repeat(3,minmax(44px,1fr)); gap:3px 10px; min-width:150px; }}
                .tel .m{{ display:flex; align-items:baseline; gap:5px; white-space:nowrap; }}
                .tel .k{{ font-size:9.5px; font-weight:700; color:var(--faint); letter-spacing:.04em; width:22px; }}
                .tel .v{{ font-family:var(--mono); font-size:11.5px; font-weight:600; color:var(--muted); }}
                .switch-row{{ display:flex; align-items:center; gap:14px; padding:16px 18px; background:var(--primary-soft);
                    border:1px solid #d3e0fb; border-radius:0; margin-bottom:16px; }}
                .switch{{ position:relative; display:inline-block; width:44px; height:24px; flex:0 0 auto; }}
                .switch input{{ opacity:0; width:0; height:0; }}
                .slider{{ position:absolute; inset:0; background:#c3cbd8; border-radius:0; transition:.18s; cursor:pointer; }}
                .slider:before{{ content:""; position:absolute; height:18px; width:18px; left:3px; top:3px; background:#fff; border-radius:0; transition:.18s; box-shadow:0 1px 2px rgba(0,0,0,.2); }}
                .switch input:checked + .slider{{ background:var(--primary); }}
                .switch input:checked + .slider:before{{ transform:translateX(20px); }}
                .switch-row .txt b{{ font-size:13.5px; font-weight:700; }}
                .switch-row .txt p{{ margin:2px 0 0; font-size:12px; color:var(--muted); }}
                .amp-dot{{ display:inline-block; width:8px; height:8px; border-radius:0; background:#cbd3de; margin-right:7px; vertical-align:middle; }}
                .amp-dot-live{{ background:var(--err); box-shadow:0 0 0 0 rgba(192,38,38,.4); animation:amp-pulse 1.4s infinite; }}
                .amp-txt{{ font-size:11px; font-weight:700; color:var(--muted); letter-spacing:.03em; }}
                @keyframes amp-pulse{{ 0%{{ box-shadow:0 0 0 0 rgba(192,38,38,.4);}} 70%{{ box-shadow:0 0 0 6px rgba(192,38,38,0);}} 100%{{ box-shadow:0 0 0 0 rgba(192,38,38,0);}} }}
                .note{{ display:flex; align-items:flex-start; gap:7px; font-size:12px; color:var(--faint); line-height:1.5; padding:14px 22px 18px; }}
                .note svg{{ width:15px; height:15px; flex:0 0 auto; margin-top:1px; color:var(--faint); }}
                .matrix-grid{{ width:auto; border-collapse:collapse; border-spacing:0; min-width:0; }}
                .matrix-grid th{{ background:var(--track); color:var(--muted); font-size:10px; font-weight:700;
                    text-transform:uppercase; letter-spacing:.04em; text-align:center; padding:5px 8px; border:1px solid var(--line); white-space:nowrap; }}
                .matrix-label-col{{ text-align:center !important; white-space:nowrap; font-size:11.5px; font-weight:700; color:var(--ink);
                    padding:0 !important; width:30px; background:var(--track); border:1px solid var(--line); }}
                .matrix-cell-td{{ text-align:center; padding:0 !important; border:1px solid var(--line); }}
                .matrix-cell{{ width:28px; height:28px; display:block; margin:0; border-radius:0; background:var(--track); border:none; cursor:pointer; transition:.1s; }}
                .matrix-cell:hover{{ box-shadow:inset 0 0 0 2px var(--primary); }}
                .matrix-cell.matrix-on{{ background:var(--ok); }}
                .matrix-cell.matrix-on:hover{{ background:var(--ok); }}
                .matrix-cell.matrix-pending{{ opacity:.5; cursor:wait; }}
                .actionbar{{ position:fixed; left:50%; bottom:22px; z-index:30;
                    transform:translate(-50%, 140%); opacity:0; pointer-events:none;
                    background:var(--card); border:1px solid var(--line); box-shadow:0 8px 24px rgba(15,23,42,.16);
                    transition:transform .2s ease, opacity .2s ease; }}
                .actionbar.visible{{ transform:translate(-50%, 0); opacity:1; pointer-events:auto; }}
                .actionbar-inner{{ padding:12px 16px 12px 20px; display:flex; align-items:center; gap:16px; }}
                .action-hint{{ font-size:12px; color:var(--faint); white-space:nowrap; }}
                .btn-primary{{ background:var(--primary); color:#fff; border:none; padding:11px 26px; font-family:inherit; font-weight:700;
                    font-size:14px; border-radius:0; cursor:pointer; transition:.15s; box-shadow:0 1px 2px rgba(37,99,235,.25); white-space:nowrap; }}
                .btn-primary:hover{{ background:var(--primary-hover); }}
                .btn-primary:active{{ transform:scale(.98); }}
                .toast-container{{ position:fixed; top:20px; right:20px; z-index:50; display:flex; flex-direction:column; gap:10px; max-width:380px; }}
                .toast{{ padding:14px 18px; font-weight:600; font-size:13.5px; border-radius:0; box-shadow:0 6px 20px rgba(15,23,42,.14);
                    opacity:0; transform:translateY(-10px); transition:opacity .2s ease, transform .2s ease; }}
                .toast.show{{ opacity:1; transform:translateY(0); }}
                .toast-ok{{ color:var(--ok); background:var(--ok-bg); border:1px solid var(--ok-line); }}
                .toast-err{{ color:var(--err); background:var(--err-bg); border:1px solid var(--err-line); }}
            </style>
        </head>
        <body>
            <div id="toast-container" class="toast-container"></div>
            <div class="topbar">
                <div class="topbar-inner">
                    <div class="brand">
                        <div class="brand-mark">A<span>12</span></div>
                        <div>
                            <div class="brand-name">Aquilla 12 Gateway</div>
                            <div class="brand-sub">Secure Voice Configuration Console</div>
                        </div>
                    </div>
                    <div class="topbar-spacer"></div>
                    <div class="pill"><span class="dot"></span> System Active</div>
                    <a href="/config" class="btn-ghost"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/></svg> Refresh</a>
                </div>
            </div>

            <div class="wrap">
                {}

                <div class="tabs">
                    <button type="button" class="tab-btn active" data-tab="tab-channels" onclick="switchTab('tab-channels', this)">Channels</button>
                    <button type="button" class="tab-btn" data-tab="tab-amp" onclick="switchTab('tab-amp', this)">A-MP</button>
                    <button type="button" class="tab-btn" data-tab="tab-bridge" onclick="switchTab('tab-bridge', this)">AMP Bridge</button>
                    <button type="button" class="tab-btn" data-tab="tab-dispatch" onclick="switchTab('tab-dispatch', this)">Dispatcher</button>
                </div>

                <form id="config-form" method="POST" action="/config/save" onsubmit="handleSubmit(event)">
                  <div id="tab-channels" class="tab-panel active">
                    <div class="card">
                      <div class="card-head">
                        <div class="card-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></div>
                        <div><div class="card-title">System Interface</div><div class="card-desc">Primary signalling port and audio capture device</div></div>
                      </div>
                      <div class="card-body">
                        <div class="grid2">
                          <div class="field">
                            <label for="sip_port">Listening Port</label>
                            <input type="number" id="sip_port" name="sip_port" value="{}" min="1024" max="65535" required />
                          </div>
                          <div class="field">
                            <label for="selected_device">Active Audio Input Interface</label>
                            <select id="selected_device" name="selected_device">{}</select>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div class="card">
                      <div class="card-head">
                        <div class="card-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 3v4M8 3v4M2 11h20"/></svg></div>
                        <div><div class="card-title">Port Mapping</div><div class="card-desc">Per-channel protocol, destination and live telemetry</div></div>
                      </div>
                      <div class="table-scroll">
                        <table class="grid">
                          <thead>
                            <tr>
                              <th class="col-c">Slot</th>
                              <th>Protocol</th>
                              <th>Status</th>
                              <th>Channel Alias</th>
                              <th class="col-c">SRTP</th>
                              <th class="col-c">SIP Auth</th>
                              <th class="col-c">ED-137</th>
                              <th class="col-c">PTT ID</th>
                              <th>Receiver / User</th>
                              <th>Destination IP</th>
                              <th>Dest Port</th>
                              <th>Local Port</th>
                              <th>Codec</th>
                              <th>Stream Quality</th>
                            </tr>
                          </thead>
                          <tbody>
                            {}
                          </tbody>
                        </table>
                      </div>
                      <div class="note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg><span>Channel parameters (alias, destination, codec) cannot be modified while a channel is active (routing or dialing).</span></div>
                    </div>
                  </div>

                  <div id="tab-amp" class="tab-panel">
                    <div class="card">
                      <div class="card-head">
                        <div class="card-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="9"/></svg></div>
                        <div><div class="card-title">A-MP (Aquilla Multiduplex Protocol)</div><div class="card-desc">Duplicate active calls to a recording destination</div></div>
                      </div>
                      <div class="card-body">
                        <div class="switch-row">
                          <label class="switch"><input type="checkbox" id="amp_enabled" name="amp_enabled" {} /><span class="slider"></span></label>
                          <div class="txt"><b>Enable audio stream mirroring</b><p>Global master switch. Set a channel port to 0 to disable mirroring for that channel.</p></div>
                        </div>
                        <div class="table-scroll">
                          <table class="grid">
                            <thead>
                              <tr>
                                <th class="col-c">Slot</th>
                                <th>Channel Alias</th>
                                <th class="col-c">Enable</th>
                                <th>Recorder Destination IP</th>
                                <th>Recorder UDP Port</th>
                                <th class="col-c">Mirror State</th>
                              </tr>
                            </thead>
                            <tbody>
                              {}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div id="tab-bridge" class="tab-panel">
                    <div class="card">
                      <div class="card-head">
                        <div class="card-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 1l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 23l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg></div>
                        <div><div class="card-title">AMP Bridge</div><div class="card-desc">Two-way interop leg mixed live into the call &mdash; not just a recording tap</div></div>
                      </div>
                      <div class="card-body">
                        <div class="switch-row">
                          <label class="switch"><input type="checkbox" id="bridge_enabled" name="bridge_enabled" {} /><span class="slider"></span></label>
                          <div class="txt"><b>Enable AMP Bridge</b><p>Global master switch. The bridge leg is started/stopped with the call and is heard on, and can talk into, both ends of the primary channel.</p></div>
                        </div>
                        <div class="table-scroll">
                          <table class="grid">
                            <thead>
                              <tr>
                                <th class="col-c">Slot</th>
                                <th>Channel Alias</th>
                                <th class="col-c">Enable</th>
                                <th>AMP Bridge Destination IP</th>
                                <th>AMP Bridge UDP Port</th>
                                <th>Local Port (tell the AMP Bridge peer to send here)</th>
                                <th class="col-c">Bridge State</th>
                              </tr>
                            </thead>
                            <tbody>
                              {}
                            </tbody>
                          </table>
                        </div>
                        <div class="note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg><span>Unlike A-MP, this is a live two-way leg: the AMP Bridge party is mixed into the local speaker output and forwarded to the primary destination as its own RTP stream.</span></div>
                      </div>
                    </div>
                  </div>

                  <div id="tab-dispatch" class="tab-panel">
                    {}
                    {}
                  </div>

                  <div id="actionbar" class="actionbar">
                    <div class="actionbar-inner">
                      <span class="action-hint">Unsaved changes &mdash; new calls only</span>
                      <button type="submit" class="btn-primary">Apply Configuration</button>
                    </div>
                  </div>
                </form>
            </div>
            <script>
            // Toast notifications — replaces the old full-width alert banner
            // that required a page reload (?saved=true / ?error=...) to show.
            function showToast(message, type) {{
                const container = document.getElementById("toast-container");
                if (!container) return;
                const toast = document.createElement("div");
                toast.className = "toast " + (type === "error" ? "toast-err" : "toast-ok");
                toast.textContent = message;
                container.appendChild(toast);
                requestAnimationFrame(() => toast.classList.add("show"));
                setTimeout(() => {{
                    toast.classList.remove("show");
                    setTimeout(() => toast.remove(), 250);
                }}, 5000);
            }}

            // Floating "Apply Configuration" button — only shown once the form
            // has unsaved changes, hidden again right after a successful save.
            const configForm = document.getElementById("config-form");
            const actionbar = document.getElementById("actionbar");
            let formIsDirty = false;
            function markFormDirty() {{
                if (!formIsDirty) {{
                    formIsDirty = true;
                    if (actionbar) actionbar.classList.add("visible");
                }}
            }}
            function clearFormDirty() {{
                formIsDirty = false;
                if (actionbar) actionbar.classList.remove("visible");
            }}
            if (configForm) {{
                configForm.addEventListener("input", markFormDirty);
                configForm.addEventListener("change", markFormDirty);
            }}

            function switchTab(tabId, btn) {{
                document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
                document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
                const panel = document.getElementById(tabId);
                if (panel) panel.classList.add("active");
                if (btn) btn.classList.add("active");
            }}

            // Dispatcher patch matrix — instant toggle, no Apply/reload.
            function toggleDispatchCell(el) {{
                if (el.classList.contains("matrix-pending")) return;
                const channelId = parseInt(el.dataset.channel, 10);
                const groupId = parseInt(el.dataset.group, 10);
                el.classList.add("matrix-pending");
                fetch("/api/dispatch/toggle", {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify({{ groupId: groupId, channelId: channelId }})
                }}).then((r) => r.json()).then((data) => {{
                    el.classList.remove("matrix-pending");
                    if (data && data.success) {{
                        el.classList.toggle("matrix-on", !!data.isMember);
                    }}
                }}).catch(() => {{
                    el.classList.remove("matrix-pending");
                }});
            }}

            // Keep the matrix in sync with changes made from elsewhere (the
            // console app's own quick-access matrix, or another admin tab).
            (function connectDispatchMatrixSync() {{
                function connect() {{
                    try {{
                        const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
                        const ws = new WebSocket(proto + "//" + window.location.host + "/events");
                        ws.onmessage = function (evt) {{
                            try {{
                                const payload = JSON.parse(evt.data);
                                if (payload.type === "dispatch_matrix_update") {{
                                    const groups = payload.data.groups || [];
                                    groups.forEach(function (g) {{
                                        document.querySelectorAll('.matrix-cell[data-group="' + g.id + '"]').forEach(function (cell) {{
                                            const chId = parseInt(cell.dataset.channel, 10);
                                            const isMember = (g.memberIds || []).indexOf(chId) !== -1;
                                            cell.classList.toggle("matrix-on", isMember);
                                        }});
                                    }});
                                }}
                            }} catch (e) {{ /* ignore malformed message */ }}
                        }};
                        ws.onclose = function () {{ setTimeout(connect, 3000); }};
                        ws.onerror = function () {{ ws.close(); }};
                    }} catch (e) {{ /* WebSocket unavailable, matrix still works via direct clicks */ }}
                }}
                connect();
            }})();
            function updateSipUserState(id) {{
                const protoSelect = document.getElementsByName("protocol_" + id)[0];
                const sipUserInput = document.getElementsByName("sip_user_" + id)[0];
                const targetPortInput = document.getElementsByName("target_port_" + id)[0];
                if (protoSelect && sipUserInput) {{
                    if (protoSelect.value === "RTP") {{
                        sipUserInput.disabled = true;
                        sipUserInput.style.backgroundColor = "var(--track)";
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
                if (window.__initialToast) {{
                    showToast(window.__initialToast.message, window.__initialToast.type);
                }}
            }});
            function handleSubmit(event) {{
                event.preventDefault();
                document.querySelectorAll("input").forEach(i => i.style.borderColor = "");
                const errors = [];
                const sipPort = parseInt(document.getElementById("sip_port").value, 10);
                if (isNaN(sipPort) || sipPort < 1024 || sipPort > 65535) {{
                    errors.push("Listening Port must be between 1024 and 65535.");
                    document.getElementById("sip_port").style.borderColor = "var(--err)";
                }}
                const localPorts = {{}};
                const mirrorPorts = {{}};
                const bridgePorts = {{}};
                const ampEnabled = document.getElementById("amp_enabled").checked;
                const bridgeEnabled = document.getElementById("bridge_enabled").checked;
                for (let id = 1; id <= 12; id++) {{
                    const labelInput = document.getElementsByName("label_" + id)[0];
                    const localPortInput = document.getElementsByName("local_port_" + id)[0];
                    const targetIpInput = document.getElementsByName("target_ip_" + id)[0];
                    const targetPortInput = document.getElementsByName("target_port_" + id)[0];
                    if (labelInput && !labelInput.disabled) {{
                        const labelVal = labelInput.value.trim();
                        if (labelVal.length === 0) {{
                            errors.push("Channel " + id + " Alias cannot be empty.");
                            labelInput.style.borderColor = "var(--err)";
                        }}
                        const targetIpVal = targetIpInput.value.trim();
                        if (targetIpVal.length === 0) {{
                            errors.push("Channel " + id + " Destination IP cannot be empty.");
                            targetIpInput.style.borderColor = "var(--err)";
                        }}
                        const targetPortVal = parseInt(targetPortInput.value, 10);
                        if (isNaN(targetPortVal) || targetPortVal < 1 || targetPortVal > 65535) {{
                            errors.push("Channel " + id + " Destination Port must be between 1 and 65535.");
                            targetPortInput.style.borderColor = "var(--err)";
                        }}
                        if (localPortInput && localPortInput.value.trim() !== "") {{
                            const localPortVal = parseInt(localPortInput.value, 10);
                            if (isNaN(localPortVal) || localPortVal < 1024 || localPortVal > 65535) {{
                                errors.push("Channel " + id + " Local Port must be between 1024 and 65535.");
                                localPortInput.style.borderColor = "var(--err)";
                            }} else if (localPortVal === sipPort) {{
                                errors.push("Channel " + id + " Local Port (" + localPortVal + ") conflicts with primary Listening Port.");
                                localPortInput.style.borderColor = "var(--err)";
                            }} else if (localPorts[localPortVal]) {{
                                errors.push("Channel " + id + " Local Port (" + localPortVal + ") is duplicated with Channel " + localPorts[localPortVal] + ".");
                                localPortInput.style.borderColor = "var(--err)";
                                document.getElementsByName("local_port_" + localPorts[localPortVal])[0].style.borderColor = "var(--err)";
                            }} else {{
                                localPorts[localPortVal] = id;
                            }}
                        }}
                    }}
                    const ampChanEnabledInput = document.getElementsByName("amp_channel_enabled_" + id)[0];
                    const ampPortInput = document.getElementsByName("amp_port_" + id)[0];
                    if (ampEnabled && ampChanEnabledInput && ampChanEnabledInput.checked) {{
                        if (ampPortInput) {{
                            const ampPortVal = parseInt(ampPortInput.value, 10);
                            if (isNaN(ampPortVal) || ampPortVal < 1 || ampPortVal > 65535) {{
                                errors.push("Channel " + id + " Mirror Port must be between 1 and 65535 when mirroring is enabled.");
                                ampPortInput.style.borderColor = "var(--err)";
                            }} else if (mirrorPorts[ampPortVal]) {{
                                errors.push("Channel " + id + " Mirror Port (" + ampPortVal + ") is duplicated with Channel " + mirrorPorts[ampPortVal] + ".");
                                ampPortInput.style.borderColor = "var(--err)";
                                document.getElementsByName("amp_port_" + mirrorPorts[ampPortVal])[0].style.borderColor = "var(--err)";
                            }} else {{
                                mirrorPorts[ampPortVal] = id;
                            }}
                        }}
                    }}

                    const bridgeChanEnabledInput = document.getElementsByName("bridge_channel_enabled_" + id)[0];
                    const bridgePortInput = document.getElementsByName("bridge_port_" + id)[0];
                    if (bridgeEnabled && bridgeChanEnabledInput && bridgeChanEnabledInput.checked) {{
                        if (bridgePortInput) {{
                            const bridgePortVal = parseInt(bridgePortInput.value, 10);
                            if (isNaN(bridgePortVal) || bridgePortVal < 1 || bridgePortVal > 65535) {{
                                errors.push("Channel " + id + " Bridge Port must be between 1 and 65535 when AMP Bridge is enabled.");
                                bridgePortInput.style.borderColor = "var(--err)";
                            }} else if (bridgePorts[bridgePortVal]) {{
                                errors.push("Channel " + id + " Bridge Port (" + bridgePortVal + ") is duplicated with Channel " + bridgePorts[bridgePortVal] + ".");
                                bridgePortInput.style.borderColor = "var(--err)";
                                document.getElementsByName("bridge_port_" + bridgePorts[bridgePortVal])[0].style.borderColor = "var(--err)";
                            }} else {{
                                bridgePorts[bridgePortVal] = id;
                            }}
                        }}
                    }}

                    const bridgeLocalPortInput = document.getElementsByName("bridge_local_port_" + id)[0];
                    if (bridgeLocalPortInput && bridgeLocalPortInput.value.trim() !== "") {{
                        const bridgeLocalPortVal = parseInt(bridgeLocalPortInput.value, 10);
                        if (isNaN(bridgeLocalPortVal) || bridgeLocalPortVal < 1024 || bridgeLocalPortVal > 65535) {{
                            errors.push("Channel " + id + " Bridge Local Port must be between 1024 and 65535.");
                            bridgeLocalPortInput.style.borderColor = "var(--err)";
                        }} else if (bridgeLocalPortVal === sipPort) {{
                            errors.push("Channel " + id + " Bridge Local Port (" + bridgeLocalPortVal + ") conflicts with primary Listening Port.");
                            bridgeLocalPortInput.style.borderColor = "var(--err)";
                        }} else if (localPorts[bridgeLocalPortVal]) {{
                            errors.push("Channel " + id + " Bridge Local Port (" + bridgeLocalPortVal + ") is duplicated with another Local Port on Channel " + localPorts[bridgeLocalPortVal] + ".");
                            bridgeLocalPortInput.style.borderColor = "var(--err)";
                        }} else {{
                            localPorts[bridgeLocalPortVal] = id;
                        }}
                    }}
                }}
                const dispatchMirrorPorts = {{}};
                for (let gid = 1; gid <= 4; gid++) {{
                    const mirrorEnabledInput = document.getElementsByName("dispatch_mirror_enabled_" + gid)[0];
                    const mirrorPortInput = document.getElementsByName("dispatch_mirror_port_" + gid)[0];
                    if (mirrorEnabledInput && mirrorEnabledInput.checked && mirrorPortInput) {{
                        const mirrorPortVal = parseInt(mirrorPortInput.value, 10);
                        if (isNaN(mirrorPortVal) || mirrorPortVal < 1 || mirrorPortVal > 65535) {{
                            errors.push("Dispatcher Group " + gid + " Mirror Port must be between 1 and 65535 when the mirror is enabled.");
                            mirrorPortInput.style.borderColor = "var(--err)";
                        }} else if (dispatchMirrorPorts[mirrorPortVal]) {{
                            errors.push("Dispatcher Group " + gid + " Mirror Port (" + mirrorPortVal + ") is duplicated with Group " + dispatchMirrorPorts[mirrorPortVal] + ".");
                            mirrorPortInput.style.borderColor = "var(--err)";
                            document.getElementsByName("dispatch_mirror_port_" + dispatchMirrorPorts[mirrorPortVal])[0].style.borderColor = "var(--err)";
                        }} else {{
                            dispatchMirrorPorts[mirrorPortVal] = gid;
                        }}
                    }}
                    const mirrorLocalPortInput = document.getElementsByName("dispatch_mirror_local_port_" + gid)[0];
                    if (mirrorLocalPortInput && mirrorLocalPortInput.value.trim() !== "") {{
                        const mirrorLocalPortVal = parseInt(mirrorLocalPortInput.value, 10);
                        if (isNaN(mirrorLocalPortVal) || mirrorLocalPortVal < 1024 || mirrorLocalPortVal > 65535) {{
                            errors.push("Dispatcher Group " + gid + " Local Port must be between 1024 and 65535.");
                            mirrorLocalPortInput.style.borderColor = "var(--err)";
                        }} else if (mirrorLocalPortVal === sipPort) {{
                            errors.push("Dispatcher Group " + gid + " Local Port (" + mirrorLocalPortVal + ") conflicts with primary Listening Port.");
                            mirrorLocalPortInput.style.borderColor = "var(--err)";
                        }} else if (localPorts[mirrorLocalPortVal]) {{
                            errors.push("Dispatcher Group " + gid + " Local Port (" + mirrorLocalPortVal + ") is duplicated with another Local Port on Channel " + localPorts[mirrorLocalPortVal] + ".");
                            mirrorLocalPortInput.style.borderColor = "var(--err)";
                        }} else {{
                            localPorts[mirrorLocalPortVal] = "Dispatcher Group " + gid;
                        }}
                    }}
                }}
                if (errors.length > 0) {{
                    const summary = errors.length === 1
                        ? errors[0]
                        : errors.length + " issues found: " + errors[0] + (errors.length > 1 ? " (+" + (errors.length - 1) + " more)" : "");
                    showToast(summary, "error");
                    const firstBad = document.querySelector('input[style*="border-color"]');
                    if (firstBad) firstBad.scrollIntoView({{ behavior: "smooth", block: "center" }});
                    return;
                }}

                // Client-side validation passed — submit via fetch so the page
                // never reloads. Disabled fields and unchecked checkboxes are
                // automatically left out of FormData, same as a normal submit.
                const submitBtn = configForm.querySelector('button[type="submit"]');
                if (submitBtn) submitBtn.disabled = true;
                fetch(configForm.action || "/config/save", {{
                    method: "POST",
                    headers: {{ "Accept": "application/json" }},
                    body: new URLSearchParams(new FormData(configForm))
                }}).then((r) => r.json().catch(() => ({{}})).then((data) => ({{ ok: r.ok, data: data }})))
                  .then(({{ ok, data }}) => {{
                    if (ok && data && data.success) {{
                        showToast(data.message || "Configuration saved successfully and synced to console panel.", "success");
                        clearFormDirty();
                    }} else {{
                        showToast((data && data.error) || "Failed to save configuration.", "error");
                    }}
                }}).catch(() => {{
                    showToast("Failed to save configuration. Check the connection and try again.", "error");
                }}).finally(() => {{
                    if (submitBtn) submitBtn.disabled = false;
                }});
            }}
            </script>
        </body>
        </html>
        
        "##,
        message_banner,
        lock.sip_port,
        devices_options,
        channels_rows,
        amp_enabled_checked,
        amp_rows,
        bridge_enabled_checked,
        bridge_rows,
        dispatch_matrix_html,
        dispatch_settings_html
    );

    Html(html_content)
}

// POST: Save configurations from web form
async fn save_config_handler(
    State(state): State<Arc<Mutex<AppState>>>,
    Form(form_data): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let mut lock = state.lock().await;
    
    // Let's first validate the incoming Form data!
    let mut sip_port = lock.sip_port;
    if let Some(port_str) = form_data.get("sip_port") {
        if let Ok(port) = port_str.parse::<u16>() {
            sip_port = port;
            if port < 1024 {
                return config_error("Listening Port must be between 1024 and 65535").into_response();
            }
        } else {
            return config_error("Invalid Listening Port").into_response();
        }
    }

    let mut local_ports = std::collections::HashMap::new();
    let mut mirror_ports = std::collections::HashMap::new();
    let mut bridge_ports = std::collections::HashMap::new();
    let amp_enabled = form_data.contains_key("amp_enabled");
    let bridge_enabled = form_data.contains_key("bridge_enabled");

    for id in 1..=12 {
        let label_key = format!("label_{}", id);
        let target_ip_key = format!("target_ip_{}", id);
        let target_port_key = format!("target_port_{}", id);
        let local_port_key = format!("local_port_{}", id);
        let amp_channel_enabled_key = format!("amp_channel_enabled_{}", id);
        let amp_port_key = format!("amp_port_{}", id);

        let ch_opt = lock.channels.iter().find(|c| c.id == id);
        let is_routing_or_dialing = if let Some(ch) = ch_opt {
            ch.status == "CONNECTED" || ch.status == "RINGING" || ch.status == "INCOMING"
        } else {
            false
        };

        // Note: if channel is active, the form fields are disabled (so they won't be sent in form_data)
        let ch_label = if is_routing_or_dialing {
            ch_opt.map(|c| c.label.clone()).unwrap_or_default()
        } else if let Some(label) = form_data.get(&label_key) {
            label.trim().to_string()
        } else {
            ch_opt.map(|c| c.label.clone()).unwrap_or_default()
        };

        if !is_routing_or_dialing && ch_label.is_empty() {
            return config_error(format!("Channel {:02} Alias cannot be empty", id)).into_response();
        }

        let ch_target_ip = if is_routing_or_dialing {
            ch_opt.map(|c| c.target_ip.clone()).unwrap_or_default()
        } else if let Some(ip) = form_data.get(&target_ip_key) {
            ip.trim().to_string()
        } else {
            ch_opt.map(|c| c.target_ip.clone()).unwrap_or_default()
        };

        if !is_routing_or_dialing && ch_target_ip.is_empty() {
            return config_error(format!("Channel {:02} Destination IP cannot be empty", id)).into_response();
        }

        let _ch_target_port = if is_routing_or_dialing {
            ch_opt.map(|c| c.target_port).unwrap_or(0)
        } else if let Some(port_str) = form_data.get(&target_port_key) {
            if let Ok(port) = port_str.parse::<u16>() {
                if port < 1 {
                    return config_error(format!("Channel {:02} Destination Port must be between 1 and 65535", id)).into_response();
                }
                port
            } else {
                return config_error(format!("Invalid Destination Port for Channel {:02}", id)).into_response();
            }
        } else {
            ch_opt.map(|c| c.target_port).unwrap_or(0)
        };

        let ch_local_port = if is_routing_or_dialing {
            ch_opt.and_then(|c| c.local_port)
        } else if let Some(port_str) = form_data.get(&local_port_key) {
            if port_str.is_empty() {
                None
            } else if let Ok(port) = port_str.parse::<u16>() {
                if port < 1024 {
                    return config_error(format!("Channel {:02} Local Port must be between 1024 and 65535", id)).into_response();
                }
                Some(port)
            } else {
                return config_error(format!("Invalid Local Port for Channel {:02}", id)).into_response();
            }
        } else {
            ch_opt.and_then(|c| c.local_port)
        };

        if let Some(port) = ch_local_port {
            if port == sip_port {
                return config_error(format!("Channel {:02} Local Port ({}) conflicts with SIP Listening Port", id, port)).into_response();
            }
            if let Some(other_id) = local_ports.insert(port, id) {
                return config_error(format!("Duplicate Local Port ({}) between Channel {:02} and Channel {:02}", port, other_id, id)).into_response();
            }
        }

        let ch_amp_enabled = form_data.contains_key(&amp_channel_enabled_key);
        let ch_amp_port = if let Some(port_str) = form_data.get(&amp_port_key) {
            port_str.parse::<u16>().unwrap_or(0)
        } else {
            ch_opt.map(|c| c.amp_port).unwrap_or(0)
        };

        if amp_enabled && ch_amp_enabled {
            if ch_amp_port < 1 {
                return config_error(format!("Channel {:02} Mirror Port must be between 1 and 65535 when mirroring is enabled", id)).into_response();
            }
            if let Some(other_id) = mirror_ports.insert(ch_amp_port, id) {
                return config_error(format!("Duplicate Mirror Port ({}) between Channel {:02} and Channel {:02}", ch_amp_port, other_id, id)).into_response();
            }
        }

        let bridge_channel_enabled_key = format!("bridge_channel_enabled_{}", id);
        let bridge_port_key = format!("bridge_port_{}", id);
        let ch_bridge_enabled = form_data.contains_key(&bridge_channel_enabled_key);
        let ch_bridge_port = if let Some(port_str) = form_data.get(&bridge_port_key) {
            port_str.parse::<u16>().unwrap_or(0)
        } else {
            ch_opt.map(|c| c.bridge_port).unwrap_or(0)
        };

        if bridge_enabled && ch_bridge_enabled {
            if ch_bridge_port < 1 {
                return config_error(format!("Channel {:02} AMP Bridge Port must be between 1 and 65535 when AMP Bridge is enabled", id)).into_response();
            }
            if let Some(other_id) = bridge_ports.insert(ch_bridge_port, id) {
                return config_error(format!("Duplicate AMP Bridge Port ({}) between Channel {:02} and Channel {:02}", ch_bridge_port, other_id, id)).into_response();
            }
        }

        // AMP Bridge local port: the port this console binds to and tells the
        // interop peer to send its RTP to. Shares the `local_ports` collision map
        // with the primary channel's own Local Port field since both are real
        // local binds on this machine.
        let bridge_local_port_key = format!("bridge_local_port_{}", id);
        let ch_bridge_local_port = if let Some(port_str) = form_data.get(&bridge_local_port_key) {
            if port_str.trim().is_empty() {
                None
            } else if let Ok(port) = port_str.parse::<u16>() {
                if port < 1024 {
                    return config_error(format!("Channel {:02} AMP Bridge Local Port must be between 1024 and 65535", id)).into_response();
                }
                Some(port)
            } else {
                return config_error(format!("Invalid AMP Bridge Local Port for Channel {:02}", id)).into_response();
            }
        } else {
            ch_opt.and_then(|c| c.bridge_local_port)
        };

        if let Some(port) = ch_bridge_local_port {
            if port == sip_port {
                return config_error(format!("Channel {:02} AMP Bridge Local Port ({}) conflicts with SIP Listening Port", id, port)).into_response();
            }
            if let Some(other_id) = local_ports.insert(port, id) {
                return config_error(format!("Duplicate Local Port ({}) between Channel {:02} and Channel {:02}", port, other_id, id)).into_response();
            }
        }
    }

    // Validate + build the 4 fixed Dispatcher patch groups. Each group's mirror
    // is its own independent external destination (same as A-MP/AMP Bridge's
    // per-channel destinations), so collisions are only checked between the
    // Dispatcher groups themselves, not against the per-channel amp/bridge maps.
    let mut dispatch_mirror_ports: std::collections::HashMap<u16, u32> = std::collections::HashMap::new();
    let mut new_dispatch_groups: Vec<DispatchGroup> = Vec::new();
    for gid in 1..=DISPATCH_GROUP_COUNT {
        let name = form_data.get(&format!("dispatch_name_{}", gid))
            .map(|s| { let mut t = s.trim().to_string(); t.truncate(24); t })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("Patch {}", gid));

        // Membership is managed exclusively via the instant matrix toggle
        // endpoint (/api/dispatch/toggle) now, not this form — the matrix UI
        // has no `dispatch_member_*` checkboxes to submit. Preserve whatever
        // the current roster already is so a routine "Apply Configuration"
        // (e.g. just renaming a group or changing the SIP port) can't
        // accidentally wipe out live patches.
        let member_ids = lock.dispatch_groups.iter().find(|g| g.id == gid).map(|g| g.member_ids.clone()).unwrap_or_default();

        let mirror_enabled = form_data.contains_key(&format!("dispatch_mirror_enabled_{}", gid));
        let mirror_ip = form_data.get(&format!("dispatch_mirror_ip_{}", gid))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let mirror_port = form_data.get(&format!("dispatch_mirror_port_{}", gid))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        if mirror_enabled {
            if mirror_port < 1 {
                return config_error(format!("Dispatcher Group {} Mirror Port must be between 1 and 65535 when the mirror is enabled", gid)).into_response();
            }
            if let Some(other_gid) = dispatch_mirror_ports.insert(mirror_port, gid) {
                return config_error(format!("Duplicate Dispatcher Mirror Port ({}) between Group {} and Group {}", mirror_port, other_gid, gid)).into_response();
            }
        }

        // Mirror local port: the port THIS console binds to and tells the
        // external party (e.g. a two-way headset resource) to send its RTP to,
        // so it can talk back into the whole patch. It's a real local bind, so
        // it shares the `local_ports` collision map with every per-channel
        // Local Port / Bridge Local Port field validated above.
        let mirror_local_port_key = format!("dispatch_mirror_local_port_{}", gid);
        let mirror_local_port = if let Some(port_str) = form_data.get(&mirror_local_port_key) {
            if port_str.trim().is_empty() {
                None
            } else if let Ok(port) = port_str.parse::<u16>() {
                if port < 1024 {
                    return config_error(format!("Dispatcher Group {} Local Port must be between 1024 and 65535", gid)).into_response();
                }
                Some(port)
            } else {
                return config_error(format!("Invalid Dispatcher Group {} Local Port", gid)).into_response();
            }
        } else {
            None
        };

        if let Some(port) = mirror_local_port {
            if port == sip_port {
                return config_error(format!("Dispatcher Group {} Local Port ({}) conflicts with primary Listening Port", gid, port)).into_response();
            }
            // Values >100 in `local_ports` are Dispatcher group markers (100+gid),
            // real channel ids are 1-12 — used only to make the collision message
            // readable for both cases.
            if let Some(other_id) = local_ports.insert(port, 100 + gid) {
                let other_desc = if other_id > 100 {
                    format!("Dispatcher Group {}", other_id - 100)
                } else {
                    format!("Channel {:02}", other_id)
                };
                return config_error(format!("Duplicate Local Port ({}) between Dispatcher Group {} and {}", port, gid, other_desc)).into_response();
            }
        }

        new_dispatch_groups.push(DispatchGroup {
            id: gid,
            name,
            member_ids,
            mirror_enabled,
            mirror_ip,
            mirror_port,
            mirror_local_port,
        });
    }

    // Parse general settings after validation is complete
    lock.sip_port = sip_port;
    if let Some(device) = form_data.get("selected_device") {
        if device == "none" || device.is_empty() {
            lock.selected_device = None;
        } else {
            lock.selected_device = Some(device.clone());
        }
    }

    // global mirror enabled
    lock.amp_enabled = amp_enabled;
    // global ACU bridge enabled
    lock.bridge_enabled = bridge_enabled;
    // Dispatcher patch groups (fixed 4 slots)
    lock.dispatch_groups = new_dispatch_groups;
    // Any live shared group-mirror tap/listener reflects the OLD settings;
    // drop them so the next connecting member lazily rebuilds against the new
    // ip/port/local port (see get_or_create_dispatch_mirror). Existing calls'
    // per-member relay tasks/buses are untouched — only the external mirror
    // leg is affected, and only takes effect for members that (re)connect
    // after this save.
    for (_, handle) in lock.dispatch_mirror_listeners.drain() {
        handle.abort();
    }
    lock.dispatch_mirror_taps.clear();

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
                    let mut truncated = label.trim().to_string();
                    truncated.truncate(7);
                    ch.label = truncated;
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
                ch.bridge_enabled = form_data.contains_key(&format!("bridge_channel_enabled_{}", id));
                ch.ed137_enabled = form_data.contains_key(&format!("ed137_enabled_{}", id));
                if let Some(ptt_id_str) = form_data.get(&format!("ed137_ptt_id_{}", id)) {
                    if let Ok(ptt_id) = ptt_id_str.parse::<u8>() {
                        ch.ed137_ptt_id = ptt_id.min(63);
                    }
                }

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

            // per-channel recorder destination — editable regardless of call state
            if let Some(ip) = form_data.get(&format!("amp_ip_{}", id)) {
                ch.amp_ip = if ip.trim().is_empty() { "127.0.0.1".to_string() } else { ip.trim().to_string() };
            }
            if let Some(port_str) = form_data.get(&format!("amp_port_{}", id)) {
                if let Ok(p) = port_str.parse::<u16>() {
                    ch.amp_port = p;
                }
            }

            // per-channel ACU bridge destination — editable regardless of call state
            if let Some(ip) = form_data.get(&format!("bridge_ip_{}", id)) {
                ch.bridge_ip = if ip.trim().is_empty() { "127.0.0.1".to_string() } else { ip.trim().to_string() };
            }
            if let Some(port_str) = form_data.get(&format!("bridge_port_{}", id)) {
                if let Ok(p) = port_str.parse::<u16>() {
                    ch.bridge_port = p;
                }
            }
            if let Some(port_str) = form_data.get(&format!("bridge_local_port_{}", id)) {
                if port_str.trim().is_empty() {
                    ch.bridge_local_port = None;
                } else if let Ok(p) = port_str.parse::<u16>() {
                    ch.bridge_local_port = Some(p);
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
            "ampEnabled": lock.amp_enabled,
            "bridgeEnabled": lock.bridge_enabled
        }
    }).to_string();
    let _ = lock.tx.send(config_msg);

    // Update mirror streaming status dynamically based on current configuration.
    // Note: unlike A-MP (a passive tap that config alone fully determines),
    // `bridge_connected` reflects a live, two-way task started at call time —
    // it is intentionally NOT recomputed here, since flipping it without the
    // matching bridge_listener task actually running would show a misleading
    // "connected" indicator. It is only ever set by the call lifecycle handlers.
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

    // Respond with JSON so the client can apply it without a full page reload.
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Configuration saved successfully and synced to console panel."
    }))).into_response()
}

/// Build a JSON error response for the web config save endpoint. Replaces the
/// old query-string `Redirect::to("/config?error=...")` flow now that saving
/// happens via fetch() and shows a toast instead of reloading the page.
fn config_error(msg: impl Into<String>) -> axum::response::Response {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({
        "success": false,
        "error": msg.into()
    }))).into_response()
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
            "ampEnabled": lock.amp_enabled,
            "bridgeEnabled": lock.bridge_enabled
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
