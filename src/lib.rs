use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;
use std::sync::OnceLock;
use std::fs;

use lb_core::mantle::ops::channel::ChannelId;
use lb_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::{ZoneSequencer, SequencerCheckpoint};
use logos_blockchain_zone_sdk::indexer::ZoneIndexer;
use reqwest::Url;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static TRACING_INIT: OnceLock<()> = OnceLock::new();

fn init_tracing() {
    TRACING_INIT.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
            )
            .with_writer(std::io::stderr)
            .init();
    });
}

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

fn load_checkpoint(path: &str) -> Option<SequencerCheckpoint> {
    if path.is_empty() { return None; }
    let data = fs::read(path).ok()?;
    let mut cp: SequencerCheckpoint = serde_json::from_slice(&data).ok()?;
    // Always clear pending_txs on load: they may be stale (from a session that ended
    // before LIB confirmation), and restoring them causes the sequencer to wait for
    // transactions that the node may have already dropped.  The last_msg_id is kept
    // so the chain stays contiguous.
    if !cp.pending_txs.is_empty() {
        eprintln!("load_checkpoint: cleared {} stale pending_txs", cp.pending_txs.len());
        cp.pending_txs.clear();
    }
    Some(cp)
}

fn save_checkpoint(path: &str, checkpoint: &SequencerCheckpoint) {
    if path.is_empty() { return; }
    if let Ok(data) = serde_json::to_vec(checkpoint) {
        let _ = fs::write(path, data);
    }
}

/// Publish data to a zone channel.
///
/// - node_url: HTTP endpoint e.g. "http://192.168.0.209:8080"
/// - channel_id_hex: 64-char hex channel ID (32 bytes) to publish to
/// - signing_key_hex: 64-char hex (32-byte Ed25519 seed).
/// - data: text to inscribe
/// - checkpoint_path: file to load/save checkpoint ("" to disable). On first publish for a
///   fresh channel, pass a path but it's fine if the file doesn't exist yet.
///
/// Returns heap-allocated hex inscription ID, or NULL on error. Free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_publish(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    signing_key_hex: *const c_char,
    data: *const c_char,
    checkpoint_path: *const c_char,
) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| zone_publish_inner(node_url, channel_id_hex, signing_key_hex, data, checkpoint_path));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_publish: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_publish: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_publish_inner(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    signing_key_hex: *const c_char,
    data: *const c_char,
    checkpoint_path: *const c_char,
) -> Option<CString> {
    if node_url.is_null() || channel_id_hex.is_null() || signing_key_hex.is_null() || data.is_null() {
        eprintln!("zone_publish: null argument");
        return None;
    }

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;
    let signing_key_str = unsafe { CStr::from_ptr(signing_key_hex) }.to_str().ok()?;
    let data_str = unsafe { CStr::from_ptr(data) }.to_str().ok()?;
    let ckpt_path = if checkpoint_path.is_null() { "" } else {
        unsafe { CStr::from_ptr(checkpoint_path) }.to_str().unwrap_or("")
    };

    let key_bytes: [u8; 32] = hex::decode(signing_key_str).ok()?.try_into().ok()?;
    let signing_key = Ed25519Key::from_bytes(&key_bytes);
    let channel_bytes: [u8; 32] = hex::decode(channel_id_hex_str).ok()?.try_into().ok()?;
    let channel_id = ChannelId::from(channel_bytes);
    let url: Url = node_url_str.parse().ok()?;

    let checkpoint = load_checkpoint(ckpt_path);
    eprintln!("zone_publish: node={} channel={} checkpoint={}",
        url, channel_id_hex_str,
        if checkpoint.is_some() { "loaded" } else { "fresh" });

    let data_bytes = data_str.as_bytes().to_vec();
    eprintln!("zone_publish: publishing {} bytes...", data_bytes.len());

    let rt = get_runtime();

    let result = rt.block_on(async {
        let sequencer = ZoneSequencer::init(channel_id, signing_key, url, None, checkpoint);

        let mut attempts = 0;
        loop {
            attempts += 1;
            match sequencer.publish(data_bytes.clone()).await {
                Ok(result) => {
                    let id_bytes: [u8; 32] = result.inscription_id.into();
                    let id_hex = hex::encode(id_bytes);
                    eprintln!("zone_publish: inscription_id={}", id_hex);
                    // Save checkpoint with pending_txs cleared.
                    // The sequencer saves the fresh publish as a pending_tx (not yet in LIB),
                    // but if we persist that and the session ends before LIB confirmation
                    // (~10 min), the next session blocks forever waiting for it to resolve.
                    // Clearing pending_txs lets the next init start without that deadlock;
                    // the sequencer will re-discover the chain head from last_msg_id instead.
                    if !ckpt_path.is_empty() {
                        if let Ok(data) = serde_json::to_vec(&result.checkpoint) {
                            if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(&data) {
                                val["pending_txs"] = serde_json::json!([]);
                                if let Ok(cleaned) = serde_json::to_vec(&val) {
                                    let _ = fs::write(ckpt_path, cleaned);
                                }
                            }
                        }
                    }
                    return Some(id_hex);
                }
                Err(e) => {
                    if attempts > 5 {
                        eprintln!("zone_publish: failed after {} attempts: {}", attempts, e);
                        return None;
                    }
                    eprintln!("zone_publish: attempt {}: {} — retrying in 1s...", attempts, e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    })?;

    CString::new(result).ok()
}

/// Query inscriptions from a zone channel.
///
/// - node_url: HTTP endpoint e.g. "http://192.168.0.209:8080"
/// - channel_id_hex: 64-char hex channel ID (32 bytes)
/// - limit: max number of inscriptions to return
///
/// Returns JSON array string: [{"id":"hex","data":"text"}, ...]
/// or NULL on error. Caller must free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_query_channel(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    limit: i32,
) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| zone_query_channel_inner(node_url, channel_id_hex, limit));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_query_channel: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_query_channel: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_query_channel_inner(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    limit: i32,
) -> Option<CString> {
    if node_url.is_null() || channel_id_hex.is_null() {
        eprintln!("zone_query_channel: null argument");
        return None;
    }

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;

    let channel_id = ChannelId::from(<[u8; 32]>::try_from(hex::decode(channel_id_hex_str).ok()?).ok()?);
    let url: Url = node_url_str.parse().ok()?;
    let url_for_indexer = url.clone();
    let indexer = ZoneIndexer::new(channel_id, url_for_indexer, None);

    eprintln!("zone_query_channel: channel={} limit={}", channel_id_hex_str, limit);

    let rt = get_runtime();
    let result = rt.block_on(async {
        // Get current chain tip to start from recent blocks only
        // Scanning from genesis is too slow — start from (tip - lookback) instead
        let http_client = lb_common_http_client::CommonHttpClient::new(None);
        let start_cursor = match http_client.consensus_info(url.clone()).await {
            Ok(info) => {
                let tip_slot: u64 = info.slot.into();
                let lookback: u64 = 50000; // scan last 50k slots (~14 hours at 1s slots)
                let start_slot = tip_slot.saturating_sub(lookback);
                eprintln!("zone_query_channel: tip_slot={} start_slot={}", tip_slot, start_slot);
                serde_json::from_str::<logos_blockchain_zone_sdk::indexer::Cursor>(
                        &format!(r#"{{"slot":{},"last_id":null}}"#, start_slot)
                    ).ok()
            }
            Err(e) => {
                eprintln!("zone_query_channel: consensus_info error: {:?} — scanning from genesis", e);
                None // fall back to genesis if we can't get tip
            }
        };

        let poll = match indexer.next_messages(start_cursor, limit as usize).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("zone_query_channel: next_messages error: {:?}", e);
                return None;
            }
        };
        eprintln!("zone_query_channel: got {} messages", poll.messages.len());
        let items: Vec<serde_json::Value> = poll.messages.iter().map(|b| {
            serde_json::json!({
                "id": hex::encode(<[u8; 32]>::from(b.id)),
                "data": String::from_utf8_lossy(&b.data).to_string()
            })
        }).collect();
        Some(serde_json::to_string(&items).ok()?)
    })?;

    CString::new(result).ok()
}

/// Derive the 64-char hex channel ID from an Ed25519 signing key without publishing.
///
/// - signing_key_hex: 64-char hex (32-byte Ed25519 seed)
///
/// Returns heap-allocated 64-char hex channel ID, or NULL on error. Free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_derive_channel_id(signing_key_hex: *const c_char) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| zone_derive_channel_id_inner(signing_key_hex));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_derive_channel_id: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_derive_channel_id: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_derive_channel_id_inner(signing_key_hex: *const c_char) -> Option<CString> {
    if signing_key_hex.is_null() {
        eprintln!("zone_derive_channel_id: null argument");
        return None;
    }
    let signing_key_str = unsafe { CStr::from_ptr(signing_key_hex) }.to_str().ok()?;
    let key_bytes: [u8; 32] = hex::decode(signing_key_str).ok()?.try_into().ok()?;
    let signing_key = Ed25519Key::from_bytes(&key_bytes);
    let channel_bytes: [u8; 32] = signing_key.public_key().to_bytes();
    CString::new(hex::encode(channel_bytes)).ok()
}

/// Query a zone channel with cursor-based pagination for full history backfill.
///
/// - node_url: HTTP endpoint e.g. "http://192.168.0.209:8080"
/// - channel_id_hex: 64-char hex channel ID (32 bytes)
/// - cursor_json: JSON cursor from previous call, or NULL to start from genesis
/// - limit: max number of inscriptions to return per page
///
/// Returns JSON object:
/// {"messages":[{"id":"hex","data":"text"},...],
///  "cursor":{"slot":N,"last_id":null},
///  "cursor_slot":N,
///  "lib_slot":N,
///  "done":bool}
/// or NULL on error. Caller must free with zone_free_string().
/// "done" is true when cursor_slot >= lib_slot (reached LIB — all finalized history scanned).
#[no_mangle]
pub extern "C" fn zone_query_channel_paged(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    cursor_json: *const c_char,
    limit: i32,
) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| {
        zone_query_channel_paged_inner(node_url, channel_id_hex, cursor_json, limit)
    });
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_query_channel_paged: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_query_channel_paged: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_query_channel_paged_inner(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    cursor_json: *const c_char,
    limit: i32,
) -> Option<CString> {
    if node_url.is_null() || channel_id_hex.is_null() {
        eprintln!("zone_query_channel_paged: null argument");
        return None;
    }

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;

    let channel_id = ChannelId::from(
        <[u8; 32]>::try_from(hex::decode(channel_id_hex_str).ok()?).ok()?
    );
    let url: Url = node_url_str.parse().ok()?;

    // Parse optional incoming cursor (NULL or empty = from genesis)
    let start_cursor: Option<logos_blockchain_zone_sdk::indexer::Cursor> = if cursor_json.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(cursor_json) }.to_str().unwrap_or("");
        if cstr.is_empty() || cstr == "null" {
            None
        } else {
            serde_json::from_str(cstr).ok()
        }
    };

    let cursor_slot_hint = start_cursor.as_ref().map(|c| {
        // Extract slot from cursor JSON for progress reporting
        serde_json::to_value(c).ok()
            .and_then(|v| v["slot"].as_u64())
            .unwrap_or(0)
    }).unwrap_or(0);

    eprintln!("zone_query_channel_paged: channel={} cursor_slot={} limit={}",
        channel_id_hex_str, cursor_slot_hint, limit);

    let indexer = ZoneIndexer::new(channel_id, url.clone(), None);
    let rt = get_runtime();

    let result = rt.block_on(async {
        // Get LIB slot for progress / done detection
        let http_client = lb_common_http_client::CommonHttpClient::new(None);
        let lib_slot: u64 = match http_client.consensus_info(url.clone()).await {
            Ok(info) => {
                // consensus_info returns tip; LIB is typically ~600 slots behind
                let tip: u64 = info.slot.into();
                tip.saturating_sub(600)
            }
            Err(e) => {
                eprintln!("zone_query_channel_paged: consensus_info error: {:?}", e);
                0
            }
        };

        let poll = match indexer.next_messages(start_cursor, limit as usize).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("zone_query_channel_paged: next_messages error: {:?}", e);
                return None;
            }
        };

        let items: Vec<serde_json::Value> = poll.messages.iter().map(|b| {
            serde_json::json!({
                "id": hex::encode(<[u8; 32]>::from(b.id)),
                "data": String::from_utf8_lossy(&b.data).to_string()
            })
        }).collect();

        let cursor_val = serde_json::to_value(&poll.cursor).unwrap_or(serde_json::Value::Null);
        let new_cursor_slot = cursor_val["slot"].as_u64().unwrap_or(0);
        let done = lib_slot > 0 && new_cursor_slot >= lib_slot;

        eprintln!("zone_query_channel_paged: got {} messages, cursor_slot={}, lib_slot={}, done={}",
            items.len(), new_cursor_slot, lib_slot, done);

        let out = serde_json::json!({
            "messages": items,
            "cursor": cursor_val,
            "cursor_slot": new_cursor_slot,
            "lib_slot": lib_slot,
            "done": done
        });
        Some(serde_json::to_string(&out).ok()?)
    })?;

    CString::new(result).ok()
}

/// Free a string returned by zone_publish, zone_query_channel, zone_derive_channel_id,
/// or zone_query_channel_paged.
#[no_mangle]
pub extern "C" fn zone_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}
