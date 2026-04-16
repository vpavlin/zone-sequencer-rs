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
    serde_json::from_slice(&data).ok()
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
/// - signing_key_hex: 64-char hex (32-byte Ed25519 seed). Channel ID derived from public key.
/// - data: text to inscribe
/// - checkpoint_path: file to load/save checkpoint ("" to disable). On first publish for a
///   fresh channel, pass a path but it's fine if the file doesn't exist yet.
///
/// Returns heap-allocated hex inscription ID, or NULL on error. Free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_publish(
    node_url: *const c_char,
    signing_key_hex: *const c_char,
    data: *const c_char,
    checkpoint_path: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| zone_publish_inner(node_url, signing_key_hex, data, checkpoint_path));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_publish: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_publish: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_publish_inner(
    node_url: *const c_char,
    signing_key_hex: *const c_char,
    data: *const c_char,
    checkpoint_path: *const c_char,
) -> Option<CString> {
    if node_url.is_null() || signing_key_hex.is_null() || data.is_null() {
        eprintln!("zone_publish: null argument");
        return None;
    }

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let signing_key_str = unsafe { CStr::from_ptr(signing_key_hex) }.to_str().ok()?;
    let data_str = unsafe { CStr::from_ptr(data) }.to_str().ok()?;
    let ckpt_path = if checkpoint_path.is_null() { "" } else {
        unsafe { CStr::from_ptr(checkpoint_path) }.to_str().unwrap_or("")
    };

    let key_bytes: [u8; 32] = hex::decode(signing_key_str).ok()?.try_into().ok()?;
    let signing_key = Ed25519Key::from_bytes(&key_bytes);
    let channel_bytes: [u8; 32] = signing_key.public_key().to_bytes();
    let channel_id = ChannelId::from(channel_bytes);
    let url: Url = node_url_str.parse().ok()?;

    let checkpoint = load_checkpoint(ckpt_path);
    eprintln!("zone_publish: node={} channel={} checkpoint={}",
        url, hex::encode(channel_bytes),
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
                    save_checkpoint(ckpt_path, &result.checkpoint);
                    tokio::time::sleep(Duration::from_secs(5)).await;
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
        let start_cursor = if let Ok(info) = http_client.consensus_info(url.clone()).await {
            let tip_slot: u64 = info.slot.into();
            let lookback: u64 = 50000; // scan last 50k slots (~14 hours at 1s slots)
            let start_slot = tip_slot.saturating_sub(lookback);
            serde_json::from_str::<logos_blockchain_zone_sdk::indexer::Cursor>(
                    &format!(r#"{{"slot":{},"last_id":null}}"#, start_slot)
                ).ok()
        } else {
            None // fall back to genesis if we can't get tip
        };

        let poll = indexer.next_messages(start_cursor, limit as usize).await.ok()?;
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

/// Free a string returned by zone_publish, zone_query_channel, or zone_derive_channel_id.
#[no_mangle]
pub extern "C" fn zone_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}
