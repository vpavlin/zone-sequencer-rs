#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// Publish data. channel_id_hex: 64-char hex channel ID to publish to.
// checkpoint_path: file to load/save checkpoint ("" to disable).
// Returns hex inscription ID (caller must free with zone_free_string), or NULL on error.
char* zone_publish(const char* node_url, const char* channel_id_hex, const char* signing_key_hex,
                   const char* data, const char* checkpoint_path);

// Query inscriptions from a zone channel.
// Returns JSON array string: [{"id":"hex","data":"text"}, ...] or NULL on error.
// Caller must free with zone_free_string().
char* zone_query_channel(const char* node_url, const char* channel_id_hex, int limit);

// Derive the 64-char hex channel ID from a signing key without publishing.
// Returns heap-allocated 64-char hex channel ID, or NULL on error.
// Caller must free with zone_free_string().
char* zone_derive_channel_id(const char* signing_key_hex);

// Query inscriptions from a zone channel with cursor-based pagination for full history backfill.
// cursor_json: JSON cursor from previous call, or NULL to start from genesis.
// Returns JSON object: {"messages":[...],"cursor":{...},"cursor_slot":N,"lib_slot":N,"done":bool}
// or NULL on error. Caller must free with zone_free_string().
// "done" is true when cursor_slot >= lib_slot (all finalized history scanned).
char* zone_query_channel_paged(const char* node_url, const char* channel_id_hex, const char* cursor_json, int limit);

// ── Persistent sequencer handle (preferred over stateless zone_publish) ──────

// Create a persistent sequencer. The background actor connects to the node
// and stays alive until zone_sequencer_destroy is called. Checkpoint is
// validated against channel_id via a .channel sidecar file.
// Returns opaque handle, or NULL on error.
void* zone_sequencer_create(const char* node_url, const char* channel_id_hex,
                            const char* signing_key_hex, const char* checkpoint_path);

// Publish data using an existing sequencer handle.
// Returns hex inscription ID (caller must free with zone_free_string), or NULL on error.
char* zone_sequencer_publish(void* handle, const char* data);

// Get current checkpoint as JSON string. Caller must free with zone_free_string.
char* zone_sequencer_checkpoint(void* handle);

// Destroy a sequencer handle. Stops the background actor.
void zone_sequencer_destroy(void* handle);

// Free a string returned by any zone_* function that returns char*.
void zone_free_string(char* s);

#ifdef __cplusplus
}
#endif
