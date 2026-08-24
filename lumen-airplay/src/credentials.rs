//! Persistent pairing credentials, mirroring `credentials.go` from upstream.
//!
//! Stored as a JSON file keyed by receiver deviceID, in exactly the same shape
//! the Go implementation writes, so existing
//! `~/.config/lumen/credentials.json` files keep working:
//!
//! ```json
//! {
//!   "<deviceID>": {
//!     "pairing_id": "…",
//!     "ed25519_public": "<base64>",
//!     "ed25519_seed": "<base64>",
//!     "restore_token": "…"
//!   }
//! }
//! ```
//!
//! Go's `encoding/json` encodes `[]byte` as standard (padded) base64; the
//! `restore_token` field is omitted when empty.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SEED_SIZE: usize = 32;

/// Saved pairing credentials for a single device.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SavedCredentials {
    #[serde(rename = "pairing_id", default)]
    pub pairing_id: String,
    #[serde(
        rename = "ed25519_public",
        default,
        serialize_with = "ser_base64",
        deserialize_with = "de_base64"
    )]
    pub ed25519_public: Vec<u8>,
    #[serde(
        rename = "ed25519_seed",
        default,
        serialize_with = "ser_base64",
        deserialize_with = "de_base64"
    )]
    pub ed25519_seed: Vec<u8>,
    #[serde(
        rename = "restore_token",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub restore_token: String,
}

impl SavedCredentials {
    /// Whether the saved entry contains a usable AirPlay pairing identity.
    pub fn has_pairing_credentials(&self) -> bool {
        !self.pairing_id.is_empty()
            && self.ed25519_public.len() == ED25519_PUBLIC_KEY_SIZE
            && self.ed25519_seed.len() == ED25519_SEED_SIZE
    }
}

fn ser_base64<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&BASE64.encode(bytes))
}

fn de_base64<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(de)?;
    BASE64
        .decode(s)
        .map_err(|e| serde::de::Error::custom(format!("invalid base64: {e}")))
}

/// A per-device credential store backed by a JSON file.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    path: PathBuf,
    devices: HashMap<String, SavedCredentials>,
}

impl CredentialStore {
    /// Loads (or creates) the store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let devices = if path.exists() {
            let data = fs::read(&path).map_err(|e| format!("read credential store: {e}"))?;
            serde_json::from_slice(&data)
                .map_err(|e| format!("unmarshal credential store: {e}"))?
        } else {
            HashMap::new()
        };
        Ok(CredentialStore { path, devices })
    }

    /// Returns the default path `~/.config/lumen/credentials.json`.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".into());
        Path::new(&home).join(".config").join("lumen").join("credentials.json")
    }

    /// Looks up saved credentials for a device, or `None`.
    pub fn lookup(&self, device_id: &str) -> Option<&SavedCredentials> {
        self.devices.get(device_id)
    }

    /// Number of stored credential entries.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Stores pairing credentials for a device, persisting to disk.
    pub fn save(
        &mut self,
        device_id: &str,
        pairing_id: &str,
        public: &[u8],
        seed: &[u8],
    ) -> Result<(), String> {
        let creds = self.devices.entry(device_id.to_string()).or_default();
        creds.pairing_id = pairing_id.to_string();
        creds.ed25519_public = public.to_vec();
        creds.ed25519_seed = seed.to_vec();
        self.persist()
    }

    /// Stores a Wayland screencast restore token for a device.
    pub fn save_restore_token(&mut self, device_id: &str, token: &str) -> Result<(), String> {
        if token.is_empty() {
            return Ok(());
        }
        let creds = self.devices.entry(device_id.to_string()).or_default();
        creds.restore_token = token.to_string();
        self.persist()
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("create credential dir: {e}"))?;
        }
        let data = serde_json::to_string_pretty(&self.devices)
            .map_err(|e| format!("marshal credential store: {e}"))?;
        fs::write(&self.path, data).map_err(|e| format!("write credential store: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_credentials() {
        let dir = std::env::temp_dir().join(format!("dt-cred-test-{}", std::process::id()));
        let path = dir.join("credentials.json");
        let _ = fs::remove_dir_all(&dir);

        let mut store = CredentialStore::new(&path).expect("create store");
        store
            .save("AA:BB", "pair-1", &[7u8; 32], &[9u8; 32])
            .expect("save");
        store.save_restore_token("AA:BB", "tok-123").expect("save token");

        let reloaded = CredentialStore::new(&path).expect("reload store");
        let creds = reloaded.lookup("AA:BB").expect("lookup");
        assert_eq!(creds.pairing_id, "pair-1");
        assert_eq!(creds.ed25519_public, vec![7u8; 32]);
        assert_eq!(creds.ed25519_seed, vec![9u8; 32]);
        assert_eq!(creds.restore_token, "tok-123");
        assert!(creds.has_pairing_credentials());
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.lookup("NOPE").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    /// Proves Go compatibility: the JSON we write uses standard padded base64
    /// and omits restore_token when empty.
    #[test]
    fn json_shape_matches_go() {
        let mut store = CredentialStore::new(std::env::temp_dir().join("dt-cred-shape.json"))
            .expect("create");
        store
            .save("DD:EE", "p", &[0x01, 0x02, 0x03, 0x04], &[0xaa, 0xbb])
            .expect("save");
        // Go would write: {"DD:EE":{"pairing_id":"p","ed25519_public":"AQIDBA==","ed25519_seed":"qrs="}}
        let json = serde_json::to_string_pretty(&store.devices).expect("json");
        assert!(json.contains("\"ed25519_public\": \"AQIDBA==\""));
        assert!(json.contains("\"ed25519_seed\": \"qrs=\""));
        assert!(!json.contains("restore_token"));
    }
}
