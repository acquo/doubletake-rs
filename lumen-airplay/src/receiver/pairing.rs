//! Receiver-side pairing: SRP-6a pair-setup (server role), HAP pair-verify, and
//! the ChaCha20-Poly1305 HAP control-channel stream. Ported from
//! `internal/airplay/receiver_pairing.go`.

use crate::pairing::{
    hkdf_sha512, pad_to, sha512, srp_g, srp_n, x25519_base, x25519_shared,
};
use crate::tlv8 as tlv;
use crate::tlv8::Tlv8Item;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

const TLV_METHOD: u8 = 0x00;
const TLV_IDENTIFIER: u8 = 0x01;
const TLV_SALT: u8 = 0x02;
const TLV_PUBLIC_KEY: u8 = 0x03;
const TLV_PROOF: u8 = 0x04;
const TLV_ENCRYPTED_DATA: u8 = 0x05;
const TLV_STATE: u8 = 0x06;
const TLV_ERROR: u8 = 0x07;
const TLV_SIGNATURE: u8 = 0x0A;
const TLV_FLAGS: u8 = 0x13;

const PAIR_FLAG_TRANSIENT: u32 = 0x0000_0010;
const AUTH_ERROR: u8 = 0x02;

#[derive(Debug, Clone, Default)]
pub struct SessionKeys {
    pub shared_secret: Vec<u8>,
    pub read_key: Vec<u8>,
    pub write_key: Vec<u8>,
    pub encrypted: bool,
}

struct SrpSetupState {
    salt: Vec<u8>,
    b: Vec<u8>,
    v: Vec<u8>,
    server_pub: Vec<u8>,
    shared_key: Option<Vec<u8>>,
    transient: bool,
}

struct HapVerifyState {
    client_public: Vec<u8>,
    server_public: Vec<u8>,
    shared_secret: Vec<u8>,
    verify_key: Vec<u8>,
}

pub struct ReceiverPairing {
    identifier: Vec<u8>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// SRP "username": the receiver's deviceID, which Apple clients use as the
    /// SRP username (not the literal "Pair-Setup").
    username: String,
    pin: String,
    controllers: HashMap<String, Vec<u8>>,
    transient: HashMap<String, Vec<u8>>,
    setup: Option<SrpSetupState>,
    verify: Option<HapVerifyState>,
    session: SessionKeys,
    verified: bool,
}

impl ReceiverPairing {
    pub fn new(identifier: &str, username: &str, signing_key: SigningKey, pin: &str) -> Self {
        let verifying_key = signing_key.verifying_key();
        ReceiverPairing {
            identifier: identifier.as_bytes().to_vec(),
            signing_key,
            verifying_key,
            username: username.to_string(),
            pin: pin.to_string(),
            controllers: HashMap::new(),
            transient: HashMap::new(),
            setup: None,
            verify: None,
            session: SessionKeys::default(),
            verified: false,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        self.verifying_key.as_bytes()
    }

    pub fn session_keys(&self) -> Option<SessionKeys> {
        if !self.verified {
            return None;
        }
        Some(SessionKeys {
            shared_secret: self.session.shared_secret.clone(),
            read_key: self.session.read_key.clone(),
            write_key: self.session.write_key.clone(),
            encrypted: self.session.encrypted,
        })
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Handles one /pair-setup message. Returns the response body.
    pub fn pair_setup(&mut self, body: &[u8]) -> Vec<u8> {
        if body.len() == 32 {
            // raw legacy exchange (no PIN): echoes our public key.
            if !self.pin.is_empty() {
                return tlv_err(4);
            }
            self.reset();
            return self.verifying_key.as_bytes().to_vec();
        }
        let message = tlv::decode(body);
        let state = match message.get(&TLV_STATE) {
            Some(v) if v.len() == 1 => v[0],
            _ => return tlv_err(4),
        };
        match state {
            1 => self.begin_srp_setup(&message),
            3 => self.verify_srp_proof(&message),
            5 => self.finish_srp_setup(&message),
            _ => tlv_err(4),
        }
    }

    fn begin_srp_setup(&mut self, msg: &HashMap<u8, Vec<u8>>) -> Vec<u8> {
        // Accept the SRP setup methods Apple clients send: 0 = with PIN, 1 =
        // "PairSetupWithPK" (no PIN), 3 = legacy no-PIN. Only reject bad ones.
        if let Some(m) = msg.get(&TLV_METHOD) {
            if m.len() != 1 || !matches!(m[0], 0 | 1 | 3) {
                return tlv_err(2);
            }
        } else {
            return tlv_err(2);
        }
        let mut transient = false;
        if let Some(flags) = msg.get(&TLV_FLAGS) {
            // Apple sends flags as a varying-width integer; accept 1 or 4 bytes
            // and detect the transient (no-PIN) pairing bit.
            let is_transient = match flags.len() {
                1 => flags[0] & PAIR_FLAG_TRANSIENT as u8 != 0,
                4 => u32::from_le_bytes(flags[..4].try_into().unwrap()) & PAIR_FLAG_TRANSIENT != 0,
                _ => return tlv_err(2),
            };
            if !is_transient {
                return tlv_err(2);
            }
            transient = true;
        }
        if transient && !self.pin.is_empty() {
            return tlv_err(2);
        }
        self.reset();

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);

        let pin = if transient { "" } else { self.pin.as_str() };
        let x = bigint(&srp_x(&salt, &self.username, pin));
        let n = srp_n();
        let g = srp_g();
        let v = g.modpow(&x, &n);
        let k = srp_multiplier();
        let server_pub = (((k * &v) % &n) + g.modpow(&bigint(&b.to_vec()), &n)) % &n;

        self.setup = Some(SrpSetupState {
            salt: salt.to_vec(),
            b: b.to_vec(),
            v: v.to_bytes_be(),
            server_pub: server_pub.to_bytes_be(),
            shared_key: None,
            transient,
        });
        tlv::encode_ordered(&[
            Tlv8Item::new(TLV_STATE, vec![2]),
            Tlv8Item::new(TLV_SALT, salt.to_vec()),
            Tlv8Item::new(TLV_PUBLIC_KEY, pad_to(&server_pub.to_bytes_be(), 384)),
        ])
    }

    fn verify_srp_proof(&mut self, msg: &HashMap<u8, Vec<u8>>) -> Vec<u8> {
        let (salt, b, v, server_pub) = match &self.setup {
            Some(s) if s.shared_key.is_none() => {
                (s.salt.clone(), s.b.clone(), s.v.clone(), s.server_pub.clone())
            }
            _ => return tlv_err(4),
        };
        let client_pub = match msg.get(&TLV_PUBLIC_KEY) {
            Some(v) if v.len() == 384 => v.clone(),
            _ => {
                self.setup = None;
                return tlv_err(4);
            }
        };
        let client_proof = match msg.get(&TLV_PROOF) {
            Some(v) if v.len() == 64 => v.clone(),
            _ => {
                self.setup = None;
                return tlv_err(4);
            }
        };

        let n = srp_n();
        let cp_int = bigint(&client_pub);
        let s_pub_int = bigint(&server_pub);
        let u = bigint(&sha512(&[pad_to(&client_pub, 384), pad_to(&server_pub, 384)].concat()));
        if u == bigint(&[0u8]) {
            self.setup = None;
            return tlv_err(4);
        }
        let vu = bigint(&v).modpow(&u, &n);
        let base = (cp_int.clone() * vu) % &n;
        let shared = base.modpow(&bigint(&b), &n);
        let shared_key: Vec<u8> = sha512(&shared.to_bytes_be()).to_vec();
        let want = srp_client_proof(&salt, &cp_int, &s_pub_int, &shared_key);
        log::debug!("[pair] SRP M3 salt={} client_pub={:x?} server_pub={:x?}", hex(&salt), &client_pub[..8], &server_pub[..8]);
        log::debug!("[pair] SRP M3 want={} got={}", hex(&want), hex(&client_proof));
        if want != client_proof {
            self.setup = None;
            return tlv_err(4);
        }
        if let Some(s) = self.setup.as_mut() {
            s.shared_key = Some(shared_key.clone());
        }
        let server_proof = sha512(&[client_pub.clone(), want, shared_key].concat());
        tlv::encode_ordered(&[
            Tlv8Item::new(TLV_STATE, vec![4]),
            Tlv8Item::new(TLV_PROOF, server_proof),
        ])
    }

    fn finish_srp_setup(&mut self, msg: &HashMap<u8, Vec<u8>>) -> Vec<u8> {
        let shared_key = match &self.setup {
            Some(s) if s.shared_key.is_some() => s.shared_key.clone().unwrap(),
            _ => return tlv_err(6),
        };
        let encrypted = match msg.get(&TLV_ENCRYPTED_DATA) {
            Some(v) if v.len() >= 16 => v.clone(),
            _ => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        let session_key = hkdf_sha512(&shared_key, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info", 32);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
        let plain = match cipher.decrypt(Nonce::from_slice(&nonce("PS-Msg05")), encrypted.as_ref()) {
            Ok(p) => p,
            Err(_) => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        let identity = tlv::decode(&plain);
        let identifier = match identity.get(&TLV_IDENTIFIER) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        let pubkey = match identity.get(&TLV_PUBLIC_KEY) {
            Some(v) if v.len() == 32 => v.clone(),
            _ => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        let sig = match identity.get(&TLV_SIGNATURE) {
            Some(v) if v.len() == 64 => v.clone(),
            _ => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        let sign_key = hkdf_sha512(&shared_key, b"Pair-Setup-Controller-Sign-Salt", b"Pair-Setup-Controller-Sign-Info", 32);
        let signed = [sign_key, identifier.clone(), pubkey.clone()].concat();
        let pk_arr: [u8; 32] = match pubkey[..].try_into() {
            Ok(a) => a,
            Err(_) => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        let vk = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(v) => v,
            Err(_) => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        let s = match Signature::from_slice(&sig) {
            Ok(s) => s,
            Err(_) => {
                self.setup = None;
                return tlv_err(6);
            }
        };
        if vk.verify_strict(&signed, &s).is_err() {
            self.setup = None;
            return tlv_err(6);
        }
        let controller_id = String::from_utf8_lossy(&identifier).to_string();
        if self.setup.as_ref().map(|s| s.transient).unwrap_or(false) {
            self.transient.insert(controller_id, pubkey);
        } else {
            self.controllers.insert(controller_id, pubkey);
        }

        let acc_sign_key = hkdf_sha512(&shared_key, b"Pair-Setup-Accessory-Sign-Salt", b"Pair-Setup-Accessory-Sign-Info", 32);
        let acc_signed = [acc_sign_key, self.identifier.clone(), self.verifying_key.as_bytes().to_vec()].concat();
        let acc_sig = self.signing_key.sign(&acc_signed).to_bytes();
        let response_identity = tlv::encode_ordered(&[
            Tlv8Item::new(TLV_IDENTIFIER, self.identifier.clone()),
            Tlv8Item::new(TLV_PUBLIC_KEY, self.verifying_key.as_bytes().to_vec()),
            Tlv8Item::new(TLV_SIGNATURE, acc_sig.to_vec()),
        ]);
        let response_enc = cipher
            .encrypt(Nonce::from_slice(&nonce("PS-Msg06")), response_identity.as_slice())
            .unwrap_or_default();
        self.setup = None;
        tlv::encode_ordered(&[
            Tlv8Item::new(TLV_STATE, vec![6]),
            Tlv8Item::new(TLV_ENCRYPTED_DATA, response_enc),
        ])
    }

    /// Handles one /pair-verify message. Returns (response_body, session_keys to
    /// enable HAP encryption, session_keys are Some only on the final exchange).
    pub fn pair_verify(&mut self, body: &[u8]) -> (Vec<u8>, Option<SessionKeys>) {
        let message = tlv::decode(body);
        let state = match message.get(&TLV_STATE) {
            Some(v) if v.len() == 1 => v[0],
            _ => return (tlv_err(2), None),
        };
        match state {
            1 => (self.begin_hap_verify(&message), None),
            3 => {
                let resp = self.finish_hap_verify(&message);
                if self.is_verified() {
                    let keys = self.session_keys().unwrap();
                    (resp, Some(keys))
                } else {
                    (resp, None)
                }
            }
            _ => (tlv_err(2), None),
        }
    }

    fn begin_hap_verify(&mut self, msg: &HashMap<u8, Vec<u8>>) -> Vec<u8> {
        let client_public = match msg.get(&TLV_PUBLIC_KEY) {
            Some(v) if v.len() == 32 => v.clone(),
            _ => return tlv_err(2),
        };
        self.reset_verify();

        let mut server_private = [0u8; 32];
        OsRng.fill_bytes(&mut server_private);
        let server_public = x25519_base(server_private);
        let shared = x25519_shared(server_private, client_public[..32].try_into().unwrap());
        let verify_key = hkdf_sha512(&shared, b"Pair-Verify-Encrypt-Salt", b"Pair-Verify-Encrypt-Info", 32);

        let signed = [server_public.to_vec(), self.identifier.clone(), client_public.clone()].concat();
        let signature = self.signing_key.sign(&signed).to_bytes();
        let identity = tlv::encode_ordered(&[
            Tlv8Item::new(TLV_IDENTIFIER, self.identifier.clone()),
            Tlv8Item::new(TLV_SIGNATURE, signature.to_vec()),
        ]);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&verify_key));
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce("PV-Msg02")), identity.as_slice())
            .unwrap_or_default();

        self.verify = Some(HapVerifyState {
            client_public: client_public.clone(),
            server_public: server_public.to_vec(),
            shared_secret: shared.to_vec(),
            verify_key: verify_key.clone(),
        });
        tlv::encode_ordered(&[
            Tlv8Item::new(TLV_STATE, vec![2]),
            Tlv8Item::new(TLV_PUBLIC_KEY, server_public),
            Tlv8Item::new(TLV_ENCRYPTED_DATA, encrypted),
        ])
    }

    fn finish_hap_verify(&mut self, msg: &HashMap<u8, Vec<u8>>) -> Vec<u8> {
        let verify = match &self.verify {
            Some(v) => v,
            None => return tlv_err(4),
        };
        let encrypted = match msg.get(&TLV_ENCRYPTED_DATA) {
            Some(v) if v.len() >= 16 => v.clone(),
            _ => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&verify.verify_key));
        let plain = match cipher.decrypt(Nonce::from_slice(&nonce("PV-Msg03")), encrypted.as_ref()) {
            Ok(p) => p,
            Err(_) => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        let identity = tlv::decode(&plain);
        let identifier = match identity.get(&TLV_IDENTIFIER) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        let signature = match identity.get(&TLV_SIGNATURE) {
            Some(v) if v.len() == 64 => v.clone(),
            _ => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        let controller_id = String::from_utf8_lossy(&identifier).to_string();
        let controller_key = self
            .transient
            .get(&controller_id)
            .or_else(|| self.controllers.get(&controller_id))
            .cloned();
        let controller_key = match controller_key {
            Some(k) => k,
            None => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        let signed = [verify.client_public.clone(), identifier.clone(), verify.server_public.clone()].concat();
        let ck_arr: [u8; 32] = match controller_key[..].try_into() {
            Ok(a) => a,
            Err(_) => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        let vk = match VerifyingKey::from_bytes(&ck_arr) {
            Ok(v) => v,
            Err(_) => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        let s = match Signature::from_slice(&signature) {
            Ok(s) => s,
            Err(_) => {
                self.verify = None;
                return tlv_err(4);
            }
        };
        if vk.verify_strict(&signed, &s).is_err() {
            self.verify = None;
            return tlv_err(4);
        }

        let shared = verify.shared_secret.clone();
        self.session = SessionKeys {
            shared_secret: shared.clone(),
            read_key: hkdf_sha512(&shared, b"Control-Salt", b"Control-Write-Encryption-Key", 32),
            write_key: hkdf_sha512(&shared, b"Control-Salt", b"Control-Read-Encryption-Key", 32),
            encrypted: true,
        };
        self.verified = true;
        self.verify = None;
        tlv::encode_ordered(&[Tlv8Item::new(TLV_STATE, vec![4])])
    }

    fn reset(&mut self) {
        self.reset_verify();
        self.setup = None;
        let _ = &self.verify;
    }
    fn reset_verify(&mut self) {
        self.verify = None;
        self.session = SessionKeys::default();
        self.verified = false;
    }
}

// ---------- HAP (ChaCha20-Poly1305) control-channel stream ----------

pub struct HapStream {
    conn: TcpStream,
    read_cipher: ChaCha20Poly1305,
    write_cipher: ChaCha20Poly1305,
    read_nonce: u64,
    write_nonce: u64,
    read_buf: Vec<u8>,
}

impl HapStream {
    pub fn new(conn: TcpStream, read_key: &[u8], write_key: &[u8]) -> std::io::Result<Self> {
        let read_cipher = ChaCha20Poly1305::new(Key::from_slice(read_key));
        let write_cipher = ChaCha20Poly1305::new(Key::from_slice(write_key));
        Ok(HapStream {
            conn,
            read_cipher,
            write_cipher,
            read_nonce: 0,
            write_nonce: 0,
            read_buf: Vec::new(),
        })
    }

    fn nonce(counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&counter.to_le_bytes());
        n
    }
}

impl Read for HapStream {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if self.read_buf.is_empty() {
            let mut size_bytes = [0u8; 2];
            self.conn.read_exact(&mut size_bytes)?;
            let size = u16::from_le_bytes(size_bytes) as usize;
            if size < 1 || size > 1024 {
                return Err(std::io::Error::other(format!("invalid HAP frame size {size}")));
            }
            let mut sealed = vec![0u8; size + 16];
            self.conn.read_exact(&mut sealed)?;
            let plain = self
                .read_cipher
                .decrypt(
                    Nonce::from_slice(&Self::nonce(self.read_nonce)),
                    Payload {
                        msg: sealed.as_slice(),
                        aad: &size_bytes,
                    },
                )
                .map_err(|_| std::io::Error::other("HAP frame decrypt failed"))?;
            self.read_nonce += 1;
            self.read_buf = plain;
        }
        let n = dst.len().min(self.read_buf.len());
        dst[..n].copy_from_slice(&self.read_buf[..n]);
        self.read_buf.drain(..n);
        Ok(n)
    }
}

impl Write for HapStream {
    fn write(&mut self, plain: &[u8]) -> std::io::Result<usize> {
        let total = plain.len();
        let mut offset = 0;
        while offset < plain.len() {
            let chunk = &plain[offset..(offset + 1024).min(plain.len())];
            let size_bytes = (chunk.len() as u16).to_le_bytes();
            let mut frame = size_bytes.to_vec();
            let sealed = self
                .write_cipher
                .encrypt(
                    Nonce::from_slice(&Self::nonce(self.write_nonce)),
                    Payload {
                        msg: chunk,
                        aad: &size_bytes,
                    },
                )
                .map_err(|_| std::io::Error::other("HAP frame encrypt failed"))?;
            frame.extend_from_slice(&sealed);
            self.conn.write_all(&frame)?;
            self.write_nonce += 1;
            offset += chunk.len();
        }
        Ok(total)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.conn.flush()
    }
}

// ---------- helpers ----------

fn nonce(label: &str) -> [u8; 12] {
    let mut n = [0u8; 12];
    let b = label.as_bytes();
    let l = b.len().min(8);
    n[4..4 + l].copy_from_slice(&b[..l]);
    n
}

fn tlv_err(state: u8) -> Vec<u8> {    tlv::encode_ordered(&[
        Tlv8Item::new(TLV_STATE, vec![state]),
        Tlv8Item::new(TLV_ERROR, vec![AUTH_ERROR]),
    ])
}

fn bigint(b: &[u8]) -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_be(b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("")
}

fn srp_x(salt: &[u8], username: &str, pin: &str) -> Vec<u8> {
    let inner = sha512(format!("{username}:{pin}").as_bytes());
    sha512(&[salt.to_vec(), inner.to_vec()].concat()).to_vec()
}

fn srp_multiplier() -> num_bigint::BigUint {
    bigint(&sha512(&[pad_to(&srp_n().to_bytes_be(), 384), pad_to(&srp_g().to_bytes_be(), 384)].concat()))
}

fn srp_client_proof(
    salt: &[u8],
    client_public: &num_bigint::BigUint,
    server_public: &num_bigint::BigUint,
    shared_key: &[u8],
) -> Vec<u8> {
    let hash_n = sha512(&srp_n().to_bytes_be());
    let hash_g = sha512(&srp_g().to_bytes_be());
    let mut xor = [0u8; 64];
    for i in 0..64 {
        xor[i] = hash_n[i] ^ hash_g[i];
    }
    sha512(&[
        xor.to_vec(),
        sha512(b"Pair-Setup").to_vec(),
        salt.to_vec(),
        client_public.to_bytes_be(),
        server_public.to_bytes_be(),
        shared_key.to_vec(),
    ]
    .concat())
    .to_vec()
}
