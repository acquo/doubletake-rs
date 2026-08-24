//! AirPlay pairing — SRP-6a PIN pairing, pair-verify, and raw (legacy)
//! pairing, ported from upstream `pairing.go`.
//!
//! All cryptographic pieces are pure functions so they can be validated
//! against a mock receiver in tests and against the real Go test receiver in
//! interop tests.

use crate::error::{Error, Result};
use crate::info::ReceiverInfo;
use crate::tlv8::{self, Tlv8Item};
use crate::transport::Transport;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

/// X-Apple-HKP pairing types used by current Apple senders.
pub const PAIRING_TYPE_LEGACY: u8 = 3;
pub const PAIRING_TYPE_TRANSIENT: u8 = 4;
pub const PAIRING_TYPE_SCREEN_CAPTURE: u8 = 5;

/// Bit 4: ephemeral/transient pairing flag.
pub const PAIRING_FLAG_TRANSIENT: u32 = 0x0000_0010;

pub const DEFAULT_PAIRING_CLIENT_NAME: &str = "doubletake device";

/// OPACK encoding of `{"com.apple.ScreenCapture": true}`. Apple includes this
/// access request in pair-setup M5 for X-Apple-HKP type 5, and current
/// receivers reject a screen-capture identity that omits it.
pub const SCREEN_CAPTURE_ACL: &[u8] = b"\xe1\x57com.apple.ScreenCapture\x01";

/// SRP-6a parameters (3072-bit group from RFC 5054).
const SRP_N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

fn srp_n() -> BigUint {
    BigUint::parse_bytes(SRP_N_HEX.as_bytes(), 16).expect("valid SRP N")
}

fn srp_g() -> BigUint {
    BigUint::from(5u8)
}

fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// Pads data with leading zeros to `size` bytes.
pub fn pad_to(data: &[u8], size: usize) -> Vec<u8> {
    if data.len() >= size {
        return data.to_vec();
    }
    let mut padded = vec![0u8; size];
    padded[size - data.len()..].copy_from_slice(data);
    padded
}

/// HKDF-SHA-512 key derivation.
pub fn hkdf_sha512(secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::new(Some(salt), secret);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

/// A 12-byte ChaCha20 nonce: four zero bytes followed by a 8-byte tag.
fn chacha_nonce(tag: &[u8; 8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(tag);
    nonce
}

/// SHA-512(salt || secret)[:16], used by the raw (AirMyPC) pair-verify.
fn sha512_derive_key(salt: &[u8], secret: &[u8]) -> [u8; 16] {
    let mut h = Sha512::new();
    h.update(salt);
    h.update(secret);
    let mut key = [0u8; 16];
    key.copy_from_slice(&h.finalize()[..16]);
    key
}

/// X25519 private-key clamping, matching Go's `curve25519` package.
fn clamp_scalar(mut b: [u8; 32]) -> [u8; 32] {
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
    b
}

/// X25519 base-point multiplication (matches Go's `ScalarBaseMult`).
fn x25519_base(secret: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(secret).to_bytes()
}

/// X25519 Diffie-Hellman shared secret (matches Go's `curve25519.X25519`).
fn x25519_shared(secret: [u8; 32], their_public: [u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(clamp_scalar(secret));
    let point = MontgomeryPoint(their_public);
    (&scalar * &point).to_bytes()
}

/// AES-128-CTR keystream XOR starting at `offset` bytes into the stream.
fn ctr_xor(key: &[u8; 16], iv: &[u8; 16], offset: usize, input: &[u8], output: &mut [u8]) {
    use aes::Aes128;
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;

    let mut cipher = Ctr128BE::<Aes128>::new(key.into(), iv.into());
    let mut skip = vec![0u8; offset];
    cipher.apply_keystream(&mut skip);
    output.copy_from_slice(input);
    cipher.apply_keystream(output);
}

// ---------------------------------------------------------------------------
// SRP-6a math (client side)
// ---------------------------------------------------------------------------

/// x = H(salt, H(username, ":", password))
fn srp_x(username: &[u8], password: &[u8], salt: &[u8]) -> BigUint {
    let mut inner = Vec::with_capacity(username.len() + 1 + password.len());
    inner.extend_from_slice(username);
    inner.push(b':');
    inner.extend_from_slice(password);
    let inner_hash = sha512(&inner);

    let mut x_input = Vec::with_capacity(salt.len() + 64);
    x_input.extend_from_slice(salt);
    x_input.extend_from_slice(&inner_hash);
    BigUint::from_bytes_be(&sha512(&x_input))
}

/// k = H(N, pad(g))
fn srp_k() -> BigUint {
    let n = srp_n();
    let g = srp_g();
    let mut input = pad_to(&n.to_bytes_be(), 384);
    input.extend_from_slice(&pad_to(&g.to_bytes_be(), 384));
    BigUint::from_bytes_be(&sha512(&input))
}

/// A = g^a mod N
fn srp_client_public(a: &BigUint) -> BigUint {
    srp_g().modpow(a, &srp_n())
}

/// u = H(pad(A, 384), pad(B, 384))
fn srp_u(client_public: &[u8], server_public: &[u8]) -> BigUint {
    let mut input = pad_to(client_public, 384);
    input.extend_from_slice(&pad_to(server_public, 384));
    BigUint::from_bytes_be(&sha512(&input))
}

/// S = (B - k·g^x mod N)^(a + u·x) mod N
fn srp_shared_secret(server_b: &[u8], a: &BigUint, x: &BigUint, u: &BigUint) -> BigUint {
    let n = srp_n();
    let b = BigUint::from_bytes_be(server_b);
    let gx = srp_g().modpow(x, &n);
    let kgx = (srp_k() * gx) % &n;
    let diff = if b >= kgx { b - kgx } else { (b + &n) - kgx };
    let exp = u * x + a;
    diff.modpow(&exp, &n)
}

/// K = H(S), using S's natural (unpadded) byte representation.
fn srp_session_key(s: &BigUint) -> [u8; 64] {
    sha512(&s.to_bytes_be())
}

/// M1 proof = H(H(N) XOR H(g), H(I), s, A, B, K)
fn srp_client_proof(
    username: &[u8],
    salt: &[u8],
    client_public: &[u8],
    server_public: &[u8],
    k: &[u8; 64],
) -> [u8; 64] {
    let hn = sha512(&srp_n().to_bytes_be());
    let hg = sha512(&srp_g().to_bytes_be());
    let mut hxor = [0u8; 64];
    for i in 0..64 {
        hxor[i] = hn[i] ^ hg[i];
    }
    let hu = sha512(username);

    let mut input = Vec::new();
    input.extend_from_slice(&hxor);
    input.extend_from_slice(&hu);
    input.extend_from_slice(salt);
    input.extend_from_slice(client_public);
    input.extend_from_slice(server_public);
    input.extend_from_slice(k);
    sha512(&input)
}

/// Server proof = H(A, M1, K)
fn srp_server_proof(client_public: &[u8], client_proof: &[u8; 64], k: &[u8; 64]) -> [u8; 64] {
    let mut input = Vec::new();
    input.extend_from_slice(client_public);
    input.extend_from_slice(client_proof);
    input.extend_from_slice(k);
    sha512(&input)
}

// ---------------------------------------------------------------------------
// Session state and pairing flows
// ---------------------------------------------------------------------------

/// Long-term and session keys from pairing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PairKeys {
    pub ed25519_public: Vec<u8>,
    pub ed25519_seed: Vec<u8>, // 32-byte seed; private key is derived from it
    pub shared_secret: Vec<u8>,
    pub write_key: Vec<u8>,
    pub read_key: Vec<u8>,
}

/// State for one pairing exchange with a receiver.
#[derive(Debug, Clone)]
pub struct PairingSession {
    pub pairing_id: String,
    pub pair_type: u8,
    pub keys: PairKeys,
    pub info: Option<ReceiverInfo>,
    pub encrypted: bool,
    pub enc_write_key: Vec<u8>,
    pub enc_read_key: Vec<u8>,
}

impl PairingSession {
    pub fn new(pairing_id: String) -> Self {
        PairingSession {
            pairing_id,
            pair_type: PAIRING_TYPE_SCREEN_CAPTURE,
            keys: PairKeys::default(),
            info: None,
            encrypted: false,
            enc_write_key: Vec::new(),
            enc_read_key: Vec::new(),
        }
    }

    pub fn with_info(pairing_id: String, info: ReceiverInfo) -> Self {
        let mut s = PairingSession::new(pairing_id);
        s.info = Some(info);
        s
    }

    fn signing_key(&self) -> Result<SigningKey> {
        let seed: [u8; 32] = self
            .keys
            .ed25519_seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protocol("ed25519 seed is not 32 bytes".into()))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    fn generate_ed25519(&mut self) {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        self.keys.ed25519_seed = seed.to_vec();
        self.keys.ed25519_public = signing.verifying_key().to_bytes().to_vec();
    }

    fn effective_pair_type(&self) -> u8 {
        if self.info.as_ref().map_or(false, ReceiverInfo::prefers_legacy_pairing) {
            PAIRING_TYPE_LEGACY
        } else if self.pair_type == 0 {
            PAIRING_TYPE_SCREEN_CAPTURE
        } else {
            self.pair_type
        }
    }

    fn transient_pairing_type(&self) -> u8 {
        if self.info.as_ref().map_or(false, ReceiverInfo::prefers_legacy_pairing) {
            PAIRING_TYPE_LEGACY
        } else {
            PAIRING_TYPE_TRANSIENT
        }
    }

    fn pin_pairing_type(&self) -> u8 {
        if self.info.as_ref().map_or(false, ReceiverInfo::prefers_legacy_pairing) {
            PAIRING_TYPE_LEGACY
        } else {
            PAIRING_TYPE_SCREEN_CAPTURE
        }
    }

    /// Headers identifying this sender on Apple pairing requests.
    fn pair_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        if self.effective_pair_type() == PAIRING_TYPE_LEGACY {
            headers.insert("X-Apple-HKP".into(), PAIRING_TYPE_LEGACY.to_string());
            return headers;
        }
        headers.insert("X-Apple-Client-Name".into(), pairing_client_name());
        headers.insert("X-Apple-HKP".into(), self.effective_pair_type().to_string());
        if !self.pairing_id.is_empty() {
            headers.insert("X-Apple-Client-ID".into(), self.pairing_id.clone());
        }
        headers
    }

    /// Headers for a paired-device verification exchange.
    fn pair_verify_headers(&self) -> HashMap<String, String> {
        let mut headers = self.pair_headers();
        if self.effective_pair_type() != PAIRING_TYPE_LEGACY {
            headers.insert("X-Apple-PD".into(), "1".into());
        }
        headers
    }

    /// Headers for pair-pin-start (4-digit PIN kept compatible with plasmoid).
    fn pin_start_headers(&self) -> HashMap<String, String> {
        let mut headers = self.pair_headers();
        if self.effective_pair_type() != PAIRING_TYPE_LEGACY {
            headers.insert("X-Apple-SupportedPINLengths".into(), "4".into());
        }
        headers
    }

    /// Triggers the on-screen PIN display on the receiver.
    pub fn start_pin_display(&mut self, transport: &mut dyn Transport) -> Result<()> {
        self.pair_type = self.pin_pairing_type();
        let resp = transport.request("POST", "/pair-pin-start", "", &[], &self.pin_start_headers())?;
        if resp.status == 453 {
            // Receiver accepted the PIN request asynchronously.
            return Ok(());
        }
        Error::ok_body(Ok(resp)).map(|_| ())
    }

    /// PIN-based pairing: pair-setup (M1–M6) then pair-verify.
    pub fn pair_with_pin(&mut self, transport: &mut dyn Transport, pin: &str) -> Result<()> {
        self.pair_type = self.pin_pairing_type();
        self.generate_ed25519();
        self.pair_setup(transport, pin)?;
        self.pair_verify(transport)
    }

    /// Transient (PIN-less) pairing.
    pub fn pair_transient(&mut self, transport: &mut dyn Transport) -> Result<()> {
        if self.info.as_ref().map_or(false, ReceiverInfo::requires_pin_pairing) {
            return Err(Error::Protocol("receiver requires PIN pairing".into()));
        }
        self.pair_type = self.transient_pairing_type();
        self.generate_ed25519();
        self.perform_transient_setup_and_verify(transport)
    }

    fn perform_transient_setup_and_verify(&mut self, transport: &mut dyn Transport) -> Result<()> {
        let modern_transient = self
            .info
            .as_ref()
            .map_or(false, |i| i.uses_modern_pairing() && i.supports_transient_pairing());
        if modern_transient {
            self.pair_setup_transient(transport)?;
            return self.pair_verify(transport);
        }

        // Raw binary pair-setup (UxPlay / legacy AirPlay protocol) first.
        match self.raw_pair_setup(transport) {
            Ok(server_pub) => {
                let info = self.info.get_or_insert_with(ReceiverInfo::default);
                info.pk = crate::plist_types::PlistData(server_pub.to_vec());
                self.raw_pair_verify(transport)
            }
            Err(_) => {
                self.pair_setup_transient(transport)?;
                self.pair_verify(transport)
            }
        }
    }

    /// Sends the 32-byte Ed25519 public key to /pair-setup, expecting the
    /// receiver's 32-byte Ed25519 public key back (UxPlay-style).
    fn raw_pair_setup(&mut self, transport: &mut dyn Transport) -> Result<Vec<u8>> {
        let resp = Error::ok_body(transport.request(
            "POST",
            "/pair-setup",
            "application/octet-stream",
            &self.keys.ed25519_public,
            &HashMap::new(),
        ))?;
        if resp.len() != 32 {
            return Err(Error::Protocol(format!(
                "pair-setup: expected 32 bytes, got {}",
                resp.len()
            )));
        }
        Ok(resp)
    }

    /// Transient (ephemeral, no-PIN) TLV8 pair-setup.
    fn pair_setup_transient(&mut self, transport: &mut dyn Transport) -> Result<()> {
        let mut flags = [0u8; 4];
        flags.copy_from_slice(&PAIRING_FLAG_TRANSIENT.to_le_bytes());

        let m1 = tlv8::encode_ordered(&[
            Tlv8Item::new(tlv8::TLV_METHOD, vec![0x00]),
            Tlv8Item::new(tlv8::TLV_STATE, vec![0x01]),
            Tlv8Item::new(tlv8::TLV_FLAGS, flags.to_vec()),
        ]);
        let m2_bytes = Error::ok_body(transport.request(
            "POST",
            "/pair-setup",
            "application/octet-stream",
            &m1,
            &self.pair_headers(),
        ))?;
        let m2 = tlv8::decode(&m2_bytes);
        if let Some(err) = m2.get(&tlv8::TLV_ERROR) {
            return Err(Error::Protocol(format!("pair-setup M2 error: {}", err[0])));
        }
        let server_salt = m2
            .get(&tlv8::TLV_SALT)
            .cloned()
            .ok_or_else(|| Error::Protocol("M2: missing salt".into()))?;
        let server_pub = m2
            .get(&tlv8::TLV_PUBLIC_KEY)
            .cloned()
            .ok_or_else(|| Error::Protocol("M2: missing server public key".into()))?;

        // SRP-6a exchange with empty PIN for transient pairing.
        self.complete_srp_exchange(transport, "", &server_salt, &server_pub)
    }

    /// PIN-based TLV8 pair-setup (M1 → M6).
    fn pair_setup(&mut self, transport: &mut dyn Transport, pin: &str) -> Result<()> {
        let m1 = tlv8::encode_ordered(&[
            Tlv8Item::new(tlv8::TLV_METHOD, vec![0x00]),
            Tlv8Item::new(tlv8::TLV_STATE, vec![0x01]),
        ]);
        let m2_bytes = Error::ok_body(transport.request(
            "POST",
            "/pair-setup",
            "application/octet-stream",
            &m1,
            &self.pair_headers(),
        ))?;
        let m2 = tlv8::decode(&m2_bytes);
        if let Some(err) = m2.get(&tlv8::TLV_ERROR) {
            return Err(Error::Protocol(format!("pair-setup M2 error: {}", err[0])));
        }
        let salt = m2
            .get(&tlv8::TLV_SALT)
            .cloned()
            .ok_or_else(|| Error::Protocol("M2: missing salt".into()))?;
        let server_pub_b = m2
            .get(&tlv8::TLV_PUBLIC_KEY)
            .cloned()
            .ok_or_else(|| Error::Protocol("M2: missing public key".into()))?;
        self.complete_srp_exchange(transport, pin, &salt, &server_pub_b)
    }

    /// Finishes SRP from M3 onward (shared by PIN and transient flows).
    fn complete_srp_exchange(
        &mut self,
        transport: &mut dyn Transport,
        pin: &str,
        salt: &[u8],
        server_pub_b: &[u8],
    ) -> Result<()> {
        let username: &[u8] = b"Pair-Setup";
        let password = pin.as_bytes();

        let x = srp_x(username, password, salt);

        let mut a_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let a = if a == BigUint::from(0u8) { BigUint::from(1u8) } else { a };
        let a_pub = srp_client_public(&a);
        let client_public = a_pub.to_bytes_be();

        let b = BigUint::from_bytes_be(server_pub_b);
        if b == BigUint::from(0u8) || b >= srp_n() {
            return Err(Error::Protocol("M2: invalid server public key".into()));
        }
        let server_public = b.to_bytes_be();

        let u = srp_u(&client_public, &server_public);
        let s = srp_shared_secret(server_pub_b, &a, &x, &u);
        let k = srp_session_key(&s);

        let m1_proof = srp_client_proof(username, salt, &client_public, &server_public, &k);

        // M3: client public key + proof.
        let m3 = tlv8::encode_ordered(&[
            Tlv8Item::new(tlv8::TLV_STATE, vec![0x03]),
            Tlv8Item::new(tlv8::TLV_PUBLIC_KEY, pad_to(&client_public, 384)),
            Tlv8Item::new(tlv8::TLV_PROOF, m1_proof.to_vec()),
        ]);
        let m4_bytes = Error::ok_body(transport.request(
            "POST",
            "/pair-setup",
            "application/octet-stream",
            &m3,
            &self.pair_headers(),
        ))?;
        let m4 = tlv8::decode(&m4_bytes);
        if let Some(err) = m4.get(&tlv8::TLV_ERROR) {
            return Err(Error::Protocol(format!("pair-setup M4 error: {}", err[0])));
        }

        // Verify the server proof: H(A, M1, K) with unpadded A.
        let m2_proof_expected = srp_server_proof(&client_public, &m1_proof, &k);
        if let Some(server_proof) = m4.get(&tlv8::TLV_PROOF) {
            if server_proof.as_slice() != m2_proof_expected.as_slice() {
                return Err(Error::Protocol("server proof mismatch".into()));
            }
        }

        // M5: exchange Ed25519 keys over the encrypted channel.
        let session_key =
            hkdf_sha512(&k, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info", 32);
        let sig_key =
            hkdf_sha512(&k, b"Pair-Setup-Controller-Sign-Salt", b"Pair-Setup-Controller-Sign-Info", 32);

        let client_id = self.pairing_id.as_bytes();
        let signing_key = self.signing_key()?;

        let mut sig_input = sig_key;
        sig_input.extend_from_slice(client_id);
        sig_input.extend_from_slice(&self.keys.ed25519_public);
        let signature = signing_key.sign(&sig_input).to_bytes();

        let mut sub_items = vec![
            Tlv8Item::new(tlv8::TLV_IDENTIFIER, client_id.to_vec()),
            Tlv8Item::new(tlv8::TLV_PUBLIC_KEY, self.keys.ed25519_public.clone()),
            Tlv8Item::new(tlv8::TLV_SIGNATURE, signature.to_vec()),
        ];
        if self.effective_pair_type() == PAIRING_TYPE_SCREEN_CAPTURE {
            sub_items.push(Tlv8Item::new(tlv8::TLV_ACL, SCREEN_CAPTURE_ACL.to_vec()));
        }
        let sub_tlv = tlv8::encode_ordered(&sub_items);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
        let nonce = chacha_nonce(b"PS-Msg05");
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), sub_tlv.as_slice())
            .map_err(|e| Error::Crypto(format!("chacha20 seal M5: {e}")))?;

        let m5 = tlv8::encode_ordered(&[
            Tlv8Item::new(tlv8::TLV_ENCRYPTED_DATA, encrypted),
            Tlv8Item::new(tlv8::TLV_STATE, vec![0x05]),
        ]);
        let m6_bytes = Error::ok_body(transport.request(
            "POST",
            "/pair-setup",
            "application/octet-stream",
            &m5,
            &self.pair_headers(),
        ))?;
        let m6 = tlv8::decode(&m6_bytes);
        if let Some(err) = m6.get(&tlv8::TLV_ERROR) {
            return Err(Error::Protocol(format!("pair-setup M6 error: {}", err[0])));
        }

        self.keys.shared_secret = k.to_vec();
        Ok(())
    }

    /// Establishes an encrypted channel using X25519 + Ed25519.
    pub fn pair_verify(&mut self, transport: &mut dyn Transport) -> Result<()> {
        // Ephemeral X25519 key pair.
        let mut client_private = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_private);
        let client_public = x25519_base(client_private);

        // V1: send our ephemeral X25519 public key.
        let v1 = tlv8::encode_ordered(&[
            Tlv8Item::new(tlv8::TLV_STATE, vec![0x01]),
            Tlv8Item::new(tlv8::TLV_PUBLIC_KEY, client_public.to_vec()),
        ]);
        let v2_bytes = Error::ok_body(transport.request(
            "POST",
            "/pair-verify",
            "application/octet-stream",
            &v1,
            &self.pair_verify_headers(),
        ))?;
        let v2 = tlv8::decode(&v2_bytes);
        if let Some(err) = v2.get(&tlv8::TLV_ERROR) {
            return Err(Error::Protocol(format!("pair-verify V2 error: {}", err[0])));
        }
        let server_key_data = v2
            .get(&tlv8::TLV_PUBLIC_KEY)
            .ok_or_else(|| Error::Protocol("V2: missing server public key".into()))?;
        let server_encrypted = v2.get(&tlv8::TLV_ENCRYPTED_DATA).cloned().unwrap_or_default();
        if server_key_data.len() < 32 {
            return Err(Error::Protocol("V2: server public key too short".into()));
        }
        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(&server_key_data[..32]);

        // Shared secret + session key.
        let shared = x25519_shared(client_private, server_public);
        let verify_key = hkdf_sha512(&shared, b"Pair-Verify-Encrypt-Salt", b"Pair-Verify-Encrypt-Info", 32);

        // Decrypt and verify the server's response if encrypted data present.
        if !server_encrypted.is_empty() {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&verify_key));
            let nonce = chacha_nonce(b"PV-Msg02");
            cipher
                .decrypt(Nonce::from_slice(&nonce), server_encrypted.as_slice())
                .map_err(|e| Error::Crypto(format!("decrypt V2: {e}")))?;
        }

        // V3: sign(clientX25519Public || pairingID || serverX25519Public).
        let signing_key = self.signing_key()?;
        let client_id = self.pairing_id.as_bytes();
        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&client_public);
        sig_input.extend_from_slice(client_id);
        sig_input.extend_from_slice(&server_public);
        let signature = signing_key.sign(&sig_input).to_bytes();

        let sub_tlv = tlv8::encode_ordered(&[
            Tlv8Item::new(tlv8::TLV_IDENTIFIER, client_id.to_vec()),
            Tlv8Item::new(tlv8::TLV_SIGNATURE, signature.to_vec()),
        ]);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&verify_key));
        let nonce = chacha_nonce(b"PV-Msg03");
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), sub_tlv.as_slice())
            .map_err(|e| Error::Crypto(format!("chacha20 seal V3: {e}")))?;

        let v3 = tlv8::encode_ordered(&[
            Tlv8Item::new(tlv8::TLV_STATE, vec![0x03]),
            Tlv8Item::new(tlv8::TLV_ENCRYPTED_DATA, encrypted),
        ]);
        let v4_bytes = Error::ok_body(transport.request(
            "POST",
            "/pair-verify",
            "application/octet-stream",
            &v3,
            &self.pair_verify_headers(),
        ))?;
        if !v4_bytes.is_empty() {
            let v4 = tlv8::decode(&v4_bytes);
            if let Some(err) = v4.get(&tlv8::TLV_ERROR) {
                return Err(Error::Protocol(format!("pair-verify V4 error: {}", err[0])));
            }
        }

        // After pair-verify, the AirPlay control channel is encrypted using
        // HAP framing. Derive the channel keys from the X25519 secret.
        self.keys.shared_secret = shared.to_vec();
        self.enc_write_key =
            hkdf_sha512(&shared, b"Control-Salt", b"Control-Write-Encryption-Key", 32);
        self.enc_read_key =
            hkdf_sha512(&shared, b"Control-Salt", b"Control-Read-Encryption-Key", 32);
        self.keys.write_key = self.enc_write_key.clone();
        self.keys.read_key = self.enc_read_key.clone();
        self.encrypted = true;

        Ok(())
    }

    /// Non-HAP ("AirMyPC-style") pair-verify that keeps the connection in
    /// plaintext, required by legacy receivers that reject FairPlay fp-setup
    /// over HAP-encrypted connections.
    fn raw_pair_verify(&mut self, transport: &mut dyn Transport) -> Result<()> {
        // Ephemeral X25519 key pair.
        let mut client_private = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_private);
        let client_public = x25519_base(client_private);

        // V1: flags(4) + X25519_pub(32) + Ed25519_pub(32) = 68 bytes.
        let mut v1 = vec![0u8; 68];
        v1[0] = 0x01; // auth type 1
        v1[4..36].copy_from_slice(&client_public);
        v1[36..68].copy_from_slice(&self.keys.ed25519_public);

        let v2 = Error::ok_body(transport.request_raw(
            "POST",
            "/pair-verify",
            "application/octet-stream",
            &v1,
            &HashMap::new(),
        ))?;
        if v2.len() != 96 {
            return Err(Error::Protocol(format!("V2: expected 96 bytes, got {}", v2.len())));
        }
        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(&v2[..32]);
        let encrypted_server_sig = &v2[32..96];

        let shared = x25519_shared(client_private, server_public);

        // AES-128-CTR key/IV from SHA-512(salt || secret)[:16].
        let aes_key = sha512_derive_key(b"Pair-Verify-AES-Key", &shared);
        let aes_iv = sha512_derive_key(b"Pair-Verify-AES-IV", &shared);

        // Decrypt the server's signature (CTR offset 0).
        let mut server_sig = [0u8; 64];
        ctr_xor(&aes_key, &aes_iv, 0, encrypted_server_sig, &mut server_sig);

        // Verify the server's Ed25519 signature over
        // (server_X25519 || client_X25519) using the /info pk.
        let server_ed_pub = self
            .info
            .as_ref()
            .and_then(|i| (i.pk.as_slice().len() >= 32).then(|| i.pk.as_slice()))
            .ok_or_else(|| {
                Error::Protocol("server Ed25519 public key not available (call GET /info first)".into())
            })?;
        let server_ed_pub: [u8; 32] = server_ed_pub[..32]
            .try_into()
            .map_err(|_| Error::Protocol("invalid server Ed25519 public key".into()))?;
        let verifying = VerifyingKey::from_bytes(&server_ed_pub)
            .map_err(|e| Error::Crypto(format!("server ed25519 pub: {e}")))?;
        let mut server_sig_msg = [0u8; 64];
        server_sig_msg[..32].copy_from_slice(&server_public);
        server_sig_msg[32..].copy_from_slice(&client_public);
        let sig = Signature::from_slice(&server_sig)
            .map_err(|e| Error::Crypto(format!("server signature: {e}")))?;
        verifying
            .verify(&server_sig_msg, &sig)
            .map_err(|_| Error::Crypto("server signature verification failed".into()))?;

        // Sign our proof: Ed25519_sign(client_X25519 || server_X25519).
        let signing_key = self.signing_key()?;
        let mut client_sig_msg = [0u8; 64];
        client_sig_msg[..32].copy_from_slice(&client_public);
        client_sig_msg[32..].copy_from_slice(&server_public);
        let client_sig = signing_key.sign(&client_sig_msg).to_bytes();

        // Encrypt our signature at CTR offset 64.
        let mut encrypted_client_sig = [0u8; 64];
        ctr_xor(&aes_key, &aes_iv, 64, &client_sig, &mut encrypted_client_sig);

        // V3: flags(4, zero) + encrypted_client_sig(64) = 68 bytes.
        let mut v3 = vec![0u8; 68];
        v3[4..68].copy_from_slice(&encrypted_client_sig);

        let v4 = Error::ok_body(transport.request_raw(
            "POST",
            "/pair-verify",
            "application/octet-stream",
            &v3,
            &HashMap::new(),
        ))?;
        if !v4.is_empty() {
            log::warn!("[RAW-PV] unexpected {} bytes in V4 response", v4.len());
        }

        // Store the shared secret, but do NOT enable HAP encryption.
        self.keys.shared_secret = shared.to_vec();
        Ok(())
    }
}

/// The client name shown by the receiver while it asks the user to allow
/// pairing. Prefer the machine's hostname, sanitized.
fn pairing_client_name() -> String {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();
    sanitize_pairing_client_name(&hostname)
}

fn sanitize_pairing_client_name(name: &str) -> String {
    let name = name.trim();
    if name.is_empty() || name.chars().any(char::is_control) {
        return DEFAULT_PAIRING_CLIENT_NAME.to_string();
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_headers_advertise_identity_and_pairing_type() {
        let pairing_id = "12345678-1234-4234-8234-123456789abc";
        let mut s = PairingSession::new(pairing_id.into());

        // zero value pair_type defaults to screen capture
        s.pair_type = 0;
        let h = s.pair_headers();
        assert_eq!(h["X-Apple-HKP"], "5");
        assert_eq!(h["X-Apple-Client-ID"], pairing_id);
        assert!(h.contains_key("X-Apple-Client-Name"));

        // transient
        s.pair_type = PAIRING_TYPE_TRANSIENT;
        let h = s.pair_headers();
        assert_eq!(h["X-Apple-HKP"], "4");

        // legacy: only X-Apple-HKP
        s.pair_type = PAIRING_TYPE_LEGACY;
        let h = s.pair_headers();
        assert_eq!(h.len(), 1);
        assert_eq!(h["X-Apple-HKP"], "3");
    }

    #[test]
    fn pair_verify_headers_advertise_paired_device() {
        let mut s = PairingSession::new("12345678-1234-4234-8234-123456789abc".into());
        let h = s.pair_verify_headers();
        assert_eq!(h["X-Apple-PD"], "1");
        assert_eq!(h["X-Apple-HKP"], "5");

        s.pair_type = PAIRING_TYPE_LEGACY;
        let h = s.pair_verify_headers();
        assert_eq!(h.len(), 1);
        assert_eq!(h["X-Apple-HKP"], "3");
    }

    #[test]
    fn pairing_type_follows_receiver_profile() {
        let roku_features: u64 = 0x38bcf46007f8ad0;

        // modern Apple receiver
        let info = ReceiverInfo {
            features: crate::info::FEATURE_SYSTEM_PAIRING | crate::info::FEATURE_TRANSIENT_PAIRING,
            ..Default::default()
        };
        let mut s = PairingSession::with_info("id".into(), info);
        assert_eq!(s.transient_pairing_type(), PAIRING_TYPE_TRANSIENT);
        assert_eq!(s.pin_pairing_type(), PAIRING_TYPE_SCREEN_CAPTURE);
        s.pair_type = PAIRING_TYPE_SCREEN_CAPTURE;
        assert_eq!(s.effective_pair_type(), PAIRING_TYPE_SCREEN_CAPTURE);

        // Roku
        let info = ReceiverInfo {
            features: roku_features,
            ..Default::default()
        };
        let s = PairingSession::with_info("id".into(), info);
        assert_eq!(s.transient_pairing_type(), PAIRING_TYPE_LEGACY);
        assert_eq!(s.pin_pairing_type(), PAIRING_TYPE_LEGACY);

        // legacy/unknown receiver
        let s = PairingSession::with_info("id".into(), ReceiverInfo::default());
        assert_eq!(s.transient_pairing_type(), PAIRING_TYPE_LEGACY);
        assert_eq!(s.pin_pairing_type(), PAIRING_TYPE_LEGACY);

        // missing receiver info
        let s = PairingSession::new("id".into());
        assert_eq!(s.transient_pairing_type(), PAIRING_TYPE_TRANSIENT);
        assert_eq!(s.pin_pairing_type(), PAIRING_TYPE_SCREEN_CAPTURE);
    }

    #[test]
    fn client_name_sanitization() {
        assert_eq!(sanitize_pairing_client_name("  "), DEFAULT_PAIRING_CLIENT_NAME);
        assert_eq!(sanitize_pairing_client_name(""), DEFAULT_PAIRING_CLIENT_NAME);
        assert_eq!(sanitize_pairing_client_name("My-PC"), "My-PC");
        assert_eq!(sanitize_pairing_client_name("bad\u{0007}name"), DEFAULT_PAIRING_CLIENT_NAME);
    }

    // ------------------------------------------------------------------
    // Mock receiver: implements the SRP-6a server side + pair-verify so the
    // client flows can be validated without any network.
    // ------------------------------------------------------------------

    struct MockReceiver {
        pin: String,
        // SRP server state
        salt: Vec<u8>,
        server_b: BigUint,
        server_v: BigUint,
        server_b_pub: Vec<u8>, // padded 384
        session_key: Vec<u8>,  // K
        // pair-setup M5 state
        client_ed_pub: Option<Vec<u8>>,
        setup_cipher_key: Option<Vec<u8>>,
        // pair-verify state
        verify_key: Option<Vec<u8>>,
        server_x_pub: Option<[u8; 32]>,
        client_x_pub: Option<[u8; 32]>,
        // receiver Ed25519 identity
        receiver_ed: SigningKey,
        received_m5: bool,
        proof_valid: bool,
        m5_payload: Option<HashMap<u8, Vec<u8>>>,
        v3_payload: Option<HashMap<u8, Vec<u8>>>,
    }

    impl MockReceiver {
        fn new(pin: &str) -> Self {
            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);

            let mut b_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut b_bytes);
            let b = BigUint::from_bytes_be(&b_bytes);

            // x = H(salt, H("Pair-Setup:pin")), v = g^x mod N
            let x = srp_x(b"Pair-Setup", pin.as_bytes(), &salt);
            let v = srp_g().modpow(&x, &srp_n());
            // B = (k*v + g^b) mod N
            let gb = srp_g().modpow(&b, &srp_n());
            let kv = (srp_k() * &v) % srp_n();
            let b_pub = (kv + gb) % srp_n();

            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let receiver_ed = SigningKey::from_bytes(&seed);

            MockReceiver {
                pin: pin.to_string(),
                salt: salt.to_vec(),
                server_b: b,
                server_v: v,
                server_b_pub: pad_to(&b_pub.to_bytes_be(), 384),
                session_key: Vec::new(),
                client_ed_pub: None,
                setup_cipher_key: None,
                verify_key: None,
                server_x_pub: None,
                client_x_pub: None,
                receiver_ed,
                received_m5: false,
                proof_valid: false,
                m5_payload: None,
                v3_payload: None,
            }
        }

        fn handle_pair_setup(&mut self, body: &[u8]) -> Vec<u8> {
            let msg = tlv8::decode(body);
            let state = msg.get(&tlv8::TLV_STATE).and_then(|s| s.first()).copied();
            match state {
                Some(1) => {
                    // M2: salt + server public key
                    tlv8::encode_ordered(&[
                        Tlv8Item::new(tlv8::TLV_SALT, self.salt.clone()),
                        Tlv8Item::new(tlv8::TLV_PUBLIC_KEY, self.server_b_pub.clone()),
                    ])
                }
                Some(3) => {
                    // M4: verify client proof, return server proof
                    let client_pub_raw = msg
                        .get(&tlv8::TLV_PUBLIC_KEY)
                        .expect("M3 public key");
                    // trim leading zeros to natural representation
                    let start = client_pub_raw
                        .iter()
                        .position(|&b| b != 0)
                        .unwrap_or(client_pub_raw.len().saturating_sub(1));
                    let client_pub = &client_pub_raw[start..];
                    let client_proof = msg.get(&tlv8::TLV_PROOF).expect("M3 proof");
                    let mut proof: [u8; 64] = [0; 64];
                    proof.copy_from_slice(client_proof);

                    let client_b = BigUint::from_bytes_be(&self.server_b_pub);
                    let u = srp_u(client_pub, &client_b.to_bytes_be());
                    // S = (A * v^u)^b mod N
                    let a = BigUint::from_bytes_be(client_pub);
                    let vu = self.server_v.modpow(&u, &srp_n());
                    let s = (a * vu).modpow(&self.server_b, &srp_n());
                    let k = srp_session_key(&s);
                    self.session_key = k.to_vec();
                    self.setup_cipher_key = Some(
                        hkdf_sha512(&k, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info", 32),
                    );

                    let expected = srp_client_proof(b"Pair-Setup", &self.salt, client_pub, &client_b.to_bytes_be(), &k);
                    self.proof_valid = expected.as_slice() == client_proof;
                    let server_proof = srp_server_proof(client_pub, &proof, &k);

                    tlv8::encode_ordered(&[Tlv8Item::new(tlv8::TLV_PROOF, server_proof.to_vec())])
                }
                Some(5) => {
                    // M6: decrypt M5, remember identity
                    let cipher_key = self.setup_cipher_key.clone().expect("setup cipher key");
                    let encrypted = msg
                        .get(&tlv8::TLV_ENCRYPTED_DATA)
                        .expect("M5 encrypted data");
                    let cipher = ChaCha20Poly1305::new(Key::from_slice(&cipher_key));
                    let nonce = chacha_nonce(b"PS-Msg05");
                    let plain = cipher
                        .decrypt(Nonce::from_slice(&nonce), encrypted.as_slice())
                        .expect("decrypt M5");
                    self.m5_payload = Some(tlv8::decode(&plain));
                    self.client_ed_pub = self.m5_payload.as_ref().and_then(|m| m.get(&tlv8::TLV_PUBLIC_KEY)).cloned();
                    self.received_m5 = true;
                    Vec::new()
                }
                _ => Vec::new(),
            }
        }

        fn handle_pair_verify(&mut self, body: &[u8]) -> Vec<u8> {
            let msg = tlv8::decode(body);
            let state = msg.get(&tlv8::TLV_STATE).and_then(|s| s.first()).copied();
            match state {
                Some(1) => {
                    // V2: server X25519 pub + encrypted proof
                    let mut server_private = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut server_private);
                    let server_x_pub = x25519_base(server_private);
                    let client_x = msg.get(&tlv8::TLV_PUBLIC_KEY).expect("V1 public key");
                    let mut client_x_arr = [0u8; 32];
                    client_x_arr.copy_from_slice(&client_x[..32]);
                    self.client_x_pub = Some(client_x_arr);

                    let shared = x25519_shared(server_private, client_x_arr);
                    let verify_key =
                        hkdf_sha512(&shared, b"Pair-Verify-Encrypt-Salt", b"Pair-Verify-Encrypt-Info", 32);
                    self.verify_key = Some(verify_key.clone());

                    // Server proof over (server_x || client_x), encrypted with PV-Msg02.
                    let mut sig_msg = [0u8; 64];
                    sig_msg[..32].copy_from_slice(&server_x_pub);
                    sig_msg[32..].copy_from_slice(&client_x_arr);
                    let sig = self.receiver_ed.sign(&sig_msg).to_bytes();

                    let sub = tlv8::encode_ordered(&[
                        Tlv8Item::new(tlv8::TLV_IDENTIFIER, b"mock-receiver".to_vec()),
                        Tlv8Item::new(tlv8::TLV_SIGNATURE, sig.to_vec()),
                    ]);
                    let cipher = ChaCha20Poly1305::new(Key::from_slice(&verify_key));
                    let nonce = chacha_nonce(b"PV-Msg02");
                    let encrypted = cipher
                        .encrypt(Nonce::from_slice(&nonce), sub.as_slice())
                        .expect("encrypt V2");

                    self.server_x_pub = Some(server_x_pub);
                    tlv8::encode_ordered(&[
                        Tlv8Item::new(tlv8::TLV_PUBLIC_KEY, server_x_pub.to_vec()),
                        Tlv8Item::new(tlv8::TLV_ENCRYPTED_DATA, encrypted),
                    ])
                }
                Some(3) => {
                    // V4: decrypt and verify client signature
                    let encrypted = msg
                        .get(&tlv8::TLV_ENCRYPTED_DATA)
                        .expect("V3 encrypted data");
                    let cipher = ChaCha20Poly1305::new(Key::from_slice(self.verify_key.as_ref().unwrap()));
                    let nonce = chacha_nonce(b"PV-Msg03");
                    let plain = cipher
                        .decrypt(Nonce::from_slice(&nonce), encrypted.as_slice())
                        .expect("decrypt V3");
                    self.v3_payload = Some(tlv8::decode(&plain));
                    let payload = self.v3_payload.clone().unwrap();
                    let sig_bytes: [u8; 64] = payload
                        .get(&tlv8::TLV_SIGNATURE)
                        .expect("V3 signature")
                        .as_slice()
                        .try_into()
                        .unwrap();
                    let client_ed: [u8; 32] = self.client_ed_pub.clone().unwrap().as_slice().try_into().unwrap();
                    let verifying = VerifyingKey::from_bytes(&client_ed).unwrap();
                    // signature input is client_x || id || server_x
                    let mut full = Vec::new();
                    full.extend_from_slice(&self.client_x_pub.unwrap());
                    full.extend_from_slice(payload.get(&tlv8::TLV_IDENTIFIER).unwrap());
                    full.extend_from_slice(&self.server_x_pub.unwrap());
                    verifying
                        .verify(&full, &Signature::from_slice(&sig_bytes).unwrap())
                        .expect("client signature valid");
                    Vec::new()
                }
                _ => Vec::new(),
            }
        }
    }

    impl Transport for MockReceiver {
        fn request(
            &mut self,
            _method: &str,
            path: &str,
            _content_type: &str,
            body: &[u8],
            _extra_headers: &HashMap<String, String>,
        ) -> Result<crate::transport::Response> {
            use crate::transport::Response;
            match path {
                "/pair-setup" => {
                    let body = self.handle_pair_setup(body);
                    Ok(Response {
                        status: 200,
                        headers: HashMap::new(),
                        body,
                    })
                }
                "/pair-verify" => {
                    let body = self.handle_pair_verify(body);
                    Ok(Response {
                        status: 200,
                        headers: HashMap::new(),
                        body,
                    })
                }
                _ => Ok(Response {
                    status: 404,
                    headers: HashMap::new(),
                    body: Vec::new(),
                }),
            }
        }

        fn request_raw(
            &mut self,
            _method: &str,
            _path: &str,
            _content_type: &str,
            _body: &[u8],
            _extra_headers: &HashMap<String, String>,
        ) -> Result<crate::transport::Response> {
            Err(Error::Protocol("raw transport not used in this test".into()))
        }
    }

    #[test]
    fn full_pin_pairing_flow_succeeds() {
        const PIN: &str = "4827";
        let mut receiver = MockReceiver::new(PIN);

        let mut session = PairingSession::new("12345678-1234-4234-8234-123456789abc".into());
        session
            .pair_with_pin(&mut receiver, PIN)
            .expect("pair-with-pin succeeds");

        assert!(receiver.proof_valid, "receiver must accept the client SRP proof");
        assert!(receiver.received_m5, "receiver must receive encrypted M5");
        assert!(session.encrypted, "pair-verify enables HAP encryption");
        assert_eq!(session.enc_write_key.len(), 32);
        assert_eq!(session.enc_read_key.len(), 32);
        assert_eq!(session.keys.ed25519_public.len(), 32);

        // M5 payload carried id, pubkey, signature and the screen-capture ACL.
        let m5 = receiver.m5_payload.as_ref().expect("m5 payload");
        assert_eq!(
            m5.get(&tlv8::TLV_IDENTIFIER).unwrap(),
            b"12345678-1234-4234-8234-123456789abc"
        );
        assert_eq!(
            m5.get(&tlv8::TLV_ACL).unwrap(),
            SCREEN_CAPTURE_ACL
        );
    }

    #[test]
    fn wrong_pin_fails_proof_verification() {
        let mut receiver = MockReceiver::new("4827");
        let mut session = PairingSession::new("id-1234".into());
        // The server proof check runs on M4; with a wrong PIN the client's
        // derived K differs from the receiver's, so the client's M1 proof is
        // rejected by the mock, but the mock still returns a proof computed
        // from ITS key — which will not match the client's expectation.
        let err = session.pair_with_pin(&mut receiver, "0000");
        assert!(err.is_err());
        // Either the mock rejected our proof or our server-proof check failed.
        assert!(!receiver.proof_valid || err.is_err());
    }
}
