//! FairPlay SAP handshake and stream-key derivation, ported from
//! `fairplay.go` and `fairplay_crypto.go`.

use crate::error::{Error, Result};
use crate::fpsap::FpsapSession;
use crate::info::ReceiverInfo;
use crate::transport::Transport;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

/// Error message when the receiver does not advertise FairPlay SAP.
pub const ERR_FAIRPLAY_UNSUPPORTED: &str = "receiver does not support FairPlay SAP";

/// Outcome of a complete FairPlay setup.
#[derive(Debug, Clone)]
pub struct FairPlayResult {
    /// 72-byte wrapped key record for the SETUP descriptor.
    pub ekey: [u8; 72],
    /// Random 16-byte stream IV.
    pub stream_iv: [u8; 16],
    /// The key the receiver will decrypt the stream with.
    pub stream_key: [u8; 16],
    /// The raw FairPlay key before derivation.
    pub raw_key: [u8; 16],
    /// The m3 record (needed for ekey construction later).
    pub m3: [u8; 164],
}

/// Returns the key the receiver will decrypt the stream with, given the raw
/// FairPlay key that ekey wraps.
///
/// A HAP-paired receiver mixes the pair-verify secret in:
///
/// SHA-512(fairplay_decrypt(ekey) || ecdh_secret)[:16]
///
/// A legacy receiver does not. `hap_encrypted` is the discriminator, not the
/// presence of a secret (raw pair-verify stores a secret but stays plaintext).
pub fn derive_stream_master_key(raw_key: &[u8], secret: &[u8], hap_encrypted: bool) -> Vec<u8> {
    if !hap_encrypted || secret.is_empty() {
        return raw_key.to_vec();
    }
    let mut h = Sha512::new();
    h.update(raw_key);
    h.update(secret);
    h.finalize()[..16].to_vec()
}

/// Performs the complete FairPlay SAP handshake over the control transport.
pub fn fairplay_setup(
    transport: &mut dyn Transport,
    info: &ReceiverInfo,
    shared_secret: &[u8],
    hap_encrypted: bool,
) -> Result<FairPlayResult> {
    if !info.supports_fairplay_sap() {
        return Err(Error::Protocol(format!(
            "{ERR_FAIRPLAY_UNSUPPORTED}: FPSAP feature bit is not advertised (features=0x{:x})",
            info.features
        )));
    }

    let mut entropy = [0u8; 126];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mut session = FpsapSession::new(&entropy)?;

    // Phase 1: m1 → m2.
    let m1 = session.message1();
    let m2 = post_fp_setup(transport, &m1)?;

    // Phase 2: m3 → m4.
    let m3 = session.exchange_m3(&m2)?;
    let m4 = post_fp_setup(transport, &m3)?;
    session.confirm_m4(&m4)?;

    // Random stream IV + raw audio key, wrapped in the ekey record.
    let mut stream_iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut stream_iv);
    let mut raw_key = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw_key);
    let mut mask = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut mask);
    let ekey = session.wrap_key(raw_key, mask)?;

    let master = derive_stream_master_key(&raw_key, shared_secret, hap_encrypted);
    let mut stream_key = [0u8; 16];
    stream_key.copy_from_slice(&master);

    let mut m3_arr = [0u8; 164];
    m3_arr.copy_from_slice(&m3);

    Ok(FairPlayResult {
        ekey,
        stream_iv,
        stream_key,
        raw_key,
        m3: m3_arr,
    })
}

/// POSTs an FPLY message to /fp-setup with the `X-Apple-ET: 32` header.
fn post_fp_setup(transport: &mut dyn Transport, body: &[u8]) -> Result<Vec<u8>> {
    let headers = HashMap::from([("X-Apple-ET".to_string(), "32".to_string())]);
    let resp = transport.request("POST", "/fp-setup", "application/octet-stream", body, &headers)?;
    if resp.status == 404 {
        return Err(Error::Protocol(format!(
            "{ERR_FAIRPLAY_UNSUPPORTED}: /fp-setup returned 404"
        )));
    }
    Error::ok_body(Ok(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_md5::{fairplay_md5_compress, fairplay_words_from_little_endian, FairplayMd5Mutation};
    use crate::fairplay_message::{decrypt_fairplay_message, encrypt_fairplay_message};
    use crate::fairplay_sap::fairplay_sap_hash;
    use crate::fpsap::{
        decrypt_fpsap_body, fpsap_descriptor_for_sap, fpsap_exchange_for_sap, new_fpsap_record,
        validate_fpsap_m4, wrap_fair_play_key, FpsapSession,
    };
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use sha2::Sha256;

    fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
        let decoded = hex::decode(s).expect("valid hex");
        assert_eq!(decoded.len(), N, "hex length mismatch");
        let mut out = [0u8; N];
        out.copy_from_slice(&decoded);
        out
    }

    /// Receiver SAP from the independent playfair_decrypt reference vector.
    fn reference_receiver_sap() -> [u8; 128] {
        hex_arr(
            "0001cc342a5e5b1a6773c20e21b8224df862481864ef810aae2e3703c8819c23\
             539de5f5d749bc5b7a266c496283ce7f03937ae1f616de0c15ff338ccaffb09e\
             aabbe40f5d5f558fb97f1731f8f7da60a0ec6579c33ea98312c3b67135a6694f\
             f82305d9ba5c615fa254d2b1834583cee42d4426c835a7a5f6c8421c0da3f1c7",
        )
    }

    /// Local SAP recovered from the old post-m1 emulator snapshot.
    fn reference_local_sap() -> [u8; 128] {
        hex_arr(
            "0001e4e3dd688293e6fa66b95ba41768e587c65f750218ff1be21543d573cefb\
             087bd36e0c6363c3c8242f4abcfa6d660b801032015405eb4ab04dda7aeff38f\
             fb36f4cfa48f0b5d92ae363f68b45925bbe6413ab6bdc4968f548d21e67d20f\
             1912b6820e53f1013cde29df7350a9b9fa7c51320aea62d2949786c87642e34ba",
        )
    }

    /// Test-side unwrap of an ekey record (receiver operation).
    fn unwrap_key_for_test(receiver_sap: &[u8; 128], m3: &[u8], ekey: &[u8]) -> [u8; 16] {
        let aes_key = crate::fpsap::derive_fairplay_wrapping_key(receiver_sap, m3);
        let cipher = aes::Aes128::new_from_slice(&aes_key).expect("aes key");
        let mut block = aes::Block::from([0u8; 16]);
        block.copy_from_slice(&ekey[56..72]);
        cipher.decrypt_block(&mut block);
        let mut key = [0u8; 16];
        for i in 0..16 {
            key[i] = block[i] ^ ekey[16 + i];
        }
        key
    }

    fn primitive_block() -> [u8; 64] {
        let mut block = [0u8; 64];
        for (i, b) in block.iter_mut().enumerate() {
            *b = (i * 3 + 1) as u8;
        }
        block
    }

    #[test]
    fn fairplay_primitive_vectors() {
        let block = primitive_block();
        let key: [u8; 16] = (0..16).collect::<Vec<u8>>().try_into().unwrap();
        let words = fairplay_md5_compress(
            fairplay_words_from_little_endian(&key),
            &block,
            FairplayMd5Mutation::FairplayKdf,
        );
        let mut modified = [0u8; 16];
        for (i, w) in words.iter().enumerate() {
            modified[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        assert_eq!(hex::encode(modified), "f6f728cb5a4397b675664f9291b859aa");

        let hashed = fairplay_sap_hash(&block);
        assert_eq!(hex::encode(hashed), "75498a4e218773030e9cdf04f0c49367");
    }

    #[test]
    fn fairplay_sap_hash_corpus() {
        let mut corpus = Sha256::new();
        let mut state: u64 = 0x6a09e667f3bcc909;
        for _ in 0..64 {
            let mut block = [0u8; 64];
            for b in block.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            let digest = fairplay_sap_hash(&block);
            corpus.update(digest);
        }
        assert_eq!(
            hex::encode(corpus.finalize()),
            "36ad2a7920076af59452d9f0c91e3b7d1aebc53f9143bd6819e39119d4535c92"
        );
    }

    #[test]
    fn fairplay_message_vectors() {
        let cases = [
            (0u8, "b66a3295ffa6b56e02ed1b3d67fef74b90fe148570de65e6773669126a4905d8405644cae0b2f5ed6109c099c7aea7398dac8d623fbd69b87242b374d98f89502bb5a63e29c46a8ed0e98466966191ec1e6c8675087fde21337db1c8fab4c21db824026335f6fc37e2e5b6f53357d06994bd383d6029a0aff654fb1521bcdde4", "f7dd1ccb9e745f7951a6e325d73a1f5f"),
            (1u8, "0f95c6ddc8987eda18577da2db074e7c04715af8b3914a73be1b3d6c111953017ee0a39dfcab3e0d57f2f9fbd59c5e18101788c2ab8e3cbb403bcb48b53f3e5bf74f949e79fa5ca679df4bfcb33a69b1442675d03f948fe5bd0c5ffb64b73a5ab58f46d6baae097b599624147c2487991163ecffc4d966240f9526346a10fdb0", "b44ad891396f097aa309bc132f5b8889"),
            (2u8, "40f18751b44d733e0aa0416401a7d3f40375fad3ce56900602578bca14660909820e6ef3a5e943cafef5370f72c52177d9b82278b414811201a3d99202bedcca26a4d1ad08bc2669f4bae6ca54b8a120d0425edb6082f51f5aecdb547bfdb319099c9ea2729ae6a1c4480827ce9991e273843cf1c7d74ebbebc2657659bcea9f", "d38cd8efecdb20f333273c4312d9b236"),
            (3u8, "70a3c30edf0e1dfa1785ce4336ed547062672a47f714a0c1f89a83d95691103dfe5cf653d4cb8299793faf33fd0d4482ef5333b41ab094a90e1baf996bcf4989783f6918397fbacddaf00a2b97556dd8099841578bc5eb1444912b47298eaf356fdd6701bb3f64e725a80eb4c6f3556195de35c93e7cc703bdd24351468e9847", "769e2fe4c5ad7fbe6fd6772d00f529f4"),
        ];
        let receiver_sap = reference_receiver_sap();
        for (mode, decrypted_want, aes_key_want) in cases {
            let mut message = [0u8; 164];
            message[12] = mode;
            for (i, b) in message.iter_mut().enumerate().skip(16).take(128) {
                *b = (i * 5 + 7) as u8;
            }
            let mut decrypted = [0u8; 128];
            decrypt_fairplay_message(&message, &mut decrypted);
            assert_eq!(hex::encode(decrypted), decrypted_want, "mode {mode} decrypt");

            let mut encrypted = [0u8; 128];
            encrypt_fairplay_message(mode, &decrypted, &mut encrypted).expect("encrypt");
            assert_eq!(
                hex::encode(encrypted),
                hex::encode(&message[16..144]),
                "mode {mode} encrypt round-trip"
            );

            let aes_key = crate::fpsap::derive_fairplay_wrapping_key(&receiver_sap, &message);
            assert_eq!(hex::encode(aes_key), aes_key_want, "mode {mode} aes key");
        }
    }

    #[test]
    fn fairplay_key_unwrap_vector() {
        let mut m3 = [0u8; 164];
        m3[12] = 3;
        for (i, b) in m3.iter_mut().enumerate().skip(16).take(128) {
            *b = (i * 5 + 7) as u8;
        }
        let mut ekey = [0u8; 72];
        for (i, b) in ekey.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let got = unwrap_key_for_test(&reference_receiver_sap(), &m3, &ekey);
        assert_eq!(hex::encode(got), "903e5be94732428e9965afb262b193a4");
    }

    #[test]
    fn fpsap_m1_record() {
        let entropy: Vec<u8> = (1..=126).collect();
        let session = FpsapSession::new(&entropy).expect("session");
        assert_eq!(
            hex::encode(session.message1()),
            "46504c590301010000000004020003bb"
        );
    }

    #[test]
    fn fpsap_exchange_golden_vectors() {
        let local = reference_local_sap();
        let captured_m2 = hex::decode(
            "46504c59030102000000008202034a114c26b77d4e2eec2c8f89fdb653b5b32d3576bc176816d110a14c3f53c08dbb936183bfdfe0a4f3c12e85216003b46f738c40c54da6c436d29d1b342d63c7b314309ae79a33bb1787709ef077cbfe4190117a3423e270fd1a2eac44da1a7934f59dc681d1b70783f228c4d077c2d495f5285c3bf8df586fc2ebfe17fb5b65",
        )
        .expect("hex");

        let cases: [(&str, [u8; 128], &str); 7] = [
            ("all-zeros", [0u8; 128], "6f627565f3e77f5b5ede91beee7baf92e4241e0b"),
            ("all-ff", [0xffu8; 128], "dc2cc74f2ed55484f59f95b96082f0f5c017dd17"),
            ("captured-m2", {
                let mut p = [0u8; 128];
                p.copy_from_slice(&captured_m2[14..142]);
                p
            }, "4b911e48af23d8406368aeafbb61bfcd569e3e55"),
            ("42-at-0", sparse(0), "9bfb9556b8659c2ac94b7ef9e587d71e159ea624"),
            ("42-at-63", sparse(63), "150d9fa4eb456e73ba48de5779c5c996b16b3b23"),
            ("42-at-64", sparse(64), "a167db30424ff8890d085c0f1c92b2c5cc06fc45"),
            ("42-at-127", sparse(127), "d246ec5e7adc8118994b8df77146529486ac7caf"),
        ];
        for (name, payload, want) in cases {
            let m2_sap = decrypt_fpsap_body(3, payload).expect("decrypt");
            let got = fpsap_exchange_for_sap(&local, &m2_sap);
            assert_eq!(hex::encode(got), want, "{name}");
        }
    }

    fn sparse(index: usize) -> [u8; 128] {
        let mut p = [0u8; 128];
        p[index] = 0x42;
        p
    }

    #[test]
    fn fpsap_descriptor_vectors() {
        let local = reference_local_sap();
        let cases = [
            ([0u8; 128], "7e38958ffe4ed433743919fe7eb16376afa4eb9e"),
            ({
                let mut p = [0u8; 128];
                p[0] = 1;
                p
            }, "ea46797d726c6a9be43ffa72385ff97ce1c54f1b"),
        ];
        for (payload, want) in cases {
            let m2_sap = decrypt_fpsap_body(3, payload).expect("decrypt");
            let got = fpsap_descriptor_for_sap(&local, &m2_sap);
            assert_eq!(hex::encode(got), want);
        }
    }

    #[test]
    fn fpsap_session_exchange() {
        let mut m2 = new_fpsap_record(2, 130);
        m2[12] = 2;
        m2[13] = 3;
        let entropy: Vec<u8> = (1..=126).collect();
        let mut session = FpsapSession::new(&entropy).expect("session");
        let m3 = session.exchange_m3(&m2).expect("exchange");

        let mut got_sap = [0u8; 128];
        decrypt_fairplay_message(&m3, &mut got_sap);
        let mut want_sap = [0u8; 128];
        want_sap[1] = 1;
        want_sap[2..].copy_from_slice(&entropy);
        assert_eq!(got_sap, want_sap, "m3 carries the local SAP");

        let mut m2_cipher = [0u8; 128];
        m2_cipher.copy_from_slice(&m2[14..]);
        let want_receiver_sap = decrypt_fpsap_body(3, m2_cipher).expect("decrypt m2");
        assert_eq!(session.remote_sap, want_receiver_sap);

        let want_tail = fpsap_exchange_for_sap(&want_sap, &want_receiver_sap);
        assert_eq!(m3[144..], want_tail, "m3 tail");

        // wrap + unwrap round-trip
        let raw_key: [u8; 16] = (0..16).collect::<Vec<u8>>().try_into().unwrap();
        let ekey = session.wrap_key(raw_key, [0x5a; 16]).expect("wrap");
        assert_eq!(unwrap_key_for_test(&want_receiver_sap, &m3, &ekey), raw_key);

        // error cases
        assert!(FpsapSession::new(&entropy[..125]).is_err(), "short entropy rejected");
        assert!(session.exchange_m3(&m2[..141]).is_err(), "short m2 rejected");
        for mode in [4u8, 0xff] {
            let mut bad = m2.clone();
            bad[13] = mode;
            assert!(FpsapSession::new(&entropy).unwrap().exchange_m3(&bad).is_err(), "bad mode {mode} rejected");
        }

        // distinct sessions produce distinct m3 bodies
        let other: Vec<u8> = vec![0xa5; 126];
        let mut other_session = FpsapSession::new(&other).expect("other");
        let other_m3 = other_session.exchange_m3(&m2).expect("other exchange");
        assert_ne!(m3[16..144], other_m3[16..144], "distinct m3 bodies");
    }

    #[test]
    fn fpsap_validate_m4() {
        let mut m3 = [0u8; 164];
        for (i, b) in m3.iter_mut().enumerate().skip(144) {
            *b = i as u8;
        }
        let mut m4 = vec![0u8; 32];
        m4[..4].copy_from_slice(b"FPLY");
        m4[4..8].copy_from_slice(&[3, 1, 4, 0]);
        m4[8..12].copy_from_slice(&20u32.to_be_bytes());
        m4[12..].copy_from_slice(&m3[144..]);

        validate_fpsap_m4(&m4, &m3).expect("valid m4");
        // (m3 field not set; validate_fpsap_m4 only checks length + tail)
        m4[31] ^= 1;
        assert!(validate_fpsap_m4(&m4, &m3).is_err(), "mismatched m4 rejected");
    }

    #[test]
    fn fairplay_key_wrap_roundtrip_all_modes() {
        for mode in 0u8..=3 {
            let m3 = test_fairplay_m3(mode);
            let receiver_sap = test_fairplay_receiver_sap(mode);
            let mut raw_key = [0u8; 16];
            raw_key[..15].copy_from_slice(&[0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe]);
            raw_key[15] = mode;
            let mask: [u8; 16] = (1..=16).collect::<Vec<u8>>().try_into().unwrap();

            let ekey = wrap_fair_play_key(&receiver_sap, &m3, raw_key, mask).expect("wrap");
            assert_eq!(
                hex::encode(&ekey[..16]),
                "46504c59010201000000003c00000000",
                "mode {mode} header"
            );
            assert_eq!(u32::from_be_bytes(ekey[32..36].try_into().unwrap()), 16);
            assert_eq!(&ekey[16..32], &mask[..]);

            // MAC recomputation
            let mut sender_sap = [0u8; 128];
            decrypt_fairplay_message(&m3, &mut sender_sap);
            let mac_key = fpsap_descriptor_for_sap(&sender_sap, &receiver_sap);
            use hmac::{Hmac, Mac};
            use sha1::Sha1;
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&mac_key).unwrap();
            mac.update(&ekey[..36]);
            mac.update(&raw_key);
            assert_eq!(&ekey[36..56], &mac.finalize().into_bytes()[..], "mode {mode} mac");

            assert_eq!(unwrap_key_for_test(&receiver_sap, &m3, &ekey), raw_key, "mode {mode} unwrap");
        }
    }

    fn test_fairplay_m3(mode: u8) -> Vec<u8> {
        let mut m3 = vec![0u8; 164];
        m3[..4].copy_from_slice(b"FPLY");
        m3[4..8].copy_from_slice(&[3, 1, 3, 0]);
        m3[8..12].copy_from_slice(&152u32.to_be_bytes());
        m3[12] = mode;
        for (i, b) in m3.iter_mut().enumerate().skip(13) {
            *b = (i * 7 + 3) as u8;
        }
        m3
    }

    fn test_fairplay_receiver_sap(seed: u8) -> [u8; 128] {
        let mut sap = [0u8; 128];
        sap[1] = 1;
        for (i, b) in sap.iter_mut().enumerate().skip(2) {
            *b = ((i * 11) as u8) ^ seed;
        }
        sap
    }

    #[test]
    fn fairplay_25f84_mac_vector() {
        let m2 = hex_arr::<142>(
            "46504c5903010200000000820201cf32a25714b2524f8aa0ad7af164e37bcf4424e200047efc0ad67afcd95ded1c2730bb591b962ed63a9c4ded88ba8fc78de64d91ccfd5c7b56da88e31f5cceafc7431995a01665a54e1939d25b94db64b9e45d8d063e1e6af07e9656162b0efa404275ea5a44d9591c7256b9fbe6513898b80227721988571650942ad946688a",
        );
        let m3 = hex_arr::<164>(
            "46504c590301030000000098018f1a9c5b9228300aafe0b41f28b66a62a6cd62bf84eb623273dead10b1f034a8d568126faa133f6ad5ab91acda3839817b4d9530b679fee43ac9e950f6e7aaf1381bd2d3d5198a03bf5648890d19234270a3583e4651893be09c6c75463c42e544fec9abc9f7722a2cc254364365ef91ded76b8c00f9674b08920fb9401e4be6d52a33f2f9ed6fadb672be45c3cde5ad94f3fea5b32ee4",
        );
        let raw_key: [u8; 16] = hex_arr("000102030405060708090a0b0c0d0e0f");
        let mask: [u8; 16] = hex_arr("c853e777b9b65e7652d768d97c974f15");

        let mut m2_frame = [0u8; 144];
        m2_frame[12] = m2[13];
        m2_frame[16..].copy_from_slice(&m2[14..]);
        let mut receiver_sap = [0u8; 128];
        decrypt_fairplay_message(&m2_frame, &mut receiver_sap);
        assert_eq!(receiver_sap, reference_receiver_sap(), "receiver SAP matches reference");

        let ekey = wrap_fair_play_key(&receiver_sap, &m3, raw_key, mask).expect("wrap");
        assert_eq!(
            hex::encode(&ekey[..56]),
            "46504c59010201000000003c00000000c853e777b9b65e7652d768d97c974f15000000102a53a0008888fe26bfb1e1f825f38f50d6730059"
        );

        let mut sender_sap = [0u8; 128];
        decrypt_fairplay_message(&m3, &mut sender_sap);
        let mac_key = fpsap_descriptor_for_sap(&sender_sap, &receiver_sap);
        assert_eq!(hex::encode(mac_key), "2fd95dc2c23122bc77c57b983a9188c4760db322");
    }

    #[test]
    fn captured_fairplay_key_decrypt() {
        let m3 = hex_arr::<164>(
            "46504c590301030000000098018f1a9c7d0af257b31f21f5c2d2bc814c032d457835ad0b06250574bbc7ab4a58cca6eead2c911d7f3e1e7ed4c058955dff3d5ceef014387a985bdb34995015e3dfbdacc56047cb926e093b13e9fdb5e1eee317c018bbc87fc5453c7671647da686da3d564875d03f8aea9d60092de06110bc7be0c16f391c369c75344ae47f33acfcf10e63a9b58bfce215e96001c49e4be967c5067f2a",
        );
        let ekey = hex_arr::<72>(
            "46504c59010201000000003c0000000088e4f82c8178c18b4751ac24b27c0c2a00000010c899dc6965c1081de6a9d966e2ba3e34548cdbc651c322db18dc22f58fe154a60aecee18",
        );
        assert_eq!(u32::from_be_bytes(ekey[32..36].try_into().unwrap()), 16);
        let got = unwrap_key_for_test(&reference_receiver_sap(), &m3, &ekey);
        assert_eq!(hex::encode(got), "8e1214398d46d72e7b1b8e32f80c8bf0");
    }

    #[test]
    fn derive_stream_master_key_behavior() {
        let raw = [1u8; 16];
        // No HAP encryption → raw key.
        assert_eq!(derive_stream_master_key(&raw, &[9u8; 32], false), raw.to_vec());
        // HAP + secret → SHA-512(key || secret)[:16].
        let mixed = derive_stream_master_key(&raw, &[9u8; 32], true);
        assert_ne!(mixed, raw.to_vec());
        assert_eq!(mixed.len(), 16);
        // HAP but no secret → raw key.
        assert_eq!(derive_stream_master_key(&raw, &[], true), raw.to_vec());
    }
}
