//! Receiver-side FairPlay SAP (fp-setup) two-request exchange, ported from
//! `internal/airplay/receiver_fairplay.go`. The receiver receives m1 → answers
//! m2; receives m3 → verifies the exchange confirmation and answers m4.

use crate::error::{Error, Result};
use crate::fairplay_message::{decrypt_fairplay_message, encrypt_fairplay_message};
use crate::fp_tables_generated::FPSAP_M3_LABEL;
use crate::fpsap::{fpsap_exchange_for_sap, new_fpsap_record, validate_fpsap_record};
use rand::rngs::OsRng;
use rand::RngCore;

const FPSAP_MODE: u8 = 3;
const FPSAP_M1_PAYLOAD: [u8; 4] = [0x02, 0x00, 0x03, 0xbb];

/// Receiver half of the FairPlay SAP exchange.
pub struct ReceiverFpsap {
    receiver_sap: [u8; 128],
    mode: u8,
    phase: u8,
    #[allow(dead_code)]
    m3: [u8; 164],
}

impl Default for ReceiverFpsap {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiverFpsap {
    pub fn new() -> Self {
        let mut receiver_sap = [0u8; 128];
        receiver_sap[1] = 1;
        let mut entropy = [0u8; 126];
        OsRng.fill_bytes(&mut entropy);
        receiver_sap[2..].copy_from_slice(&entropy);
        ReceiverFpsap {
            receiver_sap,
            mode: FPSAP_MODE,
            phase: 0,
            m3: [0u8; 164],
        }
    }

    /// Processes one /fp-setup request, returning the response body.
    pub fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        match self.phase {
            0 => self.exchange_m2(request),
            1 => self.exchange_m4(request),
            _ => Err(Error::Protocol("FairPlay SAP exchange already complete".into())),
        }
    }

    fn exchange_m2(&mut self, m1: &[u8]) -> Result<Vec<u8>> {
        validate_fpsap_record(m1, 1, 4)?;
        if &m1[12..16] != &FPSAP_M1_PAYLOAD {
            return Err(Error::Protocol(format!(
                "unsupported m1 capabilities {:02x?}",
                &m1[12..16]
            )));
        }

        let mut m2 = new_fpsap_record(2, 130);
        m2[12] = 2;
        m2[13] = self.mode;
        let mut body = [0u8; 128];
        encrypt_fairplay_message(self.mode, &self.receiver_sap, &mut body)?;
        m2[14..142].copy_from_slice(&body);
        self.phase = 1;
        Ok(m2)
    }

    fn exchange_m4(&mut self, m3: &[u8]) -> Result<Vec<u8>> {
        validate_fpsap_record(m3, 3, 152)?;
        if m3[12] != self.mode {
            return Err(Error::Protocol(format!(
                "m3 mode {} does not match selected mode {}",
                m3[12], self.mode
            )));
        }
        if &m3[13..16] != &FPSAP_M3_LABEL {
            return Err(Error::Protocol(format!("invalid m3 label {:02x?}", &m3[13..16])));
        }

        let mut sender_sap = [0u8; 128];
        decrypt_fairplay_message(m3, &mut sender_sap);
        let want = fpsap_exchange_for_sap(&sender_sap, &self.receiver_sap);
        if &m3[144..164] != &want {
            return Err(Error::Protocol("m3 exchange confirmation is invalid".into()));
        }

        self.m3.copy_from_slice(m3);
        self.phase = 2;
        let mut m4 = new_fpsap_record(4, 20);
        m4[12..].copy_from_slice(&m3[144..]);
        Ok(m4)
    }

    pub fn complete(&self) -> bool {
        self.phase == 2
    }
}
