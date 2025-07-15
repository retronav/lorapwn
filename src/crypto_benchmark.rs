//! Comprehensive cryptographic performance benchmarking
//! Compares AES-128-CTR+CMAC vs AES-GCM vs ChaCha20-Poly1305 for LoRaWAN

#![cfg_attr(not(feature = "std"), no_std)]

use rand::Rng;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// AES-128-CTR + CMAC (Traditional LoRaWAN)
use aes::Aes128;
use cmac::{Cmac, Mac};
use ctr::Ctr64BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

// AES-GCM AEAD
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use aes_gcm::aead::{Aead as AesAead, Payload as AesPayload, KeyInit as AesKeyInit};

// ChaCha20-Poly1305 AEAD
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNoce};
use chacha20poly1305::aead::{Aead as ChaChaAead, Payload as ChaChaPayload, KeyInit as ChaChaKeyInit};

const LORAWAN_KEY_SIZE: usize = 16;
const AES_GCM_KEY_SIZE: usize = 16;
const CHACHA20_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

/// Generate random test data
pub fn generate_test_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

/// Generate LoRaWAN-style AAD
pub fn generate_lorawan_aad(dev_addr: u32, fcnt: u32, _dir: u8) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.push(0x40); // MHDR
    aad.extend_from_slice(&dev_addr.to_le_bytes());
    aad.push(0x00); // FCtrl
    aad.extend_from_slice(&(fcnt as u16).to_le_bytes());
    aad.push(0x01); // FPort
    aad
}

/// AES-128-CTR + CMAC Implementation (Traditional LoRaWAN)
pub struct AesCtrCmac {
    key: [u8; LORAWAN_KEY_SIZE],
}

impl AesCtrCmac {
    pub fn new(key: [u8; LORAWAN_KEY_SIZE]) -> Self {
        Self { key }
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8], fcnt: u32, dev_addr: u32, dir: u8) -> Result<(Vec<u8>, [u8; 4]), &'static str> {
        // Create CTR nonce
        let mut nonce = [0u8; 16];
        nonce[0] = 0x01; // Algorithm identifier
        nonce[1..5].copy_from_slice(&dev_addr.to_le_bytes());
        nonce[5..9].copy_from_slice(&fcnt.to_le_bytes());
        nonce[9] = dir;

        // AES-CTR encryption
        let mut cipher = Ctr64BE::<Aes128>::new((&self.key).into(), (&nonce).into());
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // CMAC calculation - use explicit disambiguation for Mac trait
        let mut mac = <Cmac<Aes128> as Mac>::new(&self.key.into());
        mac.update(aad);
        mac.update(&ciphertext);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        let mut mic = [0u8; 4];
        mic.copy_from_slice(&code_bytes[0..4]);

        Ok((ciphertext, mic))
    }

    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8], mic: &[u8; 4], fcnt: u32, dev_addr: u32, dir: u8) -> Result<Vec<u8>, &'static str> {
        // Verify CMAC - use explicit disambiguation for Mac trait
        let mut mac = <Cmac<Aes128> as Mac>::new(&self.key.into());
        mac.update(aad);
        mac.update(ciphertext);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if &code_bytes[0..4] != mic {
            return Err("CMAC verification failed");
        }

        // Create CTR nonce
        let mut nonce = [0u8; 16];
        nonce[0] = 0x01;
        nonce[1..5].copy_from_slice(&dev_addr.to_le_bytes());
        nonce[5..9].copy_from_slice(&fcnt.to_le_bytes());
        nonce[9] = dir;

        // AES-CTR decryption
        let mut cipher = Ctr64BE::<Aes128>::new((&self.key).into(), (&nonce).into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

/// AES-GCM Implementation
pub struct AesGcmImpl {
    cipher: Aes128Gcm,
}

impl AesGcmImpl {
    pub fn new(key: [u8; AES_GCM_KEY_SIZE]) -> Self {
        Self {
            cipher: <Aes128Gcm as AesKeyInit>::new_from_slice(&key).unwrap(),
        }
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8], fcnt: u32, dev_addr: u32, dir: u8) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..4].copy_from_slice(&dev_addr.to_le_bytes());
        nonce[4..8].copy_from_slice(&fcnt.to_le_bytes());
        nonce[8] = dir;

        let nonce = AesNonce::from_slice(&nonce);
        let payload = AesPayload { msg: plaintext, aad };

        match self.cipher.encrypt(nonce, payload) {
            Ok(ciphertext) => {
                let tag_start = ciphertext.len() - 16;
                let actual_ciphertext = ciphertext[..tag_start].to_vec();
                let tag = ciphertext[tag_start..].to_vec();
                Ok((actual_ciphertext, tag))
            },
            Err(_) => Err("AES-GCM encryption failed"),
        }
    }

    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8], tag: &[u8], fcnt: u32, dev_addr: u32, dir: u8) -> Result<Vec<u8>, &'static str> {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..4].copy_from_slice(&dev_addr.to_le_bytes());
        nonce[4..8].copy_from_slice(&fcnt.to_le_bytes());
        nonce[8] = dir;

        let nonce = AesNonce::from_slice(&nonce);
        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(tag);

        let payload = AesPayload { msg: &ciphertext_with_tag, aad };

        match self.cipher.decrypt(nonce, payload) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err("AES-GCM decryption failed"),
        }
    }
}

/// ChaCha20-Poly1305 Implementation
pub struct ChaCha20Poly1305Impl {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Impl {
    pub fn new(key: [u8; CHACHA20_KEY_SIZE]) -> Self {
        Self {
            cipher: <ChaCha20Poly1305 as ChaChaKeyInit>::new_from_slice(&key).unwrap(),
        }
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8], fcnt: u32, dev_addr: u32, dir: u8) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..4].copy_from_slice(&dev_addr.to_le_bytes());
        nonce[4..8].copy_from_slice(&fcnt.to_le_bytes());
        nonce[8] = dir;

        let nonce = ChaChaNoce::from_slice(&nonce);
        let payload = ChaChaPayload { msg: plaintext, aad };

        match self.cipher.encrypt(nonce, payload) {
            Ok(ciphertext) => {
                let tag_start = ciphertext.len() - 16;
                let actual_ciphertext = ciphertext[..tag_start].to_vec();
                let tag = ciphertext[tag_start..].to_vec();
                Ok((actual_ciphertext, tag))
            },
            Err(_) => Err("ChaCha20-Poly1305 encryption failed"),
        }
    }

    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8], tag: &[u8], fcnt: u32, dev_addr: u32, dir: u8) -> Result<Vec<u8>, &'static str> {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..4].copy_from_slice(&dev_addr.to_le_bytes());
        nonce[4..8].copy_from_slice(&fcnt.to_le_bytes());
        nonce[8] = dir;

        let nonce = ChaChaNoce::from_slice(&nonce);
        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(tag);

        let payload = ChaChaPayload { msg: &ciphertext_with_tag, aad };

        match self.cipher.decrypt(nonce, payload) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err("ChaCha20-Poly1305 decryption failed"),
        }
    }
}