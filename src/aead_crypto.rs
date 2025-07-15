//! AEAD crypto operations for LoRaWAN security using ChaCha20-Poly1305

#![cfg_attr(not(feature = "std"), no_std)]

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key,
};

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// Constants
pub const NONCE_SIZE: usize = 12;
pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_TAG_SIZE: usize = 16;

/// Convert bytes to hex string for debugging
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

/// AEAD encrypt data using ChaCha20-Poly1305
/// Returns the ciphertext and the FULL 16-byte tag
pub fn aead_encrypt(
    key: &[u8; CHACHA20_KEY_SIZE],
    aad: &[u8],
    data: &[u8],
    fcnt: u32,
    devaddr: u32,
    dir: u8
) -> Result<(Vec<u8>, [u8; CHACHA20_TAG_SIZE]), &'static str> {
    println!("🔐 AEAD Encrypt Debug:");
    println!("  └─ AAD: {}", hex_string(aad));
    println!("  └─ Data: {}", hex_string(data));
    println!("  └─ FCnt: {}, DevAddr: 0x{:08X}, Dir: {}", fcnt, devaddr, dir);

    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    // Create nonce
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..4].copy_from_slice(&devaddr.to_le_bytes());
    nonce[4..8].copy_from_slice(&fcnt.to_le_bytes());
    nonce[8] = dir;

    println!("  └─ Nonce: {}", hex_string(&nonce));

    let nonce = Nonce::from_slice(&nonce);

    // Encrypt with AAD
    let payload = chacha20poly1305::aead::Payload {
        msg: data,
        aad: aad,
    };

    match cipher.encrypt(nonce, payload) {
        Ok(ciphertext) => {
            println!("  └─ Full ciphertext+tag: {}", hex_string(&ciphertext));

            if ciphertext.len() < CHACHA20_TAG_SIZE {
                return Err("Ciphertext too short for tag");
            }

            let tag_start = ciphertext.len() - CHACHA20_TAG_SIZE;
            let actual_ciphertext = ciphertext[..tag_start].to_vec();

            // Extract the FULL 16-byte tag
            let mut tag = [0u8; CHACHA20_TAG_SIZE];
            tag.copy_from_slice(&ciphertext[tag_start..]);

            println!("  └─ Ciphertext: {}", hex_string(&actual_ciphertext));
            println!("  └─ Full tag: {}", hex_string(&tag));

            Ok((actual_ciphertext, tag))
        },
        Err(e) => {
            println!("  └─ Encryption error: {:?}", e);
            Err("ChaCha20-Poly1305 encryption failed")
        },
    }
}

/// AEAD decrypt data using ChaCha20-Poly1305
/// Uses the FULL 16-byte tag for verification
pub fn aead_decrypt(
    key: &[u8; CHACHA20_KEY_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; CHACHA20_TAG_SIZE],
    fcnt: u32,
    devaddr: u32,
    dir: u8
) -> Result<Vec<u8>, &'static str> {
    println!("🔓 AEAD Decrypt Debug:");
    println!("  └─ AAD: {}", hex_string(aad));
    println!("  └─ Ciphertext: {}", hex_string(ciphertext));
    println!("  └─ Full tag: {}", hex_string(tag));
    println!("  └─ FCnt: {}, DevAddr: 0x{:08X}, Dir: {}", fcnt, devaddr, dir);

    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    // Create nonce
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..4].copy_from_slice(&devaddr.to_le_bytes());
    nonce[4..8].copy_from_slice(&fcnt.to_le_bytes());
    nonce[8] = dir;

    println!("  └─ Nonce: {}", hex_string(&nonce));

    let nonce = Nonce::from_slice(&nonce);

    // Combine ciphertext and full tag (no reconstruction needed!)
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    println!("  └─ Ciphertext+tag for decryption: {}", hex_string(&ciphertext_with_tag));

    // Decrypt and verify
    let payload = chacha20poly1305::aead::Payload {
        msg: &ciphertext_with_tag,
        aad: aad,
    };

    match cipher.decrypt(nonce, payload) {
        Ok(plaintext) => {
            println!("  └─ ✅ Decryption successful!");
            println!("  └─ Plaintext: {}", hex_string(&plaintext));
            Ok(plaintext)
        },
        Err(e) => {
            println!("  └─ ❌ Decryption error: {:?}", e);
            Err("ChaCha20-Poly1305 decryption failed: authentication tag mismatch")
        },
    }
}

/// Convert 16-byte LoRaWAN key to 32-byte ChaCha20 key
pub fn derive_chacha20_key(lorawan_key: &[u8; 16]) -> [u8; CHACHA20_KEY_SIZE] {
    let mut chacha_key = [0u8; CHACHA20_KEY_SIZE];

    chacha_key[0..16].copy_from_slice(lorawan_key);
    chacha_key[16..32].copy_from_slice(lorawan_key);

    for i in 16..32 {
        chacha_key[i] ^= 0x5A;
    }

    chacha_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let lorawan_key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let chacha_key = derive_chacha20_key(&lorawan_key);

        assert_eq!(chacha_key.len(), 32);
        assert_eq!(&chacha_key[0..16], &lorawan_key);
        assert_ne!(&chacha_key[16..32], &lorawan_key);
    }

    #[test]
    fn test_full_tag_aead_encrypt_decrypt() {
        let lorawan_key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let chacha_key = derive_chacha20_key(&lorawan_key);

        let aad = b"test_aad";
        let data = b"Hello";
        let fcnt = 42;
        let devaddr = 0x01020304;
        let dir = 0;

        println!("Testing with full 16-byte tag...");

        let (encrypted, tag) = aead_encrypt(&chacha_key, aad, data, fcnt, devaddr, dir).unwrap();
        let decrypted = aead_decrypt(&chacha_key, aad, &encrypted, &tag, fcnt, devaddr, dir).unwrap();

        assert_eq!(decrypted, data);
        println!("✅ Full tag test passed!");
    }
}