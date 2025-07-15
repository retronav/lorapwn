//! Traditional LoRaWAN AES-CTR + CMAC implementation for comparison with AEAD

#![cfg_attr(not(feature = "std"), no_std)]

use aes::Aes128;
use cmac::{Cmac, Mac};
use ctr::Ctr128BE;
use aes::cipher::{KeyInit, StreamCipher, KeyIvInit};

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// Constants for traditional LoRaWAN
pub const LORAWAN_KEY_SIZE: usize = 16;
pub const LORAWAN_MIC_SIZE: usize = 4;
pub const AES_BLOCK_SIZE: usize = 16;

type AesCtr = Ctr128BE<Aes128>;
type AesCmac = Cmac<Aes128>;

/// Convert bytes to hex string for debugging
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

/// Create AES-CTR encryption/decryption stream
fn create_aes_ctr_cipher(key: &[u8; LORAWAN_KEY_SIZE], counter_block: &[u8; AES_BLOCK_SIZE]) -> AesCtr {
    AesCtr::new(key.into(), counter_block.into())
}

/// Create CMAC instance for MIC calculation
fn create_cmac(key: &[u8; LORAWAN_KEY_SIZE]) -> AesCmac {
    <AesCmac as KeyInit>::new(key.into())
}

/// Build LoRaWAN counter block for AES-CTR
fn build_counter_block(
    dir: u8,
    devaddr: u32,
    fcnt: u32,
    counter: u8,
) -> [u8; AES_BLOCK_SIZE] {
    let mut block = [0u8; AES_BLOCK_SIZE];

    block[0] = 0x01; // Flag for encryption
    block[1] = 0x00; // Reserved
    block[2] = 0x00; // Reserved
    block[3] = 0x00; // Reserved
    block[4] = 0x00; // Reserved
    block[5] = dir;
    block[6..10].copy_from_slice(&devaddr.to_le_bytes());
    block[10..14].copy_from_slice(&fcnt.to_le_bytes());
    block[14] = 0x00; // Reserved
    block[15] = counter;

    block
}

/// Build LoRaWAN MIC block for CMAC
fn build_mic_block(
    dir: u8,
    devaddr: u32,
    fcnt: u32,
    len: u8,
) -> [u8; AES_BLOCK_SIZE] {
    let mut block = [0u8; AES_BLOCK_SIZE];

    block[0] = 0x49; // Flag for MIC
    block[1] = 0x00; // Reserved
    block[2] = 0x00; // Reserved
    block[3] = 0x00; // Reserved
    block[4] = 0x00; // Reserved
    block[5] = dir;
    block[6..10].copy_from_slice(&devaddr.to_le_bytes());
    block[10..14].copy_from_slice(&fcnt.to_le_bytes());
    block[14] = 0x00; // Reserved
    block[15] = len;

    block
}

/// Traditional LoRaWAN AES-CTR encryption
pub fn aes_ctr_encrypt(
    key: &[u8; LORAWAN_KEY_SIZE],
    data: &[u8],
    fcnt: u32,
    devaddr: u32,
    dir: u8,
) -> Result<Vec<u8>, &'static str> {
    println!("🔐 AES-CTR Encrypt Debug:");
    println!("  └─ Data: {}", hex_string(data));
    println!("  └─ FCnt: {}, DevAddr: 0x{:08X}, Dir: {}", fcnt, devaddr, dir);

    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut encrypted = data.to_vec();
    let mut counter = 1u8;

    // Encrypt in 16-byte blocks
    for chunk in encrypted.chunks_mut(AES_BLOCK_SIZE) {
        let counter_block = build_counter_block(dir, devaddr, fcnt, counter);
        println!("  └─ Counter block {}: {}", counter, hex_string(&counter_block));

        let mut cipher = create_aes_ctr_cipher(key, &counter_block);
        cipher.apply_keystream(chunk);

        counter = counter.wrapping_add(1);
    }

    println!("  └─ Encrypted: {}", hex_string(&encrypted));
    Ok(encrypted)
}

/// Traditional LoRaWAN AES-CTR decryption (same as encryption)
pub fn aes_ctr_decrypt(
    key: &[u8; LORAWAN_KEY_SIZE],
    ciphertext: &[u8],
    fcnt: u32,
    devaddr: u32,
    dir: u8,
) -> Result<Vec<u8>, &'static str> {
    println!("🔓 AES-CTR Decrypt Debug:");
    println!("  └─ Ciphertext: {}", hex_string(ciphertext));
    println!("  └─ FCnt: {}, DevAddr: 0x{:08X}, Dir: {}", fcnt, devaddr, dir);

    // AES-CTR decryption is the same as encryption
    aes_ctr_encrypt(key, ciphertext, fcnt, devaddr, dir)
}

/// Calculate LoRaWAN MIC using CMAC
pub fn calculate_mic(
    key: &[u8; LORAWAN_KEY_SIZE],
    mhdr: u8,
    fhdr: &[u8],
    fport: Option<u8>,
    frm_payload: &[u8],
    fcnt: u32,
    devaddr: u32,
    dir: u8,
) -> Result<[u8; LORAWAN_MIC_SIZE], &'static str> {
    println!("🔒 MIC Calculate Debug:");
    println!("  └─ MHDR: 0x{:02X}", mhdr);
    println!("  └─ FHDR: {}", hex_string(fhdr));
    println!("  └─ FPort: {:?}", fport);
    println!("  └─ FRMPayload: {}", hex_string(frm_payload));
    println!("  └─ FCnt: {}, DevAddr: 0x{:08X}, Dir: {}", fcnt, devaddr, dir);

    // Calculate total length
    let total_len = 1 + fhdr.len() + if fport.is_some() { 1 } else { 0 } + frm_payload.len();

    // Build MIC block
    let mic_block = build_mic_block(dir, devaddr, fcnt, total_len as u8);
    println!("  └─ MIC block: {}", hex_string(&mic_block));

    // Create CMAC
    let mut mac = create_cmac(key);

    // Add MIC block first
    mac.update(&mic_block);

    // Add MHDR
    mac.update(&[mhdr]);

    // Add FHDR
    mac.update(fhdr);

    // Add FPort if present
    if let Some(port) = fport {
        mac.update(&[port]);
    }

    // Add FRMPayload
    mac.update(frm_payload);

    // Finalize and get first 4 bytes as MIC
    let result = mac.finalize().into_bytes();
    let mut mic = [0u8; LORAWAN_MIC_SIZE];
    mic.copy_from_slice(&result[..LORAWAN_MIC_SIZE]);

    println!("  └─ Full CMAC: {}", hex_string(&result));
    println!("  └─ MIC (first 4 bytes): {}", hex_string(&mic));

    Ok(mic)
}

/// Verify LoRaWAN MIC
pub fn verify_mic(
    key: &[u8; LORAWAN_KEY_SIZE],
    mhdr: u8,
    fhdr: &[u8],
    fport: Option<u8>,
    frm_payload: &[u8],
    received_mic: &[u8; LORAWAN_MIC_SIZE],
    fcnt: u32,
    devaddr: u32,
    dir: u8,
) -> Result<bool, &'static str> {
    let calculated_mic = calculate_mic(key, mhdr, fhdr, fport, frm_payload, fcnt, devaddr, dir)?;

    let is_valid = calculated_mic == *received_mic;
    println!("  └─ MIC verification: {}", if is_valid { "✅ VALID" } else { "❌ INVALID" });

    Ok(is_valid)
}

/// Get intermediate AES round keys for side-channel analysis
pub fn get_aes_round_keys(key: &[u8; LORAWAN_KEY_SIZE]) -> Vec<[u8; LORAWAN_KEY_SIZE]> {
    // This is a simplified implementation - in a real side-channel analysis,
    // you'd want to extract the actual AES round keys from the key schedule
    let mut round_keys = Vec::new();

    // For now, just return the original key and some derived keys
    round_keys.push(*key);

    // Generate some pseudo-round keys for demonstration
    for i in 1..11 {
        let mut round_key = *key;
        for j in 0..LORAWAN_KEY_SIZE {
            round_key[j] = key[j].wrapping_add(i as u8).wrapping_mul(i as u8);
        }
        round_keys.push(round_key);
    }

    round_keys
}

/// Get AES intermediate states for side-channel analysis
pub fn get_aes_intermediate_state(
    key: &[u8; LORAWAN_KEY_SIZE],
    plaintext: &[u8; AES_BLOCK_SIZE],
    round: u8,
) -> [u8; AES_BLOCK_SIZE] {
    // This is a simplified implementation for side-channel analysis
    // In practice, you'd implement the full AES rounds and capture intermediate states

    let mut state = *plaintext;

    // XOR with key (simplified)
    for i in 0..AES_BLOCK_SIZE {
        state[i] ^= key[i % LORAWAN_KEY_SIZE];
    }

    // Apply some transformations based on round number
    for _ in 0..round {
        for i in 0..AES_BLOCK_SIZE {
            state[i] = state[i].wrapping_add(round).rotate_left(round as u32);
        }
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ctr_encrypt_decrypt() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                   0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let data = b"Hello LoRaWAN!";
        let fcnt = 42;
        let devaddr = 0x01020304;
        let dir = 0;

        let encrypted = aes_ctr_encrypt(&key, data, fcnt, devaddr, dir).unwrap();
        let decrypted = aes_ctr_decrypt(&key, &encrypted, fcnt, devaddr, dir).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_mic_calculation() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                   0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let mhdr = 0x40;
        let fhdr = &[0x04, 0x03, 0x02, 0x01, 0x00, 0x2A, 0x00];
        let fport = Some(1u8);
        let frm_payload = b"Hello";
        let fcnt = 42;
        let devaddr = 0x01020304;
        let dir = 0;

        let mic = calculate_mic(&key, mhdr, fhdr, fport, frm_payload, fcnt, devaddr, dir).unwrap();

        // Verify MIC
        let is_valid = verify_mic(&key, mhdr, fhdr, fport, frm_payload, &mic, fcnt, devaddr, dir).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_round_keys() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                   0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];

        let round_keys = get_aes_round_keys(&key);
        assert_eq!(round_keys.len(), 11); // 1 original + 10 rounds
        assert_eq!(round_keys[0], key);
    }
}
