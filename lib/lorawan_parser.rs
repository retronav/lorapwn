//! Custom LoRaWAN packet parser with ChaCha20-Poly1305 AEAD support
//! Replaces standard MIC with AEAD authentication tag

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::aead_crypto::{aead_encrypt, aead_decrypt, derive_chacha20_key};

const CHACHA20_TAG_SIZE: usize = 16; // ChaCha20-Poly1305 uses 16-byte tags
const LORAWAN_MIC_SIZE: usize = 4;   // LoRaWAN compatibility (we'll store full tag but show as 4-byte)

/// LoRaWAN packet with ChaCha20-Poly1305 AEAD security instead of AES-CTR + CMAC
pub struct AeadLorawanPacket {
    pub mhdr: u8,
    pub mac_payload: Vec<u8>,
    pub aead_tag: [u8; CHACHA20_TAG_SIZE], // Store full 16-byte tag
}

/// Metadata extracted from a LoRaWAN packet
#[derive(Debug, Clone)]
pub struct PacketMetadata {
    pub dev_addr: u32,
    pub fcnt: u32,
    pub fport: u8,
    pub payload_size: usize,
}

impl AeadLorawanPacket {
    /// Parse raw LoRaWAN PHY payload bytes into our custom structure
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 + CHACHA20_TAG_SIZE {
            return Err("Packet too short");
        }

        let mhdr = bytes[0];
        let payload_end = bytes.len() - CHACHA20_TAG_SIZE;
        let mac_payload = bytes[1..payload_end].to_vec();

        let mut aead_tag = [0u8; CHACHA20_TAG_SIZE];
        aead_tag.copy_from_slice(&bytes[payload_end..]);

        Ok(Self {
            mhdr,
            mac_payload,
            aead_tag
        })
    }

    /// Extract device address from packet (bytes 0-3)
    pub fn get_dev_addr(&self) -> Result<u32, &'static str> {
        if self.mac_payload.len() < 4 {
            return Err("MAC payload too short");
        }

        let mut addr_bytes = [0u8; 4];
        addr_bytes.copy_from_slice(&self.mac_payload[0..4]);
        Ok(u32::from_le_bytes(addr_bytes))
    }

    /// Extract frame counter from packet (bytes 5-6)
    pub fn get_fcnt(&self) -> Result<u32, &'static str> {
        if self.mac_payload.len() < 7 {
            return Err("MAC payload too short for FCnt");
        }

        let fcnt_low = self.mac_payload[5];
        let fcnt_high = self.mac_payload[6];
        Ok(u16::from_le_bytes([fcnt_low, fcnt_high]) as u32)
    }

    /// Extract FCtrl from packet (byte 4)
    pub fn get_fctrl(&self) -> Result<u8, &'static str> {
        if self.mac_payload.len() < 5 {
            return Err("MAC payload too short for FCtrl");
        }

        Ok(self.mac_payload[4])
    }

    /// Extract FPort from packet (byte 7)
    pub fn get_fport(&self) -> Result<u8, &'static str> {
        if self.mac_payload.len() < 8 {
            return Err("No FPort in packet");
        }

        Ok(self.mac_payload[7])
    }

    /// Create AAD for ChaCha20-Poly1305 AEAD operations
    fn create_aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();

        // Add MHDR
        aad.push(self.mhdr);

        // Add DevAddr (4 bytes)
        if self.mac_payload.len() >= 4 {
            aad.extend_from_slice(&self.mac_payload[0..4]);
        }

        // Add FCtrl (1 byte)
        if self.mac_payload.len() >= 5 {
            aad.push(self.mac_payload[4]);
        }

        // Add FCnt (2 bytes)
        if self.mac_payload.len() >= 7 {
            aad.extend_from_slice(&self.mac_payload[5..7]);
        }

        // Add FPort (1 byte) if present
        if self.mac_payload.len() >= 8 {
            aad.push(self.mac_payload[7]);
        }

        aad
    }

    /// Encrypt FRMPayload using ChaCha20-Poly1305 AEAD
    pub fn encrypt_payload(&mut self, lorawan_key: &[u8; 16], dev_addr: u32, fcnt: u32, dir: u8) -> Result<(), &'static str> {
        let chacha_key = derive_chacha20_key(lorawan_key);
        let aad = self.create_aad();

        if self.mac_payload.len() <= 7 {
            // No FRMPayload to encrypt, just authenticate the header
            let (_, tag) = aead_encrypt(&chacha_key, &aad, &[], fcnt, dev_addr, dir)?;
            self.aead_tag = tag; // Store full 16-byte tag
            return Ok(());
        }

        // Extract FRMPayload (everything after FPort)
        let frm_payload_start = 8;
        let frm_payload = &self.mac_payload[frm_payload_start..];

        // Encrypt the FRMPayload
        let (encrypted, tag) = aead_encrypt(&chacha_key, &aad, frm_payload, fcnt, dev_addr, dir)?;

        // Replace the FRMPayload with encrypted data
        self.mac_payload.splice(frm_payload_start.., encrypted);

        // Store full 16-byte AEAD tag
        self.aead_tag = tag;

        Ok(())
    }

    /// Decrypt FRMPayload using ChaCha20-Poly1305 AEAD
    pub fn decrypt_payload(&self, lorawan_key: &[u8; 16], dir: u8) -> Result<Vec<u8>, &'static str> {
        let dev_addr = self.get_dev_addr()?;
        let fcnt = self.get_fcnt()?;
        let chacha_key = derive_chacha20_key(lorawan_key);
        let aad = self.create_aad();

        if self.mac_payload.len() <= 7 {
            // No FRMPayload to decrypt, just verify the header
            let _decrypted = aead_decrypt(&chacha_key, &aad, &[], &self.aead_tag, fcnt, dev_addr, dir)?;
            return Ok(Vec::new());
        }

        // Extract encrypted FRMPayload
        let frm_payload_start = 8;
        let encrypted_frm_payload = &self.mac_payload[frm_payload_start..];

        // Decrypt the FRMPayload using the full 16-byte tag
        aead_decrypt(&chacha_key, &aad, encrypted_frm_payload, &self.aead_tag, fcnt, dev_addr, dir)
    }

    /// Serialize to bytes for transmission or storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.mhdr);
        bytes.extend_from_slice(&self.mac_payload);
        bytes.extend_from_slice(&self.aead_tag);
        bytes
    }

    /// Get the 4-byte MIC equivalent for LoRaWAN compatibility
    pub fn get_mic(&self) -> [u8; LORAWAN_MIC_SIZE] {
        let mut mic = [0u8; LORAWAN_MIC_SIZE];
        mic.copy_from_slice(&self.aead_tag[0..LORAWAN_MIC_SIZE]);
        mic
    }

    /// Get packet metadata for logging
    pub fn get_metadata(&self) -> Result<PacketMetadata, &'static str> {
        let encrypted_payload_size = if self.mac_payload.len() > 7 {
            self.mac_payload.len() - 8
        } else {
            0
        };

        Ok(PacketMetadata {
            dev_addr: self.get_dev_addr()?,
            fcnt: self.get_fcnt()?,
            fport: self.get_fport().unwrap_or(0),
            payload_size: encrypted_payload_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_structure() {
        let dev_addr: u32 = 0x01020304;
        let fcnt: u32 = 42;
        let fctrl: u8 = 0x00;
        let fport: u8 = 1;

        let mhdr: u8 = 0x40;
        let mut mac_payload = Vec::new();

        mac_payload.extend_from_slice(&dev_addr.to_le_bytes());
        mac_payload.push(fctrl);
        mac_payload.extend_from_slice(&(fcnt as u16).to_le_bytes());
        mac_payload.push(fport);

        println!("MAC payload structure:");
        for (i, byte) in mac_payload.iter().enumerate() {
            println!("  Position {}: 0x{:02X}", i, byte);
        }

        let packet = AeadLorawanPacket {
            mhdr,
            mac_payload,
            aead_tag: [0; CHACHA20_TAG_SIZE],
        };

        assert_eq!(packet.get_dev_addr().unwrap(), dev_addr);
        assert_eq!(packet.get_fcnt().unwrap(), fcnt);
        assert_eq!(packet.get_fctrl().unwrap(), fctrl);
        assert_eq!(packet.get_fport().unwrap(), fport);

        println!("Parsed values:");
        println!("  DevAddr: 0x{:08X}", packet.get_dev_addr().unwrap());
        println!("  FCnt: {}", packet.get_fcnt().unwrap());
        println!("  FCtrl: 0x{:02X}", packet.get_fctrl().unwrap());
        println!("  FPort: {}", packet.get_fport().unwrap());
    }

    #[test]
    fn test_packet_parsing() {
        let dev_addr: u32 = 0x01020304;
        let fcnt: u32 = 42;
        let fctrl: u8 = 0x00;
        let fport: u8 = 1;

        let mhdr: u8 = 0x40;
        let mut mac_payload = Vec::new();
        mac_payload.extend_from_slice(&dev_addr.to_le_bytes());
        mac_payload.push(fctrl);
        mac_payload.extend_from_slice(&(fcnt as u16).to_le_bytes());
        mac_payload.push(fport);

        let packet = AeadLorawanPacket {
            mhdr,
            mac_payload,
            aead_tag: [0; CHACHA20_TAG_SIZE],
        };

        assert_eq!(packet.get_dev_addr().unwrap(), dev_addr);
        assert_eq!(packet.get_fcnt().unwrap(), fcnt);
        assert_eq!(packet.get_fctrl().unwrap(), fctrl);
        assert_eq!(packet.get_fport().unwrap(), fport);
    }

    #[test]
    fn test_packet_encrypt_decrypt() {
        let lorawan_key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let dev_addr: u32 = 0x01020304;
        let fcnt: u32 = 42;
        let dir: u8 = 0;
        let data = b"Hello ChaCha20!";

        let mhdr: u8 = 0x40;
        let mut mac_payload = Vec::new();
        mac_payload.extend_from_slice(&dev_addr.to_le_bytes());
        mac_payload.push(0x00);
        mac_payload.extend_from_slice(&(fcnt as u16).to_le_bytes());
        mac_payload.push(1);
        mac_payload.extend_from_slice(data);

        let mut packet = AeadLorawanPacket {
            mhdr,
            mac_payload,
            aead_tag: [0; CHACHA20_TAG_SIZE],
        };

        // Verify parsing before encryption
        assert_eq!(packet.get_dev_addr().unwrap(), dev_addr);
        assert_eq!(packet.get_fcnt().unwrap(), fcnt);
        assert_eq!(packet.get_fport().unwrap(), 1);

        // Encrypt payload
        packet.encrypt_payload(&lorawan_key, dev_addr, fcnt, dir).expect("Encryption failed");

        // Get bytes representation
        let bytes = packet.to_bytes();

        // Parse back from bytes
        let parsed_packet = AeadLorawanPacket::parse(&bytes).expect("Parsing failed");

        // Verify parsing is still correct after encryption
        assert_eq!(parsed_packet.get_dev_addr().unwrap(), dev_addr);
        assert_eq!(parsed_packet.get_fcnt().unwrap(), fcnt);
        assert_eq!(parsed_packet.get_fport().unwrap(), 1);

        // Decrypt and verify
        let decrypted = parsed_packet.decrypt_payload(&lorawan_key, dir).expect("Decryption failed");

        assert_eq!(decrypted, data);
    }
}