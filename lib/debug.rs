//! Debug utilities for understanding packet structure

use crate::lorawan_parser::AeadLorawanPacket;

#[cfg(feature = "std")]
use std::vec::Vec;

const CHACHA20_TAG_SIZE: usize = 16;

pub fn debug_packet_structure() {
    println!("🔍 Debugging LoRaWAN Packet Structure");
    println!("=====================================");

    let dev_addr: u32 = 0x01020304;
    let fcnt: u32 = 42;
    let fctrl: u8 = 0x00;
    let fport: u8 = 1;
    let payload = b"Hello";

    println!("\n📊 Expected values:");
    println!("  DevAddr: 0x{:08X}", dev_addr);
    println!("  FCnt: {}", fcnt);
    println!("  FCtrl: 0x{:02X}", fctrl);
    println!("  FPort: {}", fport);
    println!("  Payload: {:?}", payload);

    // Create MAC payload step by step
    let mut mac_payload = Vec::new();

    println!("\n🔨 Building MAC payload:");

    // DevAddr (4 bytes, little endian)
    let dev_addr_bytes = dev_addr.to_le_bytes();
    mac_payload.extend_from_slice(&dev_addr_bytes);
    println!("  DevAddr bytes (pos 0-3): {:02X?}", dev_addr_bytes);

    // FCtrl (1 byte)
    mac_payload.push(fctrl);
    println!("  FCtrl byte (pos 4): 0x{:02X}", fctrl);

    // FCnt (2 bytes, little endian)
    let fcnt_bytes = (fcnt as u16).to_le_bytes();
    mac_payload.extend_from_slice(&fcnt_bytes);
    println!("  FCnt bytes (pos 5-6): {:02X?}", fcnt_bytes);

    // FPort (1 byte)
    mac_payload.push(fport);
    println!("  FPort byte (pos 7): 0x{:02X}", fport);

    // Payload
    mac_payload.extend_from_slice(payload);
    println!("  Payload bytes (pos 8+): {:02X?}", payload);

    println!("\n📋 Complete MAC payload:");
    for (i, byte) in mac_payload.iter().enumerate() {
        println!("  Position {}: 0x{:02X}", i, byte);
    }

    // Create packet and test parsing
    let packet = AeadLorawanPacket {
        mhdr: 0x40,
        mac_payload,
        aead_tag: [0; CHACHA20_TAG_SIZE], // Use 16-byte tag
    };

    println!("\n🔍 Parsing results:");
    println!("  Parsed DevAddr: 0x{:08X}", packet.get_dev_addr().unwrap());
    println!("  Parsed FCnt: {}", packet.get_fcnt().unwrap());
    println!("  Parsed FCtrl: 0x{:02X}", packet.get_fctrl().unwrap());
    println!("  Parsed FPort: {}", packet.get_fport().unwrap());

    // Check if parsing matches expectations
    let parsing_ok = packet.get_dev_addr().unwrap() == dev_addr &&
        packet.get_fcnt().unwrap() == fcnt &&
        packet.get_fctrl().unwrap() == fctrl &&
        packet.get_fport().unwrap() == fport;

    if parsing_ok {
        println!("✅ All parsing tests passed!");
    } else {
        println!("❌ Parsing failed!");
    }

    println!("\n📏 Packet sizes:");
    println!("  MAC payload: {} bytes", packet.mac_payload.len());
    println!("  AEAD tag: {} bytes", packet.aead_tag.len());
    println!("  Total packet: {} bytes", 1 + packet.mac_payload.len() + packet.aead_tag.len());
    println!("  LoRaWAN MIC equivalent: {} bytes", packet.get_mic().len());
}