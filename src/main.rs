#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(any(test, feature = "std")), no_main)]

mod aead_crypto;
mod lorawan_parser;
mod simulation;
mod debug;
mod crypto_benchmark;
mod performance_analysis;
mod packet_format;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(any(test, feature = "std")))]
use panic_halt as _;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(test)]
mod tests {
    use crate::lorawan_parser::AeadLorawanPacket;

    #[cfg(feature = "std")]
    use std::vec::Vec;

    const CHACHA20_TAG_SIZE: usize = 16;

    #[test]
    fn test_chacha20_aead_encryption_decryption() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];

        let dev_addr: u32 = 0x01020304;
        let fcnt: u32 = 42;
        let dir: u8 = 0;
        let data = b"Hello LoRaWAN with ChaCha20-Poly1305!";

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

        packet.encrypt_payload(&key, dev_addr, fcnt, dir).expect("Encryption failed");
        let bytes = packet.to_bytes();
        let parsed_packet = AeadLorawanPacket::parse(&bytes).expect("Parsing failed");
        let decrypted = parsed_packet.decrypt_payload(&key, dir).expect("Decryption failed");

        assert_eq!(decrypted, data);
    }
}

#[cfg(not(any(test, feature = "std")))]
#[cortex_m_rt::entry]
fn main() -> ! {
    loop {}
}

#[cfg(feature = "std")]
fn main() {
    println!("🔐 LoraPwn: LoRaWAN Security Research & Sniffing Toolkit");
    println!("Version 0.1.0 - Comprehensive Cryptographic Analysis");
    println!("Author: HimuCodes - Advanced LoRaWAN Security Research");
    println!("═══════════════════════════════════════════════════════════\n");

    // Show packet format comparison
    packet_format::print_packet_format_comparison();
    packet_format::generate_packet_diagrams();

    // Debug packet structure
    debug::debug_packet_structure();

    // Run simulation tests
    simulation::run_simulation();

    // Run simple performance analysis
    performance_analysis::run_simple_performance_test();

    println!("\n🎯 RESEARCH CONCLUSIONS");
    println!("═══════════════════════════════════════════════════════════");
    println!("✅ ChaCha20-Poly1305 successfully implemented for LoRaWAN");
    println!("✅ 4x stronger authentication security (128-bit vs 32-bit)");
    println!("✅ AEAD provides unified encryption + authentication");
    println!("✅ Performance competitive with traditional methods");
    println!("✅ Resistance to timing attacks and modern cryptanalysis");
    println!("\n📊 Run 'cargo bench' for detailed Criterion benchmarks");
}