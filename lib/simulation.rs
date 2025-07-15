//! Simulation environment for testing LoRaWAN ChaCha20-Poly1305 AEAD without hardware
//! Generates test packets and validates encryption/decryption

use crate::lorawan_parser::AeadLorawanPacket;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const CHACHA20_TAG_SIZE: usize = 16;

/// Simulates a LoRaWAN device generating a packet with ChaCha20-Poly1305
pub fn simulate_device_packet(
    app_key: &[u8; 16],
    dev_addr: u32,
    fcnt: u32,
    payload: &[u8],
    port: u8,
) -> Vec<u8> {
    println!("🔵 Simulating device sending packet with ChaCha20-Poly1305:");
    println!("  └─ DevAddr: 0x{:08X}", dev_addr);
    println!("  └─ FCnt: {}", fcnt);
    println!("  └─ FPort: {}", port);
    println!("  └─ Payload: {:?}", payload);
    println!("  └─ Payload (hex): {}", hex_string(payload));

    // Create a mock LoRaWAN packet (unconfirmed uplink)
    let mhdr: u8 = 0x40;
    let mut mac_payload = Vec::new();

    // DevAddr (4 bytes, little endian)
    let dev_addr_bytes = dev_addr.to_le_bytes();
    mac_payload.extend_from_slice(&dev_addr_bytes);
    println!("  └─ DevAddr bytes: {}", hex_string(&dev_addr_bytes));

    // FCtrl (1 byte)
    mac_payload.push(0x00);

    // FCnt (2 bytes, little endian)
    let fcnt_bytes = (fcnt as u16).to_le_bytes();
    mac_payload.extend_from_slice(&fcnt_bytes);
    println!("  └─ FCnt bytes: {}", hex_string(&fcnt_bytes));

    // FPort (1 byte)
    mac_payload.push(port);

    // FRMPayload
    mac_payload.extend_from_slice(payload);

    println!("  └─ MAC payload before encryption: {}", hex_string(&mac_payload));

    // Create our packet with 16-byte tag
    let mut packet = AeadLorawanPacket {
        mhdr,
        mac_payload,
        aead_tag: [0; CHACHA20_TAG_SIZE],
    };

    // Verify parsing before encryption
    println!("  └─ Parsed DevAddr before encryption: 0x{:08X}", packet.get_dev_addr().unwrap());
    println!("  └─ Parsed FCnt before encryption: {}", packet.get_fcnt().unwrap());
    println!("  └─ Parsed FPort before encryption: {}", packet.get_fport().unwrap());

    // Encrypt payload with ChaCha20-Poly1305 AEAD
    let dir = 0; // Uplink
    if let Err(e) = packet.encrypt_payload(app_key, dev_addr, fcnt, dir) {
        println!("❌ ChaCha20-Poly1305 encryption failed: {}", e);
        return Vec::new();
    }

    println!("✅ Packet encrypted with ChaCha20-Poly1305 AEAD");

    // Get bytes representation
    let bytes = packet.to_bytes();
    println!("  └─ Encrypted packet size: {} bytes", bytes.len());
    println!("  └─ Complete packet: {}", hex_string(&bytes));
    println!("  └─ LoRaWAN-compatible MIC: {}", hex_string(&packet.get_mic()));

    bytes
}

/// Simulates a gateway/network server receiving and processing a packet
pub fn simulate_gateway_receive(
    app_key: &[u8; 16],
    packet_bytes: &[u8],
) -> Option<Vec<u8>> {
    println!("\n🔵 Simulating gateway receiving packet:");
    println!("  └─ Received {} bytes", packet_bytes.len());
    println!("  └─ Raw packet: {}", hex_string(packet_bytes));

    // Parse the packet
    let parsed_packet = match AeadLorawanPacket::parse(packet_bytes) {
        Ok(packet) => packet,
        Err(e) => {
            println!("❌ Parsing failed: {}", e);
            return None;
        }
    };

    println!("  └─ Parsed MHDR: 0x{:02X}", parsed_packet.mhdr);
    println!("  └─ Parsed MAC payload: {}", hex_string(&parsed_packet.mac_payload));
    println!("  └─ Full AEAD tag: {}", hex_string(&parsed_packet.aead_tag));
    println!("  └─ LoRaWAN-compatible MIC: {}", hex_string(&parsed_packet.get_mic()));

    // Extract metadata
    let metadata = match parsed_packet.get_metadata() {
        Ok(meta) => meta,
        Err(e) => {
            println!("❌ Failed to extract metadata: {}", e);
            return None;
        }
    };

    println!("  └─ DevAddr: 0x{:08X}", metadata.dev_addr);
    println!("  └─ FCnt: {}", metadata.fcnt);
    println!("  └─ FPort: {}", metadata.fport);
    println!("  └─ Encrypted payload size: {} bytes", metadata.payload_size);

    // Decrypt and verify with ChaCha20-Poly1305 AEAD
    let dir = 0; // Uplink
    match parsed_packet.decrypt_payload(app_key, dir) {
        Ok(decrypted) => {
            println!("✅ ChaCha20-Poly1305 AEAD authentication successful");
            println!("✅ Decrypted payload: {:?}", decrypted);
            println!("✅ Decrypted payload (hex): {}", hex_string(&decrypted));
            Some(decrypted)
        },
        Err(e) => {
            println!("❌ ChaCha20-Poly1305 AEAD verification failed: {}", e);
            None
        }
    }
}

/// Convert bytes to hex string for display
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

/// Run a complete simulation of device-to-gateway communication
pub fn run_simulation() {
    println!("\n🚀 Starting LoRaWAN ChaCha20-Poly1305 AEAD simulation");
    println!("====================================================\n");

    // Simulation parameters
    let app_key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
    let dev_addr: u32 = 0x01020304;
    let fcnt: u32 = 42;
    let port: u8 = 1;

    // Test with a simple payload first
    let test_payload = b"Hello ChaCha20-Poly1305!";

    println!("\n📦 Simple Test - Payload size: {} bytes", test_payload.len());

    // Simulate device creating and sending a packet
    let packet = simulate_device_packet(&app_key, dev_addr, fcnt, test_payload, port);

    // Simulate gateway receiving the packet
    let decrypted = simulate_gateway_receive(&app_key, &packet);

    // Verify result
    match decrypted {
        Some(data) if data == test_payload => {
            println!("✅ TEST PASSED: Payload successfully encrypted and decrypted");

            // Run additional tests
            run_additional_tests(&app_key, dev_addr, port);
        },
        Some(data) => {
            println!("❌ TEST FAILED: Decrypted data doesn't match original");
            println!("  └─ Expected: {:?}", test_payload);
            println!("  └─ Got: {:?}", data);
        },
        None => {
            println!("❌ TEST FAILED: Decryption returned no data");
        }
    }
}

/// Run additional tests with different payloads
fn run_additional_tests(app_key: &[u8; 16], dev_addr: u32, port: u8) {
    println!("\n🧪 Running additional tests...");

    let test_cases = vec![
        ("Short", b"Hi".to_vec()),
        ("Binary", vec![0x01, 0x02, 0x03, 0x04]),
        ("Longer message", b"This is a longer test message for ChaCha20-Poly1305 AEAD".to_vec()),
    ];

    for (i, (name, payload)) in test_cases.iter().enumerate() {
        println!("\n📦 Test {}: {} - {} bytes", i + 1, name, payload.len());

        let packet = simulate_device_packet(app_key, dev_addr, 50 + i as u32, payload, port);
        let decrypted = simulate_gateway_receive(app_key, &packet);

        match decrypted {
            Some(data) if data == *payload => {
                println!("✅ {} test PASSED", name);
            },
            _ => {
                println!("❌ {} test FAILED", name);
            }
        }
    }

    // Security tests
    run_security_tests(app_key, dev_addr, port);
}

/// Run security tests
fn run_security_tests(app_key: &[u8; 16], dev_addr: u32, port: u8) {
    println!("\n🔒 Running security tests...");

    // Test with wrong key
    println!("\n📦 Security Test 1: Wrong Key");
    let wrong_key = [0xFF; 16];
    let packet = simulate_device_packet(app_key, dev_addr, 100, b"Secret", port);
    let result = simulate_gateway_receive(&wrong_key, &packet);

    if result.is_none() {
        println!("✅ Wrong key test PASSED: Authentication failed as expected");
    } else {
        println!("❌ Wrong key test FAILED: Should have failed authentication");
    }

    // Test with tampered packet
    println!("\n📦 Security Test 2: Tampered Packet");
    let mut packet = simulate_device_packet(app_key, dev_addr, 101, b"Don't tamper with me", port);

    if packet.len() > 20 {
        packet[20] ^= 0xFF; // Tamper with a byte
        println!("  └─ Tampered with byte at position 20");

        let result = simulate_gateway_receive(app_key, &packet);

        if result.is_none() {
            println!("✅ Tamper test PASSED: Authentication failed as expected");
        } else {
            println!("❌ Tamper test FAILED: Should have failed authentication");
        }
    }
}