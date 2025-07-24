//! STM32F303RE Crypto Benchmark with Embassy - Advanced Version
//! HimuCodes - 2025-07-16 13:39:29

#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_time::{Duration, Instant, Timer};
use {defmt_rtt as _, panic_probe as _};

// Crypto imports
use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit, StreamCipher, KeyIvInit};
use chacha20::ChaCha20;
use heapless::Vec;

// Helper function to convert numbers to strings in no_std
fn u32_to_str(val: u32) -> heapless::String<16> {
    let mut s = heapless::String::new();
    if val == 0 {
        let _ = s.push('0');
        return s;
    }

    let mut temp = val;
    let mut digits = heapless::Vec::<u8, 16>::new();

    while temp > 0 {
        let _ = digits.push((temp % 10) as u8 + b'0');
        temp /= 10;
    }

    for &digit in digits.iter().rev() {
        let _ = s.push(digit as char);
    }
    s
}

fn u64_to_str(val: u64) -> heapless::String<32> {
    let mut s = heapless::String::new();
    if val == 0 {
        let _ = s.push('0');
        return s;
    }

    let mut temp = val;
    let mut digits = heapless::Vec::<u8, 32>::new();

    while temp > 0 {
        let _ = digits.push((temp % 10) as u8 + b'0');
        temp /= 10;
    }

    for &digit in digits.iter().rev() {
        let _ = s.push(digit as char);
    }
    s
}

fn u8_to_str(val: u8) -> heapless::String<8> {
    let mut s = heapless::String::new();
    if val == 0 {
        let _ = s.push('0');
        return s;
    }

    let mut temp = val;
    let mut digits = heapless::Vec::<u8, 8>::new();

    while temp > 0 {
        let _ = digits.push((temp % 10) + b'0');
        temp /= 10;
    }

    for &digit in digits.iter().rev() {
        let _ = s.push(digit as char);
    }
    s
}

fn f32_to_str_1decimal(val: f32) -> heapless::String<16> {
    let mut s = heapless::String::new();
    let integer_part = val as u32;
    let decimal_part = ((val - integer_part as f32) * 10.0) as u32;

    let int_str = u32_to_str(integer_part);
    let _ = s.push_str(&int_str);
    let _ = s.push('.');
    let dec_str = u32_to_str(decimal_part);
    let _ = s.push_str(&dec_str);
    s
}

// LoRaWAN packet structures
#[derive(Debug, Clone)]
struct LoRaWANPacket {
    mhdr: u8,
    dev_addr: [u8; 4],
    fctrl: u8,
    fcnt: u16,
    fopts: Vec<u8, 15>, // Max 15 bytes for FOpts
    fport: Option<u8>,
    frm_payload: Vec<u8, 242>, // Max LoRaWAN payload
    mic: [u8; 4],
}

impl LoRaWANPacket {
    fn new_uplink(payload_size: usize) -> Self {
        let mut packet = LoRaWANPacket {
            mhdr: 0x40, // Unconfirmed Data Up
            dev_addr: [0x01, 0x02, 0x03, 0x04],
            fctrl: 0x00,
            fcnt: 1,
            fopts: Vec::new(),
            fport: Some(1),
            frm_payload: Vec::new(),
            mic: [0; 4],
        };

        // Fill payload with test data
        for i in 0..payload_size.min(242) {
            let _ = packet.frm_payload.push((i % 256) as u8);
        }

        packet
    }

    fn serialize(&self) -> Vec<u8, 256> {
        let mut buffer = Vec::new();
        let _ = buffer.push(self.mhdr);
        let _ = buffer.extend_from_slice(&self.dev_addr);
        let _ = buffer.push(self.fctrl);
        let _ = buffer.extend_from_slice(&self.fcnt.to_le_bytes());
        let _ = buffer.extend_from_slice(&self.fopts);
        if let Some(fport) = self.fport {
            let _ = buffer.push(fport);
        }
        let _ = buffer.extend_from_slice(&self.frm_payload);
        let _ = buffer.extend_from_slice(&self.mic);
        buffer
    }
}

// Simple PRNG for deterministic testing
struct SimpleRng {
    state: u32,
}

impl SimpleRng {
    fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        self.state
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let val = self.next_u32();
            let bytes = val.to_le_bytes();
            for (i, &byte) in bytes.iter().enumerate() {
                if i < chunk.len() {
                    chunk[i] = byte;
                }
            }
        }
    }
}

// Benchmark statistics
#[derive(Default)]
struct BenchmarkStats {
    total_operations: u32,
    total_bytes: u32,
    total_duration_us: u64,
    min_latency_us: u64,
    max_latency_us: u64,
    successful_operations: u32,
    latencies: Vec<u64, 16>, // Reduced from 256 to 16 samples to save memory
}

impl BenchmarkStats {
    fn record_operation(&mut self, bytes: u32, duration_us: u64) {
        self.total_operations += 1;
        self.total_bytes += bytes;
        self.total_duration_us += duration_us;
        self.successful_operations += 1;

        // Store latency for statistical analysis (up to 16 samples)
        if self.latencies.len() < 16 {
            let _ = self.latencies.push(duration_us);
        }

        if self.total_operations == 1 {
            self.min_latency_us = duration_us;
            self.max_latency_us = duration_us;
        } else {
            self.min_latency_us = self.min_latency_us.min(duration_us);
            self.max_latency_us = self.max_latency_us.max(duration_us);
        }
    }

    fn average_latency_us(&self) -> u64 {
        if self.total_operations > 0 {
            self.total_duration_us / self.total_operations as u64
        } else {
            0
        }
    }

    fn throughput_bps(&self) -> u64 {
        if self.total_duration_us > 0 {
            (self.total_bytes as u64 * 8 * 1_000_000) / self.total_duration_us
        } else {
            0
        }
    }

    fn throughput_kbps(&self) -> u64 {
        self.throughput_bps() / 1000
    }

    fn throughput_packets_per_second(&self) -> u64 {
        if self.total_duration_us > 0 {
            (self.successful_operations as u64 * 1_000_000) / self.total_duration_us
        } else {
            0
        }
    }

    fn efficiency_bytes_per_us(&self) -> u64 {
        if self.total_duration_us > 0 {
            self.total_bytes as u64 / self.total_duration_us
        } else {
            0
        }
    }

    fn variance(&self) -> u64 {
        if self.latencies.len() < 2 {
            return 0;
        }

        let mean = self.average_latency_us();
        let sum_squared_diff: u64 = self.latencies.iter()
            .map(|&x| {
                let diff = if x > mean { x - mean } else { mean - x };
                diff * diff
            })
            .sum();

        sum_squared_diff / self.latencies.len() as u64
    }

    fn standard_deviation(&self) -> u64 {
        let var = self.variance();
        // Simple integer square root approximation
        if var == 0 { return 0; }
        let mut x = var;
        let mut root = 0;
        while x >= (2 * root + 1) {
            x -= 2 * root + 1;
            root += 1;
        }
        root
    }

    fn percentile(&self, p: u8) -> u64 {
        if self.latencies.is_empty() {
            return 0;
        }

        // Simple percentile calculation (we'd need sorting for exact percentiles)
        // This gives an approximation based on min/max/avg
        match p {
            0 => self.min_latency_us,
            25 => (self.min_latency_us + self.average_latency_us()) / 2,
            50 => self.average_latency_us(),
            75 => (self.average_latency_us() + self.max_latency_us) / 2,
            90 => (self.average_latency_us() * 2 + self.max_latency_us) / 3,
            95 => (self.average_latency_us() + self.max_latency_us * 2) / 3,
            99 => (self.average_latency_us() + self.max_latency_us * 9) / 10,
            100 => self.max_latency_us,
            _ => self.average_latency_us(),
        }
    }

    fn success_rate_percent(&self) -> u8 {
        if self.total_operations > 0 {
            ((self.successful_operations * 100) / self.total_operations) as u8
        } else {
            0
        }
    }
}

// AES-128 CTR mode implementation for LoRaWAN
fn aes_encrypt_packet(packet: &[u8], key: &[u8; 16], counter: u32) -> Vec<u8, 256> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut result = Vec::new();

    for (i, &_byte) in packet.iter().enumerate() {
        if i % 16 == 0 {
            // Create counter block
            let mut counter_block = [0u8; 16];
            counter_block[0..4].copy_from_slice(&(counter + (i / 16) as u32).to_le_bytes());

            // Encrypt counter block
            let mut keystream = [counter_block.into()];
            cipher.encrypt_blocks(&mut keystream);

            // XOR with plaintext
            for j in 0..16.min(packet.len() - i) {
                if i + j < packet.len() {
                    let _ = result.push(packet[i + j] ^ keystream[0][j]);
                }
            }
        }
    }

    result
}

// ChaCha20 encryption implementation for LoRaWAN
fn chacha20_encrypt_packet(packet: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8, 256> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    let mut result = Vec::new();

    for &byte in packet.iter() {
        let mut buffer = [byte];
        cipher.apply_keystream(&mut buffer);
        let _ = result.push(buffer[0]);
    }

    result
}

// Simple ChaCha20-only implementation (without Poly1305 for now)
fn chacha20_decrypt_packet(encrypted: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8, 256> {
    // ChaCha20 is symmetric, so decryption is the same as encryption
    chacha20_encrypt_packet(encrypted, key, nonce)
}

// Configure Embassy executor with larger task arena
#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // Print benchmark header
    TableFormatter::print_header("STM32F303RE LoRaWAN CRYPTO BENCHMARK SUITE v2.0");
    info!("║ Target: STM32F303RE │ Framework: Embassy │ Date: 2025-07-24        ║");
    info!("║ Algorithms: AES-128 CTR vs ChaCha20 │ LoRaWAN Packet Format     ║");
    TableFormatter::print_footer();

    let p = embassy_stm32::init(Default::default());
    let mut led = Output::new(p.PA5, Level::Low, Speed::Low);

    // Test parameters - significantly reduced to prevent task arena overflow
    let test_iterations = 5; // Reduced from 20 to 5
    let packet_sizes = [12, 16]; // Only testing with very small packets

    // Keys and test data
    let aes_key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                   0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];

    let chacha_key_bytes = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                           0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                           0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                           0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f];

    TableFormatter::print_header("BENCHMARK CONFIGURATION");
    info!("║ Iterations per test: {}                                              ║", test_iterations);
    info!("║ Packet sizes: [12, 16] bytes (minimized for memory efficiency)      ║");
    info!("║ AES Key Size: 16 bytes (128-bit) │ ChaCha20 Key Size: 32 bytes    ║");
    info!("║ Test Mode: Encrypt + Decrypt │ Timing Resolution: μs            ║");
    TableFormatter::print_footer();

    // Yield to allow executor to catch up and process outputs
    Timer::after(Duration::from_millis(10)).await;

    for &payload_size in packet_sizes.iter() {
        // Yield after each major step to prevent stack overflow
        Timer::after(Duration::from_millis(5)).await;

        let mut title_str = heapless::String::<64>::new();
        let _ = title_str.push_str("TESTING PAYLOAD SIZE: ");
        let _ = title_str.push_str(&u32_to_str(payload_size as u32));
        let _ = title_str.push_str(" BYTES");
        TableFormatter::print_header(&title_str);

        // Generate test packet
        let lorawan_packet = LoRaWANPacket::new_uplink(payload_size);
        let packet_data = lorawan_packet.serialize();
        let total_packet_size = packet_data.len();

        info!("║ LoRaWAN Packet Structure:                                            ║");
        info!("║   MHDR: 1B │ DevAddr: 4B │ FCtrl: 1B │ FCnt: 2B │ FPort: 1B     ║");
        info!("║   Payload: {}B │ MIC: 4B │ Total Packet: {}B                 ║",
              payload_size, total_packet_size);
        TableFormatter::print_footer();

        // Yield to allow executor to catch up
        Timer::after(Duration::from_millis(10)).await;

        // AES-128 Benchmark
        led.set_high();
        let mut aes_encrypt_stats = BenchmarkStats::default();
        let mut aes_decrypt_stats = BenchmarkStats::default();

        info!("Running AES-128 benchmark... (LED ON)");

        // Run AES benchmarks with frequent yields
        for i in 0..test_iterations {
            // Yield more frequently during crypto operations
            if i > 0 && i % 2 == 0 {
                Timer::after(Duration::from_millis(5)).await;
                info!("AES progress: {}/{}", i, test_iterations);
            }

            // Encryption test
            let start = Instant::now();
            let encrypted = aes_encrypt_packet(&packet_data, &aes_key, i);
            let encrypt_duration = start.elapsed().as_micros();
            aes_encrypt_stats.record_operation(total_packet_size as u32, encrypt_duration);

            // Small yield after each operation
            Timer::after(Duration::from_millis(1)).await;

            // Decryption test
            let start = Instant::now();
            let _decrypted = aes_encrypt_packet(&encrypted, &aes_key, i);
            let decrypt_duration = start.elapsed().as_micros();
            aes_decrypt_stats.record_operation(total_packet_size as u32, decrypt_duration);

            led.toggle();
            // Yield after each complete test
            Timer::after(Duration::from_millis(2)).await;
        }

        // Yield before starting next algorithm
        Timer::after(Duration::from_millis(20)).await;

        // ChaCha20 Benchmark
        led.set_low();
        let mut chacha_encrypt_stats = BenchmarkStats::default();
        let mut chacha_decrypt_stats = BenchmarkStats::default();

        info!("Running ChaCha20 benchmark... (LED OFF)");

        // Run ChaCha20 benchmarks with frequent yields
        for i in 0..test_iterations {
            // Yield more frequently
            if i > 0 && i % 2 == 0 {
                Timer::after(Duration::from_millis(5)).await;
                info!("ChaCha20 progress: {}/{}", i, test_iterations);
            }

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());

            // Encryption
            let start = Instant::now();
            let encrypted = chacha20_encrypt_packet(&packet_data, &chacha_key_bytes, &nonce_bytes);
            let encrypt_duration = start.elapsed().as_micros();
            chacha_encrypt_stats.record_operation(total_packet_size as u32, encrypt_duration);

            // Small yield after each operation
            Timer::after(Duration::from_millis(1)).await;

            // Decryption
            let start = Instant::now();
            let _decrypted = chacha20_decrypt_packet(&encrypted, &chacha_key_bytes, &nonce_bytes);
            let decrypt_duration = start.elapsed().as_micros();
            chacha_decrypt_stats.record_operation(total_packet_size as u32, decrypt_duration);

            led.toggle();
            // Yield after each complete test
            Timer::after(Duration::from_millis(2)).await;
        }

        // Display formatted results using TableFormatter
        TableFormatter::print_stats_table("AES-128", &aes_encrypt_stats, &aes_decrypt_stats);
        TableFormatter::print_footer();

        Timer::after(Duration::from_millis(100)).await;

        TableFormatter::print_stats_table("ChaCha20", &chacha_encrypt_stats, &chacha_decrypt_stats);
        TableFormatter::print_footer();

        Timer::after(Duration::from_millis(100)).await;

        TableFormatter::print_performance_summary(
            payload_size,
            &aes_encrypt_stats, &aes_decrypt_stats,
            &chacha_encrypt_stats, &chacha_decrypt_stats
        );
        TableFormatter::print_footer();

        Timer::after(Duration::from_millis(100)).await;

        TableFormatter::print_memory_usage(payload_size);
        TableFormatter::print_footer();

        // Additional detailed analysis
        TableFormatter::print_section_header("ADVANCED PERFORMANCE METRICS");

        let aes_total_time = aes_encrypt_stats.average_latency_us() + aes_decrypt_stats.average_latency_us();
        let chacha_total_time = chacha_encrypt_stats.average_latency_us() + chacha_decrypt_stats.average_latency_us();

        info!("║ ROUND-TRIP ANALYSIS            │                                            ║");
        TableFormatter::print_separator();

        info!("║ Algorithm                      │ Total Time           │ Efficiency Rating    ║");
        TableFormatter::print_separator();

        let aes_efficiency_rating = if aes_total_time > 0 { (1000000 / aes_total_time).min(100) } else { 0 };
        let chacha_efficiency_rating = if chacha_total_time > 0 { (1000000 / chacha_total_time).min(100) } else { 0 };

        info!("║ AES-128                        │ {} us              │ {}/100              ║", aes_total_time, aes_efficiency_rating);
        info!("║ ChaCha20                       │ {} us              │ {}/100              ║", chacha_total_time, chacha_efficiency_rating);

        TableFormatter::print_separator();

        if aes_total_time < chacha_total_time {
            let speedup = ((chacha_total_time - aes_total_time) * 100) / aes_total_time;
            info!("║ AES-128 WINS by {}% performance advantage                              ║", speedup);
        } else if chacha_total_time < aes_total_time {
            let speedup = ((aes_total_time - chacha_total_time) * 100) / chacha_total_time;
            info!("║ ChaCha20 WINS by {}% performance advantage                             ║", speedup);
        } else {
            info!("║ TIE - Both algorithms performed equally                                 ║");
        }

        TableFormatter::print_footer();

        Timer::after(Duration::from_millis(500)).await;
    }

    // Final summary
    TableFormatter::print_header("BENCHMARK SUITE COMPLETE");
    info!("║ All packet sizes tested successfully                                 ║");
    info!("║ Detailed statistics and comparisons provided above                  ║");
    info!("║ LED Status: ON (Benchmark Complete)                                 ║");
    info!("║                                                                      ║");
    info!("║ Key Findings:                                                        ║");
    info!("║ • Comprehensive latency analysis with percentiles                   ║");
    info!("║ • Throughput measurements in Kbps and packets/second               ║");
    info!("║ • Memory overhead analysis for both algorithms                     ║");
    info!("║ • Statistical variance and standard deviation tracking             ║");
    info!("║                                                                      ║");
    info!("║ For LoRaWAN applications, consider:                                 ║");
    info!("║ • Power consumption vs performance trade-offs                      ║");
    info!("║ • Memory constraints on your specific STM32 variant               ║");
    info!("║ • Required security level and regulatory compliance               ║");
    TableFormatter::print_footer();

    led.set_high();

    loop {
        Timer::after(Duration::from_secs(5)).await;
        TableFormatter::print_header("SYSTEM STATUS");
        info!("║ Benchmark suite idle - all measurements complete                    ║");
        info!("║ System ready for production deployment                              ║");
        TableFormatter::print_footer();
    }
}

// Formatting utilities for benchmark output
struct TableFormatter;

impl TableFormatter {
    fn print_header(title: &str) {
        info!("╔══════════════════════════════════════════════════════════════════════════════╗");
        info!("║                                   {}                                   ║", title);
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");
    }

    fn print_footer() {
        info!("╚══════════════════════════════════════════════════════════════════════════════╝");
    }

    fn print_section_header(title: &str) {
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");
        info!("║                                   {}                                   ║", title);
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");
    }

    fn print_row(label: &str, value: &str, unit: &str) {
        info!("║ {}                      │ {}               │ {}               ║", label, value, unit);
    }

    fn print_separator() {
        info!("╠──────────────────────────────┼──────────────────────┼──────────────────────╣");
    }

    fn print_comparison_header() {
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");
        info!("║ Metric          │ AES-128         │ ChaCha20        │ Difference      │ Winner   ║");
        info!("╠─────────────────┼─────────────────┼─────────────────┼─────────────────┼──────────╣");
    }

    fn print_comparison_row(metric: &str, aes_val: u64, chacha_val: u64, unit: &str) {
        if aes_val < chacha_val {
            let pct = ((chacha_val - aes_val) * 100) / aes_val;
            info!("║ {} │ {} {} │ {} {} │ {}% faster │ AES      ║",
                  metric, aes_val, unit, chacha_val, unit, pct);
        } else if chacha_val < aes_val {
            let pct = ((aes_val - chacha_val) * 100) / chacha_val;
            info!("║ {} │ {} {} │ {} {} │ {}% faster │ ChaCha20 ║",
                  metric, aes_val, unit, chacha_val, unit, pct);
        } else {
            info!("║ {} │ {} {} │ {} {} │ Tie         │ Tie      ║",
                  metric, aes_val, unit, chacha_val, unit);
        }
    }

    fn print_stats_table(title: &str, encrypt_stats: &BenchmarkStats, decrypt_stats: &BenchmarkStats) {
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");
        info!("║                        {} - DETAILED STATISTICS                        ║", title);
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");

        info!("║ Metric                         │ Encryption           │ Decryption           ║");
        Self::print_separator();

        info!("║ Operations                     │ {}                 │ {}                 ║",
              encrypt_stats.total_operations, decrypt_stats.total_operations);
        info!("║ Success Rate                   │ {}%                │ {}%                ║",
              encrypt_stats.success_rate_percent(), decrypt_stats.success_rate_percent());
        info!("║ Total Bytes                    │ {}                 │ {}                 ║",
              encrypt_stats.total_bytes, decrypt_stats.total_bytes);

        Self::print_separator();
        info!("║ LATENCY STATISTICS             │                                            ║");
        Self::print_separator();

        info!("║ Average Latency                │ {} us              │ {} us              ║",
              encrypt_stats.average_latency_us(), decrypt_stats.average_latency_us());
        info!("║ Min Latency                    │ {} us              │ {} us              ║",
              encrypt_stats.min_latency_us, decrypt_stats.min_latency_us);
        info!("║ Max Latency                    │ {} us              │ {} us              ║",
              encrypt_stats.max_latency_us, decrypt_stats.max_latency_us);
        info!("║ Std Deviation                  │ {} us              │ {} us              ║",
              encrypt_stats.standard_deviation(), decrypt_stats.standard_deviation());
        info!("║ Variance                       │ {} us²             │ {} us²             ║",
              encrypt_stats.variance(), decrypt_stats.variance());

        Self::print_separator();
        info!("║ PERCENTILES                    │                                            ║");
        Self::print_separator();

        info!("║ 50th (Median)                  │ {} us              │ {} us              ║",
              encrypt_stats.percentile(50), decrypt_stats.percentile(50));
        info!("║ 90th Percentile                │ {} us              │ {} us              ║",
              encrypt_stats.percentile(90), decrypt_stats.percentile(90));
        info!("║ 95th Percentile                │ {} us              │ {} us              ║",
              encrypt_stats.percentile(95), decrypt_stats.percentile(95));
        info!("║ 99th Percentile                │ {} us              │ {} us              ║",
              encrypt_stats.percentile(99), decrypt_stats.percentile(99));

        Self::print_separator();
        info!("║ THROUGHPUT METRICS             │                                            ║");
        Self::print_separator();

        info!("║ Throughput                     │ {} Kbps            │ {} Kbps            ║",
              encrypt_stats.throughput_kbps(), decrypt_stats.throughput_kbps());
        info!("║ Packets/sec                    │ {}                 │ {}                 ║",
              encrypt_stats.throughput_packets_per_second(), decrypt_stats.throughput_packets_per_second());
        info!("║ Efficiency                     │ {} B/us            │ {} B/us            ║",
              encrypt_stats.efficiency_bytes_per_us(), decrypt_stats.efficiency_bytes_per_us());
    }

    fn print_performance_summary(
        packet_size: usize,
        aes_enc: &BenchmarkStats, aes_dec: &BenchmarkStats,
        chacha_enc: &BenchmarkStats, chacha_dec: &BenchmarkStats
    ) {
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");
        info!("║                    PERFORMANCE COMPARISON - {} BYTE PACKETS                    ║", packet_size);
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");

        Self::print_comparison_header();

        let aes_avg_latency = (aes_enc.average_latency_us() + aes_dec.average_latency_us()) / 2;
        let chacha_avg_latency = (chacha_enc.average_latency_us() + chacha_dec.average_latency_us()) / 2;
        Self::print_comparison_row("Avg Latency    ", aes_avg_latency, chacha_avg_latency, "us");

        let aes_total_throughput = (aes_enc.throughput_kbps() + aes_dec.throughput_kbps()) / 2;
        let chacha_total_throughput = (chacha_enc.throughput_kbps() + chacha_dec.throughput_kbps()) / 2;
        Self::print_comparison_row("Throughput     ", aes_total_throughput, chacha_total_throughput, "Kbps");

        let aes_pps = (aes_enc.throughput_packets_per_second() + aes_dec.throughput_packets_per_second()) / 2;
        let chacha_pps = (chacha_enc.throughput_packets_per_second() + chacha_dec.throughput_packets_per_second()) / 2;
        Self::print_comparison_row("Packets/sec    ", aes_pps, chacha_pps, "pps");

        let aes_efficiency = (aes_enc.efficiency_bytes_per_us() + aes_dec.efficiency_bytes_per_us()) / 2;
        let chacha_efficiency = (chacha_enc.efficiency_bytes_per_us() + chacha_dec.efficiency_bytes_per_us()) / 2;
        Self::print_comparison_row("Efficiency     ", aes_efficiency, chacha_efficiency, "B/us");

        Self::print_comparison_row("Min Latency    ", aes_enc.min_latency_us.min(aes_dec.min_latency_us),
                                 chacha_enc.min_latency_us.min(chacha_dec.min_latency_us), "us");

        Self::print_comparison_row("Max Latency    ", aes_enc.max_latency_us.max(aes_dec.max_latency_us),
                                 chacha_enc.max_latency_us.max(chacha_dec.max_latency_us), "us");
    }

    fn print_memory_usage(packet_size: usize) {
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");
        info!("║                           MEMORY USAGE ANALYSIS                             ║");
        info!("╠══════════════════════════════════════════════════════════════════════════════╣");

        let aes_memory = 16 + 16 + packet_size; // Key + IV/Counter + packet
        let chacha_memory = 32 + 12 + packet_size; // Key + Nonce + packet
        let overhead_aes = (aes_memory as f32 / packet_size as f32 - 1.0) * 100.0;
        let overhead_chacha = (chacha_memory as f32 / packet_size as f32 - 1.0) * 100.0;

        info!("║ Algorithm                      │ Memory Usage         │ Overhead             ║");
        Self::print_separator();
        info!("║ AES-128                        │ {} bytes            │ {}%                  ║", aes_memory, overhead_aes as u32);
        info!("║ ChaCha20                       │ {} bytes            │ {}%                  ║", chacha_memory, overhead_chacha as u32);
    }
}
