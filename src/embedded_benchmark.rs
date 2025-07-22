//! Embedded crypto benchmarking module for STM32 using DWT cycle counter
//! Copyright (c) 2025 - HimuCodes
//! Last updated: 2025-07-22


extern crate alloc;

// Crypto library imports
use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};
use cmac::{Cmac, Mac};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;

/// Benchmark configuration parameters
pub struct EmbeddedBenchmarkConfig {
    pub cpu_freq_hz: u32,
    pub cpu_power_ma: f32,
    pub voltage_v: f32,
}

/// Benchmark result data
pub struct BenchmarkResult {
    pub cycles: u32,
    pub bytes_processed: usize,
    pub stack_usage: Option<usize>,
}

/// Main benchmark executor
pub struct EmbeddedBenchmark {
    pub config: EmbeddedBenchmarkConfig,
}

impl EmbeddedBenchmark {
    /// Create a new benchmark instance with the given configuration
    pub fn new(config: EmbeddedBenchmarkConfig) -> Self {
        Self { config }
    }

    /// Benchmark AES-CTR + CMAC (traditional LoRaWAN security)
    pub fn benchmark_aes_ctr_cmac(&self, payload_size: usize) -> BenchmarkResult {
        // Create fixed-size arrays for no_std environment
        const MAX_PAYLOAD: usize = 256; // Maximum test payload size

        if payload_size > MAX_PAYLOAD {
            panic!("Payload size exceeds maximum");
        }

        // Create test vector with static allocation
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B];

        // Initialize data buffer
        let mut data = [0u8; MAX_PAYLOAD];
        for i in 0..payload_size {
            data[i] = i as u8;
        }

        // Reset cycle counter
        cortex_m::peripheral::DWT::cycle_count();
        unsafe {
            let dwt = &(*cortex_m::peripheral::DWT::PTR);
            dwt.cyccnt.write(0);
        }

        // Perform AES-CTR encryption
        let cipher = Aes128::new(generic_array::GenericArray::from_slice(&key));
        let mut encrypted = [0u8; MAX_PAYLOAD];
        encrypted[..payload_size].copy_from_slice(&data[..payload_size]);

        // AES block for CTR mode
        let mut ctr_block = generic_array::GenericArray::default();
        for i in 0..12 {
            ctr_block[i] = nonce[i];
        }

        // Perform CTR mode manually
        for i in 0..(payload_size + 15) / 16 {
            // Set counter value in last 4 bytes
            let ctr = i as u32;
            ctr_block[12] = (ctr >> 24) as u8;
            ctr_block[13] = (ctr >> 16) as u8;
            ctr_block[14] = (ctr >> 8) as u8;
            ctr_block[15] = ctr as u8;

            // Encrypt counter block
            let mut block = ctr_block.clone();
            cipher.encrypt_block(&mut block);

            // XOR with plaintext
            let start = i * 16;
            let end = core::cmp::min(start + 16, payload_size);
            for j in start..end {
                encrypted[j] ^= block[j - start];
            }
        }

        // Compute CMAC
        let mut cmac = <Cmac<Aes128> as Mac>::new_from_slice(&key)
            .expect("CMAC initialization failed");
        cmac.update(&encrypted[..payload_size]);
        let _mac_result = cmac.finalize().into_bytes();

        // Get cycle count
        let cycles = cortex_m::peripheral::DWT::cycle_count();

        BenchmarkResult {
            cycles,
            bytes_processed: payload_size,
            stack_usage: None,
        }
    }

    /// Benchmark ChaCha20-Poly1305 (modern AEAD)
    pub fn benchmark_chacha20_poly1305(&self, payload_size: usize) -> BenchmarkResult {
        // Create fixed-size arrays for no_std environment
        const MAX_PAYLOAD: usize = 256; // Maximum test payload size

        if payload_size > MAX_PAYLOAD {
            panic!("Payload size exceeds maximum");
        }

        // Create test vectors
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B];

        // Initialize data buffer
        let mut data = [0u8; MAX_PAYLOAD];
        for i in 0..payload_size {
            data[i] = i as u8;
        }


        // Reset cycle counter
        cortex_m::peripheral::DWT::cycle_count();
        unsafe {
            let dwt = &(*cortex_m::peripheral::DWT::PTR);
            dwt.cyccnt.write(0);
        }

        // Create ChaCha20Poly1305 instance
        let cipher_key = Key::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce_array = Nonce::from_slice(&nonce);

        // Encrypt data using the proper AEAD interface
        let plaintext = &data[..payload_size];
        let _ciphertext = cipher.encrypt(nonce_array, plaintext)
            .expect("encryption failed");

        // Get cycle count
        let cycles = cortex_m::peripheral::DWT::cycle_count();

        BenchmarkResult {
            cycles,
            bytes_processed: payload_size,
            stack_usage: None,
        }
    }

    /// Convert cycles to microseconds
    pub fn cycles_to_us(&self, cycles: u32) -> f32 {
        (cycles as f32) * (1_000_000.0 / self.config.cpu_freq_hz as f32)
    }

    /// Convert time to energy
    pub fn time_to_energy(&self, time_us: f32) -> f32 {
        // E = P * t = V * I * t
        let power_w = self.config.voltage_v * self.config.cpu_power_ma / 1000.0;
        let time_s = time_us / 1_000_000.0;
        power_w * time_s * 1_000_000.0 // Convert to µJ
    }

    /// Estimate stack usage (simplified implementation)
    pub fn estimate_stack_usage(&self) -> usize {
        // This is a simplified stack usage estimation
        // A real implementation would use stack watermarking techniques
        // with pattern filling and measurement
        512 // Return a dummy value for now
    }
}