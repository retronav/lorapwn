//! Embedded crypto benchmarking module for STM32 using DWT cycle counter
//! Copyright (c) 2025 - HimuCodes
//! Last updated: 2025-07-23

extern crate alloc;
use alloc::vec::Vec;

// Core imports
use cortex_m::peripheral::DWT;
use cortex_m_semihosting::hprintln;

// Crypto library imports
use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};
use cmac::{Cmac, Mac};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;

/// Benchmark configuration parameters with detailed power specifications
pub struct EmbeddedBenchmarkConfig {
    pub cpu_freq_hz: u32,
    pub cpu_power_ma: f32,        // CPU current draw in milliamps
    pub voltage_v: f32,           // Supply voltage in volts
    pub target_name: &'static str, // Target MCU name
}

impl Default for EmbeddedBenchmarkConfig {
    fn default() -> Self {
        Self {
            cpu_freq_hz: 72_000_000,  // STM32F3 default frequency
            cpu_power_ma: 50.0,       // Typical STM32F3 active current
            voltage_v: 3.3,           // Typical supply voltage
            target_name: "STM32F303",
        }
    }
}

/// Detailed benchmark result with comprehensive statistics
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub cycles: u32,
    pub bytes_processed: usize,
    pub stack_usage: Option<usize>,
    pub operation_type: OperationType,
    pub timestamp_us: u64,
}

/// Comprehensive benchmark statistics for multiple iterations with enhanced power metrics
#[derive(Debug)]
pub struct BenchmarkStats {
    pub min_cycles: u32,
    pub max_cycles: u32,
    pub avg_cycles: f32,
    pub median_cycles: u32,
    pub std_deviation: f32,
    pub total_iterations: usize,
    pub total_bytes: usize,

    // Time measurements
    pub avg_time_us: f32,         // Average time in microseconds
    pub avg_time_ms: f32,         // Average time in milliseconds
    pub avg_time_s: f32,          // Average time in seconds

    // Energy measurements
    pub avg_energy_uj: f32,       // Average energy in microjoules
    pub avg_energy_mj: f32,       // Average energy in millijoules
    pub avg_energy_j: f32,        // Average energy in joules
    pub energy_per_byte_uj: f32,  // Energy per byte in microjoules
    pub energy_per_byte_nj: f32,  // Energy per byte in nanojoules

    // Power measurements
    pub avg_power_mw: f32,        // Average power in milliwatts
    pub avg_power_w: f32,         // Average power in watts
    pub peak_power_mw: f32,       // Peak power in milliwatts
    pub peak_power_w: f32,        // Peak power in watts

    // Performance metrics
    pub throughput_mbps: f32,
    pub cycles_per_byte: f32,
    pub operation_type: OperationType,
    pub efficiency_score: f32,    // Custom efficiency metric
}

/// Type of cryptographic operation being benchmarked
#[derive(Debug, Clone, Copy)]
pub enum OperationType {
    AesEncrypt,
    AesDecrypt,
    ChaChaEncrypt,
    ChaChaDecrypt,
    AesCtrCmacEncrypt,
    AesCtrCmacDecrypt,
}

/// Main benchmark executor with enhanced capabilities
pub struct EmbeddedBenchmark {
    pub config: EmbeddedBenchmarkConfig,
    iteration_count: usize,
    dwt: Option<DWT>,
}

impl EmbeddedBenchmark {
    /// Create a new benchmark instance with the given configuration
    pub fn new(config: EmbeddedBenchmarkConfig) -> Self {
        Self {
            config,
            iteration_count: 100, // Default to 100 iterations
            dwt: None,
        }
    }

    /// Set the number of iterations for benchmarks
    pub fn set_iterations(&mut self, iterations: usize) {
        self.iteration_count = iterations;
    }

    /// Initialize DWT cycle counter
    pub fn init_cycle_counter(&mut self) {
        // Enable DWT and cycle counter
        unsafe {
            // Get the core peripherals
            let mut cp = cortex_m::Peripherals::steal();

            // Enable DWT
            cp.DCB.enable_trace();

            // Unlock DWT using the correct constant
            let dwt = &*cortex_m::peripheral::DWT::PTR;
            dwt.lar.write(0xC5ACCE55);

            // Enable cycle counter
            dwt.ctrl.modify(|r| r | 1);

            // Reset cycle counter
            dwt.cyccnt.write(0);
        }
    }

    /// Reset and start cycle counter
    pub fn reset_cycle_counter(&mut self) {
        unsafe {
            let dwt = &*cortex_m::peripheral::DWT::PTR;
            dwt.cyccnt.write(0);
        }
    }

    /// Get current cycle count
    pub fn get_cycle_count(&self) -> u32 {
        DWT::cycle_count()
    }

    /// Convert cycles to microseconds
    pub fn cycles_to_us(&self, cycles: u32) -> f32 {
        (cycles as f32) / (self.config.cpu_freq_hz as f32) * 1_000_000.0
    }

    /// Convert cycles to milliseconds
    pub fn cycles_to_ms(&self, cycles: u32) -> f32 {
        (cycles as f32) / (self.config.cpu_freq_hz as f32) * 1_000.0
    }

    /// Convert cycles to seconds
    pub fn cycles_to_s(&self, cycles: u32) -> f32 {
        (cycles as f32) / (self.config.cpu_freq_hz as f32)
    }

    /// Convert time to energy consumption in microjoules
    pub fn time_to_energy_uj(&self, time_us: f32) -> f32 {
        let power_w = self.config.voltage_v * self.config.cpu_power_ma / 1000.0;
        let time_s = time_us / 1_000_000.0;
        power_w * time_s * 1_000_000.0 // Convert to µJ
    }

    /// Convert time to energy consumption in millijoules
    pub fn time_to_energy_mj(&self, time_us: f32) -> f32 {
        self.time_to_energy_uj(time_us) / 1000.0
    }

    /// Convert time to energy consumption in joules
    pub fn time_to_energy_j(&self, time_us: f32) -> f32 {
        self.time_to_energy_uj(time_us) / 1_000_000.0
    }

    /// Calculate power consumption in milliwatts based on cycles
    pub fn cycles_to_power_mw(&self, _cycles: u32) -> f32 {
        self.config.voltage_v * self.config.cpu_power_ma
    }

    /// Calculate power consumption in watts based on cycles
    pub fn cycles_to_power_w(&self, cycles: u32) -> f32 {
        self.cycles_to_power_mw(cycles) / 1000.0
    }

    /// Benchmark AES-CTR + CMAC encryption (traditional LoRaWAN security)
    pub fn benchmark_aes_ctr_cmac_encrypt(&mut self, payload_size: usize) -> BenchmarkResult {
        const MAX_PAYLOAD: usize = 256;
        if payload_size > MAX_PAYLOAD {
            panic!("Payload size exceeds maximum");
        }

        // Create test vectors
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B];

        // Initialize data buffer
        let mut data = [0u8; MAX_PAYLOAD];
        for i in 0..payload_size {
            data[i] = (i % 256) as u8;
        }

        // Start timing
        self.reset_cycle_counter();

        // Perform AES-CTR encryption + CMAC
        let cipher = Aes128::new(generic_array::GenericArray::from_slice(&key));
        let mut encrypted = [0u8; MAX_PAYLOAD];
        encrypted[..payload_size].copy_from_slice(&data[..payload_size]);

        // CTR mode encryption
        let mut ctr_block = generic_array::GenericArray::default();
        for i in 0..12 {
            ctr_block[i] = nonce[i];
        }

        for i in 0..(payload_size + 15) / 16 {
            let ctr = i as u32;
            ctr_block[12] = (ctr >> 24) as u8;
            ctr_block[13] = (ctr >> 16) as u8;
            ctr_block[14] = (ctr >> 8) as u8;
            ctr_block[15] = ctr as u8;

            let mut block = ctr_block.clone();
            cipher.encrypt_block(&mut block);

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

        let cycles = self.get_cycle_count();

        BenchmarkResult {
            cycles,
            bytes_processed: payload_size,
            stack_usage: None,
            operation_type: OperationType::AesCtrCmacEncrypt,
            timestamp_us: 0,
        }
    }

    /// Benchmark AES-CTR + CMAC decryption
    pub fn benchmark_aes_ctr_cmac_decrypt(&mut self, payload_size: usize) -> BenchmarkResult {
        const MAX_PAYLOAD: usize = 256;
        if payload_size > MAX_PAYLOAD {
            panic!("Payload size exceeds maximum");
        }

        // Create test vectors (encrypted data)
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B];

        // Simulate encrypted data
        let mut encrypted_data = [0u8; MAX_PAYLOAD];
        for i in 0..payload_size {
            encrypted_data[i] = ((i + 0x55) % 256) as u8; // Simulated ciphertext
        }

        // Start timing
        self.reset_cycle_counter();

        // Verify CMAC first
        let mut cmac = <Cmac<Aes128> as Mac>::new_from_slice(&key)
            .expect("CMAC initialization failed");
        cmac.update(&encrypted_data[..payload_size]);
        let _mac_verification = cmac.finalize().into_bytes();

        // Perform AES-CTR decryption
        let cipher = Aes128::new(generic_array::GenericArray::from_slice(&key));
        let mut decrypted = [0u8; MAX_PAYLOAD];
        decrypted[..payload_size].copy_from_slice(&encrypted_data[..payload_size]);

        let mut ctr_block = generic_array::GenericArray::default();
        for i in 0..12 {
            ctr_block[i] = nonce[i];
        }

        for i in 0..(payload_size + 15) / 16 {
            let ctr = i as u32;
            ctr_block[12] = (ctr >> 24) as u8;
            ctr_block[13] = (ctr >> 16) as u8;
            ctr_block[14] = (ctr >> 8) as u8;
            ctr_block[15] = ctr as u8;

            let mut block = ctr_block.clone();
            cipher.encrypt_block(&mut block);

            let start = i * 16;
            let end = core::cmp::min(start + 16, payload_size);
            for j in start..end {
                decrypted[j] ^= block[j - start];
            }
        }

        let cycles = self.get_cycle_count();

        BenchmarkResult {
            cycles,
            bytes_processed: payload_size,
            stack_usage: None,
            operation_type: OperationType::AesCtrCmacDecrypt,
            timestamp_us: 0,
        }
    }

    /// Benchmark ChaCha20-Poly1305 encryption
    pub fn benchmark_chacha20_poly1305_encrypt(&mut self, payload_size: usize) -> BenchmarkResult {
        const MAX_PAYLOAD: usize = 256;
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

        let mut data = [0u8; MAX_PAYLOAD];
        for i in 0..payload_size {
            data[i] = (i % 256) as u8;
        }

        // Start timing
        self.reset_cycle_counter();

        // Create ChaCha20Poly1305 instance and encrypt
        let cipher_key = Key::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce_array = Nonce::from_slice(&nonce);

        let plaintext = &data[..payload_size];
        let _ciphertext = cipher.encrypt(nonce_array, plaintext)
            .expect("encryption failed");

        let cycles = self.get_cycle_count();

        BenchmarkResult {
            cycles,
            bytes_processed: payload_size,
            stack_usage: None,
            operation_type: OperationType::ChaChaEncrypt,
            timestamp_us: 0,
        }
    }

    /// Benchmark ChaCha20-Poly1305 decryption
    pub fn benchmark_chacha20_poly1305_decrypt(&mut self, payload_size: usize) -> BenchmarkResult {
        const MAX_PAYLOAD: usize = 256;
        if payload_size > MAX_PAYLOAD {
            panic!("Payload size exceeds maximum");
        }

        // Create test vectors and pre-encrypt data
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B];

        let mut data = [0u8; MAX_PAYLOAD];
        for i in 0..payload_size {
            data[i] = (i % 256) as u8;
        }

        // Pre-encrypt the data to have valid ciphertext
        let cipher_key = Key::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce_array = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce_array, &data[..payload_size])
            .expect("pre-encryption failed");

        // Start timing for decryption
        self.reset_cycle_counter();

        // Decrypt the ciphertext
        let _plaintext = cipher.decrypt(nonce_array, ciphertext.as_ref())
            .expect("decryption failed");

        let cycles = self.get_cycle_count();

        BenchmarkResult {
            cycles,
            bytes_processed: payload_size,
            stack_usage: None,
            operation_type: OperationType::ChaChaDecrypt,
            timestamp_us: 0,
        }
    }

    /// Run comprehensive benchmark with multiple iterations and calculate detailed statistics
    pub fn run_comprehensive_benchmark<F>(&mut self, mut benchmark_fn: F) -> BenchmarkStats
    where
        F: FnMut() -> BenchmarkResult,
    {
        let iterations = self.iteration_count;
        let mut results = Vec::with_capacity(iterations);

        let _ = hprintln!("🚀 Starting {} iterations of benchmark...", iterations);

        // Collect all measurements
        for i in 0..iterations {
            if i % 20 == 0 {
                let _ = hprintln!("  Progress: {}/{} iterations", i, iterations);
            }
            results.push(benchmark_fn());
        }

        // Sort for median calculation
        results.sort_by_key(|r| r.cycles);

        // Calculate statistics
        let min_cycles = results[0].cycles;
        let max_cycles = results[iterations - 1].cycles;
        let median_cycles = results[iterations / 2].cycles;

        let total_cycles: u64 = results.iter().map(|r| r.cycles as u64).sum();
        let avg_cycles = total_cycles as f32 / iterations as f32;

        // Calculate standard deviation
        let variance: f32 = results.iter()
            .map(|r| {
                let diff = r.cycles as f32 - avg_cycles;
                diff * diff
            })
            .sum::<f32>() / iterations as f32;
        let std_deviation = libm::sqrtf(variance);

        let total_bytes = results.iter().map(|r| r.bytes_processed).sum();

        // Time calculations in multiple units
        let avg_time_us = self.cycles_to_us(avg_cycles as u32);
        let avg_time_ms = self.cycles_to_ms(avg_cycles as u32);
        let avg_time_s = self.cycles_to_s(avg_cycles as u32);

        // Energy calculations in multiple units
        let avg_energy_uj = self.time_to_energy_uj(avg_time_us);
        let avg_energy_mj = self.time_to_energy_mj(avg_time_us);
        let avg_energy_j = self.time_to_energy_j(avg_time_us);

        // Power calculations in multiple units
        let avg_power_mw = self.cycles_to_power_mw(avg_cycles as u32);
        let avg_power_w = self.cycles_to_power_w(avg_cycles as u32);
        let peak_power_mw = self.cycles_to_power_mw(min_cycles); // Minimum time = peak power
        let peak_power_w = self.cycles_to_power_w(min_cycles);

        let throughput_mbps = if avg_time_us > 0.0 {
            let avg_bytes = total_bytes as f32 / iterations as f32;
            (avg_bytes * 8.0) / avg_time_us
        } else {
            0.0
        };

        let cycles_per_byte = if total_bytes > 0 {
            total_cycles as f32 / total_bytes as f32
        } else {
            0.0
        };

        let energy_per_byte_uj = if total_bytes > 0 {
            avg_energy_uj * iterations as f32 / total_bytes as f32
        } else {
            0.0
        };

        let energy_per_byte_nj = energy_per_byte_uj * 1000.0; // Convert µJ to nJ

        // Calculate efficiency score (higher is better)
        let efficiency_score = if avg_energy_uj > 0.0 && avg_time_us > 0.0 {
            (throughput_mbps * 1000.0) / (avg_energy_uj + avg_time_us / 1000.0)
        } else {
            0.0
        };

        BenchmarkStats {
            min_cycles,
            max_cycles,
            avg_cycles,
            median_cycles,
            std_deviation,
            total_iterations: iterations,
            total_bytes,
            avg_time_us,
            avg_time_ms,
            avg_time_s,
            avg_energy_uj,
            avg_energy_mj,
            avg_energy_j,
            energy_per_byte_uj,
            energy_per_byte_nj,
            avg_power_mw,
            avg_power_w,
            peak_power_mw,
            peak_power_w,
            throughput_mbps,
            cycles_per_byte,
            operation_type: results[0].operation_type,
            efficiency_score,
        }
    }

    /// Print detailed benchmark statistics with comprehensive power and energy information
    pub fn print_detailed_stats(&self, stats: &BenchmarkStats, payload_size: usize) {
        let op_name = match stats.operation_type {
            OperationType::AesCtrCmacEncrypt => "AES-CTR+CMAC Encrypt",
            OperationType::AesCtrCmacDecrypt => "AES-CTR+CMAC Decrypt",
            OperationType::ChaChaEncrypt => "ChaCha20-Poly1305 Encrypt",
            OperationType::ChaChaDecrypt => "ChaCha20-Poly1305 Decrypt",
            _ => "Unknown Operation",
        };

        let _ = hprintln!("📊 {} ({} bytes, {} iterations):", op_name, payload_size, stats.total_iterations);
        let _ = hprintln!("  ⏱️  Timing Statistics:");
        let _ = hprintln!("    • Average: {:.0} cycles ({:.2} µs, {:.3} ms)", stats.avg_cycles, stats.avg_time_us, stats.avg_time_ms);
        let _ = hprintln!("    • Minimum: {} cycles ({:.2} µs)", stats.min_cycles, self.cycles_to_us(stats.min_cycles));
        let _ = hprintln!("    • Maximum: {} cycles ({:.2} µs)", stats.max_cycles, self.cycles_to_us(stats.max_cycles));
        let _ = hprintln!("    • Median:  {} cycles ({:.2} µs)", stats.median_cycles, self.cycles_to_us(stats.median_cycles));
        let _ = hprintln!("    • Std Dev: {:.1} cycles ({:.3} µs)", stats.std_deviation, self.cycles_to_us(stats.std_deviation as u32));

        let _ = hprintln!("  ⚡ Power Consumption:");
        let _ = hprintln!("    • Average Power: {:.3} mW ({:.6} W)", stats.avg_power_mw, stats.avg_power_w);
        let _ = hprintln!("    • Peak Power:    {:.3} mW ({:.6} W)", stats.peak_power_mw, stats.peak_power_w);

        let _ = hprintln!("  🔋 Energy Consumption:");
        let _ = hprintln!("    • Energy/Op:     {:.3} µJ ({:.6} mJ, {:.9} J)", stats.avg_energy_uj, stats.avg_energy_mj, stats.avg_energy_j);
        let _ = hprintln!("    • Energy/Byte:   {:.3} µJ/byte ({:.1} nJ/byte)", stats.energy_per_byte_uj, stats.energy_per_byte_nj);

        let _ = hprintln!("  🚀 Performance:");
        let _ = hprintln!("    • Throughput:    {:.2} Mbps", stats.throughput_mbps);
        let _ = hprintln!("    • Cycles/Byte:   {:.1}", stats.cycles_per_byte);
        let _ = hprintln!("    • Efficiency:    {:.2}", stats.efficiency_score);

        let _ = hprintln!("  🔧 Hardware Info:");
        let _ = hprintln!("    • MCU:      {}", self.config.target_name);
        let _ = hprintln!("    • Freq:     {} MHz", self.config.cpu_freq_hz / 1_000_000);
        let _ = hprintln!("    • Voltage:  {:.1} V", self.config.voltage_v);
        let _ = hprintln!("    • I_cpu:    {:.1} mA", self.config.cpu_power_ma);
    }

    /// Run all crypto benchmarks with comprehensive analysis
    pub fn run_all_benchmarks(&mut self, payload_sizes: &[usize]) {
        let _ = hprintln!("🧪 Comprehensive Crypto Benchmark Suite");
        let _ = hprintln!("================================================");
        let _ = hprintln!("Target: {} @ {} MHz", self.config.target_name, self.config.cpu_freq_hz / 1_000_000);
        let _ = hprintln!("Power: {:.1} mA @ {:.1} V", self.config.cpu_power_ma, self.config.voltage_v);
        let _ = hprintln!("Iterations: {} per test", self.iteration_count);
        let _ = hprintln!("");

        for &payload_size in payload_sizes {
            let _ = hprintln!("📦 Testing payload size: {} bytes", payload_size);
            let _ = hprintln!("----------------------------------------");

            // AES-CTR+CMAC Encryption
            let iterations = self.iteration_count;
            let mut results = Vec::with_capacity(iterations);
            let _ = hprintln!("🚀 Starting {} iterations of AES-CTR+CMAC Encrypt...", iterations);
            for i in 0..iterations {
                if i % 20 == 0 {
                    let _ = hprintln!("  Progress: {}/{} iterations", i, iterations);
                }
                results.push(self.benchmark_aes_ctr_cmac_encrypt(payload_size));
            }
            let aes_enc_stats = self.calculate_stats(results);
            self.print_detailed_stats(&aes_enc_stats, payload_size);
            let _ = hprintln!("");

            // AES-CTR+CMAC Decryption
            let mut results = Vec::with_capacity(iterations);
            let _ = hprintln!("🚀 Starting {} iterations of AES-CTR+CMAC Decrypt...", iterations);
            for i in 0..iterations {
                if i % 20 == 0 {
                    let _ = hprintln!("  Progress: {}/{} iterations", i, iterations);
                }
                results.push(self.benchmark_aes_ctr_cmac_decrypt(payload_size));
            }
            let aes_dec_stats = self.calculate_stats(results);
            self.print_detailed_stats(&aes_dec_stats, payload_size);
            let _ = hprintln!("");

            // ChaCha20-Poly1305 Encryption
            let mut results = Vec::with_capacity(iterations);
            let _ = hprintln!("🚀 Starting {} iterations of ChaCha20-Poly1305 Encrypt...", iterations);
            for i in 0..iterations {
                if i % 20 == 0 {
                    let _ = hprintln!("  Progress: {}/{} iterations", i, iterations);
                }
                results.push(self.benchmark_chacha20_poly1305_encrypt(payload_size));
            }
            let chacha_enc_stats = self.calculate_stats(results);
            self.print_detailed_stats(&chacha_enc_stats, payload_size);
            let _ = hprintln!("");

            // ChaCha20-Poly1305 Decryption
            let mut results = Vec::with_capacity(iterations);
            let _ = hprintln!("🚀 Starting {} iterations of ChaCha20-Poly1305 Decrypt...", iterations);
            for i in 0..iterations {
                if i % 20 == 0 {
                    let _ = hprintln!("  Progress: {}/{} iterations", i, iterations);
                }
                results.push(self.benchmark_chacha20_poly1305_decrypt(payload_size));
            }
            let chacha_dec_stats = self.calculate_stats(results);
            self.print_detailed_stats(&chacha_dec_stats, payload_size);
            let _ = hprintln!("");

            // Comparison summary
            self.print_comparison_summary(payload_size, &[
                ("AES-CTR+CMAC Enc", &aes_enc_stats),
                ("AES-CTR+CMAC Dec", &aes_dec_stats),
                ("ChaCha20 Enc", &chacha_enc_stats),
                ("ChaCha20 Dec", &chacha_dec_stats),
            ]);
            let _ = hprintln!("========================================");
        }
    }

    /// Calculate comprehensive statistics from benchmark results
    fn calculate_stats(&self, mut results: Vec<BenchmarkResult>) -> BenchmarkStats {
        let iterations = results.len();

        // Sort for median calculation
        results.sort_by_key(|r| r.cycles);

        // Calculate statistics
        let min_cycles = results[0].cycles;
        let max_cycles = results[iterations - 1].cycles;
        let median_cycles = results[iterations / 2].cycles;

        let total_cycles: u64 = results.iter().map(|r| r.cycles as u64).sum();
        let avg_cycles = total_cycles as f32 / iterations as f32;

        // Calculate standard deviation
        let variance: f32 = results.iter()
            .map(|r| {
                let diff = r.cycles as f32 - avg_cycles;
                diff * diff
            })
            .sum::<f32>() / iterations as f32;
        let std_deviation = libm::sqrtf(variance);

        let total_bytes = results.iter().map(|r| r.bytes_processed).sum();

        // Time calculations in multiple units
        let avg_time_us = self.cycles_to_us(avg_cycles as u32);
        let avg_time_ms = self.cycles_to_ms(avg_cycles as u32);
        let avg_time_s = self.cycles_to_s(avg_cycles as u32);

        // Energy calculations in multiple units
        let avg_energy_uj = self.time_to_energy_uj(avg_time_us);
        let avg_energy_mj = self.time_to_energy_mj(avg_time_us);
        let avg_energy_j = self.time_to_energy_j(avg_time_us);

        // Power calculations in multiple units
        let avg_power_mw = self.cycles_to_power_mw(avg_cycles as u32);
        let avg_power_w = self.cycles_to_power_w(avg_cycles as u32);
        let peak_power_mw = self.cycles_to_power_mw(min_cycles);
        let peak_power_w = self.cycles_to_power_w(min_cycles);

        let throughput_mbps = if avg_time_us > 0.0 {
            let avg_bytes = total_bytes as f32 / iterations as f32;
            (avg_bytes * 8.0) / avg_time_us
        } else {
            0.0
        };

        let cycles_per_byte = if total_bytes > 0 {
            total_cycles as f32 / total_bytes as f32
        } else {
            0.0
        };

        let energy_per_byte_uj = if total_bytes > 0 {
            avg_energy_uj * iterations as f32 / total_bytes as f32
        } else {
            0.0
        };

        let energy_per_byte_nj = energy_per_byte_uj * 1000.0; // Convert µJ to nJ

        // Calculate efficiency score (higher is better)
        let efficiency_score = if avg_energy_uj > 0.0 && avg_time_us > 0.0 {
            (throughput_mbps * 1000.0) / (avg_energy_uj + avg_time_us / 1000.0)
        } else {
            0.0
        };

        BenchmarkStats {
            min_cycles,
            max_cycles,
            avg_cycles,
            median_cycles,
            std_deviation,
            total_iterations: iterations,
            total_bytes,
            avg_time_us,
            avg_time_ms,
            avg_time_s,
            avg_energy_uj,
            avg_energy_mj,
            avg_energy_j,
            energy_per_byte_uj,
            energy_per_byte_nj,
            avg_power_mw,
            avg_power_w,
            peak_power_mw,
            peak_power_w,
            throughput_mbps,
            cycles_per_byte,
            operation_type: results[0].operation_type,
            efficiency_score,
        }
    }

    /// Print comparison summary between different algorithms with enhanced power metrics
    fn print_comparison_summary(&self, payload_size: usize, results: &[(&str, &BenchmarkStats)]) {
        let _ = hprintln!("📈 Algorithm Comparison ({} bytes):", payload_size);
        let _ = hprintln!("  Algorithm            | Cycles  | Time(µs) | Power(mW) | Energy(µJ) | Energy(nJ/byte) | Throughput(Mbps)");
        let _ = hprintln!("  --------------------|---------|----------|-----------|------------|-----------------|----------------");

        for (name, stats) in results {
            let _ = hprintln!("  {:20} | {:7.0} | {:8.2} | {:9.3} | {:10.3} | {:15.1} | {:14.2}",
                name, stats.avg_cycles, stats.avg_time_us,
                stats.avg_power_mw, stats.avg_energy_uj, stats.energy_per_byte_nj, stats.throughput_mbps);
        }
        let _ = hprintln!("");

        // Find the most efficient algorithm
        let mut best_efficiency = 0.0f32;
        let mut best_algo = "";
        let mut lowest_energy = f32::MAX;
        let mut most_efficient_energy = "";

        for (name, stats) in results {
            if stats.efficiency_score > best_efficiency {
                best_efficiency = stats.efficiency_score;
                best_algo = name;
            }
            if stats.energy_per_byte_nj < lowest_energy {
                lowest_energy = stats.energy_per_byte_nj;
                most_efficient_energy = name;
            }
        }

        let _ = hprintln!("  🏆 Best Overall Efficiency: {} (score: {:.2})", best_algo, best_efficiency);
        let _ = hprintln!("  ⚡ Most Energy Efficient: {} ({:.1} nJ/byte)", most_efficient_energy, lowest_energy);
    }
}

