//! STM32F303RE Embedded AEAD Crypto Benchmarks
//! Uses DWT_CYCCNT for precise cycle counting and energy measurement
//! Copyright (c) 2025 - HimuCodes
//! Last updated: 2025-07-22

#![no_std]
#![no_main]

use alloc_cortex_m::CortexMHeap;
use cortex_m::peripheral::{DWT, DCB};
use cortex_m_rt::entry;
use cortex_m_semihosting::hprintln;
use lorapwn::embedded_benchmark::{EmbeddedBenchmark, EmbeddedBenchmarkConfig};
use panic_halt as _; // panic handler
use stm32f3xx_hal::{prelude::*, pac};

extern crate alloc;

// Global allocator for no_std Vec usage
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

// Define the heap size (adjust as needed)
const HEAP_SIZE: usize = 4096; // 4KB heap for crypto operations

#[entry]
fn main() -> ! {
    // Initialize the allocator
    {
        use core::mem::MaybeUninit;
        static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP_SIZE) }
    }

    let _ = hprintln!("Starting LoraPwn AEAD Benchmark...");
    let _ = hprintln!("Date: 2025-07-22");
    let _ = hprintln!("User: HimuCodes");

    // Initialize the STM32F303RE peripherals
    let dp = pac::Peripherals::take().unwrap();
    let cp = cortex_m::Peripherals::take().unwrap();
    let mut rcc = dp.RCC.constrain();
    let mut flash = dp.FLASH.constrain();

    // Configure clocks for STM32F303RE (up to 72 MHz)
    let clocks = rcc.cfgr
        .sysclk(72.MHz())
        .pclk1(36.MHz())
        .pclk2(72.MHz())
        .freeze(&mut flash.acr);

    // Configure the benchmarking parameters
    let config = EmbeddedBenchmarkConfig {
        cpu_freq_hz: clocks.sysclk().0,
        cpu_power_ma: 12.0,              // STM32F303RE typical active current at 72MHz
        voltage_v: 3.3,                  // 3.3V from Nucleo board
    };

    // Initialize the DWT cycle counter
    init_dwt_counter(cp.DCB, cp.DWT);

    // Create the benchmark instance
    let benchmark = EmbeddedBenchmark::new(config);

    let _ = hprintln!("=== STM32F303RE AEAD Crypto Benchmarks ===");
    let _ = hprintln!("CPU Frequency: {} Hz ({} MHz)", benchmark.config.cpu_freq_hz, benchmark.config.cpu_freq_hz / 1_000_000);
    let _ = hprintln!("Estimated Power: {:.1} mA @ {:.1}V", benchmark.config.cpu_power_ma, benchmark.config.voltage_v);
    let _ = hprintln!("");

    // Test different payload sizes typical for LoRaWAN
    let sizes = [8, 16, 32, 64, 128];
    let iterations = 10; // Multiple iterations for averaging

    // Add a warm-up period to stabilize temperature
    let _ = hprintln!("Warming up CPU...");
    for _ in 0..50 {
        let _ = benchmark.benchmark_aes_ctr_cmac(32);
        let _ = benchmark.benchmark_chacha20_poly1305(32);
    }
    let _ = hprintln!("Warm-up complete");

    let _ = hprintln!("Running {} iterations per test for accuracy...", iterations);
    let _ = hprintln!("");

    for &size in &sizes {
        let _ = hprintln!("--- Testing {} byte payloads ---", size);

        // Benchmark AES-128-CTR + CMAC (traditional LoRaWAN)
        let mut aes_total_cycles = 0u64;
        for _ in 0..iterations {
            // Disable interrupts during measurement for accuracy
            cortex_m::interrupt::free(|_| {
                let result = benchmark.benchmark_aes_ctr_cmac(size);
                aes_total_cycles += result.cycles as u64;
            });
        }
        let aes_avg_cycles = (aes_total_cycles / iterations as u64) as u32;
        let aes_time_us = benchmark.cycles_to_us(aes_avg_cycles);
        let aes_energy_uj = benchmark.time_to_energy(aes_time_us);

        let _ = hprintln!("AES-128-CTR+CMAC:");
        let _ = hprintln!("  Cycles: {} (avg)", aes_avg_cycles);
        let _ = hprintln!("  Time: {:.2} µs", aes_time_us);
        let _ = hprintln!("  Energy: {:.2} µJ", aes_energy_uj);

        // Benchmark ChaCha20-Poly1305 (modern AEAD)
        let mut chacha_total_cycles = 0u64;
        for _ in 0..iterations {
            // Disable interrupts during measurement for accuracy
            cortex_m::interrupt::free(|_| {
                let result = benchmark.benchmark_chacha20_poly1305(size);
                chacha_total_cycles += result.cycles as u64;
            });
        }
        let chacha_avg_cycles = (chacha_total_cycles / iterations as u64) as u32;
        let chacha_time_us = benchmark.cycles_to_us(chacha_avg_cycles);
        let chacha_energy_uj = benchmark.time_to_energy(chacha_time_us);

        let _ = hprintln!("ChaCha20-Poly1305:");
        let _ = hprintln!("  Cycles: {} (avg)", chacha_avg_cycles);
        let _ = hprintln!("  Time: {:.2} µs", chacha_time_us);
        let _ = hprintln!("  Energy: {:.2} µJ", chacha_energy_uj);

        // Performance comparison
        let speedup = aes_avg_cycles as f32 / chacha_avg_cycles as f32;
        let energy_ratio = aes_energy_uj / chacha_energy_uj;

        let _ = hprintln!("Performance Comparison:");
        if speedup > 1.0 {
            let _ = hprintln!("  ChaCha20 is {:.2}x faster than AES", speedup);
        } else {
            let _ = hprintln!("  AES is {:.2}x faster than ChaCha20", 1.0 / speedup);
        }

        if energy_ratio > 1.0 {
            let _ = hprintln!("  ChaCha20 uses {:.2}x less energy", energy_ratio);
        } else {
            let _ = hprintln!("  AES uses {:.2}x less energy", 1.0 / energy_ratio);
        }
        let _ = hprintln!("");
    }

    // Cache effects analysis
    let _ = hprintln!("--- Cache Effects Analysis ---");

    // Cold cache run (first execution after a delay)
    cortex_m::asm::delay(1_000_000); // Force cache flush with delay
    let cold_result = cortex_m::interrupt::free(|_| benchmark.benchmark_aes_ctr_cmac(64));

    // Hot cache run (immediate second execution)
    let hot_result = cortex_m::interrupt::free(|_| benchmark.benchmark_aes_ctr_cmac(64));

    let _ = hprintln!("Cold cache: {} cycles", cold_result.cycles);
    let _ = hprintln!("Hot cache: {} cycles", hot_result.cycles);
    let _ = hprintln!("Cache impact: {:.2}%",
              100.0 * (1.0 - (hot_result.cycles as f32 / cold_result.cycles as f32)));

    let _ = hprintln!("");
    let _ = hprintln!("=== Benchmark Complete ===");
    let _ = hprintln!("LoraPwn AEAD benchmark by HimuCodes");
    let _ = hprintln!("STM32F303RE @ {} MHz", benchmark.config.cpu_freq_hz / 1_000_000);

    // Enter low power mode
    loop {
        cortex_m::asm::wfi(); // Wait for interrupt (low power mode)
    }
}

/// Initialize the DWT cycle counter for precise timing
fn init_dwt_counter(mut dcb: DCB, dwt: DWT) {
    // Enable trace and debug
    dcb.enable_trace();

    // Set TRCENA bit in DEMCR register to enable DWT
    unsafe {
        // Set TRCENA bit
        core::ptr::write_volatile(
            0xE000EDFC as *mut u32,
            core::ptr::read_volatile(0xE000EDFC as *const u32) | 0x01000000
        );
    }

    // Enable and reset cycle counter
    unsafe {
        // Reset counter to 0
        dwt.cyccnt.write(0);
        // Enable counter
        dwt.ctrl.modify(|r| r | 1);
    }
}