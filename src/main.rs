//! STM32 Embedded Crypto Benchmark Main Application
//! Copyright (c) 2025 - HimuCodes
//! Enhanced version with 100 iterations, power analysis, and detailed statistics

#![no_std]
#![no_main]

extern crate alloc;
use alloc_cortex_m::CortexMHeap;
use cortex_m_rt::entry;
use cortex_m_semihosting::hprintln;
use panic_halt as _;

// Import STM32F3 device for interrupt vectors
use stm32f3xx_hal as hal;
use hal::pac;

use lorapwn_bench::embedded_benchmark::{EmbeddedBenchmark, EmbeddedBenchmarkConfig};

// Global allocator for Vec and other allocations
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024 * 8; // 8KB heap

#[entry]
fn main() -> ! {
    // Initialize the allocator with proper static handling
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE_USIZE: usize = HEAP_SIZE;
        static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE_USIZE] = [MaybeUninit::uninit(); HEAP_SIZE_USIZE];
        unsafe {
            let heap_ptr = HEAP.as_mut_ptr() as *mut u8;
            ALLOCATOR.init(heap_ptr as usize, HEAP_SIZE)
        }
    }

    // Take ownership of device peripherals
    let _dp = pac::Peripherals::take().unwrap();
    let _cp = cortex_m::Peripherals::take().unwrap();

    let _ = hprintln!("🚀 STM32 Embedded Crypto Benchmark Suite");
    let _ = hprintln!("==========================================");
    let _ = hprintln!("Enhanced version with detailed power analysis");
    let _ = hprintln!("Copyright (c) 2025 - HimuCodes");
    let _ = hprintln!("");

    // Configure benchmark for STM32F303RE (your specific MCU)
    let config = EmbeddedBenchmarkConfig {
        cpu_freq_hz: 72_000_000,  // 72 MHz (can run up to 72MHz)
        cpu_power_ma: 42.0,       // Typical active current for STM32F303RE at 72MHz
        voltage_v: 3.3,           // Supply voltage
        target_name: "STM32F303RE",
    };

    let mut benchmark = EmbeddedBenchmark::new(config);

    // Set to 100 iterations for detailed statistics
    benchmark.set_iterations(100);

    let _ = hprintln!("🔧 Initializing benchmark suite...");
    let _ = hprintln!("   Target: {} (512KB Flash, 64KB RAM)", benchmark.config.target_name);
    let _ = hprintln!("   CPU Frequency: {} MHz", benchmark.config.cpu_freq_hz / 1_000_000);
    let _ = hprintln!("   Supply Voltage: {:.1} V", benchmark.config.voltage_v);
    let _ = hprintln!("   CPU Current: {:.1} mA", benchmark.config.cpu_power_ma);
    let _ = hprintln!("   Total Power: {:.1} mW", benchmark.config.voltage_v * benchmark.config.cpu_power_ma);
    let _ = hprintln!("   Iterations per test: 100");
    let _ = hprintln!("");

    let _ = hprintln!("🔧 Initializing DWT cycle counter...");

    // Initialize DWT cycle counter
    benchmark.init_cycle_counter();

    let _ = hprintln!("✅ DWT cycle counter initialized successfully");
    let _ = hprintln!("");

    // Test different payload sizes (typical LoRaWAN packet sizes)
    let payload_sizes = [16, 32, 64, 128, 242]; // LoRaWAN max payload is 242 bytes

    let _ = hprintln!("🚀 Starting benchmark execution...");

    // Run comprehensive benchmark suite
    benchmark.run_all_benchmarks(&payload_sizes);

    let _ = hprintln!("🎯 Benchmark suite completed successfully!");
    let _ = hprintln!("📊 Key findings summary:");
    let _ = hprintln!("   • All tests ran with 100 iterations for statistical accuracy");
    let _ = hprintln!("   • Power consumption calculated in milliwatts (mW) and watts (W)");
    let _ = hprintln!("   • Energy consumption shown in microjoules (µJ), millijoules (mJ), and joules (J)");
    let _ = hprintln!("   • Energy per byte shown in nanojoules per byte (nJ/byte)");
    let _ = hprintln!("   • Throughput measured in megabits per second (Mbps)");
    let _ = hprintln!("   • Efficiency score combines throughput and energy efficiency");
    let _ = hprintln!("");
    let _ = hprintln!("🔍 Power & Energy Units Explanation:");
    let _ = hprintln!("   • mW (milliwatts) = Power consumption during operation");
    let _ = hprintln!("   • W (watts) = Power consumption in standard SI units");
    let _ = hprintln!("   • µJ (microjoules) = Energy consumed per operation");
    let _ = hprintln!("   • mJ (millijoules) = Energy in larger scale");
    let _ = hprintln!("   • J (joules) = Energy in standard SI units");
    let _ = hprintln!("   • nJ/byte = Energy efficiency per byte processed");
    let _ = hprintln!("   • Peak Power = Maximum instantaneous power (fastest execution)");
    let _ = hprintln!("   • Average Power = Typical power consumption across all iterations");

    loop {
        // Keep the program running for semihosting output
        cortex_m::asm::wfi();
    }
}
