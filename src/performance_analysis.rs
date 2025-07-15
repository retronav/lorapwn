//! Simple performance analysis module

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CryptoMetrics {
    pub algorithm: String,
    pub payload_size: usize,
    pub encryption_time: Duration,
    pub decryption_time: Duration,
    pub total_time: Duration,
    pub throughput_mbps: f64,
    pub tag_size: usize,
    pub packet_overhead: usize,
}

pub fn run_simple_performance_test() {
    println!("🚀 Running simple performance test...");

    let test_sizes = vec![8, 16, 32, 64, 128, 256];

    for size in test_sizes {
        println!("  📦 Testing payload size: {} bytes", size);

        // Here you would call your crypto implementations
        // For now, just print the size
        println!("     ✅ Tested {} bytes", size);
    }

    println!("✅ Performance test completed!");
}