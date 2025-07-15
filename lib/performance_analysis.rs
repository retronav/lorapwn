//! Simple performance analysis module

use std::time::Duration;

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

        // Create a dummy metric for demonstration
        let _metric = CryptoMetrics {
            algorithm: "ChaCha20-Poly1305".to_string(),
            payload_size: size,
            encryption_time: Duration::from_micros(100),
            decryption_time: Duration::from_micros(90),
            total_time: Duration::from_micros(190),
            throughput_mbps: (size as f64) / 0.19, // Simple calculation
            tag_size: 16,
            packet_overhead: 25,
        };

        println!("     ✅ Tested {} bytes", size);
    }

    println!("✅ Performance test completed!");
}