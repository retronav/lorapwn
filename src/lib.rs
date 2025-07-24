//! LoRaWAN Embedded Crypto Benchmark Library
//! Copyright (c) 2025 - HimuCodes
//! Enhanced version with comprehensive power analysis and statistics

#![no_std]

extern crate alloc;

pub mod embedded_benchmark;

pub use embedded_benchmark::{
    EmbeddedBenchmark,
    EmbeddedBenchmarkConfig,
    BenchmarkResult,
    BenchmarkStats,
    OperationType
};
