//! LoraPwn: LoRaWAN Security Research & Sniffing Toolkit
//! ChaCha20-Poly1305 AEAD Implementation

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Core library modules (now in lib/ directory)
#[path = "../lib/aead_crypto.rs"]
pub mod aead_crypto;
#[path = "../lib/lorawan_parser.rs"]
pub mod lorawan_parser;
#[path = "../lib/simulation.rs"]
pub mod simulation;
#[path = "../lib/debug.rs"]
pub mod debug;
#[path = "../lib/crypto_benchmark.rs"]
pub mod crypto_benchmark;
#[path = "../lib/performance_analysis.rs"]
pub mod performance_analysis;
#[path = "../lib/packet_format.rs"]
pub mod packet_format;

// CLI module (only available with std feature)
#[cfg(feature = "std")]
pub mod cli;

// Re-export main types for easier access
pub use aead_crypto::{aead_encrypt, aead_decrypt, derive_chacha20_key};
pub use lorawan_parser::{AeadLorawanPacket, PacketMetadata};
pub use simulation::run_simulation;
pub use debug::debug_packet_structure;
pub use packet_format::print_packet_format_comparison;
pub use performance_analysis::run_simple_performance_test;

// Constants
pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_TAG_SIZE: usize = 16;
pub const LORAWAN_KEY_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

#[cfg(test)]
#[path = "../lib/crypto_test.rs"]
pub mod crypto_test;