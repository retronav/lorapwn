//! Command Line Interface for LoRaWAN Security Research & Side-Channel Analysis Tool

#![cfg(feature = "std")]

use clap::{Parser, ValueEnum};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use crate::lorawan_aes::{get_aes_intermediate_state, aes_ctr_encrypt, LORAWAN_KEY_SIZE, AES_BLOCK_SIZE};

#[cfg(feature = "std")]
use std::vec::Vec;
use std::fs::File;
use std::io::{BufWriter, Write};
use rand::RngCore;

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    Profiling,
    Target,
    /// Generate bulk profiling data for machine learning training
    BulkProfiling,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CryptoAlgorithm {
    /// Modern ChaCha20-Poly1305 AEAD (default)
    Aead,
    /// Traditional LoRaWAN AES-CTR + CMAC
    Aes,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Stage {
    /// Initial ChaCha20 state matrix (key + nonce + counter) or AES initial state
    InitialState,
    /// State after first quarter-round (ChaCha20) or first AES round (most vulnerable)
    QuarterRound1,
    /// State after 4 quarter-rounds (ChaCha20) or 4 AES rounds (one complete round)
    Round1,
    /// State after 10 rounds (half encryption)
    Round10,
    /// Final state after 20 rounds (ChaCha20) or 10 rounds (AES)
    FinalState,
    /// Final ciphertext output
    FinalCiphertext,
}

#[derive(Parser)]
#[command(name = "lorapwn")]
#[command(about = "LoRaWAN Security Research & Side-Channel Analysis Tool")]
#[command(version = "0.1.0")]
#[command(author = "HimuCodes")]
pub struct Args {
    /// Operational mode
    #[arg(long, value_enum)]
    pub mode: Mode,

    /// Cryptographic algorithm to use
    #[arg(long, value_enum, default_value = "aead")]
    pub crypto: CryptoAlgorithm,

    /// Secret key as hex string (32 bytes for ChaCha20, 16 bytes for AES, required for profiling mode)
    #[arg(long)]
    pub key: Option<String>,

    /// Input data as hex string (12 bytes for ChaCha20 nonce, 16 bytes for AES plaintext, required for both modes)
    #[arg(long)]
    pub input: Option<String>,

    /// Select which cryptographic stage to output
    #[arg(long, value_enum, default_value = "quarter-round-1")]
    pub stage: Stage,

    /// Enable verbose output with labels and debugging info
    #[arg(long)]
    pub verbose: bool,

    /// Number of traces to generate (for bulk-profiling mode)
    #[arg(long, default_value = "1000")]
    pub num_traces: usize,

    /// Output file path for bulk profiling data (for bulk-profiling mode)
    #[arg(long)]
    pub output_file: Option<String>,
}

pub fn print_stage_output(stage: &Stage, data: &[u8], verbose: bool) {
    if verbose {
        println!("STAGE: {:?}", stage);
        println!("VALUE: {}", hex::encode(data));
        println!("HAMMING_WEIGHT: {}", data.iter().map(|b| b.count_ones()).sum::<u32>());
        println!("---");
    } else {
        // Clean output for batch processing - space-separated hex words
        let words: Vec<String> = data.chunks(4)
            .map(|chunk| {
                let mut word = [0u8; 4];
                word[..chunk.len()].copy_from_slice(chunk);
                format!("{:08x}", u32::from_le_bytes(word))
            })
            .collect();
        println!("{}", words.join(" "));
    }
}

pub fn create_chacha20_state_matrix(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    let mut state = [0u32; 16];

    // ChaCha20 constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    // Counter (1 word)
    state[12] = counter;

    // Nonce (3 words)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    state
}

pub fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

pub fn chacha20_round(state: &mut [u32; 16]) {
    // Column rounds
    chacha20_quarter_round(state, 0, 4, 8, 12);
    chacha20_quarter_round(state, 1, 5, 9, 13);
    chacha20_quarter_round(state, 2, 6, 10, 14);
    chacha20_quarter_round(state, 3, 7, 11, 15);

    // Diagonal rounds
    chacha20_quarter_round(state, 0, 5, 10, 15);
    chacha20_quarter_round(state, 1, 6, 11, 12);
    chacha20_quarter_round(state, 2, 7, 8, 13);
    chacha20_quarter_round(state, 3, 4, 9, 14);
}

pub fn get_chacha20_stage_data(key: &[u8; 32], nonce: &[u8; 12], stage: &Stage) -> Vec<u8> {
    let mut state = create_chacha20_state_matrix(key, nonce, 0);

    match stage {
        Stage::InitialState => {
            // Return initial state as bytes
            let mut bytes = Vec::new();
            for word in &state {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        }
        Stage::QuarterRound1 => {
            // Perform first quarter-round (most vulnerable)
            chacha20_quarter_round(&mut state, 0, 4, 8, 12);
            let mut bytes = Vec::new();
            for word in &state {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        }
        Stage::Round1 => {
            // Perform one complete round (4 quarter-rounds)
            chacha20_round(&mut state);
            let mut bytes = Vec::new();
            for word in &state {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        }
        Stage::Round10 => {
            // Perform 10 rounds (half encryption)
            for _ in 0..10 {
                chacha20_round(&mut state);
            }
            let mut bytes = Vec::new();
            for word in &state {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        }
        Stage::FinalState => {
            // Perform full 20 rounds
            for _ in 0..20 {
                chacha20_round(&mut state);
            }
            let mut bytes = Vec::new();
            for word in &state {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        }
        Stage::FinalCiphertext => {
            // Use the high-level ChaCha20-Poly1305 for final ciphertext
            let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
            let nonce_obj = Nonce::from_slice(nonce);
            let plaintext = b"Hello LoRaWAN with ChaCha20-Poly1305!";
            let ciphertext = cipher.encrypt(nonce_obj, plaintext.as_ref()).unwrap();
            ciphertext
        }
    }
}

pub fn get_aes_stage_data(key: &[u8; LORAWAN_KEY_SIZE], plaintext: &[u8; AES_BLOCK_SIZE], stage: &Stage) -> Vec<u8> {
    match stage {
        Stage::InitialState => {
            // Return initial AES state (plaintext XOR key)
            let mut state = *plaintext;
            for i in 0..AES_BLOCK_SIZE {
                state[i] ^= key[i % LORAWAN_KEY_SIZE];
            }
            state.to_vec()
        }
        Stage::QuarterRound1 => {
            // Get state after first AES round (most vulnerable)
            get_aes_intermediate_state(key, plaintext, 1).to_vec()
        }
        Stage::Round1 => {
            // Get state after 4 AES rounds
            get_aes_intermediate_state(key, plaintext, 4).to_vec()
        }
        Stage::Round10 => {
            // Get state after 10 AES rounds (full AES-128)
            get_aes_intermediate_state(key, plaintext, 10).to_vec()
        }
        Stage::FinalState => {
            // Same as Round10 for AES-128
            get_aes_intermediate_state(key, plaintext, 10).to_vec()
        }
        Stage::FinalCiphertext => {
            // Use AES-CTR to encrypt a test message
            let fcnt = 42;
            let devaddr = 0x01020304;
            let dir = 0;
            let plaintext_msg = b"Hello LoRaWAN with AES-CTR!";
            aes_ctr_encrypt(key, plaintext_msg, fcnt, devaddr, dir).unwrap_or_else(|_| Vec::new())
        }
    }
}

pub fn perform_profiling_mode(key_hex: &str, input_hex: &str, stage: &Stage, crypto: &CryptoAlgorithm, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    match crypto {
        CryptoAlgorithm::Aead => {
            // Parse key for ChaCha20 (32 bytes)
            let key_bytes = hex::decode(key_hex)?;
            if key_bytes.len() != 32 {
                return Err("Key must be exactly 32 bytes (64 hex characters) for ChaCha20".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            // Parse input (nonce for ChaCha20)
            let input_bytes = hex::decode(input_hex)?;
            if input_bytes.len() != 12 {
                return Err("Input must be exactly 12 bytes (24 hex characters) for ChaCha20 nonce".into());
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&input_bytes);

            if verbose {
                println!("=== PROFILING MODE (ChaCha20-Poly1305 AEAD) ===");
                println!("KEY: {}", key_hex);
                println!("INPUT: {}", input_hex);
                println!("STAGE: {:?}", stage);
                println!("===============================================");
            }

            // Get the specified stage data
            let stage_data = get_chacha20_stage_data(&key, &nonce, stage);
            print_stage_output(stage, &stage_data, verbose);
        }
        CryptoAlgorithm::Aes => {
            // Parse key for AES (16 bytes)
            let key_bytes = hex::decode(key_hex)?;
            if key_bytes.len() != LORAWAN_KEY_SIZE {
                return Err("Key must be exactly 16 bytes (32 hex characters) for AES".into());
            }
            let mut key = [0u8; LORAWAN_KEY_SIZE];
            key.copy_from_slice(&key_bytes);

            // Parse input (plaintext for AES)
            let input_bytes = hex::decode(input_hex)?;
            if input_bytes.len() != AES_BLOCK_SIZE {
                return Err("Input must be exactly 16 bytes (32 hex characters) for AES plaintext".into());
            }
            let mut plaintext = [0u8; AES_BLOCK_SIZE];
            plaintext.copy_from_slice(&input_bytes);

            if verbose {
                println!("=== PROFILING MODE (AES-CTR + CMAC) ===");
                println!("KEY: {}", key_hex);
                println!("INPUT: {}", input_hex);
                println!("STAGE: {:?}", stage);
                println!("=======================================");
            }

            // Get the specified stage data
            let stage_data = get_aes_stage_data(&key, &plaintext, stage);
            print_stage_output(stage, &stage_data, verbose);
        }
    }

    Ok(())
}

pub fn perform_target_mode(input_hex: &str, stage: &Stage, crypto: &CryptoAlgorithm, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    match crypto {
        CryptoAlgorithm::Aead => {
            // Fixed internal key for target mode (ChaCha20)
            let fixed_key = [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            ];

            // Parse input (nonce)
            let input_bytes = hex::decode(input_hex)?;
            if input_bytes.len() != 12 {
                return Err("Input must be exactly 12 bytes (24 hex characters) for ChaCha20 nonce".into());
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&input_bytes);

            if verbose {
                println!("=== TARGET MODE (ChaCha20-Poly1305 AEAD) ===");
                println!("INPUT: {}", input_hex);
                println!("STAGE: {:?}", stage);
                println!("USING_FIXED_KEY: true");
                println!("============================================");
            }

            // Get the specified stage data
            let stage_data = get_chacha20_stage_data(&fixed_key, &nonce, stage);
            print_stage_output(&stage, &stage_data, verbose);
        }
        CryptoAlgorithm::Aes => {
            // Fixed internal key for target mode (AES)
            let fixed_key = [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            ];

            // Parse input (plaintext)
            let input_bytes = hex::decode(input_hex)?;
            if input_bytes.len() != AES_BLOCK_SIZE {
                return Err("Input must be exactly 16 bytes (32 hex characters) for AES plaintext".into());
            }
            let mut plaintext = [0u8; AES_BLOCK_SIZE];
            plaintext.copy_from_slice(&input_bytes);

            if verbose {
                println!("=== TARGET MODE (AES-CTR + CMAC) ===");
                println!("INPUT: {}", input_hex);
                println!("STAGE: {:?}", stage);
                println!("USING_FIXED_KEY: true");
                println!("====================================");
            }

            // Get the specified stage data
            let stage_data = get_aes_stage_data(&fixed_key, &plaintext, stage);
            print_stage_output(&stage, &stage_data, verbose);
        }
    }

    Ok(())
}

pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; size];
    rng.fill_bytes(&mut bytes);
    bytes
}

pub fn perform_bulk_profiling_mode(stage: &Stage, crypto: &CryptoAlgorithm, num_traces: usize, output_file: Option<&str>, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    if verbose {
        println!("=== BULK PROFILING MODE ===");
        println!("STAGE: {:?}", stage);
        println!("CRYPTO: {:?}", crypto);
        println!("NUM_TRACES: {}", num_traces);
        println!("===========================");
    }

    // Determine output - either file or stdout
    let use_file = output_file.is_some();
    let mut file_writer = if let Some(path) = output_file {
        Some(BufWriter::new(File::create(path)?))
    } else {
        None
    };

    // Generate and output traces
    for i in 0..num_traces {
        if verbose && (i % 1000 == 0) {
            eprintln!("Generated {} traces...", i);
        }

        let (trace_data, key_hex, input_hex) = match crypto {
            CryptoAlgorithm::Aead => {
                // Generate random key (32 bytes for ChaCha20)
                let key_bytes = generate_random_bytes(32);
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                let key_hex = hex::encode(&key_bytes);

                // Generate random nonce (12 bytes for ChaCha20)
                let nonce_bytes = generate_random_bytes(12);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&nonce_bytes);
                let nonce_hex = hex::encode(&nonce_bytes);

                // Get stage data
                let stage_data = get_chacha20_stage_data(&key, &nonce, stage);
                (stage_data, key_hex, nonce_hex)
            }
            CryptoAlgorithm::Aes => {
                // Generate random key (16 bytes for AES)
                let key_bytes = generate_random_bytes(LORAWAN_KEY_SIZE);
                let mut key = [0u8; LORAWAN_KEY_SIZE];
                key.copy_from_slice(&key_bytes);
                let key_hex = hex::encode(&key_bytes);

                // Generate random plaintext (16 bytes for AES)
                let plaintext_bytes = generate_random_bytes(AES_BLOCK_SIZE);
                let mut plaintext = [0u8; AES_BLOCK_SIZE];
                plaintext.copy_from_slice(&plaintext_bytes);
                let plaintext_hex = hex::encode(&plaintext_bytes);

                // Get stage data
                let stage_data = get_aes_stage_data(&key, &plaintext, stage);
                (stage_data, key_hex, plaintext_hex)
            }
        };

        // Format output: trace_hex,key_hex,input_hex
        let trace_hex = hex::encode(&trace_data);
        let output_line = format!("{},{},{}", trace_hex, key_hex, input_hex);

        if use_file {
            if let Some(ref mut writer) = file_writer {
                writeln!(writer, "{}", output_line)?;
            }
        } else {
            println!("{}", output_line);
        }
    }

    if let Some(mut writer) = file_writer {
        writer.flush()?;
    }

    if verbose {
        eprintln!("Generated {} traces successfully!", num_traces);
    }

    Ok(())
}
