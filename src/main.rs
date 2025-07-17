#![no_std]
#![no_main]

extern crate alloc;

use defmt::*;
use embassy_executor::Spawner;
use embassy_time::Instant;
use {defmt_rtt as _, panic_probe as _};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::Aes256;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, Nonce};
use ctr::Ctr128BE;
use ghash::{universal_hash::UniversalHash, GHash};

// Set up a simple allocator for the alloc feature
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

type Aes256Ctr = Ctr128BE<Aes256>;

type Block = [u8; 16];

fn xor_block(a: &mut Block, b: &Block) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn increment_counter(counter: &mut Block) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> heapless::Vec<u8, 64> {
    let cipher = Aes256::new_from_slice(key).unwrap();

    // Generate H for GHASH
    let mut h_block = [0u8; 16];
    let h_block_ga = GenericArray::from_mut_slice(&mut h_block);
    cipher.encrypt_block(h_block_ga);
    let ghash_key = ghash::Key::from_slice(&h_block);
    let mut ghash = GHash::new(ghash_key);

    // Prepare initial counter
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce);
    counter[15] = 1; // Start with counter = 1

    // Encrypt plaintext
    let mut ciphertext = heapless::Vec::<u8, 64>::new();
    let mut current_counter = counter;

    for chunk in plaintext.chunks(16) {
        let mut keystream = current_counter;
        let keystream_ga = GenericArray::from_mut_slice(&mut keystream);
        cipher.encrypt_block(keystream_ga);

        for (i, &byte) in chunk.iter().enumerate() {
            let encrypted_byte = byte ^ keystream[i];
            ciphertext.push(encrypted_byte).unwrap();
        }

        increment_counter(&mut current_counter);
    }

    // Calculate authentication tag
    let aad_len = [0u8; 16];
    let mut plaintext_len = [0u8; 16];
    let plen = (plaintext.len() as u64) * 8;
    plaintext_len[8..].copy_from_slice(&plen.to_be_bytes());

    // Add ciphertext to GHASH
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        ghash.update(&[*GenericArray::from_slice(&block)]);
    }

    // Add lengths
    ghash.update(&[*GenericArray::from_slice(&aad_len)]);
    ghash.update(&[*GenericArray::from_slice(&plaintext_len)]);

    // Finalize tag
    let tag_result = ghash.finalize();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_result);

    let mut j0 = counter;
    j0[15] = 0; // J0 has counter = 0
    let j0_ga = GenericArray::from_mut_slice(&mut j0);
    cipher.encrypt_block(j0_ga);
    xor_block(&mut tag, &j0);

    // Append tag to ciphertext
    for &byte in &tag {
        ciphertext.push(byte).unwrap();
    }

    ciphertext
}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_with_tag: &[u8],
) -> Option<heapless::Vec<u8, 64>> {
    if ciphertext_with_tag.len() < 16 {
        return None; // Must have at least 16 bytes for tag
    }

    let ciphertext_len = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..ciphertext_len];
    let received_tag = &ciphertext_with_tag[ciphertext_len..];

    let cipher = Aes256::new_from_slice(key).unwrap();

    // Generate H for GHASH
    let mut h_block = [0u8; 16];
    let h_block_ga = GenericArray::from_mut_slice(&mut h_block);
    cipher.encrypt_block(h_block_ga);
    let ghash_key = ghash::Key::from_slice(&h_block);
    let mut ghash = GHash::new(ghash_key);

    // Prepare initial counter
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce);
    counter[15] = 1; // Start with counter = 1

    // Decrypt ciphertext
    let mut plaintext = heapless::Vec::<u8, 64>::new();
    let mut current_counter = counter;

    for chunk in ciphertext.chunks(16) {
        let mut keystream = current_counter;
        let keystream_ga = GenericArray::from_mut_slice(&mut keystream);
        cipher.encrypt_block(keystream_ga);

        for (i, &byte) in chunk.iter().enumerate() {
            let decrypted_byte = byte ^ keystream[i];
            plaintext.push(decrypted_byte).unwrap();
        }

        increment_counter(&mut current_counter);
    }

    // Verify authentication tag
    let aad_len = [0u8; 16];
    let mut ciphertext_len_block = [0u8; 16];
    let clen = (ciphertext.len() as u64) * 8;
    ciphertext_len_block[8..].copy_from_slice(&clen.to_be_bytes());

    // Add ciphertext to GHASH
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        ghash.update(&[*GenericArray::from_slice(&block)]);
    }

    // Add lengths
    ghash.update(&[*GenericArray::from_slice(&aad_len)]);
    ghash.update(&[*GenericArray::from_slice(&ciphertext_len_block)]);

    // Finalize tag
    let tag_result = ghash.finalize();
    let mut computed_tag = [0u8; 16];
    computed_tag.copy_from_slice(&tag_result);

    let mut j0 = counter;
    j0[15] = 0; // J0 has counter = 0
    let j0_ga = GenericArray::from_mut_slice(&mut j0);
    cipher.encrypt_block(j0_ga);
    xor_block(&mut computed_tag, &j0);

    // Verify tag
    if computed_tag == received_tag {
        Some(plaintext)
    } else {
        None
    }
}

fn aes_ctr_encrypt(key: &[u8; 32], nonce: &[u8; 16], plaintext: &[u8]) -> heapless::Vec<u8, 64> {
    let mut cipher = Aes256Ctr::new_from_slices(key, nonce).unwrap();
    let mut ciphertext = heapless::Vec::<u8, 64>::new();

    // Copy plaintext to ciphertext buffer
    for &byte in plaintext {
        ciphertext.push(byte).unwrap();
    }

    // Encrypt in place
    cipher.apply_keystream(&mut ciphertext);

    ciphertext
}

fn aes_ctr_decrypt(key: &[u8; 32], nonce: &[u8; 16], ciphertext: &[u8]) -> heapless::Vec<u8, 64> {
    // CTR mode is symmetric - decryption is the same as encryption
    aes_ctr_encrypt(key, nonce, ciphertext)
}

fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> heapless::Vec<u8, 64> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce);

    match cipher.encrypt(nonce, plaintext) {
        Ok(ciphertext) => {
            let mut result = heapless::Vec::<u8, 64>::new();
            for &byte in ciphertext.iter() {
                result.push(byte).unwrap();
            }
            result
        }
        Err(_) => heapless::Vec::new(),
    }
}

fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Option<heapless::Vec<u8, 64>> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => {
            let mut result = heapless::Vec::<u8, 64>::new();
            for &byte in plaintext.iter() {
                result.push(byte).unwrap();
            }
            Some(result)
        }
        Err(_) => None,
    }
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // Initialize the heap allocator
    use core::mem::MaybeUninit;
    const HEAP_SIZE: usize = 1024;
    static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe {
        ALLOCATOR
            .lock()
            .init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE)
    }

    let _p = embassy_stm32::init(Default::default());
    info!("Hello World!");

    let plaintext = b"lorapwn";
    let rounds = 10000;

    // Generate a random 32-byte key for AES-256 and ChaCha20
    let key_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // Generate a random 12-byte nonce for GCM and ChaCha20-Poly1305
    let nonce_bytes: [u8; 12] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    // Generate a random 16-byte IV for CTR
    let iv_bytes: [u8; 16] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    // === AES-CTR Benchmarks ===
    info!("=== AES-CTR Benchmarks ===");

    // Encrypt benchmark
    info!(
        "Starting AES-CTR encryption benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();
    let mut ctr_ciphertext = heapless::Vec::<u8, 64>::new();

    for _ in 0..rounds {
        ctr_ciphertext = aes_ctr_encrypt(&key_bytes, &iv_bytes, plaintext);
    }

    let end_time = Instant::now();
    let ctr_encrypt_duration = end_time.duration_since(start_time);

    info!("AES-CTR encryption completed!");
    info!(
        "{} CTR encryption operations took: {} ms",
        rounds,
        ctr_encrypt_duration.as_millis()
    );
    info!(
        "Average per CTR encryption: {} μs",
        ctr_encrypt_duration.as_micros() / rounds
    );

    // Decrypt benchmark
    info!(
        "Starting AES-CTR decryption benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();

    for _ in 0..rounds {
        let _result = aes_ctr_decrypt(&key_bytes, &iv_bytes, &ctr_ciphertext);
    }

    let end_time = Instant::now();
    let ctr_decrypt_duration = end_time.duration_since(start_time);

    info!("AES-CTR decryption completed!");
    info!(
        "{} CTR decryption operations took: {} ms",
        rounds,
        ctr_decrypt_duration.as_millis()
    );
    info!(
        "Average per CTR decryption: {} μs",
        ctr_decrypt_duration.as_micros() / rounds
    );

    // Complete cycle benchmark
    info!(
        "Starting AES-CTR complete cycle benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();

    for _ in 0..rounds {
        let encrypted = aes_ctr_encrypt(&key_bytes, &iv_bytes, plaintext);
        let _decrypted = aes_ctr_decrypt(&key_bytes, &iv_bytes, &encrypted);
    }

    let end_time = Instant::now();
    let ctr_cycle_duration = end_time.duration_since(start_time);

    info!("AES-CTR complete cycle completed!");
    info!(
        "{} CTR cycles took: {} ms",
        rounds,
        ctr_cycle_duration.as_millis()
    );
    info!(
        "Average per CTR cycle: {} μs",
        ctr_cycle_duration.as_micros() / rounds
    );

    // === AES-GCM Benchmarks ===
    info!("=== AES-GCM Benchmarks ===");

    // Encrypt benchmark
    info!(
        "Starting AES-GCM encryption benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();
    let mut gcm_ciphertext = heapless::Vec::<u8, 64>::new();

    for _ in 0..rounds {
        gcm_ciphertext = aes_gcm_encrypt(&key_bytes, &nonce_bytes, plaintext);
    }

    let end_time = Instant::now();
    let gcm_encrypt_duration = end_time.duration_since(start_time);

    info!("AES-GCM encryption completed!");
    info!(
        "{} GCM encryption operations took: {} ms",
        rounds,
        gcm_encrypt_duration.as_millis()
    );
    info!(
        "Average per GCM encryption: {} μs",
        gcm_encrypt_duration.as_micros() / rounds
    );

    // Decrypt benchmark
    info!(
        "Starting AES-GCM decryption benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();

    for _ in 0..rounds {
        let _result = aes_gcm_decrypt(&key_bytes, &nonce_bytes, &gcm_ciphertext);
    }

    let end_time = Instant::now();
    let gcm_decrypt_duration = end_time.duration_since(start_time);

    info!("AES-GCM decryption completed!");
    info!(
        "{} GCM decryption operations took: {} ms",
        rounds,
        gcm_decrypt_duration.as_millis()
    );
    info!(
        "Average per GCM decryption: {} μs",
        gcm_decrypt_duration.as_micros() / rounds
    );

    // Complete cycle benchmark
    info!(
        "Starting AES-GCM complete cycle benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();

    for _ in 0..rounds {
        let encrypted = aes_gcm_encrypt(&key_bytes, &nonce_bytes, plaintext);
        let _decrypted = aes_gcm_decrypt(&key_bytes, &nonce_bytes, &encrypted);
    }

    let end_time = Instant::now();
    let gcm_cycle_duration = end_time.duration_since(start_time);

    info!("AES-GCM complete cycle completed!");
    info!(
        "{} GCM cycles took: {} ms",
        rounds,
        gcm_cycle_duration.as_millis()
    );
    info!(
        "Average per GCM cycle: {} μs",
        gcm_cycle_duration.as_micros() / rounds
    );

    // === ChaCha20-Poly1305 Benchmarks ===
    info!("=== ChaCha20-Poly1305 Benchmarks ===");

    // Encrypt benchmark
    info!(
        "Starting ChaCha20-Poly1305 encryption benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();
    let mut chacha_ciphertext = heapless::Vec::<u8, 64>::new();

    for _ in 0..rounds {
        chacha_ciphertext = chacha20_poly1305_encrypt(&key_bytes, &nonce_bytes, plaintext);
    }

    let end_time = Instant::now();
    let chacha_encrypt_duration = end_time.duration_since(start_time);

    info!("ChaCha20-Poly1305 encryption completed!");
    info!(
        "{} ChaCha20-Poly1305 encryption operations took: {} ms",
        rounds,
        chacha_encrypt_duration.as_millis()
    );
    info!(
        "Average per ChaCha20-Poly1305 encryption: {} μs",
        chacha_encrypt_duration.as_micros() / rounds
    );

    // Decrypt benchmark
    info!(
        "Starting ChaCha20-Poly1305 decryption benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();

    for _ in 0..rounds {
        let _result = chacha20_poly1305_decrypt(&key_bytes, &nonce_bytes, &chacha_ciphertext);
    }

    let end_time = Instant::now();
    let chacha_decrypt_duration = end_time.duration_since(start_time);

    info!("ChaCha20-Poly1305 decryption completed!");
    info!(
        "{} ChaCha20-Poly1305 decryption operations took: {} ms",
        rounds,
        chacha_decrypt_duration.as_millis()
    );
    info!(
        "Average per ChaCha20-Poly1305 decryption: {} μs",
        chacha_decrypt_duration.as_micros() / rounds
    );

    // Complete cycle benchmark
    info!(
        "Starting ChaCha20-Poly1305 complete cycle benchmark for {} operations...",
        rounds
    );
    let start_time = Instant::now();

    for _ in 0..rounds {
        let encrypted = chacha20_poly1305_encrypt(&key_bytes, &nonce_bytes, plaintext);
        if let Some(_decrypted) = chacha20_poly1305_decrypt(&key_bytes, &nonce_bytes, &encrypted) {
            // Decryption successful
        }
    }

    let end_time = Instant::now();
    let chacha_cycle_duration = end_time.duration_since(start_time);

    info!("ChaCha20-Poly1305 complete cycle completed!");
    info!(
        "{} ChaCha20-Poly1305 cycles took: {} ms",
        rounds,
        chacha_cycle_duration.as_millis()
    );
    info!(
        "Average per ChaCha20-Poly1305 cycle: {} μs",
        chacha_cycle_duration.as_micros() / rounds
    );

    // === Performance Comparison ===
    info!("=== Performance Comparison ===");

    // Encryption comparison
    info!("Encryption Performance:");
    let ctr_encrypt_time = ctr_encrypt_duration.as_micros() / rounds;
    let gcm_encrypt_time = gcm_encrypt_duration.as_micros() / rounds;
    let chacha_encrypt_time = chacha_encrypt_duration.as_micros() / rounds;

    let fastest_encrypt = ctr_encrypt_time
        .min(gcm_encrypt_time)
        .min(chacha_encrypt_time);

    // Calculate percentage differences
    let ctr_vs_gcm_pct =
        ((gcm_encrypt_time - ctr_encrypt_time) * 10000 / ctr_encrypt_time) as f32 / 100.0;
    let ctr_vs_chacha_pct =
        ((chacha_encrypt_time - ctr_encrypt_time) * 10000 / ctr_encrypt_time) as f32 / 100.0;
    let gcm_vs_chacha_pct =
        ((chacha_encrypt_time - gcm_encrypt_time) * 10000 / gcm_encrypt_time) as f32 / 100.0;

    if gcm_encrypt_time > ctr_encrypt_time {
        info!(
            "GCM encryption is {}.{}% slower than CTR ({}μs vs {}μs)",
            (ctr_vs_gcm_pct as u32),
            ((ctr_vs_gcm_pct * 100.0) as u32 % 100),
            ctr_encrypt_time,
            gcm_encrypt_time
        );
    } else {
        let pct = ((ctr_encrypt_time - gcm_encrypt_time) * 10000 / gcm_encrypt_time) as f32 / 100.0;
        info!(
            "CTR encryption is {}.{}% slower than GCM ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            ctr_encrypt_time,
            gcm_encrypt_time
        );
    }

    if chacha_encrypt_time > ctr_encrypt_time {
        info!(
            "ChaCha20 encryption is {}.{}% slower than CTR ({}μs vs {}μs)",
            (ctr_vs_chacha_pct as u32),
            ((ctr_vs_chacha_pct * 100.0) as u32 % 100),
            ctr_encrypt_time,
            chacha_encrypt_time
        );
    } else {
        let pct =
            ((ctr_encrypt_time - chacha_encrypt_time) * 10000 / chacha_encrypt_time) as f32 / 100.0;
        info!(
            "CTR encryption is {}.{}% slower than ChaCha20 ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            ctr_encrypt_time,
            chacha_encrypt_time
        );
    }

    if chacha_encrypt_time > gcm_encrypt_time {
        info!(
            "ChaCha20 encryption is {}.{}% slower than GCM ({}μs vs {}μs)",
            (gcm_vs_chacha_pct as u32),
            ((gcm_vs_chacha_pct * 100.0) as u32 % 100),
            gcm_encrypt_time,
            chacha_encrypt_time
        );
    } else {
        let pct =
            ((gcm_encrypt_time - chacha_encrypt_time) * 10000 / chacha_encrypt_time) as f32 / 100.0;
        info!(
            "GCM encryption is {}.{}% slower than ChaCha20 ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            gcm_encrypt_time,
            chacha_encrypt_time
        );
    }

    if fastest_encrypt == ctr_encrypt_time {
        info!("Fastest encryption: AES-CTR");
    } else if fastest_encrypt == gcm_encrypt_time {
        info!("Fastest encryption: AES-GCM");
    } else {
        info!("Fastest encryption: ChaCha20-Poly1305");
    }

    // Decryption comparison
    info!("Decryption Performance:");
    let ctr_decrypt_time = ctr_decrypt_duration.as_micros() / rounds;
    let gcm_decrypt_time = gcm_decrypt_duration.as_micros() / rounds;
    let chacha_decrypt_time = chacha_decrypt_duration.as_micros() / rounds;

    let fastest_decrypt = ctr_decrypt_time
        .min(gcm_decrypt_time)
        .min(chacha_decrypt_time);

    // Calculate percentage differences
    let ctr_vs_gcm_dec_pct =
        ((gcm_decrypt_time - ctr_decrypt_time) * 10000 / ctr_decrypt_time) as f32 / 100.0;
    let ctr_vs_chacha_dec_pct =
        ((chacha_decrypt_time - ctr_decrypt_time) * 10000 / ctr_decrypt_time) as f32 / 100.0;
    let gcm_vs_chacha_dec_pct =
        ((chacha_decrypt_time - gcm_decrypt_time) * 10000 / gcm_decrypt_time) as f32 / 100.0;

    if gcm_decrypt_time > ctr_decrypt_time {
        info!(
            "GCM decryption is {}.{}% slower than CTR ({}μs vs {}μs)",
            (ctr_vs_gcm_dec_pct as u32),
            ((ctr_vs_gcm_dec_pct * 100.0) as u32 % 100),
            ctr_decrypt_time,
            gcm_decrypt_time
        );
    } else {
        let pct = ((ctr_decrypt_time - gcm_decrypt_time) * 10000 / gcm_decrypt_time) as f32 / 100.0;
        info!(
            "CTR decryption is {}.{}% slower than GCM ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            ctr_decrypt_time,
            gcm_decrypt_time
        );
    }

    if chacha_decrypt_time > ctr_decrypt_time {
        info!(
            "ChaCha20 decryption is {}.{}% slower than CTR ({}μs vs {}μs)",
            (ctr_vs_chacha_dec_pct as u32),
            ((ctr_vs_chacha_dec_pct * 100.0) as u32 % 100),
            ctr_decrypt_time,
            chacha_decrypt_time
        );
    } else {
        let pct =
            ((ctr_decrypt_time - chacha_decrypt_time) * 10000 / chacha_decrypt_time) as f32 / 100.0;
        info!(
            "CTR decryption is {}.{}% slower than ChaCha20 ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            ctr_decrypt_time,
            chacha_decrypt_time
        );
    }

    if chacha_decrypt_time > gcm_decrypt_time {
        info!(
            "ChaCha20 decryption is {}.{}% slower than GCM ({}μs vs {}μs)",
            (gcm_vs_chacha_dec_pct as u32),
            ((gcm_vs_chacha_dec_pct * 100.0) as u32 % 100),
            gcm_decrypt_time,
            chacha_decrypt_time
        );
    } else {
        let pct =
            ((gcm_decrypt_time - chacha_decrypt_time) * 10000 / chacha_decrypt_time) as f32 / 100.0;
        info!(
            "GCM decryption is {}.{}% slower than ChaCha20 ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            gcm_decrypt_time,
            chacha_decrypt_time
        );
    }

    if fastest_decrypt == ctr_decrypt_time {
        info!("Fastest decryption: AES-CTR");
    } else if fastest_decrypt == gcm_decrypt_time {
        info!("Fastest decryption: AES-GCM");
    } else {
        info!("Fastest decryption: ChaCha20-Poly1305");
    }

    // Complete cycle comparison
    info!("Complete Cycle Performance:");
    let ctr_cycle_time = ctr_cycle_duration.as_micros() / rounds;
    let gcm_cycle_time = gcm_cycle_duration.as_micros() / rounds;
    let chacha_cycle_time = chacha_cycle_duration.as_micros() / rounds;

    let fastest_cycle = ctr_cycle_time.min(gcm_cycle_time).min(chacha_cycle_time);

    // Calculate percentage differences
    let ctr_vs_gcm_cyc_pct =
        ((gcm_cycle_time - ctr_cycle_time) * 10000 / ctr_cycle_time) as f32 / 100.0;
    let ctr_vs_chacha_cyc_pct =
        ((chacha_cycle_time - ctr_cycle_time) * 10000 / ctr_cycle_time) as f32 / 100.0;
    let gcm_vs_chacha_cyc_pct =
        ((chacha_cycle_time - gcm_cycle_time) * 10000 / gcm_cycle_time) as f32 / 100.0;

    if gcm_cycle_time > ctr_cycle_time {
        info!(
            "GCM cycle is {}.{}% slower than CTR ({}μs vs {}μs)",
            (ctr_vs_gcm_cyc_pct as u32),
            ((ctr_vs_gcm_cyc_pct * 100.0) as u32 % 100),
            ctr_cycle_time,
            gcm_cycle_time
        );
    } else {
        let pct = ((ctr_cycle_time - gcm_cycle_time) * 10000 / gcm_cycle_time) as f32 / 100.0;
        info!(
            "CTR cycle is {}.{}% slower than GCM ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            ctr_cycle_time,
            gcm_cycle_time
        );
    }

    if chacha_cycle_time > ctr_cycle_time {
        info!(
            "ChaCha20 cycle is {}.{}% slower than CTR ({}μs vs {}μs)",
            (ctr_vs_chacha_cyc_pct as u32),
            ((ctr_vs_chacha_cyc_pct * 100.0) as u32 % 100),
            ctr_cycle_time,
            chacha_cycle_time
        );
    } else {
        let pct = ((ctr_cycle_time - chacha_cycle_time) * 10000 / chacha_cycle_time) as f32 / 100.0;
        info!(
            "CTR cycle is {}.{}% slower than ChaCha20 ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            ctr_cycle_time,
            chacha_cycle_time
        );
    }

    if chacha_cycle_time > gcm_cycle_time {
        info!(
            "ChaCha20 cycle is {}.{}% slower than GCM ({}μs vs {}μs)",
            (gcm_vs_chacha_cyc_pct as u32),
            ((gcm_vs_chacha_cyc_pct * 100.0) as u32 % 100),
            gcm_cycle_time,
            chacha_cycle_time
        );
    } else {
        let pct = ((gcm_cycle_time - chacha_cycle_time) * 10000 / chacha_cycle_time) as f32 / 100.0;
        info!(
            "GCM cycle is {}.{}% slower than ChaCha20 ({}μs vs {}μs)",
            (pct as u32),
            ((pct * 100.0) as u32 % 100),
            gcm_cycle_time,
            chacha_cycle_time
        );
    }

    if fastest_cycle == ctr_cycle_time {
        info!("Fastest complete cycle: AES-CTR");
    } else if fastest_cycle == gcm_cycle_time {
        info!("Fastest complete cycle: AES-GCM");
    } else {
        info!("Fastest complete cycle: ChaCha20-Poly1305");
    }

    loop {
        // In embedded systems, we typically don't "exit" like in desktop applications
        // Instead, we can enter a low-power sleep state or halt execution
        cortex_m::asm::wfi(); // Wait for interrupt - low power state
    }
}
