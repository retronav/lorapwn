#![no_std]
#![no_main]

extern crate alloc;

use defmt::*;
use embassy_executor::Spawner;
use embassy_time::Instant;
use {defmt_rtt as _, panic_probe as _};

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray, StreamCipher, KeyIvInit};
use ghash::{GHash, universal_hash::UniversalHash};
use ctr::Ctr128BE;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::Aead};

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

fn chacha20_poly1305_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> heapless::Vec<u8, 64> {
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

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // Initialize the heap allocator
    use core::mem::MaybeUninit;
    const HEAP_SIZE: usize = 1024;
    static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe { ALLOCATOR.lock().init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE) }

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

    // Benchmark AES-CTR
    info!("Starting AES-CTR benchmark for {} operations...", rounds);
    let start_time = Instant::now();

    for _ in 0..rounds {
        let _result = aes_ctr_encrypt(&key_bytes, &iv_bytes, plaintext);
    }

    let end_time = Instant::now();
    let ctr_duration = end_time.duration_since(start_time);

    info!("AES-CTR benchmark completed!");
    info!("{} CTR operations took: {} ms", rounds, ctr_duration.as_millis());
    info!("Average per CTR operation: {} ms", ctr_duration.as_millis() / rounds);

    // Benchmark AES-GCM
    info!("Starting AES-GCM benchmark for {} operations...", rounds);
    let start_time = Instant::now();

    for _ in 0..rounds {
        let _result = aes_gcm_encrypt(&key_bytes, &nonce_bytes, plaintext);
    }

    let end_time = Instant::now();
    let gcm_duration = end_time.duration_since(start_time);

    info!("AES-GCM benchmark completed!");
    info!("{} GCM operations took: {} ms", rounds, gcm_duration.as_millis());
    info!("Average per GCM operation: {} ms", gcm_duration.as_millis() / rounds);

    // Benchmark ChaCha20-Poly1305
    info!("Starting ChaCha20-Poly1305 benchmark for {} operations...", rounds);
    let start_time = Instant::now();

    for _ in 0..rounds {
        let _result = chacha20_poly1305_encrypt(&key_bytes, &nonce_bytes, plaintext);
    }

    let end_time = Instant::now();
    let chacha_duration = end_time.duration_since(start_time);

    info!("ChaCha20-Poly1305 benchmark completed!");
    info!("{} ChaCha20-Poly1305 operations took: {} ms", rounds, chacha_duration.as_millis());
    info!("Average per ChaCha20-Poly1305 operation: {} ms", chacha_duration.as_millis() / rounds);

    // Performance comparison
    info!("Performance Comparison:");

    // CTR vs GCM
    let ctr_gcm_ratio = (gcm_duration.as_micros() * 100) / ctr_duration.as_micros();
    info!("CTR vs GCM ratio: {}.{:02}x", ctr_gcm_ratio / 100, ctr_gcm_ratio % 100);

    // CTR vs ChaCha20-Poly1305
    let ctr_chacha_ratio = (chacha_duration.as_micros() * 100) / ctr_duration.as_micros();
    info!("CTR vs ChaCha20-Poly1305 ratio: {}.{:02}x", ctr_chacha_ratio / 100, ctr_chacha_ratio % 100);

    // GCM vs ChaCha20-Poly1305
    let gcm_chacha_ratio = (chacha_duration.as_micros() * 100) / gcm_duration.as_micros();
    info!("GCM vs ChaCha20-Poly1305 ratio: {}.{:02}x", gcm_chacha_ratio / 100, gcm_chacha_ratio % 100);

    // Find fastest algorithm
    let fastest_time = ctr_duration.as_micros().min(gcm_duration.as_micros()).min(chacha_duration.as_micros());
    if fastest_time == ctr_duration.as_micros() {
        info!("Fastest: AES-CTR");
    } else if fastest_time == gcm_duration.as_micros() {
        info!("Fastest: AES-GCM");
    } else {
        info!("Fastest: ChaCha20-Poly1305");
    }

    loop {
        // In embedded systems, we typically don't "exit" like in desktop applications
        // Instead, we can enter a low-power sleep state or halt execution
        cortex_m::asm::wfi(); // Wait for interrupt - low power state
    }
}
