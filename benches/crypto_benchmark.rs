use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use lorapwn::crypto_benchmark::*;

fn benchmark_encryption_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_encryption");

    let sizes = vec![8, 16, 32, 64, 128, 256];

    for size in sizes {
        let data = generate_test_data(size);
        let aad = generate_lorawan_aad(0x01020304, 42, 0);

        // AES-CTR + CMAC
        let aes_ctr_cmac = AesCtrCmac::new([0x2B; 16]);
        group.bench_with_input(BenchmarkId::new("AES-CTR+CMAC", size), &size, |b, _| {
            b.iter(|| {
                aes_ctr_cmac.encrypt(
                    black_box(&aad),
                    black_box(&data),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0)
                )
            })
        });

        // AES-GCM
        let aes_gcm = AesGcmImpl::new([0x2B; 16]);
        group.bench_with_input(BenchmarkId::new("AES-GCM", size), &size, |b, _| {
            b.iter(|| {
                aes_gcm.encrypt(
                    black_box(&aad),
                    black_box(&data),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0)
                )
            })
        });

        // ChaCha20-Poly1305
        let chacha20_poly1305 = ChaCha20Poly1305Impl::new([0x2B; 32]);
        group.bench_with_input(BenchmarkId::new("ChaCha20-Poly1305", size), &size, |b, _| {
            b.iter(|| {
                chacha20_poly1305.encrypt(
                    black_box(&aad),
                    black_box(&data),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0)
                )
            })
        });
    }

    group.finish();
}

fn benchmark_decryption_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_decryption");

    let sizes = vec![8, 16, 32, 64, 128, 256];

    for size in sizes {
        let data = generate_test_data(size);
        let aad = generate_lorawan_aad(0x01020304, 42, 0);

        // Pre-encrypt data for decryption benchmarks
        let aes_ctr_cmac = AesCtrCmac::new([0x2B; 16]);
        let (aes_ciphertext, aes_mic) = aes_ctr_cmac.encrypt(&aad, &data, 42, 0x01020304, 0).unwrap();

        let aes_gcm = AesGcmImpl::new([0x2B; 16]);
        let (gcm_ciphertext, gcm_tag) = aes_gcm.encrypt(&aad, &data, 42, 0x01020304, 0).unwrap();

        let chacha20_poly1305 = ChaCha20Poly1305Impl::new([0x2B; 32]);
        let (chacha_ciphertext, chacha_tag) = chacha20_poly1305.encrypt(&aad, &data, 42, 0x01020304, 0).unwrap();

        // Benchmark decryption
        group.bench_with_input(BenchmarkId::new("AES-CTR+CMAC", size), &size, |b, _| {
            b.iter(|| {
                aes_ctr_cmac.decrypt(
                    black_box(&aad),
                    black_box(&aes_ciphertext),
                    black_box(&aes_mic),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0),
                )
            })
        });

        group.bench_with_input(BenchmarkId::new("AES-GCM", size), &size, |b, _| {
            b.iter(|| {
                aes_gcm.decrypt(
                    black_box(&aad),
                    black_box(&gcm_ciphertext),
                    black_box(&gcm_tag),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0),
                )
            })
        });

        group.bench_with_input(BenchmarkId::new("ChaCha20-Poly1305", size), &size, |b, _| {
            b.iter(|| {
                chacha20_poly1305.decrypt(
                    black_box(&aad),
                    black_box(&chacha_ciphertext),
                    black_box(&chacha_tag),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0),
                )
            })
        });
    }

    group.finish();
}

fn benchmark_throughput_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_comparison");

    // Focus on realistic LoRaWAN payload sizes
    let lorawan_sizes = vec![8, 16, 32, 64, 128, 256];

    for size in lorawan_sizes {
        let data = generate_test_data(size);
        let aad = generate_lorawan_aad(0x01020304, 42, 0);

        // Full encrypt + decrypt cycle for throughput measurement
        let aes_ctr_cmac = AesCtrCmac::new([0x2B; 16]);
        group.bench_with_input(BenchmarkId::new("AES-CTR+CMAC_Full_Cycle", size), &size, |b, _| {
            b.iter(|| {
                let (ciphertext, mic) = aes_ctr_cmac.encrypt(
                    black_box(&aad),
                    black_box(&data),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0)
                ).unwrap();

                let _decrypted = aes_ctr_cmac.decrypt(
                    black_box(&aad),
                    black_box(&ciphertext),
                    black_box(&mic),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0),
                ).unwrap();
            })
        });

        let aes_gcm = AesGcmImpl::new([0x2B; 16]);
        group.bench_with_input(BenchmarkId::new("AES-GCM_Full_Cycle", size), &size, |b, _| {
            b.iter(|| {
                let (ciphertext, tag) = aes_gcm.encrypt(
                    black_box(&aad),
                    black_box(&data),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0)
                ).unwrap();

                let _decrypted = aes_gcm.decrypt(
                    black_box(&aad),
                    black_box(&ciphertext),
                    black_box(&tag),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0),
                ).unwrap();
            })
        });

        let chacha20_poly1305 = ChaCha20Poly1305Impl::new([0x2B; 32]);
        group.bench_with_input(BenchmarkId::new("ChaCha20-Poly1305_Full_Cycle", size), &size, |b, _| {
            b.iter(|| {
                let (ciphertext, tag) = chacha20_poly1305.encrypt(
                    black_box(&aad),
                    black_box(&data),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0)
                ).unwrap();

                let _decrypted = chacha20_poly1305.decrypt(
                    black_box(&aad),
                    black_box(&ciphertext),
                    black_box(&tag),
                    black_box(42),
                    black_box(0x01020304),
                    black_box(0),
                ).unwrap();
            })
        });
    }

    group.finish();
}

fn benchmark_security_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_overhead");

    // Test different security levels
    let test_data = generate_test_data(128); // Realistic LoRaWAN payload
    let aad = generate_lorawan_aad(0x01020304, 42, 0);

    // Traditional LoRaWAN security (32-bit MIC)
    let aes_ctr_cmac = AesCtrCmac::new([0x2B; 16]);
    group.bench_function("Traditional_32bit_Security", |b| {
        b.iter(|| {
            let (ciphertext, mic) = aes_ctr_cmac.encrypt(
                black_box(&aad),
                black_box(&test_data),
                black_box(42),
                black_box(0x01020304),
                black_box(0)
            ).unwrap();

            let _decrypted = aes_ctr_cmac.decrypt(
                black_box(&aad),
                black_box(&ciphertext),
                black_box(&mic),
                black_box(42),
                black_box(0x01020304),
                black_box(0),
            ).unwrap();
        })
    });

    // AEAD security (128-bit authentication)
    let chacha20_poly1305 = ChaCha20Poly1305Impl::new([0x2B; 32]);
    group.bench_function("AEAD_128bit_Security", |b| {
        b.iter(|| {
            let (ciphertext, tag) = chacha20_poly1305.encrypt(
                black_box(&aad),
                black_box(&test_data),
                black_box(42),
                black_box(0x01020304),
                black_box(0)
            ).unwrap();

            let _decrypted = chacha20_poly1305.decrypt(
                black_box(&aad),
                black_box(&ciphertext),
                black_box(&tag),
                black_box(42),
                black_box(0x01020304),
                black_box(0),
            ).unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_encryption_performance,
    benchmark_decryption_performance,
    benchmark_throughput_comparison,
    benchmark_security_overhead
);
criterion_main!(benches);