//! Comprehensive packet format comparison and analysis

pub fn print_packet_format_comparison() {
    println!("\n📦 LORAWAN PACKET FORMAT COMPARISON");
    println!("═══════════════════════════════════════════════════════════");

    print_traditional_format();
    print_aead_format();
    print_overhead_analysis();
    print_security_comparison();
}

fn print_traditional_format() {
    println!("\n🔒 TRADITIONAL LORAWAN (AES-128-CTR + CMAC)");
    println!("───────────────────────────────────────────────────────");
    println!("┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────────┬─────────┐");
    println!("│  MHDR   │DevAddr  │ FCtrl   │  FCnt   │ FPort   │ FRMPayload  │   MIC   │");
    println!("│ 1 byte  │4 bytes  │ 1 byte  │2 bytes  │ 1 byte  │ Variable    │ 4 bytes │");
    println!("└─────────┴─────────┴─────────┴─────────┴─────────┴─────────────┴─────────┘");
    println!();
    println!("🔐 Security Model:");
    println!("  • Encryption: AES-128-CTR (stream cipher)");
    println!("  • Authentication: CMAC (4-byte tag)");
    println!("  • Security Level: ~32-bit authentication");
    println!("  • Overhead: 13 bytes (with FPort)");
}

fn print_aead_format() {
    println!("\n🚀 AEAD LORAWAN (ChaCha20-Poly1305)");
    println!("───────────────────────────────────────────────────────");
    println!("┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────────┬─────────┐");
    println!("│  MHDR   │DevAddr  │ FCtrl   │  FCnt   │ FPort   │EncPayload  │AEADTag  │");
    println!("│ 1 byte  │4 bytes  │ 1 byte  │2 bytes  │ 1 byte  │ Variable    │16 bytes │");
    println!("└─────────┴─────────┴─────────┴─────────┴─────────┴─────────────┴─────────┘");
    println!();
    println!("🔐 Security Model:");
    println!("  • Encryption: ChaCha20 (stream cipher)");
    println!("  • Authentication: Poly1305 (16-byte tag)");
    println!("  • Security Level: ~128-bit authentication");
    println!("  • Overhead: 25 bytes (with FPort)");
}

fn print_overhead_analysis() {
    println!("\n📊 OVERHEAD ANALYSIS");
    println!("───────────────────────────────────────────────────────");

    let payload_sizes = vec![8, 16, 32, 64, 128, 256];

    println!("┌─────────┬─────────────────┬─────────────────┬─────────────────┐");
    println!("│Payload  │ Traditional     │ AEAD            │ Overhead        │");
    println!("│ Size    │ Total│    %     │ Total│    %     │ Difference      │");
    println!("├─────────┼──────┼─────────┼──────┼─────────┼─────────────────┤");

    for size in payload_sizes {
        let traditional_total = size + 13;
        let traditional_pct = (13.0 / traditional_total as f64) * 100.0;

        let aead_total = size + 25;
        let aead_pct = (25.0 / aead_total as f64) * 100.0;

        let overhead_diff = aead_total - traditional_total;

        println!("│{:^8} │{:^6} │{:^8.1}%│{:^6} │{:^8.1}%│ +{:^2} bytes ({:^.1}%)│",
                 size, traditional_total, traditional_pct,
                 aead_total, aead_pct, overhead_diff,
                 ((overhead_diff as f64 / traditional_total as f64) * 100.0));
    }

    println!("└─────────┴──────┴─────────┴──────┴─────────┴─────────────────┘");
}

fn print_security_comparison() {
    println!("\n🔒 SECURITY COMPARISON MATRIX");
    println!("───────────────────────────────────────────────────────");

    println!("┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐");
    println!("│    Property     │   Traditional   │    AES-GCM      │ ChaCha20-Poly   │");
    println!("├─────────────────┼─────────────────┼─────────────────┼─────────────────┤");
    println!("│ Encryption      │ AES-128-CTR     │ AES-128-GCM     │ ChaCha20        │");
    println!("│ Authentication  │ CMAC            │ GCM Tag         │ Poly1305        │");
    println!("│ Tag Size        │ 4 bytes         │ 16 bytes        │ 16 bytes        │");
    println!("│ Security Level  │ ~32-bit         │ ~128-bit        │ ~128-bit        │");
    println!("│ AEAD Property   │ No              │ Yes             │ Yes             │");
    println!("│ Timing Safe     │ Depends on HW   │ Depends on HW   │ Yes (software)  │");
    println!("│ Performance     │ Good            │ Excellent (HW)  │ Excellent (SW)  │");
    println!("└─────────────────┴─────────────────┴─────────────────┴─────────────────┘");

    println!("\n🎯 Key Advantages of AEAD:");
    println!("  ✅ 4x stronger authentication (128-bit vs 32-bit)");
    println!("  ✅ Unified encryption + authentication");
    println!("  ✅ Resistance to padding oracle attacks");
    println!("  ✅ Authenticated associated data (AAD) protection");
    println!("  ✅ Modern cryptographic design");

    println!("\n⚠️  Trade-offs:");
    println!("  • Larger packet size (+12 bytes)");
    println!("  • Requires updated firmware");
    println!("  • Catastrophic nonce reuse (vs recoverable in traditional)");
}

pub fn generate_packet_diagrams() {
    println!("\n🎨 DETAILED PACKET STRUCTURE DIAGRAMS");
    println!("═══════════════════════════════════════════════════════════");

    print_bit_level_comparison();
    print_memory_layout();
}

fn print_bit_level_comparison() {
    println!("\n📋 BIT-LEVEL PACKET STRUCTURE");
    println!("───────────────────────────────────────────────────────");

    println!("Traditional LoRaWAN:");
    println!("Bits: 7     0 31              0 7 0 15      0 7 0    Variable    31        0");
    println!("     ┌───────┬─────────────────┬───┬─────────┬───┬─────────────┬───────────┐");
    println!("     │ MHDR  │     DevAddr     │FCr│  FCnt   │FPt│ FRMPayload  │    MIC    │");
    println!("     │       │  (Little End.)  │   │ (L.E.)  │   │ (AES-CTR)   │  (CMAC)   │");
    println!("     └───────┴─────────────────┴───┴─────────┴───┴─────────────┴───────────┘");

    println!("\nAEAD LoRaWAN:");
    println!("Bits: 7     0 31              0 7 0 15      0 7 0    Variable    127       0");
    println!("     ┌───────┬─────────────────┬───┬─────────┬───┬─────────────┬───────────┐");
    println!("     │ MHDR  │     DevAddr     │FCr│  FCnt   │FPt│EncPayload  │ AEAD Tag  │");
    println!("     │       │  (Little End.)  │   │ (L.E.)  │   │ (ChaCha20)  │(Poly1305) │");
    println!("     └───────┴─────────────────┴───┴─────────┴───┴─────────────┴───────────┘");
}

fn print_memory_layout() {
    println!("\n💾 MEMORY LAYOUT EXAMPLE (64-byte payload)");
    println!("───────────────────────────────────────────────────────");

    println!("Traditional (81 bytes total):");
    println!("Offset: 0    1    5    6    8    9                   73   77");
    println!("       ┌────┬────┬────┬────┬────┬──────────────────┬─────────┐");
    println!("       │MHDR│DevA│FCtl│FCnt│FPrt│   64-byte Data   │ 4B MIC  │");
    println!("       │ 1B │ 4B │ 1B │ 2B │ 1B │   (encrypted)    │ (CMAC)  │");
    println!("       └────┴────┴────┴────┴────┴──────────────────┴─────────┘");

    println!("\nAEAD (89 bytes total):");
    println!("Offset: 0    1    5    6    8    9                   73   89");
    println!("       ┌────┬────┬────┬────┬────┬──────────────────┬─────────┐");
    println!("       │MHDR│DevA│FCtl│FCnt│FPrt│   64-byte Data   │16B Tag  │");
    println!("       │ 1B │ 4B │ 1B │ 2B │ 1B │   (encrypted)    │(Poly1305│");
    println!("       └────┴────┴────┴────┴────┴──────────────────┴─────────┘");

    println!("\n📏 Size Analysis:");
    println!("  • Traditional: 81 bytes (18.5% overhead)");
    println!("  • AEAD: 89 bytes (28.1% overhead)");
    println!("  • Difference: +8 bytes (+9.9% size increase)");
    println!("  • Security gain: 4x stronger authentication");
}