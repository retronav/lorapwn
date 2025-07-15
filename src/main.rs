#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(any(test, feature = "std")), no_main)]

#[cfg(not(any(test, feature = "std")))]
use panic_halt as _;

// Import the library
use lorapwn;

#[cfg(feature = "std")]
use clap::Parser;

#[cfg(feature = "std")]
use lorapwn::cli::{Args, Mode, perform_profiling_mode, perform_target_mode};

#[cfg(test)]
mod tests {
    use lorapwn::{AeadLorawanPacket, CHACHA20_TAG_SIZE};

    #[cfg(feature = "std")]
    use std::vec::Vec;

    #[test]
    fn test_chacha20_aead_encryption_decryption() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];

        let dev_addr: u32 = 0x01020304;
        let fcnt: u32 = 42;
        let dir: u8 = 0;
        let data = b"Hello LoRaWAN with ChaCha20-Poly1305!";

        let mhdr: u8 = 0x40;
        let mut mac_payload = Vec::new();
        mac_payload.extend_from_slice(&dev_addr.to_le_bytes());
        mac_payload.push(0x00);
        mac_payload.extend_from_slice(&(fcnt as u16).to_le_bytes());
        mac_payload.push(1);
        mac_payload.extend_from_slice(data);

        let mut packet = AeadLorawanPacket {
            mhdr,
            mac_payload,
            aead_tag: [0; CHACHA20_TAG_SIZE],
        };

        packet.encrypt_payload(&key, dev_addr, fcnt, dir).expect("Encryption failed");
        let bytes = packet.to_bytes();
        let parsed_packet = AeadLorawanPacket::parse(&bytes).expect("Parsing failed");
        let decrypted = parsed_packet.decrypt_payload(&key, dir).expect("Decryption failed");

        assert_eq!(decrypted, data);
    }
}

#[cfg(not(any(test, feature = "std")))]
#[cortex_m_rt::entry]
fn main() -> ! {
    loop {}
}

#[cfg(feature = "std")]
fn main() {
    let args = Args::parse();

    let result = match args.mode {
        Mode::Profiling => {
            let key = match args.key {
                Some(k) => k,
                None => {
                    eprintln!("Error: --key is required for profiling mode");
                    std::process::exit(1);
                }
            };
            let input = match args.input {
                Some(i) => i,
                None => {
                    eprintln!("Error: --input is required for profiling mode");
                    std::process::exit(1);
                }
            };
            perform_profiling_mode(&key, &input, &args.stage, args.verbose)
        }
        Mode::Target => {
            let input = match args.input {
                Some(i) => i,
                None => {
                    eprintln!("Error: --input is required for target mode");
                    std::process::exit(1);
                }
            };
            perform_target_mode(&input, &args.stage, args.verbose)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
