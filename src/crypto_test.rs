//! Simple test module to verify crypto implementations

use crate::crypto_benchmark::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ctr_cmac_basic() {
        let key = [0x2B; 16];
        let cipher = AesCtrCmac::new(key);
        let aad = b"test_aad";
        let plaintext = b"Hello World";

        let (ciphertext, mic) = cipher.encrypt(aad, plaintext, 42, 0x01020304, 0).unwrap();
        let decrypted = cipher.decrypt(aad, &ciphertext, &mic, 42, 0x01020304, 0).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_basic() {
        let key = [0x2B; 16];
        let cipher = AesGcmImpl::new(key);
        let aad = b"test_aad";
        let plaintext = b"Hello World";

        let (ciphertext, tag) = cipher.encrypt(aad, plaintext, 42, 0x01020304, 0).unwrap();
        let decrypted = cipher.decrypt(aad, &ciphertext, &tag, 42, 0x01020304, 0).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_basic() {
        let key = [0x2B; 32];
        let cipher = ChaCha20Poly1305Impl::new(key);
        let aad = b"test_aad";
        let plaintext = b"Hello World";

        let (ciphertext, tag) = cipher.encrypt(aad, plaintext, 42, 0x01020304, 0).unwrap();
        let decrypted = cipher.decrypt(aad, &ciphertext, &tag, 42, 0x01020304, 0).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}