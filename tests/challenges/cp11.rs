//! Padding oracle attacks and targets.
//!
//! From <https://cryptopals.com/sets/2/challenges/11>.

use proptest::prelude::*;
use rand::Rng;

use cryptopals::aes::{encrypt_aes_cbc, encrypt_aes_ecb, Iv, Key};
use cryptopals::detect::detect_aes_ecb;
use cryptopals::pkcs7;

/// Returns plaintext encrypted with a random key, and randomly choosing
/// AES-ECB or AES-CBC, and with some random bytes before and after.
fn encryption_oracle(plain: &[u8], use_ecb: bool) -> Vec<u8> {
    let mut rnd = rand::thread_rng();
    let mut extended = Vec::new();
    for _ in 0..rnd.gen_range(5..=10) {
        extended.push(rnd.gen());
    }
    extended.extend_from_slice(plain);
    for _ in 0..rnd.gen_range(5..=10) {
        extended.push(rnd.gen());
    }
    let key = Key::random();
    let padded = pkcs7::pad(&extended, 16);
    if use_ecb {
        encrypt_aes_ecb(&padded, &key)
    } else {
        let iv = Iv::random();
        encrypt_aes_cbc(&padded, &iv, &key)
    }
}

proptest! {
    /// Detect whether the encryption oracle is using ECB or CBC.
    #[test]
    fn challenge_11(use_ecb: bool) {
        let plain = [b'-'; 64];
        for _ in 0..64 {
            let ct = encryption_oracle(&plain, use_ecb);
            assert_eq!(detect_aes_ecb(&ct), use_ecb);
        }
    }
}
