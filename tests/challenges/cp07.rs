//! AES in ECB mode.
//!
//! <https://cryptopals.com/sets/1/challenges/7>

use cryptopals::aes::{self, decrypt_aes_ecb};
use cryptopals::base64::base64_file_to_bytes;
use cryptopals::pkcs7;

#[test]
fn challenge_07() {
    let ct = base64_file_to_bytes("input/7.txt");
    let key = aes::Key::from_slice(b"YELLOW SUBMARINE");
    let plain = pkcs7::unpad(&decrypt_aes_ecb(&ct, &key))
        .unwrap()
        .to_owned();
    let plain = String::from_utf8(plain).expect("plaintext is ascii");
    println!("{}", plain);
    assert!(plain.contains("Spaghetti with a spoon!"));
}
