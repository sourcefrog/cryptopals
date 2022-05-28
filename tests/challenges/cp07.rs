//! AES in ECB mode.
//!
//! <https://cryptopals.com/sets/1/challenges/7>

use cryptopals::aes::{self, decrypt_aes_ecb};
use cryptopals::base64::base64_file_to_bytes;

#[test]
fn challenge_07() {
    let ct = base64_file_to_bytes("input/7.txt");
    let key = aes::Key::from_slice(b"YELLOW SUBMARINE");
    let plain = decrypt_aes_ecb(&ct, &key).unwrap();
    let plain = String::from_utf8(plain).expect("plaintext is ascii");
    println!("{}", plain);
    assert!(plain.contains("Spaghetti with a spoon!"));
}
