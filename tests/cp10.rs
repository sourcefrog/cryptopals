//! AES CBC mode.
//!
//! <https://cryptopals.com/sets/2/challenges/10>

use cryptopals::aes::decrypt_aes_cbc;
use cryptopals::base64::base64_file_to_bytes;
use cryptopals::strs::bytes_to_lossy_ascii;

#[test]
fn challenge_10() {
    let input = base64_file_to_bytes("input/10.txt");
    let iv = [0u8; 16];
    let key = b"YELLOW SUBMARINE";
    let plain = decrypt_aes_cbc(&input, &iv, key);
    println!("{}", bytes_to_lossy_ascii(&plain));
    let plain = String::from_utf8(plain).expect("plaintext is not ascii");
    assert!(plain.contains("Lay down and boogie and play that funky music till you die."));
}
