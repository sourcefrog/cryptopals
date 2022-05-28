//! Break repeating-key XOR.
//!
//! <https://cryptopals.com/sets/1/challenges/6>

use std::fs::read_to_string;

use cryptopals::base64_to_bytes;
use cryptopals::xor::{break_repeating_xor, guess_key_size};

#[test]
fn challenge_06() {
    let ct = base64_to_bytes(&read_to_string("input/6.txt").unwrap());
    let (key, cleartext) = break_repeating_xor(&ct);
    println!("key: {}", key.to_lossy_ascii());
    println!("{}", cleartext);
    assert_eq!(key.as_slice(), b"Terminator X: Bring the noise");
    assert!(cleartext.starts_with("I'm back and I'm ringin' the bell"));

    // We can get the key size on the first attempt
    assert_eq!(guess_key_size(&ct)[0], 29);
}
