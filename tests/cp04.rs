//! Detect single-character XOR from a set of inputs.
//!
//! <https://cryptopals.com/sets/1/challenges/4>

use std::fs;

use cryptopals::xor::{self, repeating_key_xor};

#[test]
fn solution_04() {
    let (_score, key_byte, clear) = fs::read_to_string("input/4.txt")
        .expect("open input 4")
        .lines()
        .map(|line| cryptopals::hex_to_bytes(line))
        .flat_map(|line| {
            if let Some((score, key_byte)) = xor::guess_single_byte_key(&line) {
                Some((
                    score,
                    key_byte,
                    repeating_key_xor(&line, &xor::Key::byte(key_byte)),
                ))
            } else {
                None
            }
        })
        .max()
        .expect("no solution found");
    assert_eq!(key_byte, 0x35);
    assert_eq!(clear, b"Now that the party is jumping\n");
}
