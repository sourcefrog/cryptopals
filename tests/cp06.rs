//! Break repeating-key XOR.
//!
//! <https://cryptopals.com/sets/1/challenges/6>

use std::fs::read_to_string;

use cryptopals::base64_to_bytes;
// use cryptopals::xor::break_repeating_xor;

// #[test]
// fn challenge_06() {
//     let hex_input = read_to_string("input/6.txt").unwrap();
//     let ct = base64_to_bytes(&hex_input);
//     let (key, cleartext) = break_repeating_xor(&ct);
// }
