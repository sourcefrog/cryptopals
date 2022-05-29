//! Byte-at-a-time ECB decryption (Simple).
//!
//! From <https://cryptopals.com/sets/2/challenges/12>.

use std::iter;

use cryptopals::base64_to_bytes;
use rand::Rng;

use cryptopals::aes::{encrypt_aes_cbc, encrypt_aes_ecb, random_iv, Key};
use cryptopals::detect::detect_aes_ecb;

const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";

fn encryption_oracle(plain: &[u8], unknown_key: &Key) -> Vec<u8> {
    let mut extended = plain.to_owned();
    extended.extend_from_slice(&base64_to_bytes(UNKNOWN_STRING));
    encrypt_aes_ecb(&extended, &unknown_key)
}

fn discover_block_size(unknown_key: &Key) -> usize {
    // The idea here is that we gradually increase the input size, and
    // watch for the output to increase in size. Whatever that step
    // was is one block.
    let mut last_output_size = None;
    let my_text = [b'A'; 256];
    for i in 1..256 {
        let ct = encryption_oracle(&my_text[..i], &unknown_key);
        if let Some(last) = last_output_size {
            if ct.len() != last {
                return ct.len() - last;
            }
        }
        last_output_size = Some(ct.len())
    }
    unreachable!("no ECB block size found");
}

/// Confirm that the oracle is using ECB by injecting two identical blocks at the
/// front, and seeing that they produce two identical cyphertext blocks.
fn confirm_ecb(blk: usize, unknown_key: &Key) -> bool {
    let inject: Vec<u8> = iter::repeat(b'A').take(blk * 2).collect();
    let ct = encryption_oracle(&inject, unknown_key);
    ct[..blk] == ct[blk..(2 * blk)]
}

#[test]
fn challenge_12() {
    for _ in 0..256 {
        // various random keys to prove we're not just lucky
        let unknown_key = Key::random();
        let blk = discover_block_size(&unknown_key);
        assert_eq!(blk, 16);
        assert!(confirm_ecb(blk, &unknown_key));
        // TODO: Do the rest of the padding attack
    }
}
