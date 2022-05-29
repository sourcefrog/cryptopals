//! Byte-at-a-time ECB decryption (Simple).
//!
//! From <https://cryptopals.com/sets/2/challenges/12>.

use std::iter;

use cryptopals::base64_to_bytes;
use cryptopals::strs::bytes_to_lossy_ascii;

use cryptopals::aes::{encrypt_aes_ecb, Key};
use cryptopals::pkcs7;

const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";

fn encryption_oracle(plain: &[u8], unknown_key: &Key) -> Vec<u8> {
    let mut extended = plain.to_owned();
    extended.extend_from_slice(&base64_to_bytes(UNKNOWN_STRING));
    encrypt_aes_ecb(&pkcs7::pad(&extended, 16), unknown_key)
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

/// Extract the unknown part of the plaintext by exploiting the fact that
/// ECB is deterministic per block given a fixed (but unknown) key.
fn ecb_attack(sz: usize, unknown_key: &Key) -> Vec<u8> {
    let mut recovered = Vec::new();
    let unknown_len = encryption_oracle(&[], unknown_key).len();
    // The guess is always one block long, and the last byte of it is meant
    // to match the next byte of the unknown text that we're trying to recover.
    // The earlier part of it includes up to (sz-1) of recovered data, and
    // before that some zeros as necessary to make up the size.
    let mut guess = vec![0u8; sz];
    dbg!(UNKNOWN_STRING.len());
    dbg!(&unknown_len);
    for i in 0..unknown_len {
        debug_assert_eq!(recovered.len(), i);
        let grb = std::cmp::min(recovered.len(), sz - 1);
        guess[(sz - grb - 1)..(sz - 1)].copy_from_slice(&recovered[(recovered.len() - grb)..]);
        // println!("guess: {}", bytes_to_hex(&guess));
        // Make a dictionary of some guesses at the first block, where only the
        // last byte varies.
        let mut dict: Vec<Vec<u8>> = Vec::new();
        for x in 0u8..=255 {
            guess[sz - 1] = x;
            let ct = encryption_oracle(&guess, unknown_key);
            dict.push(ct[..sz].to_owned());
        }
        // Now insert a known prefix that's less than the block size.
        let preflen = sz - 1 - i % sz;
        debug_assert!(preflen <= (sz - 1));
        let ct = encryption_oracle(&guess[..preflen], unknown_key);
        // To recover bytes after the first block (i>sz), we can't pull them into the first
        // block; their encrypted form will be in a later still-aligned block?
        let xb = (i / sz) * sz;
        let ctx = &ct[(xb)..(xb + sz)];
        if let Some(idx) = dict
            .iter()
            .position(|b| b == ctx)
            .map(|x| x.try_into().expect("dict index out of range"))
        {
            println!(
                "{i:3}: discovered plaintext byte {idx:#02x} {:?} ct_len={}",
                (idx as char),
                ct.len(),
            );
            recovered.push(idx);
        } else {
            // As we approach the end, changing the prefix will change the contents of the
            // padding bytes, and so we don't find any matches in the dictionary. That indicates
            // we're at the end? If we're not near the end apparently something went wrong.
            debug_assert!(i < ct.len());
            if ct.len() - i <= sz {
                break;
            } else {
                panic!("block not found");
            }
        }
    }
    pkcs7::unpad(&recovered).expect("unpad").to_owned()
}

#[test]
fn challenge_12() {
    let unknown_key = Key::random();
    let sz = discover_block_size(&unknown_key);
    assert_eq!(sz, 16);
    assert!(confirm_ecb(sz, &unknown_key));
    let recovered = ecb_attack(sz, &unknown_key);
    println!("recovered: {}", bytes_to_lossy_ascii(&recovered));
    assert_eq!(&recovered, &base64_to_bytes(UNKNOWN_STRING));
}
