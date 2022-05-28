//! AES in ECB mode.
//!
//! <https://cryptopals.com/sets/1/challenges/7>

use std::fs::read_to_string;

use aes::cipher::generic_array::typenum::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use cryptopals::base64_to_bytes;

#[test]
fn challenge_07() {
    let ct = base64_to_bytes(&read_to_string("input/7.txt").unwrap());
    let key: GenericArray<u8, U16> = GenericArray::clone_from_slice(b"YELLOW SUBMARINE");

    let blocksz = 16;
    let cipher = Aes128::new(&key);
    let mut plain: Vec<u8> = Vec::with_capacity(ct.len());
    for block in ct.chunks(blocksz) {
        let mut b = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut b);
        plain.extend(&b);
    }
    let plain = String::from_utf8(plain).expect("plaintext is ascii");
    println!("{}", plain);
    assert!(plain.contains("Spaghetti with a spoon!"));
}
