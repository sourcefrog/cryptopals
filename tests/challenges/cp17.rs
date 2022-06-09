//! The CBC padding oracle.
//!
//! <https://cryptopals.com/sets/3/challenges/17>

use cryptopals::aes;
use cryptopals::pkcs7;
use rand::prelude::SliceRandom;

const TARGETS: &[&str] = &[
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

fn select_and_encrypt() -> (Vec<u8>, aes::Key, aes::Iv) {
    let key = aes::Key::random();
    let iv = aes::Iv::random();
    let mut rng = rand::thread_rng();
    let target = TARGETS.choose(&mut rng).unwrap();
    let padded = pkcs7::pad(target.as_bytes(), aes::BLOCKSIZE);
    let ct = aes::encrypt_aes_cbc(&padded, &iv, &key);
    (ct, key, iv)
}

/// Returns true if the padding is valid
fn check_padding(ct: &[u8], key: &aes::Key, iv: &aes::Iv) -> bool {
    let plain = aes::decrypt_aes_cbc(ct, iv, key);
    pkcs7::unpad(&plain).is_some()
}

#[test]
fn basic_roundtrip_is_padded() {
    for _ in 0..99 {
        let (ct, key, iv) = select_and_encrypt();
        assert!(check_padding(&ct, &key, &iv));
    }
}

#[test]
fn last_block_is_always_padded() {
    for _ in 0..99 {
        let (ct, key, iv) = select_and_encrypt();
        let o = (ct.len() - 1) & !0xff;
        assert!(check_padding(&ct[o..], &key, &iv));
    }
}
