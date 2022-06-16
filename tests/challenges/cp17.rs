//! The CBC padding oracle.
//!
//! <https://cryptopals.com/sets/3/challenges/17>

use cryptopals::aes::{self, encrypt_aes_cbc, random_iv, Key};
use cryptopals::base64::base64_to_bytes;
use cryptopals::hex::bytes_to_hex;
use cryptopals::pkcs7;
use cryptopals::strs::bytes_to_lossy_ascii;
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

fn select_and_encrypt(key: &aes::Key) -> (Vec<u8>, [u8; 16]) {
    let iv = random_iv();
    let mut rng = rand::thread_rng();
    let plain = base64_to_bytes(&TARGETS.choose(&mut rng).unwrap());
    let padded = pkcs7::pad(plain.as_slice(), aes::BLOCKSIZE);
    let ct = encrypt_aes_cbc(&padded, &iv, &key);
    (ct, iv)
}

/// Returns true if the padding is valid
fn check_padding(ct: &[u8], iv: &[u8], key: &aes::Key) -> bool {
    let plain = aes::decrypt_aes_cbc(ct, iv, key);
    let is_padded = pkcs7::unpad(&plain).is_some();
    if is_padded {
        println!("plaintext {} is_padded={is_padded}", bytes_to_hex(&plain));
    }
    is_padded
}

/// Recover the plaintext using a padding oracle attack.
fn padding_attack<P>(ct: &[u8], iv: &[u8], padding_oracle: P) -> Vec<u8>
where
    P: Fn(&[u8], &[u8]) -> bool,
{
    // Work on just one block of the cyphertext at a time.
    assert!(ct.len() >= 16);
    assert!(ct.len() & 0xf == 0);
    let blk = &ct[0..16];
    let mut miv = iv.to_vec();
    debug_assert_eq!(miv.len(), 16);
    let mut recovered = vec![0u8; 16];
    'i: for p in 1u8..=16 {
        // padding value to insert
        let i = 16 - (p as usize); // position to insert it
        for j in (i + 1)..=15 {
            // Update later bytes to all match a run of [p; i].
            miv[j] = recovered[j] ^ (p as u8) ^ iv[j];
        }
        for b in 0..=255u8 {
            miv[i] = b;
            if padding_oracle(blk, &miv) {
                // TODO: Taking the first value might not be right if it wraps around...
                let r = b ^ p ^ iv[i];
                println!("found valid padding for byte {i} b {r} {:?}", (r as char));
                recovered[i] = r;
                continue 'i;
            }
        }
        unreachable!("no acceptable mutation found for byte {i}");
    }
    // If there's more than one valid value then they probably correspond to padding of
    // 1, 2, etc. For now we could assume it's 1.
    // We know actual_pt ^ bm = 1
    recovered
}

#[test]
fn construct_padding_using_iv() {
    let key = Key::random();
    let plain = [0u8; 16];
    let mut iv = [0u8; 16];
    let ct = encrypt_aes_cbc(&plain, &iv, &key);
    assert!(!check_padding(&ct, &iv, &key));

    // Use an IV that will make the last byte 0x01, and therefore make it look padded.
    iv.as_mut()[15] = 0x01;
    assert!(check_padding(&ct, &iv, &key));

    // Try making the last 2 bytes 0x02.
    iv.as_mut()[15] = 0x02;
    iv.as_mut()[14] = 0x02;
    assert!(check_padding(&ct, &iv, &key));
}

#[test]
fn challenge_17() {
    let key = Key::random();
    let (ct, iv) = select_and_encrypt(&key);
    let recovered = padding_attack(&ct, &iv, |ct, iv| check_padding(ct, iv, &key));
    println!("recovered: {}", bytes_to_lossy_ascii(&recovered));
}

/// Can we extract a known plaintext from a single block?
#[test]
fn padding_attack_with_known_text() {
    let plain = b"0123456789abcdef";
    let iv = random_iv();
    let key = Key::random();
    let ct = encrypt_aes_cbc(plain.as_slice(), &iv, &key);
    let recovered = padding_attack(&ct, &iv, |ct, iv| check_padding(ct, iv, &key));
    assert_eq!(&recovered, plain);
}

#[test]
fn basic_roundtrip_is_padded() {
    for _ in 0..99 {
        let key = aes::Key::random();
        let (ct, iv) = select_and_encrypt(&key);
        assert!(check_padding(&ct, &iv, &key));
    }
}

#[test]
fn last_block_is_always_padded() {
    for _ in 0..99 {
        let key = aes::Key::random();
        let (ct, iv) = select_and_encrypt(&key);
        let o = (ct.len() - 1) & !0xff;
        assert!(check_padding(&ct[o..], &iv, &key,));
    }
}
