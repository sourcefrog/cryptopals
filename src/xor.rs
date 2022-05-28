//! Simple xor encryption.

use std::io::{self, Read};

use crate::hamming::hamming_distance;
use crate::strs::bytes_to_lossy_ascii;
use crate::{bytes_to_hex, score_english};

/// A key for xor encryption.
pub struct Key(Vec<u8>);

impl Key {
    pub fn to_lossy_ascii(&self) -> String {
        bytes_to_lossy_ascii(&self.0)
    }

    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.0)
    }

    pub fn new(key_bytes: &[u8]) -> Key {
        Key(key_bytes.to_owned())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn read_from<R: Read>(read: &mut R) -> io::Result<Key> {
        let mut key_bytes = Vec::new();
        read.read_to_end(&mut key_bytes)?;
        Ok(Key(key_bytes))
    }

    /// Construct a single-byte key
    pub fn byte(key_byte: u8) -> Key {
        Key(vec![key_byte])
    }
}

/// Encrypt (or decrypt) text using a key that cycles indefinitely.
pub fn repeating_key_xor(text: &[u8], key: &Key) -> Vec<u8> {
    text.iter()
        .zip(key.0.iter().cycle())
        .map(|(t, k)| t ^ k)
        .collect()
}

/// Guess the likely key size for a text xor'd with a repeating key.
///
/// Returns a vec of guesses, sorted from most likely.
pub fn guess_key_size(ct: &[u8]) -> Vec<usize> {
    // TODO: Maybe look across all blocks in the ct, not just the first two?
    let mut r: Vec<(f64, usize)> = (2..=40)
        .map(|ks| {
            let d = (hamming_distance(&ct[0..ks], &ct[ks..(2 * ks)]) as f64) / (ks as f64);
            (d, ks)
        })
        .collect();
    r.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    // dbg!(&r);
    r.iter().map(|(_d, ks)| *ks).collect()
}

/// Guess the single-byte key that decodes English text.
pub fn guess_single_byte_key(ct: &[u8]) -> Option<(u32, u8)> {
    let (best_score, best_key, best_cand) = (0..0xff)
        .map(|key| {
            let cand: Vec<u8> = ct.iter().map(|c| c ^ key).collect();
            (score_english(&cand), key, cand)
        })
        // .inspect(|(score, key_byte, cand)| {
        //     if cand.is_ascii() {
        //         println!("{score:7} {key_byte:#02x} {}", bytes_to_lossy_ascii(&cand))
        //     }
        // })
        .max()
        .unwrap();
    if best_score == 0 {
        None
    } else {
        println!(
            "{best_score:7} {best_key:#02x} {}",
            bytes_to_lossy_ascii(&best_cand)
        );
        Some((best_score, best_key))
    }
}

/// Guess the key of length n>1 that best decodes English text.
///
/// Returns: (key, plaintext)
pub fn guess_n_byte_key(ct: &[u8], keysize: usize) -> Option<Key> {
    // Guess the single-byte key that looks best on each rotating position.
    assert!(keysize >= 1);
    // println!("ct: {}", bytes_to_hex(&ct));
    let mut key = Vec::new();
    for i in 0..keysize {
        let cts: Vec<u8> = ct.iter().skip(i).step_by(keysize).cloned().collect();
        // println!("cts_{i}: {}", bytes_to_hex(&cts));
        let (_score, key_byte) = guess_single_byte_key(&cts)?;
        // println!("i={i} found key_byte={key_byte:#02x}");
        key.push(key_byte);
    }
    assert_eq!(key.len(), keysize);
    println!(
        "found key guess hex:{} str:{}",
        bytes_to_hex(&key),
        bytes_to_lossy_ascii(&key)
    );
    Some(Key(key))
}

/// Break repeating-key XOR of English text.
///
/// Returns the guessed key, and the (hopefully) cleartext.
pub fn break_repeating_xor(ct: &[u8]) -> (Key, String) {
    let mut keys: Vec<Key> = guess_key_size(ct)
        .into_iter()
        .take(100)
        .inspect(|keysize| println!("try key size {keysize}"))
        .flat_map(|keysize| guess_n_byte_key(ct, keysize))
        .collect();
    assert!(!keys.is_empty(), "no keys found");
    if keys.len() != 1 {
        todo!("find which key is the best fit")
    }
    let key = keys.pop().unwrap();
    let clear = repeating_key_xor(&ct, &key);
    assert!(clear.is_ascii());
    (key, String::from_utf8_lossy(&clear).to_string())
}
