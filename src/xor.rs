//! Simple xor encryption.

use bytes::Bytes;

use crate::hamming::hamming_distance;

/// Encrypt (or decrypt) text using a key that cycles indefinitely.
pub fn repeating_key_xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    text.iter()
        .zip(key.iter().cycle())
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
    dbg!(&r);
    r.iter().map(|(_d, ks)| *ks).collect()
}

/// Break repeating-key XOR of English text.
///
/// Returns the guessed key, and the (hopefully) cleartext.
pub fn break_repeating_xor(ct: &[u8]) -> (Bytes, String) {
    let keysize = guess_key_size(ct);
    todo!()
}
