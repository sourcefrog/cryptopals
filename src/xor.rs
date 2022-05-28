//! Simple xor encryption.

/// Encrypt (or decrypt) text using a key that cycles indefinitely.
pub fn repeating_key_xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    text.iter()
        .zip(key.iter().cycle())
        .map(|(t, k)| t ^ k)
        .collect()
}
