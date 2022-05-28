//! My cryptopals solutions.

pub mod aes;
pub mod base64;
pub mod detect;
pub mod freqs;
pub mod hamming;
mod hex;
pub mod pkcs7;
pub mod strs;
pub mod xor;

pub use base64::{base64_to_bytes, bytes_to_base64};
pub use detect::score_english;
pub use hex::{bytes_to_hex, hex_to_bytes};
