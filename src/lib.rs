//! My cryptopals solutions.

mod base64;
mod detect;
pub mod hamming;
mod hex;
pub mod xor;

pub use base64::to_base64;
pub use detect::{guess_single_byte_key, score_english};
pub use hex::{bytes_to_hex, hex_to_bytes};
