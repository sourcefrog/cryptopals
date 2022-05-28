//! Convert hex to base64
//!
//! <https://cryptopals.com/sets/1/challenges/1>

// Obviously there are libraries but let's do it by hand.

use cryptopals::{bytes_to_base64, hex_to_bytes};

pub fn main() {
    let b = hex_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    println!("{}", bytes_to_base64(&b));
}
