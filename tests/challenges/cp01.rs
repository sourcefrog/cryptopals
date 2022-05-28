//! Parse hex, generate base64.
//!
//! <https://cryptopals.com/sets/1/challenges/1>

use cryptopals::{bytes_to_base64, hex_to_bytes};

/// The given solution to <https://cryptopals.com/sets/1/challenges/1>.
#[test]
fn challenge_01() {
    let b = hex_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    dbg!(&b);
    // originally SDHjIGBpYGDpZGHgeHF1cCBicGBpZCBiaHBlIGBgcGFpcHFkZHFzIGD1cHJyZHFj
    assert_eq!(
        bytes_to_base64(&b),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
}
