//! Base64 to bytes.
//!
//! From <https://cryptopals.com/sets/1/challenges/1>

// Obviously there are libraries but let's do it by hand.

fn to_base64_char(b: u8) -> char {
    match b {
        0..=25 => (b'A' + b),
        26..=51 => (b'a' + b - 26),
        52..=61 => (b'0' + b - 52),
        62 => b'+',
        63 => b'/',
        _ => panic!("{} is out of range", b),
    }
    .into()
}

pub fn to_base64(s: &[u8]) -> String {
    if s.len() % 3 != 0 {
        todo!("base64 padding not implemented yet")
    }
    let mut i = 0;
    let mut r = String::new();
    // Take 3-byte chunks, convert them into 4x6byte numbers, then each of them
    // into a character.
    while i < s.len() {
        r.push(to_base64_char(s[i] >> 2));
        r.push(to_base64_char((s[i] & 0b11) << 4 | (s[i + 1] >> 4)));
        r.push(to_base64_char((s[i + 1] & 0b1111) << 2 | (s[i + 2] >> 6)));
        r.push(to_base64_char(s[i + 2] & 0b111111));
        i += 3;
    }
    r
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex_to_bytes;

    /// The given solution to <https://cryptopals.com/sets/1/challenges/1>.
    #[test]
    fn challenge_01() {
        let b = hex_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        dbg!(&b);
        // originally SDHjIGBpYGDpZGHgeHF1cCBicGBpZCBiaHBlIGBgcGFpcHFkZHFzIGD1cHJyZHFj
        assert_eq!(
            to_base64(&b),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )
    }
}
