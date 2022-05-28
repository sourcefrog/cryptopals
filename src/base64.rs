//! Base64 to bytes.
//!
//! From <https://cryptopals.com/sets/1/challenges/1>

// Obviously there are libraries but let's do it by hand.

const PAD: char = '=';

pub fn bytes_to_base64(s: &[u8]) -> String {
    let mut i = 0;
    let mut r = String::new();
    // Take 3-byte chunks, convert them into 4x6byte numbers, then each of them
    // into a character.
    let l = s.len();
    while i < l {
        r.push(to_base64_char(s[i] >> 2));
        if i + 1 >= l {
            r.push(to_base64_char((s[i] & 0b11) << 4));
            r.push(PAD);
            r.push(PAD);
            break;
        } else {
            r.push(to_base64_char((s[i] & 0b11) << 4 | (s[i + 1] >> 4)));
        }
        if i + 2 >= l {
            r.push(to_base64_char((s[i + 1] & 0b1111) << 2));
            r.push(PAD);
            break;
        } else {
            r.push(to_base64_char((s[i + 1] & 0b1111) << 2 | (s[i + 2] >> 6)));
            r.push(to_base64_char(s[i + 2] & 0b111111));
        }
        i += 3;
    }
    r
}

/// Decode base64 to bytes; ignore whitespace.
pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    // Take groups of four characters (ignoring whitespace); convert them into bits;
    // then break the bits into bytes...
    let bc: Vec<u8> = base64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .inspect(|c| assert!(c.is_ascii()))
        .map(|c| c as u8)
        .collect();
    let mut r = Vec::new();
    let mut padding = 0;
    for chunk in bc.chunks(4) {
        let mut a = 0u32;
        for &c in chunk {
            a <<= 6;
            if c == b'=' {
                padding += 1;
            } else {
                assert!(padding == 0, "other characters {c:?} following padding");
                a |= from_base64_char(c);
            }
        }
        // Now read 1 to 3 bytes (depending on padding) out of a.
        assert!(padding <= 2, "too much padding: {padding}");
        let mut i = 2;
        loop {
            r.push(((a >> (8 * i)) & 0xff) as u8);
            if i == padding {
                break;
            } else {
                i -= 1
            }
        }
        debug_assert!(a <= 0xffffff);
    }
    r
}

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

fn from_base64_char(c: u8) -> u32 {
    let r = match c {
        b'A'..=b'Z' => (c - b'A'),
        b'a'..=b'z' => (c - b'a' + 26),
        b'0'..=b'9' => (c - b'0' + 52),
        b'+' => 62,
        b'/' => 63,
        _ => panic!("{c:?} is not a base64 character"),
    };
    debug_assert!(r <= 63);
    r as u32
}

#[cfg(test)]
mod test {
    use std::fs::read_to_string;

    use proptest::prelude::*;

    use super::*;

    fn roundtrip(a: &[u8]) {
        let base64 = bytes_to_base64(&a);
        dbg!(&base64);
        assert_eq!(base64_to_bytes(&base64), a);
    }

    #[test]
    fn simple() {
        roundtrip(b"");
        roundtrip(&[1]);
        roundtrip(&[1, 2]);
        roundtrip(&[1, 2, 3]);
        roundtrip(b"hello");
    }

    proptest! {
        #[test]
        fn prop_roundtrip(a: Vec<u8>) {
            dbg!(&a);
            let base64 = bytes_to_base64(&a);
            dbg!(&base64);
            let b = base64_to_bytes(&base64);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn round_trip_input_6() {
        let input = read_to_string("input/6.txt").unwrap();
        let bytes = base64_to_bytes(&input);
        let no_ws: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        assert_eq!(bytes_to_base64(&bytes), no_ws);
    }
}
