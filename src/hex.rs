//! Hex to binary.

// Obviously there are libraries but let's do it by hand.

use bytes::{BufMut, Bytes, BytesMut};

fn hex_digit_to_u16(c: char) -> u8 {
    match c {
        '0'..='9' => ((c as u16) - ('0' as u16)) as u8,
        'a'..='f' => ((c as u16) - ('a' as u16) + 10) as u8,
        _ => panic!("not a hex digit: {}", c),
    }
}

pub fn hex_to_bytes(s: &str) -> Bytes {
    assert!(s.len() % 2 == 0);
    let mut b = BytesMut::new();
    let mut ch = s.chars();
    while let Some(c1) = ch.next() {
        let c2 = ch.next().unwrap();
        b.put_u8((hex_digit_to_u16(c1) << 4) | hex_digit_to_u16(c2));
    }
    b.freeze()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(hex, "{:02x}", b).unwrap();
    }
    hex
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_hex() {
        let example = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = hex_to_bytes(example);
        assert_eq!(bytes_to_hex(&bytes), example);
    }
}
