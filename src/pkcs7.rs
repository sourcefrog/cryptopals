//! PKCS#7 padding.

use std::iter;

/// Add padding in place in a buffer.
///
/// The result will be an even multiple of sz bytes long.
pub fn pad(b: &mut Vec<u8>, sz: usize) {
    assert!(sz < 256);
    assert!(sz > 0);
    let mut m = sz - (b.len() % sz);
    if m == 0 {
        m = sz
    }
    b.reserve(m);
    b.extend(iter::repeat(m as u8).take(m));
    debug_assert_eq!(b.len() % sz, 0)
}

/// Validate PKCS#7 padding and return a slice with it removed, if it's valid.
pub fn unpad(b: &[u8]) -> Option<&[u8]> {
    let l = b.len();
    if let Some(&pad) = b.last() {
        let pad_len = pad as usize;
        if pad_len <= l {
            let (body, padding) = b.split_at(l - pad_len);
            debug_assert_eq!(padding.len(), pad_len);
            if padding.iter().all(|c| *c == pad) {
                Some(body)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn bad_padding() {
        assert_eq!(unpad(b""), None);
        assert_eq!(unpad(&[3u8]), None);
    }

    #[test]
    fn good_padding() {
        // would be weird to pad to length 1 but it's legal
        assert_eq!(unpad(&[1]), Some(&[] as &[u8]));
        assert_eq!(unpad(&[1, 1]), Some(&[1u8] as &[u8]));
        assert_eq!(unpad(&[2, 2]), Some(&[] as &[u8]));
    }

    proptest! {
        #[test]
        fn pad_roundtrip(b: Vec<u8>, blk in 1..20usize) {
            let mut padded = b.clone();
            pad(&mut padded, blk);
            assert_eq!(padded.len() % blk, 0);
            assert!(padded.len() > b.len());
        }
    }
}
