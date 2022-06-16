//! PKCS#7 padding.

use std::iter;

/// Add padding in place in a buffer.
///
/// The result will be an even multiple of sz bytes long.
#[must_use]
pub fn pad(b: &[u8], sz: usize) -> Vec<u8> {
    assert!(sz < 256);
    assert!(sz > 0);
    let mut m = sz - (b.len() % sz);
    if m == 0 {
        m = sz
    }
    let mut padded = Vec::with_capacity(b.len() + m);
    padded.extend_from_slice(b);
    padded.extend(iter::repeat(m as u8).take(m));
    padded
}

/// Validate PKCS#7 padding and return a slice with it removed, if it's valid.
#[must_use]
pub fn unpad(b: &[u8]) -> Option<&[u8]> {
    let l = b.len();
    if let Some(&pad_byte) = b.last() {
        let pad_len = pad_byte as usize;
        if pad_len > 0 && pad_len <= l {
            let (body, padding) = b.split_at(l - pad_len);
            debug_assert_eq!(padding.len(), pad_len);
            if padding.iter().all(|c| *c == pad_byte) {
                Some(body)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None // empty slice
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn sixteen_zeros() {
        let plain = [0u8; 16];
        let padded = pad(&plain, 16);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[..16], plain);
        assert_eq!(&padded[16..], &[16; 16]);

        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded, plain);
    }

    #[test]
    fn bad_padding() {
        assert_eq!(unpad(b""), None);
        assert_eq!(unpad(&[3u8]), None);
        assert_eq!(unpad(&[0, 1, 2, 3u8]), None);
        assert_eq!(unpad(&[0u8; 16]), None);
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
            let padded = pad(&b, blk);
            assert_eq!(padded.len() % blk, 0);
            assert!(padded.len() > b.len());
        }
    }
}
