//! PKCS#7 padding validation
//!
//! <https://cryptopals.com/sets/2/challenges/15>

use cryptopals::pkcs7::unpad;

#[test]
fn challenge_15() {
    assert_eq!(
        unpad(b"ICE ICE BABY\x04\x04\x04\x04"),
        Some(b"ICE ICE BABY".as_slice())
    );
    assert_eq!(unpad(b"ICE ICE BABY\x05\x05\x05\x05"), None);
    assert_eq!(unpad(b"ICE ICE BABY\x01\x02\x03\x04"), None);
}
