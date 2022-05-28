//! Implement PKCS#7 padding

use cryptopals::pkcs7;

#[test]
fn challenge_09() {
    let mut buf = b"YELLOW SUBMARINE"[..].into();
    pkcs7::pad(&mut buf, 20);
    assert_eq!(&buf, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}
