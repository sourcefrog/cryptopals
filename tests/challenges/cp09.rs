//! Implement PKCS#7 padding

use cryptopals::pkcs7;

#[test]
fn challenge_09() {
    let padded = pkcs7::pad(b"YELLOW SUBMARINE", 20);
    assert_eq!(&padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}
