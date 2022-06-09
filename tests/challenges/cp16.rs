//! CBC bitflipping attacks.
//!
//! <https://cryptopals.com/sets/2/challenges/16>

use cryptopals::aes::{self, decrypt_aes_cbc, encrypt_aes_cbc};
use cryptopals::pkcs7::pad;

/// Encrypt a string including quoted user-supplied data with a prefix and
/// suffix.
fn encrypt_cookie(userdata: &str, secret_key: &aes::Key, iv: &aes::Iv) -> Vec<u8> {
    let mut plain: Vec<u8> = b"comment1=cooking%20MCs;userdata=".to_vec();
    // todo!("escape userdata");
    let userdata = userdata.replace(';', "%3b").replace('=', "%3d");
    plain.extend_from_slice(userdata.as_bytes());
    plain.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon".as_slice());
    let padded = pad(&plain, aes::BLOCKSIZE);
    encrypt_aes_cbc(&padded, iv, secret_key)
}

/// Take an encrypted cookie and say whether the contents indicate that the user
/// is admin.
fn is_admin(cookie_ct: &[u8], secret_key: &aes::Key, iv: &aes::Iv) -> bool {
    if let Some(plain) = decrypt_aes_cbc(&cookie_ct, iv, secret_key) {
        let plain_str = String::from_utf8_lossy(&plain);
        plain_str.contains(";admin=true;")
    } else {
        println!("decryption failed");
        false
    }
}

#[test]
fn not_admin_by_default() {
    let key = aes::Key::random();
    let iv = aes::Iv::random();
    let ct = encrypt_cookie("mbp", &key, &iv);
    assert_eq!(is_admin(&ct, &key, &iv), false);
}

#[test]
fn direct_injection_is_blocked_by_quoting() {
    let key = aes::Key::random();
    let iv = aes::Iv::random();
    let ct = encrypt_cookie(";admin=true", &key, &iv);
    assert_eq!(is_admin(&ct, &key, &iv), false);
}
