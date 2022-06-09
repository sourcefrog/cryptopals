//! CBC bitflipping attacks.
//!
//! <https://cryptopals.com/sets/2/challenges/16>

use cryptopals::aes::{self, decrypt_aes_cbc, encrypt_aes_cbc};
use cryptopals::pkcs7::pad;
use cryptopals::strs::bytes_to_lossy_ascii;

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
        println!("{}", bytes_to_lossy_ascii(&plain));
        let plain_str = String::from_utf8_lossy(&plain);
        plain_str.contains(";admin=true;")
    } else {
        println!("decryption failed");
        false
    }
}

#[test]
fn challenge_16() {
    // This is an interesting case where there's not really enough data in the
    // encrypted text to know that this attack will work; we'd be pretty much
    // guessing blind. However if we had a copy of the target's source code, or some
    // related source, or could look inside a server process, it'd be clear.
    //
    // This could also be seen as a big case where the server really wants integrity
    // of the cookies, but they're using crypto that really only guarantees
    // confidentiality...
    //
    // To actually do the attack: we want to insert a username that contains
    // something like "XadminYtrueX" and then do a bitflip on those two bytes to make
    // them ';' and '='.
    //
    // To do this we need to know the alignment. There are 32 bytes before the
    // userdata starts, so no need to align the attack. We could insert
    // one sacrifical block, and then one target block containing "XadminYtrueX"
    // preceded by 4 bytes more of padding.
    let key = aes::Key::random();
    let iv = aes::Iv::random();
    let userdata = "0123456789abcdef,,,,XadminYtrueX";
    let mut ct = encrypt_cookie(&userdata, &key, &iv);
    // Within the target block, we want to flip X to ';' at offset 4 and offset 15.
    // And the target starts at offset 32.
    ct[32 + 4] ^= b'X' ^ b';';
    ct[32 + 15] ^= b'X' ^ b';';
    ct[32 + 10] ^= b'Y' ^ b'=';
    assert!(is_admin(&ct, &key, &iv));
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
