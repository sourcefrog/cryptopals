//! ECB cut-and-paste.
//!
//! <https://cryptopals.com/sets/2/challenges/13>

use std::collections::BTreeMap;
use std::str::from_utf8;

use cryptopals::aes::{decrypt_aes_ecb, encrypt_aes_ecb, Key};
use cryptopals::pkcs7;

type Profile = BTreeMap<String, String>;

#[test]
fn get_admin() {
    // We can replace any block of the cyphertext if we know another cyphertext
    // block with the desired plaintext content. And, we can generate arbitrary
    // cyphertext from supplied plaintext, but with the constraint that we
    // can't get metacharacters into it. However we can probably work around that
    // by making use of block alignment: get the '=' just before the start
    // of a new block?
    //
    // So we want to concatenate cyphertexts for
    // "email=whoever&uid=10&role=" ++ "admin......"
    //
    // where both are even 16-byte blocks, and the "admin" bit is padded out
    // with eleven bytes of 11.
    //
    // There are 19 fixed bytes in the first part, so the email needs to be
    // 13 bytes to get an even 32.
    //
    // To get the "admin..." block we need to use an email that will align it to
    // the start of the second block. There's six bytes in "email=" so then
    // we need 10 more before "admin".

    let unknown_key = Key::random();
    let email_a = "0123456789abc";
    debug_assert_eq!(email_a.len(), 13);
    let ct_a = encrypted_profile(email_a, &unknown_key);
    assert_eq!(ct_a.len(), 48); // 32 desired bytes + 16 role & padding

    let admin_padded = "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    debug_assert_eq!(admin_padded.len(), 16);
    let mut email_b = "0123456789".to_string();
    email_b.push_str(admin_padded);
    let ct_b = encrypted_profile(&email_b, &unknown_key);
    debug_assert_eq!(ct_b.len(), 64);

    let mut fused_ct: Vec<u8> = ct_a[..32].to_vec(); // "email=0123456789acb&uid=10&role="
    fused_ct.extend_from_slice(&ct_b[16..32]); // admin....
    let profile = decrypt_profile(&fused_ct, &unknown_key).unwrap();
    println!("{:?}", profile);

    assert_eq!(profile["role"], "admin"); // woot!
}

pub fn parse_kv(s: &str) -> Option<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for kvstr in s.split('&') {
        let (kstr, vstr) = kvstr.split_once('=')?;
        map.insert(kstr.into(), vstr.into());
    }
    Some(map)
}

fn clean(s: &str) -> String {
    s.replace(|c| c == '&' || c == '=', "")
}

pub fn serialize_kv(kv: &BTreeMap<String, String>) -> String {
    kv.iter()
        .map(|(k, v)| format!("{}={}", clean(k), clean(v)))
        .collect::<Vec<String>>()
        .join("&")
}

pub fn profile_for(email: &str) -> String {
    format!("email={}&uid=10&role=user", clean(email))
}

pub fn encrypted_profile(email: &str, unknown_key: &Key) -> Vec<u8> {
    let plain = profile_for(email);
    let padded = pkcs7::pad(plain.as_bytes(), 16);
    encrypt_aes_ecb(&padded, unknown_key)
}

pub fn decrypt_profile(ct: &[u8], unknown_key: &Key) -> Option<Profile> {
    let padded = decrypt_aes_ecb(ct, unknown_key);
    let plain = pkcs7::unpad(&padded)?;
    let plain_str = from_utf8(plain).ok()?;
    parse_kv(plain_str)
}

#[test]
fn kv_parse_example() {
    let kv = parse_kv("foo=bar&baz=qux&zap=zazzle").expect("parse");
    assert_eq!(kv.len(), 3);
    assert_eq!(kv.get("foo").unwrap(), "bar");
    assert_eq!(kv.get("baz").unwrap(), "qux");
    assert_eq!(kv.get("zap").unwrap(), "zazzle");
    assert_eq!(serialize_kv(&kv), "baz=qux&foo=bar&zap=zazzle");
}

#[test]
fn strings_are_cleaned() {
    let mut kv = BTreeMap::new();
    kv.insert("email".into(), "foo@bar.com&role=admin".into());
    assert_eq!(serialize_kv(&kv), "email=foo@bar.comroleadmin");
}

#[test]
fn profile_example() {
    assert_eq!(
        profile_for("foo@bar.com"),
        "email=foo@bar.com&uid=10&role=user"
    );
}

#[test]
fn roundtrip_profile() {
    let unknown_key = Key::random();
    let ct = encrypted_profile("user@example.com", &unknown_key);
    let profile = decrypt_profile(&ct, &unknown_key).expect("decrypt");
    assert_eq!(profile["email"], "user@example.com");
    assert_eq!(profile["uid"], "10");
    assert_eq!(profile["role"], "user");
}
