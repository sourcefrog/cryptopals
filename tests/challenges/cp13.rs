//! ECB cut-and-paste.
//!
//! <https://cryptopals.com/sets/2/challenges/13>

use std::collections::BTreeMap;
use std::str::from_utf8;

use cryptopals::aes::{decrypt_aes_ecb, encrypt_aes_ecb, Key};
use cryptopals::pkcs7;

type Profile = BTreeMap<String, String>;

pub fn parse_kv(s: &str) -> Option<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for kvstr in s.split("&") {
        let (kstr, vstr) = kvstr.split_once("=")?;
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
    let mut kv = BTreeMap::new();
    kv.insert("email".into(), email.to_string());
    kv.insert("uid".into(), "10".into());
    kv.insert("role".into(), "user".into());
    serialize_kv(&kv)
}

pub fn encrypted_profile(email: &str, unknown_key: &Key) -> Vec<u8> {
    let plain = profile_for(email);
    let padded = pkcs7::pad(plain.as_bytes(), 16);
    encrypt_aes_ecb(&padded, &unknown_key)
}

pub fn decrypt_profile(ct: &[u8], unknown_key: &Key) -> Option<Profile> {
    let padded = decrypt_aes_ecb(ct, unknown_key);
    let plain = pkcs7::unpad(&padded)?;
    let plain_str = from_utf8(plain).ok()?;
    parse_kv(&plain_str)
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
        "email=foo@bar.com&role=user&uid=10"
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
