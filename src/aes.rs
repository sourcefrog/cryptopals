//! AES encryption.

use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::prelude::*;

use crate::pkcs7;

const BLK: usize = 16;

pub struct Key(GenericArray<u8, U16>);

impl Key {
    pub fn from_slice(key: &[u8]) -> Key {
        assert_eq!(key.len(), BLK);
        Key(GenericArray::clone_from_slice(key))
    }

    pub fn random() -> Key {
        let mut key = [0u8; BLK];
        thread_rng().fill(&mut key);
        Key(key.into())
    }
}

pub fn decrypt_aes_cbc(ct: &[u8], iv: &[u8], key: &Key) -> Option<Vec<u8>> {
    let cipher = Aes128::new(&key.0);
    let mut last_block: &[u8] = iv;
    let mut plain: Vec<u8> = Vec::with_capacity(ct.len());
    let mut buf: GenericArray<u8, U16> = GenericArray::default();
    for block in ct.chunks(BLK) {
        buf.copy_from_slice(block);
        cipher.decrypt_block(&mut buf);
        for i in 0..BLK {
            buf[i] ^= last_block[i];
        }
        plain.extend(&buf);
        last_block = block;
    }
    pkcs7::unpad(&plain).map(|s| s.to_owned())
}

pub fn encrypt_aes_cbc(plain: &[u8], iv: &[u8], key: &Key) -> Vec<u8> {
    let mut plain = plain.to_owned();
    pkcs7::pad(&mut plain, BLK);
    let cipher = Aes128::new(&key.0);
    let mut prev_ct: GenericArray<u8, U16> = GenericArray::clone_from_slice(iv);
    let mut ct: Vec<u8> = Vec::with_capacity(plain.len());
    let mut buf: GenericArray<u8, U16> = GenericArray::default();
    for block in plain.chunks(BLK) {
        buf.copy_from_slice(block);
        for i in 0..BLK {
            buf[i] ^= prev_ct[i];
        }
        cipher.encrypt_block(&mut buf);
        ct.extend(&buf);
        prev_ct.clone_from(&buf);
    }
    ct
}

pub fn decrypt_aes_ecb(ct: &[u8], key: &Key) -> Vec<u8> {
    let cipher = Aes128::new(&key.0);
    let mut plain: Vec<u8> = Vec::with_capacity(ct.len());
    for block in ct.chunks(BLK) {
        let mut b = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut b);
        plain.extend(&b);
    }
    plain
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn roundtrip(plain: Vec<u8>) {
            let key = Key::random();
            let iv = [0u8; 16];
            let ct = encrypt_aes_cbc(&plain, &iv, &key);
            let ret = decrypt_aes_cbc(&ct, &iv, &key).expect("decryption failed");
            assert_eq!(plain, ret);
        }
    }
}
