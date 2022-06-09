//! AES encryption.

use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::prelude::*;

use crate::pkcs7;

pub const BLOCKSIZE: usize = 16;

pub struct Key(GenericArray<u8, U16>);

impl Key {
    pub fn from_slice(key: &[u8]) -> Key {
        assert_eq!(key.len(), BLOCKSIZE);
        Key(GenericArray::clone_from_slice(key))
    }

    pub fn random() -> Key {
        let mut key = [0u8; BLOCKSIZE];
        thread_rng().fill(&mut key);
        Key(key.into())
    }
}

pub struct Iv([u8; 16]);

impl Iv {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn random() -> Iv {
        let mut key = [0u8; BLOCKSIZE];
        thread_rng().fill(&mut key);
        Iv(key)
    }

    pub fn from_slice(iv: &[u8]) -> Iv {
        Iv(iv.try_into().expect("wrong length"))
    }

    pub fn from_array(iv: [u8; 16]) -> Iv {
        Iv(iv)
    }
}

#[must_use]
pub fn decrypt_aes_cbc(ct: &[u8], iv: &Iv, key: &Key) -> Option<Vec<u8>> {
    let cipher = Aes128::new(&key.0);
    let mut last_block: &[u8] = iv.as_slice();
    let mut plain: Vec<u8> = Vec::with_capacity(ct.len());
    let mut buf: GenericArray<u8, U16> = GenericArray::default();
    for block in ct.chunks(BLOCKSIZE) {
        buf.copy_from_slice(block);
        cipher.decrypt_block(&mut buf);
        for i in 0..BLOCKSIZE {
            buf[i] ^= last_block[i];
        }
        plain.extend(&buf);
        last_block = block;
    }
    pkcs7::unpad(&plain).map(|s| s.to_owned())
}

#[must_use]
pub fn encrypt_aes_cbc(plain: &[u8], iv: &Iv, key: &Key) -> Vec<u8> {
    let plain = pkcs7::pad(plain, BLOCKSIZE);
    let cipher = Aes128::new(&key.0);
    let mut prev_ct: GenericArray<u8, U16> = GenericArray::clone_from_slice(iv.as_slice());
    let mut ct: Vec<u8> = Vec::with_capacity(plain.len());
    let mut buf: GenericArray<u8, U16> = GenericArray::default();
    for block in plain.chunks(BLOCKSIZE) {
        buf.copy_from_slice(block);
        for i in 0..BLOCKSIZE {
            buf[i] ^= prev_ct[i];
        }
        cipher.encrypt_block(&mut buf);
        ct.extend(&buf);
        prev_ct.clone_from(&buf);
    }
    ct
}

#[must_use]
pub fn decrypt_aes_ecb(ct: &[u8], key: &Key) -> Vec<u8> {
    assert!(ct.len() % BLOCKSIZE == 0, "plaintext is not block padded");
    let cipher = Aes128::new(&key.0);
    let mut plain: Vec<u8> = Vec::with_capacity(ct.len());
    for block in ct.chunks(BLOCKSIZE) {
        let mut b = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut b);
        plain.extend(&b);
    }
    plain
}

#[must_use]
pub fn encrypt_aes_ecb(plain: &[u8], key: &Key) -> Vec<u8> {
    assert!(
        plain.len() % BLOCKSIZE == 0,
        "plaintext is not block padded: {}",
        plain.len()
    );
    let cipher = Aes128::new(&key.0);
    let mut ct: Vec<u8> = Vec::with_capacity(plain.len());
    for block in plain.chunks(BLOCKSIZE) {
        let mut b = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut b);
        ct.extend(&b);
    }
    ct
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn roundtrip_aes_cbc(plain: Vec<u8>) {
            let key = Key::random();
            let iv = Iv::from_array([0u8; 16]);
            let ct = encrypt_aes_cbc(&plain, &iv, &key);
            let ret = decrypt_aes_cbc(&ct, &iv, &key).expect("decryption failed");
            assert_eq!(plain, ret);
        }

        #[test]
        fn roundtrip_aes_ecb(plain: Vec<u8>) {
            let key = Key::random();
            let padded = pkcs7::pad(&plain, BLOCKSIZE);
            let ct = encrypt_aes_ecb(&padded, &key);
            let ret_padded = decrypt_aes_ecb(&ct, &key);
            assert_eq!(pkcs7::unpad(&ret_padded).expect("unpad"), plain);
        }
    }
}
