//! AES encryption.

use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;

const BLK: usize = 16;

pub fn decrypt_aes_cbc(ct: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let key: GenericArray<u8, U16> = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
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
    plain
}
