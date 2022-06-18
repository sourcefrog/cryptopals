//! The CBC padding oracle.
//!
//! <https://cryptopals.com/sets/3/challenges/17>

use eyre::{Context, Result};

use cryptopals::aes::{self, encrypt_aes_cbc, random_iv, Key, BLOCKSIZE};
use cryptopals::base64::base64_to_bytes;
use cryptopals::hex::bytes_to_hex;
use cryptopals::pkcs7::{self, unpad};

use rand::prelude::SliceRandom;

const TARGETS: &[&str] = &[
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

fn select_and_encrypt(key: &aes::Key) -> (Vec<u8>, [u8; 16]) {
    let iv = random_iv();
    let mut rng = rand::thread_rng();
    let plain = base64_to_bytes(TARGETS.choose(&mut rng).unwrap());
    let padded = pkcs7::pad(plain.as_slice(), aes::BLOCKSIZE);
    let ct = encrypt_aes_cbc(&padded, &iv, key);
    (ct, iv)
}

/// Returns true if the padding is valid
fn check_padding(ct: &[u8], iv: &[u8], key: &aes::Key) -> bool {
    let plain = aes::decrypt_aes_cbc(ct, iv, key);
    let is_padded = pkcs7::unpad(&plain).is_some();
    if is_padded {
        println!("plaintext {} is_padded={is_padded}", bytes_to_hex(&plain));
    }
    is_padded
}

/// Recover the plaintext using a padding oracle attack.
fn padding_attack<P>(ct: &[u8], iv: &[u8], padding_oracle: P) -> Vec<u8>
where
    P: Fn(&[u8], &[u8]) -> bool,
{
    let mut last_ct_blk: &[u8] = iv;
    // Work on just one block of the cyphertext at a time.
    assert!(ct.len() >= BLOCKSIZE);
    assert!(ct.len() & (BLOCKSIZE - 1) == 0);
    let mut recovered = vec![0; ct.len()];
    for (iblk, blk) in ct.chunks_exact(BLOCKSIZE).enumerate() {
        let mut miv = vec![0; BLOCKSIZE];
        'i: for p in 1u8..=16 {
            // padding value to insert
            let i = 16 - (p as usize); // position to insert it
            for j in (i + 1)..=15 {
                // Update later bytes to all match a run of [p; i].
                miv[j] = recovered[iblk * BLOCKSIZE + j] ^ (p as u8) ^ last_ct_blk[j];
            }
            for b in 0..=255u8 {
                miv[i] = b;
                if padding_oracle(blk, &miv) {
                    // TODO: Taking the first value might not be right if it is close to 0:
                    // perhaps the correct next value is near 0xff??
                    let r = b ^ p ^ last_ct_blk[i];
                    let ioverall = iblk * BLOCKSIZE + i;
                    println!(
                        "found valid padding for byte {ioverall} b {r} {:?}",
                        (r as char)
                    );
                    recovered[ioverall] = r;
                    continue 'i;
                }
            }
            unreachable!("no acceptable mutation found for byte {i} in block {iblk}");
        }
        last_ct_blk = blk;
    }
    recovered
}

#[test]
fn construct_padding_using_iv() {
    let key = Key::random();
    let plain = [0u8; 16];
    let mut iv = [0u8; 16];
    let ct = encrypt_aes_cbc(&plain, &iv, &key);
    assert!(!check_padding(&ct, &iv, &key));

    // Use an IV that will make the last byte 0x01, and therefore make it look padded.
    iv.as_mut()[15] = 0x01;
    assert!(check_padding(&ct, &iv, &key));

    // Try making the last 2 bytes 0x02.
    iv.as_mut()[15] = 0x02;
    iv.as_mut()[14] = 0x02;
    assert!(check_padding(&ct, &iv, &key));
}

#[test]
/// Recover all the strings
fn challenge_17() -> Result<()> {
    let n = TARGETS.len();
    let mut all: Vec<String> = vec![String::new(); n];
    let key = Key::random();
    let mut got = 0;
    while got < n {
        let (ct, iv) = select_and_encrypt(&key);
        let recovered = padding_attack(&ct, &iv, |ct, iv| check_padding(ct, iv, &key));
        let recovered = unpad(recovered.as_ref())
            .unwrap_or_else(|| {
                panic!(
                    "recovered bytes do not seem to be padded: {}",
                    bytes_to_hex(&recovered.as_ref())
                )
            })
            .to_owned();
        let recovered = String::from_utf8_lossy(&recovered);
        println!("recovered: {:?}", recovered);
        let (prefix, message) = recovered.split_at(6);
        let pt_index: usize = prefix
            .parse()
            .with_context(|| format!("not a decimal: {:?}", prefix))?;
        if all[pt_index].is_empty() {
            got += 1;
            all[pt_index] = message.to_owned();
        } else {
            assert_eq!(all[pt_index], message);
        }
    }
    for line in all {
        println!("{line:?}");
    }
    Ok(())
}

#[test]
fn recover_one_random_string() -> Result<()> {
    let expected: &[&str] = &[
        "000000Now that the party is jumping",
        "000001With the bass kicked in and the Vega's are pumpin'",
        "000002Quick to the point, to the point, no faking",
        "000003Cooking MC's like a pound of bacon",
        "000004Burning 'em, if you ain't quick and nimble",
        "000005I go crazy when I hear a cymbal",
        "000006nd a high hat with a souped up tempo",
        "000007I'm on a roll, it's time to go solo",
        // Strangely the last two lines do seem to be missing some letters,
        // which can be confirmed from the base64-obscured plaintext.
        "000008ollin' in my five point oh",
        "000009ith my rag-top down so my hair can blow",
    ];
    let key = Key::random();
    let (ct, iv) = select_and_encrypt(&key);
    let recovered = padding_attack(&ct, &iv, |ct, iv| check_padding(ct, iv, &key));
    let recovered = unpad(recovered.as_ref())
        .unwrap_or_else(|| {
            panic!(
                "recovered bytes do not seem to be padded: {}",
                bytes_to_hex(&recovered.as_ref())
            )
        })
        .to_owned();
    let recovered = String::from_utf8(recovered.clone()).with_context(|| {
        format!(
            "recovered text is not UTF-8: {:?}",
            bytes_to_hex(&recovered)
        )
    })?;
    println!("recovered: {:?}", recovered);
    assert!(expected.contains(&recovered.as_ref()));
    Ok(())
}

/// Can we extract a known plaintext from a single block?
#[test]
fn padding_attack_with_known_text() {
    let plain = b"0123456789abcdef";
    let iv = random_iv();
    let key = Key::random();
    let ct = encrypt_aes_cbc(plain.as_slice(), &iv, &key);
    let recovered = padding_attack(&ct, &iv, |ct, iv| check_padding(ct, iv, &key));
    assert_eq!(&recovered, plain);
}

#[test]
fn basic_roundtrip_is_padded() {
    for _ in 0..99 {
        let key = aes::Key::random();
        let (ct, iv) = select_and_encrypt(&key);
        assert!(check_padding(&ct, &iv, &key));
    }
}

#[test]
fn last_block_is_always_padded() {
    for _ in 0..99 {
        let key = aes::Key::random();
        let (ct, iv) = select_and_encrypt(&key);
        let o = (ct.len() - 1) & !0xff;
        assert!(check_padding(&ct[o..], &iv, &key,));
    }
}
