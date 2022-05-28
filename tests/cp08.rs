//! Detect AES in ECB mode.
//!
//! <https://cryptopals.com/sets/1/challenges/8>

use std::fs::read_to_string;

use cryptopals::detect::detect_aes_ecb;
use cryptopals::hex_to_bytes;
use cryptopals::strs::bytes_to_lossy_ascii;

#[test]
fn challenge_08() {
    let input = read_to_string("input/8.txt").unwrap();
    let gotcha = input
        .lines()
        .filter(|line| {
            // If there's a repeated 16-byte block, it's a good sign of ECB encryption.
            detect_aes_ecb(&hex_to_bytes(&line))
        })
        .next()
        .expect("no AES-ECB line found");
    println!("AES-ECB in {gotcha}");
    for c in gotcha.as_bytes().chunks(32) {
        println!("{}", bytes_to_lossy_ascii(c));
    }
    assert_eq!(gotcha, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
}
