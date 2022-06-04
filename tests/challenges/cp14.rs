//! Byte-at-a-time ECB decryption (harder).
//!
//! From <https://cryptopals.com/sets/2/challenges/14>.

// Approach: with an unknown-length random prefix inserted before our
// attacker-controlled content we can still discover the deterministic
// cyphertext value of various blocks, but we have the extra difficult that we
// don't know exactly where in the output our probes are, and we don't know the
// alignment. However there are only 16 possible alignments, so it's not
// impossible.
//
// And, the fixed target plaintext at the end is constant from one attempt to
// the next, so we can use that both potentially as an anchor for locating the
// right side of the controlled value...
//
// Using a similar approach to in cp12, we want to discover one byte at a time
// of the target plaintext, starting from the left. We do this by arranging for
// one block to contain 15 known bytes (either zeros or previously discovered
// target plaintext) and one unknown byte. To do this we have to control the
// alignment so as to capture exactly one unknown byte. However, we cannot
// control the alignment on any one attempt.
//
// It seems this means we have to just keep retrying until we do get the exactly
// right alignment. This will happen with probability 1/16, which is not bad. In
// this case we happen to have a random prefix that takes evenly distributed
// lengths, and so it will eventually generate every offset, but let's not
// assume that.
//
// Our probe then looks like this:
//
// - 0..15 bytes of zeros, to vary the alignment. The goal is that this pads the
//   random prefix to a full block.
// - 17 repetitions of a random block, so that in the output we should see 16
//   repetitions. This also tells us something about the alignment: if there are
//   not exactly 16 repetitions it's probably not aligned.
// - 256 alphabet blocks, each starting with 15 bytes of a fixed prefix
//   (initially 0s) and then each distinct final byte. These should encrypt to
//   256 different cyphertext blocks.
// - A final incomplete "capture" block with the same prefix and one byte
//   missing. If we're correctly aligned, this will capture one byte of the
//   target plaintext, and match one of the probe cyphertext blocks.
//
// As in cp12 this gets tricky at the end when we approach the padding bytes,
// whose values will flip around as we attempt to recover them. We can just
// detect that they are unstable, and that's probably a good enough clue that we
// have reached the end.
//
// This works to get the first byte of the plaintext. To get the second byte, we
// need to build a dictionary of fourteen zero bytes, the first byte of the
// plaintext, and all 256 possible second bytes. Furthermore the capture block
// needs to be 14 bytes, so that the first two bytes of the target are pulled
// in. Similarly for the third and later bytes in the first target block.
//
// To get the second target block, we start with a known prefix of the last 15
// bytes of the first target block, and we need to insert 15 bytes of capture
// alignment.

use std::iter;

use rand::prelude::*;

use cryptopals::aes::{encrypt_aes_ecb, Key};
use cryptopals::pkcs7;
use cryptopals::random::random_bytes;
use cryptopals::strs::bytes_to_lossy_ascii;
use cryptopals::{base64_to_bytes, bytes_to_hex};

const UNKNOWN_STRING: &str = "
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";

const BLK: usize = 16;

/// Encrypt with the `unknown_key` the concatenation of
/// `random_prefix || attacker_controlled || UNKNOWN_STRING`.
///
/// Padding is added to the whole concatenated plaintext.
fn encryption_oracle(attacker_controlled: &[u8], unknown_key: &Key) -> Vec<u8> {
    let prefix_len: usize = thread_rng().gen_range(0..512);
    let mut concat = random_bytes(prefix_len);
    concat.extend_from_slice(attacker_controlled);
    concat.extend_from_slice(&base64_to_bytes(UNKNOWN_STRING));
    encrypt_aes_ecb(&pkcs7::pad(&concat, 16), unknown_key)
}

/// Find the block number where an aligned repeated block occurs at least n times.
fn find_repeated_block(b: &[u8], n: usize) -> Option<usize> {
    assert_eq!(b.len() % BLK, 0);
    let blocks: Vec<&[u8]> = b.chunks(16).collect();
    let bl = blocks.len();
    if n > bl {
        return None;
    }
    'i: for i in 0..=(bl - n) {
        for j in (i + 1)..(i + n) {
            if *blocks[j] != *blocks[i] {
                continue 'i;
            }
        }
        return Some(i);
    }
    None
}

fn check_alphabet(al: &[&[u8]]) {
    assert_eq!(al.len(), 256);
    #[allow(clippy::needless_range_loop)] // it's simpler
    for i in 0..255 {
        for j in (i + 1)..=255 {
            if al[i] == al[j] {
                for i in 0..=255 {
                    println!("{i:#02x} : {}", bytes_to_hex(al[i]));
                }
                panic!("al[{i:#x}] == al[{j:#x}]: {}", bytes_to_hex(al[i]));
            }
        }
    }
}

fn alphabet_lookup(alphabet: &[&[u8]], target: &[u8]) -> Option<u8> {
    alphabet
        .iter()
        .position(|a| *a == target)
        .map(|pos| pos.try_into().expect("alphabet offset out of range"))
}

/// Extract the unknown part of the plaintext by exploiting the fact that
/// ECB is deterministic per block given a fixed (but unknown) key.
///
/// Returns the recovered plaintext with no padding.
fn ecb_attack(unknown_key: &Key) -> Vec<u8> {
    // Recovered bytes of target plaintext.
    let mut recovered: Vec<u8> = Vec::new();
    // The prefix to the probe and capture blocks. Initially all zeros, and then it contains
    // up to 15 bytes of recovered plaintext
    let mut prefix = [0u8; 15];
    // The current guess of the number of bytes to add to the random prefix to make
    // a complete block, so that the rest of the probe is block-aligned.
    let mut offset = 0;
    // A random block used to detect alignment;
    let marker_block = random_bytes(BLK);
    // The number of alignment blocks; fairly arbitrary but chosen to prevent false positives.
    let n_markers = 17;
    let markers: Vec<u8> = iter::repeat(marker_block)
        .take(n_markers)
        .flatten()
        .collect();
    for attempt in 0..50000 {
        // Use a different offset every time; it doesn't matter which one but we
        // just want to try different values to hopefully eventually align,
        // without making assumptions about the prefix to the controlled text.
        offset = (offset + 1) % BLK;
        // Build a probe of offset || markers || alphabet || capture.
        let mut probe = vec![0; offset];
        probe.extend_from_slice(&markers);
        // println!("prefix:  {}", bytes_to_hex(&prefix));
        for b in 0..=255u8 {
            probe.extend_from_slice(&prefix);
            probe.push(b);
        }
        let align_target = BLK - ((recovered.len() + 1) % BLK);
        probe.resize(probe.len() + align_target, 0);
        let ct = encryption_oracle(&probe, unknown_key);
        debug_assert_eq!(ct.len() % BLK, 0);
        let ct_blocks: Vec<&[u8]> = ct.chunks(BLK).collect();
        // print_blocks(&ct);
        // There should always be at least this many repeats, even if it's not correctly aligned.
        assert!(
            find_repeated_block(&ct, n_markers - 1).is_some(),
            "didn't find alignment markers"
        );
        // Look for the run of equal marker blocks
        if let Some(marker_offset) = find_repeated_block(&ct, n_markers) {
            // println!("found markers at block {marker_offset}");
            // print_blocks(&ct);
            // Now the encrypted alphabet blocks should follow the markers.
            let alpha_start = marker_offset + n_markers;
            assert!(alpha_start + 256 < ct_blocks.len());
            let alphabet: &[&[u8]] = &ct_blocks[alpha_start..(alpha_start + 256)];
            check_alphabet(alphabet);
            // Now hopefully the next block matches one of the alphabet blocks. We're always
            // trying to match an aligned target block, but for later parts of the text we
            // need to fetch later blocks.
            let target_start = alpha_start + 256;
            let target_block = target_start + (recovered.len() + 1) / BLK;
            if let Some(target_byte) = alphabet_lookup(alphabet, ct_blocks[target_block]) {
                // println!(
                //     "recovered byte {target_byte:#02x}: {}",
                //     bytes_to_lossy_ascii(&recovered)
                // ); // Hooray!
                if target_byte == 0x01 {
                    // Somewhat hacky: if it's 0x01 that's probably the final padding. This wouldn't work
                    // if the target was binary and could contain 0x01; we'd need a better way to
                    // know we're done.
                    println!("solved after {attempt} attempts");
                    return recovered;
                }
                recovered.push(target_byte);
                // Move prefix left and append this byte.
                prefix.copy_within(1..15, 0);
                prefix[14] = target_byte;
            } else {
                println!("no match against alphabet");
                // let's just try again at a different alignment?
            }
        }
    }
    unreachable!("no solution found");
}

#[test]
fn challenge_12() {
    let unknown_key = Key::random();
    let recovered = ecb_attack(&unknown_key);
    println!("recovered: {}", bytes_to_lossy_ascii(&recovered));
    assert_eq!(&recovered, &base64_to_bytes(UNKNOWN_STRING));
}

#[test]
fn find_repeated_block_at_0() {
    let mut b = Vec::new();
    for _ in 0..3 {
        b.extend_from_slice(&[42; 16]);
    }
    assert_eq!(find_repeated_block(&b, 1), Some(0));
    assert_eq!(find_repeated_block(&b, 2), Some(0));
    assert_eq!(find_repeated_block(&b, 3), Some(0));
    assert_eq!(find_repeated_block(&b, 4), None);
}

#[test]
fn find_repeated_block_at_3() {
    let mut b = Vec::new();
    for _ in 0..3 {
        b.extend_from_slice(&random_bytes(16));
    }
    for _ in 0..3 {
        b.extend_from_slice(&[42; 16]);
    }
    for _ in 0..3 {
        b.extend_from_slice(&random_bytes(16));
    }
    assert_eq!(find_repeated_block(&b, 1), Some(0)); // The first block is one repeat of itself
    assert_eq!(find_repeated_block(&b, 2), Some(3));
    assert_eq!(find_repeated_block(&b, 3), Some(3));
    assert_eq!(find_repeated_block(&b, 4), None);
}
