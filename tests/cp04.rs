//! Detect single-character XOR from a set of inputs.
//!
//! <https://cryptopals.com/sets/1/challenges/4>

use std::fs;

#[test]
fn solution_04() {
    let (score, key, output) = fs::read_to_string("input/4.txt")
        .expect("open input 4")
        .lines()
        .map(|line| cryptopals::hex_to_bytes(line))
        .flat_map(|line| cryptopals::guess_single_byte_key(&line))
        .inspect(|(score, key, output)| println!("{:4}  {:#2x} {:?}", score, key, output))
        .max_by_key(|&(score, _, _)| score)
        .expect("no solution found");
    println!("{:4}  {:#2x} {:?}", score, key, output);
    assert_eq!(output, "Now that the party is jumping\n");
    assert_eq!(key, 0x35);
}
