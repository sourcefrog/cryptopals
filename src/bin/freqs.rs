//! Build byte frequency table of stdin.
//!
//! Prints the table as a CSV of 256 floating-point frequencies.

use std::io::{stdin, Read};

use cryptopals::freqs::FrequencyTable;

pub fn main() {
    let mut input = Vec::new();
    stdin().read_to_end(&mut input).unwrap();
    let freqs = FrequencyTable::from_bytes(&input);
    println!("{freqs}");
}
