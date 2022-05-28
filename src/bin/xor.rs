//! XOR stdin's content with another file.
//!
//! When encrypting, the output will typically not be printable.

use std::fs::File;
use std::io::{stdin, stdout, Read, Write};

use cryptopals::xor;

pub fn main() {
    let mut argv = std::env::args();
    if argv.len() != 2 {
        eprintln!("usage: xor KEYFILE");
        std::process::exit(1);
    }
    let key_filename = argv.nth(1).unwrap();
    let mut key_bytes = Vec::new();
    File::open(key_filename)
        .unwrap()
        .read_to_end(&mut key_bytes)
        .unwrap();
    let key = xor::Key::new(&key_bytes);
    let mut input = Vec::new();
    let len = stdin().read_to_end(&mut input).unwrap();
    assert_eq!(len, input.len());
    let output = cryptopals::xor::repeating_key_xor(&input, &key);
    stdout().write_all(&output).unwrap();
}
