//! Repeating-key xor.
//!
//! <https://cryptopals.com/sets/1/challenges/5>

use cryptopals::xor;

#[test]
fn solution_05() {
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = xor::Key::new(b"ICE");
    let ct = cryptopals::xor::repeating_key_xor(input.as_bytes(), &key);
    let hex = cryptopals::bytes_to_hex(&ct);
    assert_eq!(
        &hex,
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
        a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
}
