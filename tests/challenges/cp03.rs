use cryptopals::xor::{self, repeating_key_xor};

#[test]
fn challenge_03() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ct = cryptopals::hex_to_bytes(input);
    let (_score, key_byte) = cryptopals::xor::guess_single_byte_key(&ct).expect("no key found");
    let clear = repeating_key_xor(&ct, &xor::Key::byte(key_byte));
    assert_eq!(&clear, b"Cooking MC's like a pound of bacon");
    assert_eq!(key_byte, 0x58);
}
