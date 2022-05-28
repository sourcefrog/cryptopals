use bytes::Bytes;

use cryptopals::hex_to_bytes;

#[test]
fn challenge_02() {
    let b1 = hex_to_bytes("1c0111001f010100061a024b53535009181c");
    let b2 = hex_to_bytes("686974207468652062756c6c277320657965");
    let xor: Bytes = b1.iter().zip(b2.iter()).map(|(a, b)| a ^ b).collect();
    assert_eq!(&xor, &hex_to_bytes("746865206b696420646f6e277420706c6179"));
}
