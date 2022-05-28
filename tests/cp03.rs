#[test]
fn solution_03() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ct = cryptopals::hex_to_bytes(input);
    let (best_score, best_key, best_cand) =
        cryptopals::guess_single_byte_key(&ct).expect("no key found");
    println!("{} {:#2x} {:?}", best_score, best_key, best_cand);
    assert_eq!(&best_cand, "Cooking MC's like a pound of bacon");
    assert_eq!(best_key, 0x58);
}
