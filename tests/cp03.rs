use bytes::Bytes;

fn decrypt(key: u8, ct: &[u8]) -> Bytes {
    ct.iter().map(|c| c ^ key).collect()
}

fn score(cand: &[u8]) -> i32 {
    if cand
        .iter()
        .any(|&b| b == 0 || b >= 127 || (b <= 31 && b != b'\n'))
    {
        return 0;
    }
    // There should be some spaces, and there should be some frequently-used letters?
    cand.iter().filter(|&&b| b == b' ').count() as i32
}

#[test]
fn solution_03() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ct = cryptopals::hex_to_bytes(input);

    let (best_score, best_key, best_cand) = (0..0xff)
        .map(|key| {
            let cand = decrypt(key, &ct);
            (score(&cand), key, cand)
        })
        .max()
        .unwrap();
    println!("{} {:#2x} {:?}", best_score, best_key, best_cand);
    assert_eq!(&best_cand, "Cooking MC's like a pound of bacon");
    assert_eq!(best_key, 0x58);
}
