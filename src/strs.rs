pub fn bytes_to_lossy_ascii(s: &[u8]) -> String {
    s.iter()
        .map(|b| match b {
            0..=31 => '.',
            32..=126 => *b as char,
            127.. => '.',
        })
        .collect()
}
