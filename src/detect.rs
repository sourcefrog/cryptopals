//! Detect whether content seems to be English text.

/// Detect whether content seems to be English text.
///
/// Return value of 0 means it's definitely not English text, and
/// larger positive values indicate more confidence that it is English.
pub fn score_english(cand: &[u8]) -> i32 {
    if cand
        .iter()
        .any(|&b| b == 0 || b >= 127 || (b <= 31 && b != b'\n'))
    {
        return 0;
    }
    // There should be some spaces, and there should be some frequently-used letters?
    cand.iter().filter(|&&b| b == b' ').count() as i32
}

/// Guess the single-byte key that decodes English text.
pub fn guess_single_byte_key(ct: &[u8]) -> Option<(i32, u8, String)> {
    let (best_score, best_key, best_cand) = (0..0xff)
        .map(|key| {
            let cand: Vec<u8> = ct.iter().map(|c| c ^ key).collect();
            (score_english(&cand), key, cand)
        })
        .max()
        .unwrap();
    if best_score == 0 {
        None
    } else {
        Some((best_score, best_key, String::from_utf8(best_cand).unwrap()))
    }
}
