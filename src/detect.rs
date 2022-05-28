//! Detect whether content seems to be English text.

use lazy_static::lazy_static;
use std::str::FromStr;

use crate::freqs::FrequencyTable;

const ENGLISH_FREQ_INPUT: &str = "0,0,0,0,0,0,0,0,0,0.000098982135,0.019374102,0,0.000072586896,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0.17406338,0.000013197618,0.0025504397,0,0,0.000009898214,0,0.0005180065,0.0014649356,0.0018311695,0.0011877856,0,0.008835806,0.0020357326,0.0069716414,0.00048501245,0.00063018623,0.0010987017,0.000725869,0.00040582675,0.00020456308,0.00020126367,0.00022765891,0.00013527558,0.00012867678,0.0002309583,0.00039592854,0.00049161125,0.00012867678,0.000112179754,0.00012867678,0,0,0.0038240098,0.00085454574,0.0035435604,0.0025306433,0.004282627,0.0018476665,0.0018575647,0.0014649356,0.004691753,0.00006598809,0.000098982135,0.005147071,0.0015177261,0.0031938236,0.003108039,0.0026527212,0.00008248511,0.0031344343,0.0038603032,0.004681855,0.0016727981,0.0007225696,0.001158091,0.00019136546,0.0020852236,0.000072586896,0.000036293448,0,0.000036293448,0,0.0005773958,0.00009238332,0.048940066,0.011617203,0.02830559,0.024927001,0.08731214,0.018179718,0.010604286,0.029612156,0.060487982,0.00053780293,0.00376792,0.022920962,0.016817065,0.05048749,0.06466173,0.015701866,0.00076216244,0.05290595,0.04388208,0.06753221,0.021429632,0.007836086,0.009205339,0.0018674629,0.01567877,0.00017486843,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0";

lazy_static! {
    static ref ENGLISH_FREQS: FrequencyTable =
        FrequencyTable::from_str(ENGLISH_FREQ_INPUT).unwrap();
}

/// Detect whether content seems to be English text.
///
/// Return value of 0 means it's definitely not English text, and
/// larger positive values indicate more confidence that it is English.
///
/// Panics if the input is empty.
pub fn score_english(cand: &[u8]) -> u32 {
    assert!(!cand.is_empty());
    if cand
        .iter()
        .any(|&b| b == 0 || b >= 127 || (b <= 31 && b != b'\n' && b != b'\t'))
    {
        return 0;
    }
    let cand_freqs = FrequencyTable::from_bytes(cand);
    let high: f32 = 100000f32;
    let p = high * (1f32 - ENGLISH_FREQS.rms_error(&cand_freqs));
    assert!(p >= 0f32);
    assert!(p <= high);
    p as u32
}

/// Detect AES ECB causing repeated blocks.
pub fn detect_aes_ecb(ct: &[u8]) -> bool {
    const BLK: usize = 16;
    let n = ct.len() / BLK;
    assert!(n > 1);
    fn chunk(ct: &[u8], i: usize) -> &[u8] {
        &ct[(i * BLK)..((i + 1) * BLK)]
    }
    for i in 0..(n - 1) {
        for j in (i + 1)..n {
            if chunk(ct, i) == chunk(ct, j) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod test {
    use crate::score_english;

    #[test]
    fn zero_score_non_ascii() {
        assert_eq!(score_english(b"\0"), 0);
        assert_eq!(score_english(b"null term\0"), 0);
        assert_eq!(score_english(b"high bits set\xee"), 0);
        assert_eq!(score_english(b"bel \x07"), 0);
    }

    #[test]
    fn detect_by_freq() {
        let s1 = score_english(b"This is really English text");
        let no_spaces = score_english(b"ThisisreallyEnglishtext");
        let s1a = score_english(b"This is really English text(*U&(*&*(&(*&*(&(*&");
        let s2 = score_english(b"zxcv,zxc/vm,zxcvz/xcmv,");
        let s3 = score_english(b"~~~~~~#######");
        assert!(s1 > s2, "real text above random letters");
        assert!(s1 > s1a, "real text better than with appended junk");
        assert!(s1 > no_spaces, "better with spaces than without");
        assert!(s2 > s3, "random letters better than punctuation");
    }
}
