//! Hamming distance.

/// Return the Hamming distance between two byte strings: the number of differing bits.
///
/// The strings must be the same length.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len(), "strings must be the same length");
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| (a ^ b).count_ones() as usize)
        .sum()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hamming_example() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
    }
}
