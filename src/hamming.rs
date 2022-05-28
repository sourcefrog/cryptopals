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

/// Return the mean Hamming distance between consecutive pairs of blocks in a buffer.
pub fn mean_hamming_distance(a: &[u8], sz: usize) -> f64 {
    assert!(sz > 0);
    let distances = a
        .chunks_exact(sz)
        .zip(a.chunks_exact(sz).skip(1))
        .map(|(a, b)| hamming_distance(a, b))
        .collect::<Vec<usize>>();
    let n = distances.len();
    (distances.iter().sum::<usize>() as f64) / (sz as f64) / (n as f64)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hamming_example() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
    }
}
