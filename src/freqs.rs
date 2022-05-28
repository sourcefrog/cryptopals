//! Byte frequency tables.

use std::fmt::{self, Display};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct FrequencyTable {
    /// The relative frequency of byte value `i`. The sum should be 1.0.
    freqs: Vec<f32>,
}

impl FrequencyTable {
    /// Calculate byte frequencies in a slice.
    ///
    /// Panics if the slice is empty.
    pub fn from_bytes(s: &[u8]) -> FrequencyTable {
        assert!(!s.is_empty());
        let mut count = vec![0usize; 256];
        for c in s {
            count[*c as usize] += 1;
        }
        let tot = s.len();
        debug_assert_eq!(count.iter().sum::<usize>(), tot);
        let freqs: Vec<f32> = count.iter().map(|c| (*c as f32) / (tot as f32)).collect();
        let sum = freqs.iter().sum::<f32>();
        debug_assert!((sum - 1.0f32).abs() < 0.0001, "sum {sum} is wrong?");
        debug_assert_eq!(freqs.len(), 256);
        FrequencyTable { freqs }
    }

    /// From a raw table of frequencies
    pub fn from_frequencies(f: &[f32]) -> FrequencyTable {
        assert_eq!(f.len(), 256);
        let sum = f.iter().sum::<f32>();
        assert!((sum - 1.0f32).abs() < 0.0001);
        FrequencyTable { freqs: f.into() }
    }

    /// Get the frequency of byte value b as a number in 0..=1.
    pub fn get(&self, b: u8) -> f32 {
        self.freqs[b as usize]
    }

    /// Get a vec of the bytes that occur, sorted from most common to least, and within that by the byte value.
    pub fn most_common(&self) -> Vec<u8> {
        let mut r: Vec<(u8, f32)> = self
            .freqs
            .iter()
            .cloned()
            .enumerate()
            .filter(|(_i, c)| *c > 0.0)
            .map(|(i, c)| (i as u8, c))
            .collect();
        r.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap().reverse().then(a.0.cmp(&b.0)));
        r.into_iter().map(|(i, _c)| i).collect()
    }

    /// Calculate the root-mean-square error between two tables, as an indication how
    /// different the populations are. 0 would indicate identity.
    pub fn rms_error(&self, other: &FrequencyTable) -> f32 {
        debug_assert_eq!(self.freqs.len(), 256);
        debug_assert_eq!(other.freqs.len(), 256);
        self.freqs
            .iter()
            .zip(other.freqs.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            / 256f32.sqrt()
    }
}

impl Display for FrequencyTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for freq in &self.freqs {
            if !first {
                f.write_str(",")?;
            } else {
                first = false;
            }
            write!(f, "{}", freq)?;
        }
        Ok(())
    }
}

impl FromStr for FrequencyTable {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let freqs: Vec<f32> = s.split(',').flat_map(|w| w.parse::<f32>()).collect();
        assert_eq!(freqs.len(), 256, "wrong length");
        Ok(FrequencyTable { freqs })
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::FrequencyTable;

    #[test]
    fn simple() {
        let freqs = FrequencyTable::from_bytes(b"hello world");
        assert_eq!(freqs.get(b'z'), 0.0);
        assert_eq!(freqs.get(b'l'), 3f32 / 11f32);
        assert_eq!(freqs.most_common(), b"lo dehrw");
    }

    proptest! {
        #[test]
        fn rms_error_self_is_0(a: Vec<u8>) {
            if !a.is_empty() {
                let f1 = FrequencyTable::from_bytes(&a);
                let f2 = FrequencyTable::from_bytes(&a);
                assert_eq!(f1.rms_error(&f2), 0.0);
            }
        }

        #[test]
        fn rms_error_duplicated_is_same(a: Vec<u8>) {
            if !a.is_empty() {
                let f1 = FrequencyTable::from_bytes(&a);
                let mut a2 = a.clone();
                a2.extend(&a);
                let f2 = FrequencyTable::from_bytes(&a2);
                assert_eq!(f1.rms_error(&f2), 0.0);
            }
        }

        #[test]
        fn rms_error_different_vecs(a: Vec<u8>, b: Vec<u8>) {
            // This could be flaky; there's no guarantee they're not permutations?
            // But maybe it's unlikely enough that proptest would generate that..
            if !a.is_empty() && !b.is_empty() && a != b {
                let f1 = FrequencyTable::from_bytes(&a);
                let f2 = FrequencyTable::from_bytes(&b);
                let err = f1.rms_error(&f2);
                assert!(err <= 1.0);
                assert!(err > 0.0);
            }
        }
    }
}
