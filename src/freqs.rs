//! Byte frequency tables.

use std::fmt::{self, Display};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct FrequencyTable {
    /// The relative frequency of byte value `i`. The sum should be 1.0
    freqs: Vec<f32>,
}

impl FrequencyTable {
    pub fn from_text(s: &[u8]) -> FrequencyTable {
        let mut count = vec![0usize; 256];
        for c in s {
            count[*c as usize] += 1;
        }
        let tot = s.len();
        debug_assert_eq!(count.iter().sum::<usize>(), tot);
        let freqs: Vec<f32> = count.iter().map(|c| (*c as f32) / (tot as f32)).collect();
        debug_assert!((freqs.iter().sum::<f32>() - 1.0f32).abs() < 0.000001);
        FrequencyTable { freqs }
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
    use super::FrequencyTable;

    #[test]
    fn simple() {
        let freqs = FrequencyTable::from_text(b"hello world");
        assert_eq!(freqs.get(b'z'), 0.0);
        assert_eq!(freqs.get(b'l'), 3f32 / 11f32);
        assert_eq!(freqs.most_common(), b"lo dehrw");
    }
}
