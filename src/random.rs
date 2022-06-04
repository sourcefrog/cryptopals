//! Random number helpers.

use rand::prelude::*;

/// Return a vector of `n` random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    (0..n).map(|_| rng.gen()).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn random_bytes_right_size() {
        for n in [0, 1, 4, 6, 1203] {
            let r = random_bytes(n);
            assert_eq!(r.len(), n);
        }
    }
}
