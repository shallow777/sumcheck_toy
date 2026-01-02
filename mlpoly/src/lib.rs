//! Multilinear polynomial in evaluation form
//!
//! A multilinear polynomial over n variables is stored as its evaluations
//! at all 2^n points of the boolean hypercube {0,1}^n.

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Multilinear polynomial in evaluation form
///
/// For a polynomial f(x_1, ..., x_n), we store evaluations:
/// `evals[i] = f(b_1, ..., b_n)` where `(b_1, ..., b_n)` is the binary representation of i.
///
/// The indexing convention is: x_1 is the least significant bit.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MLPoly<F: Field> {
    /// Number of variables
    pub n_vars: usize,
    /// Evaluations over the boolean hypercube, length = 2^n_vars
    pub evals: Vec<F>,
}

impl<F: Field> MLPoly<F> {
    /// Create a zero polynomial with n_vars variables
    pub fn zero(n_vars: usize) -> Self {
        Self {
            n_vars,
            evals: vec![F::ZERO; 1 << n_vars],
        }
    }

    /// Create from evaluations, inferring n_vars from length
    ///
    /// # Panics
    /// Panics if evals.len() is not a power of 2
    pub fn from_evals(evals: Vec<F>) -> Self {
        let len = evals.len();
        assert!(len.is_power_of_two(), "evals length must be a power of 2");
        let n_vars = len.trailing_zeros() as usize;
        Self { n_vars, evals }
    }

    /// Number of evaluations (= 2^n_vars)
    #[inline]
    pub fn len(&self) -> usize {
        self.evals.len()
    }

    /// Returns true if the polynomial has no evaluations
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.evals.is_empty()
    }

    /// Returns true if this is a constant polynomial (n_vars = 0)
    #[inline]
    pub fn is_constant(&self) -> bool {
        self.n_vars == 0
    }

    /// Get evaluation at index i
    #[inline]
    pub fn get(&self, index: usize) -> Option<&F> {
        self.evals.get(index)
    }

    /// Sum of all evaluations: ∑_{x ∈ {0,1}^n} f(x)
    pub fn sum_all(&self) -> F {
        self.evals.iter().sum()
    }

    /// Fold the first variable at point r
    ///
    /// Returns a new polynomial f'(x_2, ..., x_n) = f(r, x_2, ..., x_n)
    /// where f(r, ...) is computed via linear interpolation.
    pub fn fold_first_var(&self, r: F) -> Self {
        assert!(self.n_vars > 0, "cannot fold a constant polynomial");
        let half = self.len() / 2;
        let one_minus_r = F::ONE - r;

        let evals: Vec<F> = (0..half)
            .map(|i| self.evals[2 * i] * one_minus_r + self.evals[2 * i + 1] * r)
            .collect();

        Self {
            n_vars: self.n_vars - 1,
            evals,
        }
    }

    /// Fold multiple variables sequentially
    ///
    /// `fold_many(&[r_1, r_2, ..., r_k])` returns f(r_1, r_2, ..., r_k, x_{k+1}, ..., x_n)
    pub fn fold_many(&self, r_vec: &[F]) -> Self {
        assert!(
            r_vec.len() <= self.n_vars,
            "too many r values: given {}, but n_vars is {}",
            r_vec.len(),
            self.n_vars
        );
        let mut cur = self.clone();
        for &r in r_vec {
            cur = cur.fold_first_var(r);
        }
        cur
    }

    /// Evaluate at a point x ∈ F^n
    pub fn eval_at(&self, x: &[F]) -> F {
        assert_eq!(
            x.len(),
            self.n_vars,
            "wrong number of evaluation points: given {}, expected {}",
            x.len(),
            self.n_vars
        );
        self.fold_many(x).evals[0]
    }

    /// Compute g(0) and g(1) for the round polynomial in sumcheck
    ///
    /// Returns (g(0), g(1)) where:
    /// - g(0) = ∑_{x_2,...,x_n} f(0, x_2, ..., x_n)
    /// - g(1) = ∑_{x_2,...,x_n} f(1, x_2, ..., x_n)
    pub fn round_sum_g0_g1(&self) -> (F, F) {
        let half = self.len() / 2;
        let mut g0 = F::ZERO;
        let mut g1 = F::ZERO;
        for j in 0..half {
            g0 += self.evals[2 * j];
            g1 += self.evals[2 * j + 1];
        }
        (g0, g1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::UniformRand;

    #[test]
    fn test_from_evals() {
        let evals = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let poly = MLPoly::from_evals(evals.clone());
        assert_eq!(poly.n_vars, 2);
        assert_eq!(poly.evals, evals);
    }

    #[test]
    #[should_panic]
    fn test_from_evals_invalid_length() {
        let evals = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        MLPoly::from_evals(evals);
    }

    #[test]
    fn test_sum_all() {
        let evals = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let poly = MLPoly::from_evals(evals);
        assert_eq!(poly.sum_all(), Fr::from(10u64));
    }

    #[test]
    fn test_fold_first_var() {
        // f(x_1, x_2) with evals [f(0,0), f(1,0), f(0,1), f(1,1)] = [1, 2, 3, 4]
        let evals = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let poly = MLPoly::from_evals(evals);

        // Fold at x_1 = 0: should get [f(0,0), f(0,1)] = [1, 3]
        let folded = poly.fold_first_var(Fr::from(0u64));
        assert_eq!(folded.n_vars, 1);
        assert_eq!(folded.evals, vec![Fr::from(1u64), Fr::from(3u64)]);

        // Fold at x_1 = 1: should get [f(1,0), f(1,1)] = [2, 4]
        let folded = poly.fold_first_var(Fr::from(1u64));
        assert_eq!(folded.evals, vec![Fr::from(2u64), Fr::from(4u64)]);
    }

    #[test]
    fn test_eval_at() {
        // f(x_1, x_2) = 1 + x_1 + 2*x_2 + x_1*x_2
        // evals: f(0,0)=1, f(1,0)=2, f(0,1)=3, f(1,1)=5
        let evals = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(5u64)];
        let poly = MLPoly::from_evals(evals);

        // Check at boolean points
        assert_eq!(poly.eval_at(&[Fr::from(0u64), Fr::from(0u64)]), Fr::from(1u64));
        assert_eq!(poly.eval_at(&[Fr::from(1u64), Fr::from(0u64)]), Fr::from(2u64));
        assert_eq!(poly.eval_at(&[Fr::from(0u64), Fr::from(1u64)]), Fr::from(3u64));
        assert_eq!(poly.eval_at(&[Fr::from(1u64), Fr::from(1u64)]), Fr::from(5u64));
    }

    #[test]
    fn test_round_sum_consistency() {
        let mut rng = ark_std::test_rng();
        let evals: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MLPoly::from_evals(evals);

        let (g0, g1) = poly.round_sum_g0_g1();

        // g(0) + g(1) should equal sum_all
        assert_eq!(g0 + g1, poly.sum_all());
    }

    #[test]
    fn test_serialization_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        let mut rng = ark_std::test_rng();
        let evals: Vec<Fr> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MLPoly::from_evals(evals);

        let mut bytes = Vec::new();
        poly.serialize_compressed(&mut bytes).unwrap();

        let poly2: MLPoly<Fr> = MLPoly::deserialize_compressed(&bytes[..]).unwrap();
        assert_eq!(poly, poly2);
    }
}
