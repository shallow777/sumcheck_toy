//! Oracle trait for polynomial evaluation queries

use ark_ff::PrimeField;
use mlpoly::MLPoly;

/// Oracle that answers point queries on the polynomial
pub trait Oracle<F: PrimeField> {
    /// Evaluate the polynomial at point x
    fn query(&self, x: &[F]) -> F;
}

/// Concrete oracle wrapping a multilinear polynomial
/// 
/// Used for testing or when the verifier has direct access to the polynomial
pub struct PolyOracle<F: PrimeField> {
    pub poly: MLPoly<F>,
}

impl<F: PrimeField> PolyOracle<F> {
    pub fn new(poly: MLPoly<F>) -> Self {
        Self { poly }
    }
}

impl<F: PrimeField> Oracle<F> for PolyOracle<F> {
    fn query(&self, x: &[F]) -> F {
        self.poly.eval_at(x)
    }
}
