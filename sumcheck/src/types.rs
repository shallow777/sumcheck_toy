//! Core types for the sumcheck protocol

use ark_ff::Field;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

/// Public statement for sumcheck: proves that sum of polynomial over boolean hypercube equals claim
#[derive(Clone, Debug)]
pub struct Statement<F: Field> {
    /// Number of variables in the multilinear polynomial
    pub n_vars: usize,
    /// Claimed sum: ∑_{x ∈ {0,1}^n} f(x)
    pub claim_sum: F,
}

/// A degree-1 polynomial represented by its evaluations at 0 and 1
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RoundPoly<F: Field> {
    /// [g(0), g(1)] - evaluations at 0 and 1
    pub evals: Vec<F>,
}

impl<F: Field> RoundPoly<F> {
    /// Create a new round polynomial from evaluations at 0 and 1
    pub fn new(g0: F, g1: F) -> Self {
        Self { evals: vec![g0, g1] }
    }

    /// Get g(0)
    #[inline]
    pub fn eval_0(&self) -> F {
        self.evals[0]
    }

    /// Get g(1)
    #[inline]
    pub fn eval_1(&self) -> F {
        self.evals[1]
    }

    /// Return coefficients [c0, c1] where g(x) = c0 + c1 * x
    pub fn coeffs(&self) -> (F, F) {
        let c0 = self.evals[0];
        let c1 = self.evals[1] - self.evals[0];
        (c0, c1)
    }

    /// Evaluate at point x: g(x) = g(0) + (g(1) - g(0)) * x
    pub fn eval(&self, x: F) -> F {
        self.evals[0] + (self.evals[1] - self.evals[0]) * x
    }
}

/// Sumcheck proof containing round polynomials
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumcheckProof<F: Field> {
    /// One round polynomial per variable
    pub round_polys: Vec<RoundPoly<F>>,
}

impl<F: Field> SumcheckProof<F> {
    /// Number of rounds (equals number of variables)
    pub fn num_rounds(&self) -> usize {
        self.round_polys.len()
    }
}

