use ark_ff::{Field, PrimeField};
use crate::{Statement, Result, Error};
use crate::poly::LinearPoly;
use crate::oracle::Oracle;
use mlpoly::MLPoly;

pub trait SumcheckProverCore<F: Field> {
    fn n_vars(&self) -> usize;
    fn round_poly_linear(&mut self, round: usize) -> LinearPoly<F>;
    fn fold_challenge(&mut self, round: usize, r_vec: &[F]) -> ();
}

pub struct SumcheckProver<F: PrimeField> {
    pub stmt: Statement<F>,
    pub round: usize,
    pub poly: MLPoly<F>,
    pub r_vec: Vec<F>,
}

impl<F: PrimeField> SumcheckProver<F> {
    pub fn new(stmt: Statement<F>, poly: MLPoly<F>) -> Self {
        Self {
            stmt,
            round: 0,
            poly: poly,
            r_vec: Vec::new(),
        }
    }

    pub fn round_poly_linear(&mut self, round: usize) -> LinearPoly<F> {
        let mut poly = self.poly.clone();
        poly = poly.fold_first_var(self.r_vec[round]);
        LinearPoly {
            c0: poly.evals[0],
            c1: poly.evals[1],
        }
    }

    pub fn fold_challenge(&mut self, round: usize, r_vec: &[F]) -> () {
        self.r_vec[round] = r_vec[round];
        self.poly = self.poly.fold_first_var(r_vec[round]);
        self.round += 1;
    }
}

pub struct VerifierState<F: PrimeField> {
    pub stmt: Statement<F>,
    pub round: usize,
    pub claim: F,
    pub r_vec: Vec<F>,
}

impl<F: PrimeField> VerifierState<F> {
    pub fn new(stmt: Statement<F>, claim: F) -> Self {
        Self {
            stmt,
            round: 0,
            claim,
            r_vec: Vec::new(),
        }
    }

    pub fn update_challenge<R: rand_core::RngCore>(&mut self, poly: &LinearPoly<F>, rng: &mut R) -> Result<F> where F: ark_ff::UniformRand {
        let g0 = poly.c0;
        let g1 = poly.c1;
        if g0+g1 != self.claim{
            return Err(Error::InvalidProof("claim mismatch"));
        }
        let r_i = F::rand(rng);
        self.claim = poly.c0 + poly.c1 * r_i;
        self.r_vec.push(r_i);
        self.round += 1;
        Ok(r_i)
    }

    pub fn finalize_with_oracle<O:Oracle<F>>(&self,oracle: &O) -> Result<bool> {
        if self.r_vec.len() != self.stmt.n_vars{
            return Err(Error::DimensionMismatch("r_vec length mismatch"));
        }
        let v = oracle.query(&self.r_vec);
        Ok(v == self.claim)
    }
}

