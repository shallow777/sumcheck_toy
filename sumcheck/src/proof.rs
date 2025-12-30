use ark_ff::Field;
use crate::poly::{RoundPoly, LinearPoly};

#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    pub round_polys: Vec<LinearPoly<F>>,
}

