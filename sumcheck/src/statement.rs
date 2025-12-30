use ark_ff::Field;

#[derive(Clone, Debug)]
pub struct Statement<F: Field> {
    pub n_vars: usize,
    pub claim_sum: F,
}

