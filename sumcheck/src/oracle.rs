use ark_ff::Field;

pub trait Oracle<F: Field> {
    fn query(&self, x: F) -> F;
}