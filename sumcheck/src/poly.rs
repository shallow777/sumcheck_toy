use ark_ff::Field;

pub trait RoundPoly<F: Field> {
    fn coeffs(&self) -> &[F];
    fn eval(&self, x: F) -> F;

}

#[derive(Clone, Debug)]
pub struct LinearPoly<F: Field> {
    pub c0: F,
    pub c1: F,
}

impl<F: Field> LinearPoly<F> {
    fn coeffs(&self) -> &[F] {
        &[self.c0, self.c1]
    }
    fn eval(&self, x: F) -> F {
        self.c0 + self.c1 * x
    }
}
