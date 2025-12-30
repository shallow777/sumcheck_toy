use ark_ff::Field;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLPoly<F: Field> {
    pub n_vars: usize,
    pub evals: Vec<F>,
}

impl<F: Field> MLPoly<F> {
    pub fn new(n_vars: usize) -> Self {
        Self {
            n_vars,
            evals: vec![F::ZERO; 1 << n_vars],
        }
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.evals.len()
    }
    #[inline]
    pub fn is_constant(&self) -> bool {
        self.n_vars == 0 && self.evals.len() == 1
    }
    #[inline]
    pub fn get(&self, index: usize) -> Option<&F> {
        self.evals.get(index)
    }
    pub fn sum_all(&self) -> F {
        self.evals.iter().sum()
    }
    
    pub fn fold_first_var(&self, r: F) -> Self {
        assert!(self.n_vars > 0, "n_vars must be greater than 0");
        let half = self.len() / 2;
        let mut out = Vec::with_capacity(half);
        for i in 0..half {
            out.push(self.evals[2*i]*(F::ONE - r)+self.evals[2*i+1]*r)
        }
        Self {
            n_vars: self.n_vars - 1,
            evals: out,
        }
    }
    pub fn fold_many(&self, r_vec: &[F]) -> Self {
        assert!(r_vec.len() <= self.n_vars, "too many r values: given {} r values, but n_vars is {}", r_vec.len(), self.n_vars);
        let mut cur = self.clone();
        for i in 0..r_vec.len() {
            cur = cur.fold_first_var(r_vec[i]);
        }
        cur
    }

    pub fn eval_at(&self, x: &[F]) -> F{
        assert!(x.len() == self.n_vars, "too many x values: given {} x values, but n_vars is {}", x.len(), self.n_vars);
        let cur = self.fold_many(x);
        cur.evals[0]
    }

    pub fn round_sum_g0_g1(&self) -> (F, F) {
        let mut g0 = F::ZERO;
        let mut g1 = F::ZERO;
        let half = self.len() / 2;
        for j in 0..half {
            g0+=self.evals[2*j];
            g1+=self.evals[2*j+1];
        }
        (g0, g1)
    }
}