use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use blake2::Blake2s256;
use digest::{Digest, FixedOutputReset};

#[derive(Clone, Debug)]
pub struct Transcript{
    h: Blake2s256,
    ctr: u64,
}

impl Transcript {
    pub fn new(domain: &'static [u8]) -> Self{
        let mut h = Blake2s256::new();
        h.update(domain);
        h.update((domain.len() as u64).to_le_bytes());
        h.update(domain);
        Self {h,ctr:0}
    }

    pub fn append_message(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.h.update(b"APPEND_MESSAGE");
        self.h.update((label.len() as u64).to_le_bytes());
        self.h.update(label);
        self.h.update((bytes.len() as u64).to_le_bytes());
        self.h.update(bytes);
    }

    pub fn append_field<F:PrimeField>(&mut self, label: &'static [u8], x: &F) {
        let mut buf = Vec::new();
        x.serialize_compressed(&mut buf).expect("serialize");
        self.append_message(label, &buf);
    }

    pub fn challenge_scalar<F:PrimeField>(&mut self, label: &'static [u8]) -> F {
        let mut fork = self.h.clone();
        fork.update(b"chal");
        fork.update((label.len() as u64).to_le_bytes());
        fork.update(label);
        fork.update((self.ctr as u64).to_le_bytes());

        let out = fork.finalize_fixed_reset();

        self.h.update(b"ratchet");
        self.h.update(out.as_slice());
        self.ctr += 1;
        F::from_le_bytes_mod_order(&out)
    }
}