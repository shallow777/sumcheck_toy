//! Non-interactive sumcheck protocol using Fiat-Shamir transform

use ark_ff::PrimeField;
use mlpoly::MLPoly;

use crate::error::{Error, Result};
use crate::oracle::Oracle;
use crate::transcript::Transcript;
use crate::types::{RoundPoly, Statement, SumcheckProof};

/// Generate a sumcheck proof
/// 
/// # Arguments
/// * `stmt` - Public statement containing n_vars and claimed sum
/// * `poly` - The multilinear polynomial to prove
/// * `transcript` - Fiat-Shamir transcript for challenge generation
/// 
/// # Returns
/// A `SumcheckProof` containing one round polynomial per variable
pub fn prove<F: PrimeField>(
    stmt: &Statement<F>,
    poly: &MLPoly<F>,
    transcript: &mut Transcript,
) -> SumcheckProof<F> {
    let mut current_poly = poly.clone();
    let mut round_polys = Vec::with_capacity(stmt.n_vars);

    for _ in 0..stmt.n_vars {
        // 1. Compute round polynomial g_i(X) where g_i(0) + g_i(1) = current claim
        let (g0, g1) = current_poly.round_sum_g0_g1();
        let round_poly = RoundPoly::new(g0, g1);

        // 2. Commit to round polynomial via transcript
        transcript.append_field(b"g0", &g0);
        transcript.append_field(b"g1", &g1);
        round_polys.push(round_poly);

        // 3. Get challenge from transcript (Fiat-Shamir)
        let r: F = transcript.challenge_scalar(b"r");

        // 4. Fold polynomial: f'(x_2, ..., x_n) = f(r, x_2, ..., x_n)
        current_poly = current_poly.fold_first_var(r);
    }

    SumcheckProof { round_polys }
}

/// Verify a sumcheck proof
/// 
/// # Arguments
/// * `stmt` - Public statement containing n_vars and claimed sum
/// * `proof` - The sumcheck proof to verify
/// * `oracle` - Oracle for querying the final polynomial evaluation
/// * `transcript` - Fiat-Shamir transcript (must use same domain as prover)
/// 
/// # Returns
/// * `Ok(true)` if the proof is valid
/// * `Ok(false)` if the final oracle check fails
/// * `Err(_)` if a round check fails
pub fn verify<F: PrimeField, O: Oracle<F>>(
    stmt: &Statement<F>,
    proof: &SumcheckProof<F>,
    oracle: &O,
    transcript: &mut Transcript,
) -> Result<bool> {
    // Check proof has correct number of rounds
    if proof.num_rounds() != stmt.n_vars {
        return Err(Error::DimensionMismatch("wrong number of round polynomials"));
    }

    let mut claim = stmt.claim_sum;
    let mut r_vec = Vec::with_capacity(stmt.n_vars);

    for round_poly in &proof.round_polys {
        let g0 = round_poly.eval_0();
        let g1 = round_poly.eval_1();

        // Check: g(0) + g(1) == current claim
        if g0 + g1 != claim {
            return Err(Error::InvalidProof("sum check failed"));
        }

        // Replay transcript (must match prover)
        transcript.append_field(b"g0", &g0);
        transcript.append_field(b"g1", &g1);

        // Derive same challenge as prover (Fiat-Shamir)
        let r: F = transcript.challenge_scalar(b"r");
        r_vec.push(r);

        // Update claim: claim = g(r)
        claim = round_poly.eval(r);
    }

    // Final check: oracle(r_1, ..., r_n) == final claim
    let oracle_eval = oracle.query(&r_vec);
    Ok(oracle_eval == claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::PolyOracle;
    use ark_bn254::Fr;
    use ark_std::UniformRand;

    #[test]
    fn test_sumcheck_honest_prover() {
        let mut rng = ark_std::test_rng();
        let n_vars = 4;

        // Create random polynomial
        let evals: Vec<Fr> = (0..(1 << n_vars)).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MLPoly { n_vars, evals };

        // Compute true sum
        let claim_sum = poly.sum_all();
        let stmt = Statement { n_vars, claim_sum };

        // Prove
        let mut prover_transcript = Transcript::new(b"sumcheck-test");
        let proof = prove(&stmt, &poly, &mut prover_transcript);

        // Verify
        let oracle = PolyOracle::new(poly);
        let mut verifier_transcript = Transcript::new(b"sumcheck-test");
        let result = verify(&stmt, &proof, &oracle, &mut verifier_transcript);

        assert!(result.unwrap(), "honest proof should verify");
    }

    #[test]
    fn test_sumcheck_wrong_claim_fails() {
        let mut rng = ark_std::test_rng();
        let n_vars = 3;

        let evals: Vec<Fr> = (0..(1 << n_vars)).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MLPoly { n_vars, evals };

        // Wrong claim
        let wrong_claim = poly.sum_all() + Fr::from(1u64);
        let stmt = Statement { n_vars, claim_sum: wrong_claim };

        let mut prover_transcript = Transcript::new(b"sumcheck-test");
        let proof = prove(&stmt, &poly, &mut prover_transcript);

        let oracle = PolyOracle::new(poly);
        let mut verifier_transcript = Transcript::new(b"sumcheck-test");
        let result = verify(&stmt, &proof, &oracle, &mut verifier_transcript);

        assert!(result.is_err(), "wrong claim should fail verification");
    }

    #[test]
    fn test_proof_serialization_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        let mut rng = ark_std::test_rng();
        let n_vars = 3;

        let evals: Vec<Fr> = (0..(1 << n_vars)).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MLPoly { n_vars, evals };
        let claim_sum = poly.sum_all();
        let stmt = Statement { n_vars, claim_sum };

        // Generate proof
        let mut transcript = Transcript::new(b"sumcheck-test");
        let proof = prove(&stmt, &poly, &mut transcript);

        // Serialize
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).expect("serialize");

        // Deserialize
        let proof2: SumcheckProof<Fr> =
            SumcheckProof::deserialize_compressed(&bytes[..]).expect("deserialize");

        // Verify deserialized proof works
        let oracle = PolyOracle::new(poly);
        let mut transcript = Transcript::new(b"sumcheck-test");
        let result = verify(&stmt, &proof2, &oracle, &mut transcript);

        assert!(result.unwrap(), "deserialized proof should verify");

        // Check proof size
        println!("Proof size for {} vars: {} bytes", n_vars, bytes.len());
    }

    #[test]
    fn test_single_variable() {
        let mut rng = ark_std::test_rng();
        let n_vars = 1;

        let evals: Vec<Fr> = (0..(1 << n_vars)).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MLPoly { n_vars, evals };
        let claim_sum = poly.sum_all();
        let stmt = Statement { n_vars, claim_sum };

        let mut prover_transcript = Transcript::new(b"sumcheck-test");
        let proof = prove(&stmt, &poly, &mut prover_transcript);

        let oracle = PolyOracle::new(poly);
        let mut verifier_transcript = Transcript::new(b"sumcheck-test");
        let result = verify(&stmt, &proof, &oracle, &mut verifier_transcript);

        assert!(result.unwrap());
    }
}

