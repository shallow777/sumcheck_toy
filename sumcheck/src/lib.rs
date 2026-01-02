//! Sumcheck protocol implementation
//!
//! This crate provides a non-interactive sumcheck protocol using Fiat-Shamir transform.
//!
//! # Example
//!
//! ```ignore
//! use sumcheck::{prove, verify, Statement, PolyOracle, Transcript};
//! use mlpoly::MLPoly;
//!
//! // Create polynomial and statement
//! let poly = MLPoly { n_vars: 3, evals: vec![...] };
//! let stmt = Statement { n_vars: 3, claim_sum: poly.sum_all() };
//!
//! // Prove
//! let mut transcript = Transcript::new(b"my-protocol");
//! let proof = prove(&stmt, &poly, &mut transcript);
//!
//! // Verify
//! let oracle = PolyOracle::new(poly);
//! let mut transcript = Transcript::new(b"my-protocol");
//! assert!(verify(&stmt, &proof, &oracle, &mut transcript).unwrap());
//! ```

pub mod error;
pub mod types;
pub mod oracle;
pub mod transcript;
pub mod protocol;

// Re-export main types for convenience
pub use error::{Error, Result};
pub use types::{Statement, RoundPoly, SumcheckProof};
pub use oracle::{Oracle, PolyOracle};
pub use transcript::Transcript;
pub use protocol::{prove, verify};
