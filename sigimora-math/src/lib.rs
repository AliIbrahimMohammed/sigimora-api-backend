//! # sigimora-math
//!
//! Thin, well-typed wrappers over `blstrs` providing BLS12-381
//! field and group arithmetic for the SIGIMORA accountable threshold signing system.
//!
//! ## Types
//! - [`Scalar`] — element of Z_r (the scalar field, order r ≈ 2²⁵⁵)
//! - [`G1Point`] — element of G₁ (on E(𝔽_q))
//! - [`G2Point`] — element of G₂ (on E'(𝔽_q²))
//! - [`GtElement`] — element of G_T (subgroup of 𝔽_q¹²*)
//!
//! ## Pairing
//! The bilinear pairing e: G₁ × G₂ → G_T satisfies:
//!   e([a]P, [b]Q) = e(P, Q)^{ab} for all a, b ∈ Z_r
//!
//! All scalar operations are constant-time via the `blstrs` assembly backend.

pub mod error;
pub mod scalar;
pub mod g1;
pub mod g2;
pub mod gt;
pub mod pairing;

pub use error::MathError;
pub use scalar::Scalar;
pub use g1::G1Point;
pub use g2::G2Point;
pub use gt::GtElement;
pub use pairing::{pairing, multi_pairing, pairing_check};
pub use g1::{hash_to_g1, hash_to_g1_with_epoch};
