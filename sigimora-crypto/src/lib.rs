//! # sigimora-crypto
//!
//! Cryptographic primitives for the SIGIMORA accountable threshold signing system:
//! - BLS signatures (key generation, signing, verification, aggregation)
//! - Shamir Secret Sharing over Z_r
//! - Pedersen Verifiable Secret Sharing (VSS - uses two generators for hiding)
//! - Pedersen Distributed Key Generation (DKG)
//! - BLS Threshold Signing (single-round after DKG)
//!
//! All secret material implements `Zeroize` and `ZeroizeOnDrop`.

pub mod error;
pub mod bls;
pub mod shamir;
pub mod feldman;
pub mod pedersen;
pub mod dkg;
pub mod frost;
pub mod bls_threshold;

pub use error::CryptoError;
pub use shamir::lagrange_at_zero;
