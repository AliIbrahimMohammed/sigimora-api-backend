//! Error types for sigimora-ats.

use thiserror::Error;

/// Errors in ATS operations.
#[derive(Debug, Error)]
pub enum AtsError {
    /// Insufficient partial signatures for threshold.
    #[error("need at least {threshold} partial sigs, got {got}")]
    InsufficientPartials { threshold: usize, got: usize },

    /// Epoch mismatch between partial signatures.
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    /// Partial signature verification failed.
    #[error("partial signature from index {0} is invalid")]
    InvalidPartialSig(u16),

    /// A signer is not in the member list.
    #[error("signer {0} is not a registered member")]
    NonMember(u16),

    /// Combined ATS signature verification failed.
    #[error("ATS signature verification failed")]
    VerificationFailed,

    /// Crypto layer error.
    #[error("crypto error: {0}")]
    CryptoError(#[from] sigimora_crypto::CryptoError),

    /// Math layer error.
    #[error("math error: {0}")]
    MathError(#[from] sigimora_math::MathError),
}
