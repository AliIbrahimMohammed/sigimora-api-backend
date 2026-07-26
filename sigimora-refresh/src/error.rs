//! Error types for sigimora-refresh.

use thiserror::Error;

/// Errors in the refresh protocol.
#[derive(Debug, Error)]
pub enum RefreshError {
    /// Missing share for this party in contribution.
    #[error("missing share for party in contribution")]
    MissingShare,

    /// Contribution verification failed.
    #[error("contribution from party {0} failed verification")]
    VerificationFailed(u16),

    /// Invalid commitment.
    #[error("invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Insufficient contributions received.
    #[error("insufficient contributions: expected {expected}, got {got}")]
    InsufficientContributions { expected: usize, got: usize },

    /// No key available.
    #[error("no key available")]
    NoKey,

    /// Crypto layer error.
    #[error("crypto error: {0}")]
    CryptoError(#[from] sigimora_crypto::CryptoError),

    /// Math layer error.
    #[error("math error: {0}")]
    MathError(#[from] sigimora_math::MathError),
}
