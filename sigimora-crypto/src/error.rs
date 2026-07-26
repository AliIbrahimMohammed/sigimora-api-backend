//! Error types for sigimora-crypto.

use thiserror::Error;

/// Errors in cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Insufficient shares for secret reconstruction.
    #[error("need at least {threshold} shares, got {got}")]
    InsufficientShares { threshold: usize, got: usize },

    /// A share failed Feldman VSS verification.
    #[error("share verification failed for index {0}")]
    ShareVerificationFailed(u16),

    /// BLS signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Proof-of-possession verification failed.
    #[error("proof of possession verification failed")]
    PopVerificationFailed,

    /// DKG protocol error.
    #[error("DKG error: {0}")]
    DkgError(String),

    /// Encryption/decryption error.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Math layer error.
    #[error("math error: {0}")]
    MathError(#[from] sigimora_math::MathError),

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,

    /// Invalid shares.
    #[error("invalid shares")]
    InvalidShares,

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),
}
