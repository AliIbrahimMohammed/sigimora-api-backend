//! Error types for sigimora-math.

use thiserror::Error;

/// Errors that can occur in mathematical operations.
#[derive(Debug, Error)]
pub enum MathError {
    /// Failed to deserialize a scalar from bytes.
    #[error("invalid scalar encoding")]
    InvalidScalar,

    /// Failed to deserialize a G1 point from bytes.
    #[error("invalid G1 point encoding")]
    InvalidG1Point,

    /// Failed to deserialize a G2 point from bytes.
    #[error("invalid G2 point encoding")]
    InvalidG2Point,

    /// The scalar has no multiplicative inverse (it is zero).
    #[error("scalar is not invertible (zero)")]
    NotInvertible,

    /// Generic deserialization error.
    #[error("deserialization error: {0}")]
    Deserialization(String),
}
