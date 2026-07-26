//! Error types for sigimora-mcp.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum McpError {
    #[error("MPC protocol error: {0}")]
    ProtocolError(String),
    
    #[error("DKG error: {0}")]
    DkgError(String),
    
    #[error("signature error: {0}")]
    SignatureError(String),
    
    #[error("ZKP proof verification failed: {0}")]
    ZkpVerificationFailed(String),
    
    #[error("insufficient participants: got {got}, need {need}")]
    InsufficientParticipants { got: usize, need: usize },
    
    #[error("invalid share from participant {0}")]
    InvalidShare(u16),
    
    #[error("threshold not reached: got {got}, need {need}")]
    ThresholdNotReached { got: usize, need: usize },
    
    #[error("serialization error: {0}")]
    SerializationError(String),
    
    #[error("network error: {0}")]
    NetworkError(String),
    
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },
    
    #[error("cheating detected by participant {0}: {1}")]
    CheatingDetected(u16, String),
}
