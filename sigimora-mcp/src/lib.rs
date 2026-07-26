//! # sigimora-mcp
//!
//! MPC Orchestration Engine for the SIGIMORA Accountable Threshold Signing Network.
//!
//! Replaces BFT consensus with pure Multi-Party Computation:
//! - **MPC Protocol**: Distributed key generation and signing without consensus rounds
//! - **ZKP Integration**: Zero-knowledge proofs for stake, compliance, no-cheating, threshold
//! - **Network Layer**: P2P TCP communication adapted for MPC message flows
//! - **Identity**: BLS-based node identity preserved
//!
//! ## Protocol Flow
//!
//! ```text
//! DKG Round 1 (Commit):  Broadcast Pedersen commitment + ZKP(stake)
//! DKG Round 2 (Share):   Distribute encrypted shares + ZKP(compliance)
//! DKG Round 3 (Verify):  Disqualify cheaters + ZKP(no-cheating)
//!
//! Sign Round 1 (Commit): Broadcast commitment + ZKP(membership)
//! Sign Round 2 (Reveal): Reveal partial sig + ZKP(compliance)
//! Sign Round 3 (Verify): Combine + verify threshold + ZKP(threshold)
//! ```

pub mod error;
pub mod protocol;
pub mod zkp;
pub mod network;
pub mod node;
pub mod state;
pub mod identity;
pub mod ledger;

pub use error::McpError;
pub use protocol::{
    McpPhase, McpProtocol, McpState, McpMessage, ParticipantId,
};
pub use zkp::{
    ZkpEngine, StakeProof, ComplianceProof, NoCheatingProof, 
    ThresholdProof, MembershipProof,
};
pub use network::{McpNetworkNode, NetworkConfig};
pub use node::{McpNode, start_mcp_node};
pub use state::{NodeState, NodePhase};
pub use identity::{NodeIdentity, NodeAddress, NodeCredential, AuthorizedNodes};
pub use ledger::{TransactionLedger, ApprovedTransaction, PendingTransaction, RejectedTransaction, LedgerStats};
