//! # MCP Protocol: MPC-based Threshold Signature Orchestration
//!
//! Replaces BFT consensus with a pure Multi-Party Computation approach:
//! - **Round 1 - Commit**: Parties broadcast Pedersen commitments + ZKP of valid share
//! - **Round 2 - Share**: Encrypted shares distributed with ZKP of correct evaluation
//! - **Round 3 - Combine**: Signature aggregation with ZKP of threshold reached
//! - **Round 4 - Verify**: Collective ZKP verification (no individual identity revealed)
//!
//! ## Zero-Knowledge Properties
//!
//! | Property | ZKP Purpose |
//! |----------|------------|
//! | Verify Stake | Prove key quota usage without revealing quota |
//! | Prove Compliance | Prove correct protocol steps without revealing secrets |
//! | Prove No Cheating | Detect inconsistent contributions via ZKP |
//! | Prove Threshold | Prove ≥t signers without revealing who |

use crate::error::McpError;
use crate::zkp::{
    ComplianceProof, MembershipProof, NoCheatingProof, StakeProof, ThresholdProof,
    ZkpEngine,
};
use serde::{Deserialize, Serialize};
use sigimora_ats::{
    NetworkPublicParams, PartialSignature, SignerConfig,
};
use sigimora_crypto::dkg::{DkgState, DkgOutput};
use sigimora_crypto::pedersen::{PedersenSetup, VssPublic};
use sigimora_math::{G1Point, G2Point};
use std::collections::HashMap;

pub type ParticipantId = u16;

// ══════════════════════════════════════════════════════════════════════
//  MCP Protocol State Machine
// ══════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpPhase {
    Idle,
    DkgCommit,
    DkgShare,
    DkgVerify,
    Ready,
    SignCommit,
    SignReveal,
    SignCombine,
    VerifyZkp,
}

impl std::fmt::Display for McpPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpPhase::Idle => write!(f, "Idle"),
            McpPhase::DkgCommit => write!(f, "DKG: Commit Phase"),
            McpPhase::DkgShare => write!(f, "DKG: Share Distribution"),
            McpPhase::DkgVerify => write!(f, "DKG: Verification"),
            McpPhase::Ready => write!(f, "Ready"),
            McpPhase::SignCommit => write!(f, "Sign: Commit Phase"),
            McpPhase::SignReveal => write!(f, "Sign: Reveal Phase"),
            McpPhase::SignCombine => write!(f, "Sign: Combine Phase"),
            McpPhase::VerifyZkp => write!(f, "ZKP: Verification"),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
//  MPC Messages
// ══════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum McpMessage {
    /// Connection handshake with BLS identity proof.
    Handshake {
        from: ParticipantId,
        public_key: G2Point,          // BLS public key of the node
        identity_proof: Vec<u8>,      // BLS signature over "SIGIMORA-HANDSHAKE" || node_id
        timestamp: u64,
    },

    /// Phase 1: Commit with Pedersen commitment + ZKP of valid share
    DkgCommit {
        from: ParticipantId,
        public_key: G2Point,
        vss_public: VssPublic,
        stake_proof: StakeProof,
    },
    
    /// Phase 2: Encrypted share with compliance proof
    DkgShare {
        from: ParticipantId,
        to: ParticipantId,
        encrypted_share: Vec<u8>,
        compliance_proof: ComplianceProof,
    },
    
    /// Phase 3: Disqualification vote with no-cheating proof
    Disqualify {
        from: ParticipantId,
        accused: ParticipantId,
        no_cheating_proof: NoCheatingProof,
    },
    
    /// Signing Round 1: Commit to signature contribution + membership proof
    SignCommit {
        from: ParticipantId,
        commitment: G1Point,
        membership_proof: MembershipProof,
    },
    
    /// Signing Round 2: Reveal partial signature + compliance proof
    SignReveal {
        from: ParticipantId,
        partial_sig: PartialSignature,
        compliance_proof: ComplianceProof,
    },
    
    /// Final: Combined signature with ZKP of threshold reached
    CombinedSignature {
        from: ParticipantId,
        combined_sig: sigimora_ats::AtsSignature,
        threshold_proof: ThresholdProof,
    },
}

// ══════════════════════════════════════════════════════════════════════
//  MPC Protocol State
// ══════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct McpState {
    pub n: usize,
    pub t: usize,
    pub my_id: ParticipantId,
    pub phase: McpPhase,
    pub dkg_state: Option<DkgState>,
    pub my_signer_config: Option<SignerConfig>,
    pub network_params: Option<NetworkPublicParams>,
    pub received_commits: HashMap<ParticipantId, (G2Point, VssPublic, StakeProof)>,
    pub received_shares: Vec<(ParticipantId, Vec<u8>, ComplianceProof)>,
    pub received_sign_commits: HashMap<ParticipantId, (G1Point, MembershipProof)>,
    pub received_sign_reveals: Vec<(ParticipantId, PartialSignature, ComplianceProof)>,
    pub zkp_engine: ZkpEngine,
}

impl McpState {
    pub fn new(n: usize, t: usize, my_id: ParticipantId) -> Self {
        McpState {
            n,
            t,
            my_id,
            phase: McpPhase::Idle,
            dkg_state: None,
            my_signer_config: None,
            network_params: None,
            received_commits: HashMap::new(),
            received_shares: Vec::new(),
            received_sign_commits: HashMap::new(),
            received_sign_reveals: Vec::new(),
            zkp_engine: ZkpEngine::new(),
        }
    }
    
    pub fn transition_to(&mut self, phase: McpPhase) -> Result<(), McpError> {
        let valid = match (&self.phase, &phase) {
            (McpPhase::Idle, McpPhase::DkgCommit) => true,
            (McpPhase::DkgCommit, McpPhase::DkgShare) => true,
            (McpPhase::DkgShare, McpPhase::DkgVerify) => true,
            (McpPhase::DkgVerify, McpPhase::Ready) => true,
            (McpPhase::Ready, McpPhase::SignCommit) => true,
            (McpPhase::SignCommit, McpPhase::SignReveal) => true,
            (McpPhase::SignReveal, McpPhase::SignCombine) => true,
            (McpPhase::SignCombine, McpPhase::VerifyZkp) => true,
            (McpPhase::VerifyZkp, McpPhase::Ready) => true,
            _ => false,
        };
        
        if !valid {
            return Err(McpError::InvalidStateTransition {
                from: self.phase.to_string(),
                to: phase.to_string(),
            });
        }
        
        self.phase = phase;
        Ok(())
    }
    
    pub fn is_ready(&self) -> bool {
        self.phase == McpPhase::Ready
    }
    
    pub fn quorum_size(&self) -> usize {
        self.t + 1
    }
}

// ══════════════════════════════════════════════════════════════════════
//  MPC Protocol Implementation
// ══════════════════════════════════════════════════════════════════════

pub struct McpProtocol {
    pub state: McpState,
}

impl McpProtocol {
    pub fn new(n: usize, t: usize, my_id: ParticipantId) -> Self {
        McpProtocol {
            state: McpState::new(n, t, my_id),
        }
    }
    
    // ── DKG Phase ──────────────────────────────────────────────────────
    
    pub fn start_dkg(&mut self, pedersen: &PedersenSetup, rng: &mut impl rand_core::RngCore) 
        -> Result<(G2Point, VssPublic, StakeProof), McpError> 
    {
        self.state.transition_to(McpPhase::DkgCommit)?;
        
        let mut dkg = DkgState::new(self.state.n, self.state.t, self.state.my_id, pedersen.clone());
        dkg.start(rng);
        
        let my_pk = dkg.my_public_key()
            .ok_or_else(|| McpError::DkgError("no public key".to_string()))?;
        let my_vss = dkg.my_vss_public()
            .ok_or_else(|| McpError::DkgError("no vss public".to_string()))?;
        
        // Generate ZKP that we used our actual key quota (stake proof)
        let dkg_secret = dkg.my_key();
        let stake_proof = self.state.zkp_engine.generate_stake_proof(
            &my_pk,
            &my_vss,
            pedersen,
            dkg_secret.as_ref(),
        ).map_err(|e| McpError::ProtocolError(format!("zkp stake proof: {}", e)))?;
        
        self.state.dkg_state = Some(dkg);
        self.state.received_commits.insert(
            self.state.my_id, 
            (my_pk.clone(), my_vss.clone(), stake_proof.clone())
        );
        
        Ok((my_pk, my_vss, stake_proof))
    }
    
    pub fn process_dkg_commit(
        &mut self,
        from: ParticipantId,
        public_key: G2Point,
        vss_public: VssPublic,
        stake_proof: StakeProof,
    ) -> Result<(), McpError> {
        if self.state.phase != McpPhase::DkgCommit {
            return Err(McpError::ProtocolError(
                "not in DKG commit phase".to_string()
            ));
        }
        
        // Verify the ZKP that the participant used their actual key quota
        self.state.zkp_engine.verify_stake_proof(
            &public_key,
            &vss_public,
            &stake_proof,
        ).map_err(|e| McpError::ZkpVerificationFailed(format!("stake proof from {}: {}", from, e)))?;
        
        self.state.received_commits.insert(from, (public_key, vss_public, stake_proof));
        
        // Transition to share phase once we have enough commits
        if self.state.received_commits.len() >= self.state.n {
            self.state.transition_to(McpPhase::DkgShare)?;
        }
        
        Ok(())
    }
    
    pub fn distribute_dkg_share(
        &mut self,
        recipient: ParticipantId,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(ParticipantId, Vec<u8>, ComplianceProof), McpError> {
        let dkg = self.state.dkg_state.as_ref()
            .ok_or_else(|| McpError::DkgError("DKG not started".to_string()))?;
        
        let share = dkg.shares_for(recipient)
            .ok_or_else(|| McpError::DkgError(format!("no share for {}", recipient)))?;
        
        // Encrypt share for recipient
        let recipient_pk = self.state.received_commits.get(&recipient)
            .map(|(pk, _, _)| pk.clone())
            .ok_or_else(|| McpError::DkgError(format!("no public key for {}", recipient)))?;
        
        let encrypted = sigimora_crypto::dkg::encrypt_share(&share, &recipient_pk, rng);
        
        // Generate compliance proof
        let compliance_proof = self.state.zkp_engine.generate_compliance_proof(
            &share,
            &self.state.received_commits,
        ).map_err(|e| McpError::ProtocolError(format!("compliance proof: {}", e)))?;
        
        Ok((recipient, encrypted, compliance_proof))
    }
    
    pub fn process_dkg_share(
        &mut self,
        from: ParticipantId,
        encrypted_share: Vec<u8>,
        compliance_proof: ComplianceProof,
    ) -> Result<(), McpError> {
        if self.state.phase != McpPhase::DkgShare {
            return Err(McpError::ProtocolError(
                "not in DKG share phase".to_string()
            ));
        }
        
        // Verify compliance proof
        self.state.zkp_engine.verify_compliance_proof(
            from,
            &encrypted_share,
            &compliance_proof,
        ).map_err(|e| McpError::ZkpVerificationFailed(format!("compliance from {}: {}", from, e)))?;
        
        self.state.received_shares.push((from, encrypted_share, compliance_proof));
        
        // Transition when all shares received
        if self.state.received_shares.len() >= self.state.n - 1 {
            self.state.transition_to(McpPhase::DkgVerify)?;
        }
        
        Ok(())
    }
    
    pub fn finalize_dkg(&mut self) -> Result<DkgOutput, McpError> {
        self.state.transition_to(McpPhase::DkgVerify)?;
        
        let dkg = self.state.dkg_state.as_mut()
            .ok_or_else(|| McpError::DkgError("DKG not started".to_string()))?;
        
        let output = dkg.finalize()
            .map_err(|e| McpError::DkgError(format!("{:?}", e)))?;
        
        self.state.transition_to(McpPhase::Ready)?;
        Ok(output)
    }
    
    // ── Signing Phase (MPC-based) ─────────────────────────────────────
    
    pub fn start_signing_round(&mut self) -> Result<(), McpError> {
        self.state.transition_to(McpPhase::SignCommit)?;
        self.state.received_sign_commits.clear();
        self.state.received_sign_reveals.clear();
        Ok(())
    }
    
    pub fn create_sign_commitment(
        &mut self,
        msg: &[u8],
        signer: &SignerConfig,
        _rng: &mut impl rand_core::RngCore,
    ) -> Result<(G1Point, MembershipProof), McpError> {
        let h = sigimora_math::hash_to_g1(msg, b"SIGIMORA_MCP_SIG");
        let sigma_i = h.mul(&signer.dkg_share);
        
        // Membership proof: proves signer is authorized without revealing identity
        let membership_proof = self.state.zkp_engine.generate_membership_proof(
            signer,
            self.state.network_params.as_ref()
                .ok_or_else(|| McpError::ProtocolError("network params not set".to_string()))?,
        ).map_err(|e| McpError::ProtocolError(format!("membership proof: {}", e)))?;
        
        Ok((sigma_i, membership_proof))
    }
    
    pub fn process_sign_commitment(
        &mut self,
        from: ParticipantId,
        commitment: G1Point,
        membership_proof: MembershipProof,
    ) -> Result<(), McpError> {
        if self.state.phase != McpPhase::SignCommit {
            return Err(McpError::ProtocolError(
                "not in sign commit phase".to_string()
            ));
        }
        
        // Verify membership proof
        self.state.zkp_engine.verify_membership_proof(
            from,
            &membership_proof,
            self.state.network_params.as_ref()
                .ok_or_else(|| McpError::ProtocolError("network params not set".to_string()))?,
        ).map_err(|e| McpError::ZkpVerificationFailed(format!("membership from {}: {}", from, e)))?;
        
        self.state.received_sign_commits.insert(from, (commitment, membership_proof));
        
        // Transition to reveal when threshold reached
        if self.state.received_sign_commits.len() >= self.state.quorum_size() {
            self.state.transition_to(McpPhase::SignReveal)?;
        }
        
        Ok(())
    }
    
    pub fn create_sign_reveal(
        &mut self,
        msg: &[u8],
        signer: &SignerConfig,
        tracking_pk: &G2Point,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(PartialSignature, ComplianceProof), McpError> {
        let partial = sigimora_ats::sign_partial(signer, msg, tracking_pk, rng);
        
        let compliance_proof = self.state.zkp_engine.generate_compliance_proof(
            &partial,
            &self.state.received_commits,
        ).map_err(|e| McpError::ProtocolError(format!("sign compliance: {}", e)))?;
        
        Ok((partial, compliance_proof))
    }
    
    pub fn process_sign_reveal(
        &mut self,
        from: ParticipantId,
        partial_sig: PartialSignature,
        compliance_proof: ComplianceProof,
    ) -> Result<(), McpError> {
        if self.state.phase != McpPhase::SignReveal {
            return Err(McpError::ProtocolError(
                "not in sign reveal phase".to_string()
            ));
        }
        
        self.state.zkp_engine.verify_compliance_proof(
            from,
            &partial_sig.sigma.to_bytes(),
            &compliance_proof,
        ).map_err(|e| McpError::ZkpVerificationFailed(format!("sign compliance from {}: {}", from, e)))?;
        
        self.state.received_sign_reveals.push((from, partial_sig, compliance_proof));
        
        if self.state.received_sign_reveals.len() >= self.state.quorum_size() {
            self.state.transition_to(McpPhase::SignCombine)?;
        }
        
        Ok(())
    }
    
    pub fn combine_signatures(
        &mut self,
        params: &NetworkPublicParams,
        _msg: &[u8],
        epoch: u64,
        _aggregator_id: ParticipantId,
    ) -> Result<sigimora_ats::AtsSignature, McpError> {
        self.state.transition_to(McpPhase::SignCombine)?;
        
        let partials: Vec<PartialSignature> = self.state.received_sign_reveals
            .iter()
            .map(|(_, sig, _)| sig.clone())
            .collect();
        
        let sig = sigimora_ats::aggregate(&partials, params, epoch, self.state.my_id)
            .map_err(|e| McpError::SignatureError(format!("aggregation: {}", e)))?;
        
        self.state.transition_to(McpPhase::VerifyZkp)?;
        Ok(sig)
    }
    
    pub fn verify_combined_signature(
        &mut self,
        params: &NetworkPublicParams,
        msg: &[u8],
        sig: &sigimora_ats::AtsSignature,
    ) -> Result<bool, McpError> {
        self.state.transition_to(McpPhase::VerifyZkp)?;
        
        let valid = sigimora_ats::verify(params, msg, sig);
        
        if valid {
            self.state.transition_to(McpPhase::Ready)?;
        }
        
        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mcp_state_transitions() {
        let mut state = McpState::new(5, 3, 0);
        
        assert_eq!(state.phase, McpPhase::Idle);
        
        state.transition_to(McpPhase::DkgCommit).unwrap();
        assert_eq!(state.phase, McpPhase::DkgCommit);
        
        state.transition_to(McpPhase::DkgShare).unwrap();
        assert_eq!(state.phase, McpPhase::DkgShare);
        
        state.transition_to(McpPhase::DkgVerify).unwrap();
        state.transition_to(McpPhase::Ready).unwrap();
        
        assert!(state.is_ready());
        assert!(state.transition_to(McpPhase::SignCommit).is_ok());
    }
    
    #[test]
    fn test_invalid_transition() {
        let mut state = McpState::new(5, 3, 0);
        
        // Cannot go from Idle to Ready directly
        assert!(state.transition_to(McpPhase::Ready).is_err());
    }
    
    #[test]
    fn test_mcp_protocol_lifecycle() {
        let mut protocol = McpProtocol::new(5, 3, 1);
        
        // Start DKG
        let pedersen = PedersenSetup::deterministic();
        let (pk, vss, stake_proof) = protocol.start_dkg(&pedersen, &mut rand::thread_rng()).unwrap();
        
        // Process own commit — phase stays DkgCommit until all n=5 commits arrive
        protocol.process_dkg_commit(1, pk, vss, stake_proof).unwrap();
        assert_eq!(protocol.state.phase, McpPhase::DkgCommit, "Phase remains DkgCommit until all peers commit");
        
        // Process remaining 4 commits — generate REAL proofs for each peer
        // using the ZKP engine with the actual DKG secret.
        for i in 2..=5 {
            let mut peer_dkg = sigimora_crypto::dkg::DkgState::new(
                protocol.state.n, protocol.state.t, i, pedersen.clone()
            );
            peer_dkg.start(&mut rand::thread_rng());
            let peer_pk = peer_dkg.my_public_key().unwrap();
            let peer_vss = peer_dkg.my_vss_public().unwrap();
            let peer_secret = peer_dkg.my_key();
            let peer_proof = protocol.state.zkp_engine.generate_stake_proof(
                &peer_pk, &peer_vss, &pedersen, peer_secret.as_ref(),
            ).unwrap();
            protocol.process_dkg_commit(
                i, peer_pk, peer_vss, peer_proof,
            ).unwrap();
        }
        
        assert_eq!(protocol.state.phase, McpPhase::DkgShare, "After all n commits, phase transitions to DkgShare");
    }
}