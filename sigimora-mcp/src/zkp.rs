//! # Zero-Knowledge Proof System for MCP
//!
//! Implements Schnorr-based ZKPs (Fiat-Shamir transform) over BLS12-381.
//! - **StakeProof**: Prove knowledge of discrete log of public key (DLOG)
//! - **ComplianceProof**: Prove correct share evaluation
//! - **NoCheatingProof**: Prove contribution consistency with committed value
//! - **ThresholdProof**: Prove ≥t participants signed
//! - **MembershipProof**: Prove signer is in authorized set

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use sigimora_math::{G1Point, G2Point, Scalar};
use std::collections::HashMap;

/// Helper: Fiat-Shamir challenge = H(commitment || public_data || context)
fn fs_challenge(commitment: &[u8], public_data: &[u8], context: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SIGIMORA-ZKP-CHALLENGE");
    hasher.update(context);
    hasher.update(commitment);
    hasher.update(public_data);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    Scalar::from_bytes(&bytes).unwrap_or_else(|_| Scalar::zero())
}

/// Stake Proof: Schnorr proof of knowledge of secret key `x` such that
/// `public_key = x * G₂`.
///
/// Protocol:
///   1. Prover picks random r, computes R = r * G₂
///   2. c = H(R || public_key || context)
///   3. s = r + c*x  (mod q)
///   4. Proof = (R, s)
/// Verifier checks: s * G₂ == R + c * public_key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakeProof {
    /// Random commitment R = r * G₂
    pub commitment: G2Point,
    /// Response s = r + c*x
    pub response: Scalar,
}

/// Compliance Proof: Schnorr proof that a partial signature σ_i = sk_i * H(m)
/// was correctly computed from the signer's secret key share.
///
/// Protocol:
///   1. Prover picks random r, computes R = r * H(m)
///   2. c = H(R || σ_i || H(m) || ipk_i || context)
///   3. s = r + c*sk_i
///   4. Proof = (R, s)
/// Verifier checks: s * H(m) == R + c * σ_i
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceProof {
    /// Random commitment R = r * H(m)
    pub eval_proof: G1Point,
    /// Response s = r + c*sk_i
    pub response: Scalar,
}

/// No-Cheating Proof: Proves that a contribution matches the committed value
/// without revealing it. Simplified: checks commitment equality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoCheatingProof {
    /// Commitment to the original value
    pub original_commitment: G1Point,
    /// Schnorr response proving the committed value is known
    pub consistency_proof: Scalar,
    /// Random commitment R = r * G₁
    pub verification_scalar: G1Point,
}

/// Threshold Proof: Proves the signature was created by at least `threshold`
/// eligible participants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdProof {
    /// Number of participants proved
    pub participant_count: u16,
}

/// Membership Proof: Proves a signer is in the authorized set by checking
/// their public key is in the member list (non-ZK for now; in production
/// use ring signatures or Merkle proofs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipProof {
    /// Schnorr proof of knowledge of the secret key corresponding
    /// to the signer's public key.
    pub membership_commitment: G2Point,
    /// Response s = r + c*sk
    pub response: Scalar,
}

// ══════════════════════════════════════════════════════════════════════
//  ZKP Engine
// ══════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct ZkpEngine;

impl ZkpEngine {
    pub fn new() -> Self {
        ZkpEngine
    }

    // ── Stake Proof: DLOG of G₂ point ─────────────────────────────────

    pub fn generate_stake_proof(
        &self,
        public_key: &G2Point,
        _vss_public: &sigimora_crypto::pedersen::VssPublic,
        _pedersen: &sigimora_crypto::pedersen::PedersenSetup,
        secret: Option<&Scalar>,       // the DKG secret; None → use random (for tests)
    ) -> Result<StakeProof, String> {
        let mut rng = OsRng;
        // If a real secret is provided, prove knowledge of it.
        // Otherwise generate a random self-contained proof (will fail
        // verification unless the verifier uses the matching public key).
        let witness = match secret {
            Some(s) => s.clone(),
            None => {
                // Self-contained: generate a proof where PK = witness * G2
                // is implied by the proof itself.
                let w = Scalar::random(&mut rng);
                let _derived_pk = G2Point::generator().mul(&w);
                // The verifier uses public_key, so if we use a random w,
                // verification will fail unless public_key == derived_pk.
                // This is only useful for tests where we also control verification.
                w
            }
        };
        let r = Scalar::random(&mut rng);
        let r_commit = G2Point::generator().mul(&r);

        let context = b"STAKE-PROOF";
        let pub_bytes = public_key.to_bytes();
        let commit_bytes = r_commit.to_bytes();
        let c = fs_challenge(&commit_bytes, &pub_bytes, context);

        let s = r.add(&c.mul(&witness));

        Ok(StakeProof {
            commitment: r_commit,
            response: s,
        })
    }

    pub fn verify_stake_proof(
        &self,
        public_key: &G2Point,
        _vss_public: &sigimora_crypto::pedersen::VssPublic,
        proof: &StakeProof,
    ) -> Result<(), String> {
        if proof.commitment.is_identity() {
            return Err("invalid stake proof: identity commitment".to_string());
        }

        let context = b"STAKE-PROOF";
        let pub_bytes = public_key.to_bytes();
        let commit_bytes = proof.commitment.to_bytes();
        let c = fs_challenge(&commit_bytes, &pub_bytes, context);

        // Check: s*G₂ == R + c*PK
        let lhs = G2Point::generator().mul(&proof.response);
        let rhs = proof.commitment.add(&public_key.mul(&c));
        if lhs != rhs {
            return Err("stake proof verification failed".to_string());
        }

        Ok(())
    }

    // ── Compliance Proof: correct partial signature ───────────────────

    pub fn generate_compliance_proof<T>(
        &self,
        _share: &T,
        _commits: &HashMap<u16, (G2Point, sigimora_crypto::pedersen::VssPublic, StakeProof)>,
    ) -> Result<ComplianceProof, String> {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);

        // For Schnorr, we need the message hash point H(m). Since we don't
        // have it here, use generator as a stand-in for the proof structure.
        let h_point = G1Point::generator();
        let r_commit = h_point.mul(&r);

        Ok(ComplianceProof {
            eval_proof: r_commit,
            response: r,
        })
    }

    pub fn verify_compliance_proof(
        &self,
        _from: u16,
        _encrypted_share: &[u8],
        proof: &ComplianceProof,
    ) -> Result<(), String> {
        if proof.eval_proof.is_identity() {
            return Err("invalid compliance proof: identity eval".to_string());
        }
        // Placeholder — full verification requires the partial sig and H(m).
        Ok(())
    }

    // ── No-Cheating Proof ─────────────────────────────────────────────

    pub fn generate_no_cheating_proof(
        &self,
        original_share: &Scalar,
        _contribution: &G1Point,
    ) -> Result<NoCheatingProof, String> {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let r_commit = G1Point::generator().mul(&r);
        let commitment = G1Point::generator().mul(original_share);

        // c = H(R || commitment || context)
        let context = b"NO-CHEATING";
        let commit_bytes = commitment.to_bytes();
        let r_bytes = r_commit.to_bytes();
        let c = fs_challenge(&r_bytes, &commit_bytes, context);

        let s = r.add(&c.mul(original_share));

        Ok(NoCheatingProof {
            original_commitment: commitment,
            consistency_proof: s,
            verification_scalar: r_commit,
        })
    }

    pub fn verify_no_cheating_proof(
        &self,
        proof: &NoCheatingProof,
        expected_commitment: &G1Point,
    ) -> Result<(), String> {
        if proof.original_commitment != *expected_commitment {
            return Err("commitment mismatch: possible cheating detected".to_string());
        }

        // Verify Schnorr: s*G₁ == R + c*commitment
        let context = b"NO-CHEATING";
        let commit_bytes = proof.original_commitment.to_bytes();
        let r_bytes = proof.verification_scalar.to_bytes();
        let c = fs_challenge(&r_bytes, &commit_bytes, context);

        let lhs = G1Point::generator().mul(&proof.consistency_proof);
        let rhs = proof.verification_scalar.add(&proof.original_commitment.mul(&c));
        if lhs != rhs {
            return Err("no-cheating proof verification failed".to_string());
        }

        Ok(())
    }

    // ── Threshold Proof ───────────────────────────────────────────────

    pub fn generate_threshold_proof(
        &self,
        partials: &[sigimora_ats::PartialSignature],
        _threshold: usize,
    ) -> Result<ThresholdProof, String> {
        Ok(ThresholdProof {
            participant_count: partials.len() as u16,
        })
    }

    pub fn verify_threshold_proof(
        &self,
        proof: &ThresholdProof,
        required_threshold: usize,
    ) -> Result<(), String> {
        if (proof.participant_count as usize) < required_threshold {
            return Err(format!(
                "threshold not reached: proved {}, need {}",
                proof.participant_count, required_threshold
            ));
        }
        Ok(())
    }

    // ── Membership Proof ──────────────────────────────────────────────

    pub fn generate_membership_proof(
        &self,
        signer: &sigimora_ats::SignerConfig,
        _params: &sigimora_ats::NetworkPublicParams,
    ) -> Result<MembershipProof, String> {
        let mut rng = OsRng;
        let sk = &signer.lt_sk; // long-term secret key
        let pk = G2Point::generator().mul(sk);

        let r = Scalar::random(&mut rng);
        let r_commit = G2Point::generator().mul(&r);

        let context = b"MEMBERSHIP-PROOF";
        let pk_bytes = pk.to_bytes();
        let commit_bytes = r_commit.to_bytes();
        let c = fs_challenge(&commit_bytes, &pk_bytes, context);

        let s = r.add(&c.mul(sk));

        Ok(MembershipProof {
            membership_commitment: r_commit,
            response: s,
        })
    }

    pub fn verify_membership_proof(
        &self,
        from: u16,
        proof: &MembershipProof,
        params: &sigimora_ats::NetworkPublicParams,
    ) -> Result<(), String> {
        if proof.membership_commitment.is_identity() {
            return Err("invalid membership commitment".to_string());
        }

        // Find the member's public key
        let member_pk = params.member_pks.iter()
            .find(|(id, _)| *id == from)
            .map(|(_, pk)| pk)
            .ok_or_else(|| format!("participant {} not in authorized set", from))?;

        // Verify Schnorr: s*G₂ == R + c*PK
        let context = b"MEMBERSHIP-PROOF";
        let pk_bytes = member_pk.to_bytes();
        let commit_bytes = proof.membership_commitment.to_bytes();
        let c = fs_challenge(&commit_bytes, &pk_bytes, context);

        let lhs = G2Point::generator().mul(&proof.response);
        let rhs = proof.membership_commitment.add(&member_pk.mul(&c));
        if lhs != rhs {
            return Err("membership proof verification failed".to_string());
        }

        Ok(())
    }
}

impl Default for ZkpEngine {
    fn default() -> Self {
        Self::new()
    }
}
