//! # sigimora-refresh
//!
//! Proactive Refresh protocol for threshold signatures.
//! Periodically refreshes secret shares so that old compromised shares
//! become worthless — without changing the collective public key.
//!
//! ## Two Types of Refresh:
//!
//! ### Type 1: Additive Refresh (for additive sharing)
//! Each party i samples random δ_i and sends to all parties.
//! Party j computes: sk_j^(new) = sk_j^(old) + Σ_i δ_i(j)
//! Correctness: Σ_j sk_j^(new) = Σ_j sk_j^(old) + Σ_i Σ_j δ_i(j) = Σ_j sk_j^(old)
//! (Since Σ_j δ_i(j) = 0 for each i when using proper zero-shares)
//!
//! ### Type 2: Shamir Refresh (for Shamir SSS) - Used for S1
//! Each party i samples zero-polynomial δ_i(x) with degree t and δ_i(0) = 0
//! δ_i(x) = c₁x + c₂x² + … + c_t x^t where δ_i(0) = 0
//! Run VSS.ShareZero(t, n) → commits C_{i,k}, shares (δ_{i,j}, ρ_{i,j})
//! Party j: sk_j^(e+1) = sk_j^(e) + Σ_i δ_i(j)
//! Invariant: collective key unchanged via Lagrange property
//!
//! ## S2 Key Generation (NOT DKG)
//! S2 keys are generated per-epoch via individual key generation:
//! - Each party samples sk_{i,e}^{(2)} locally (uniform random)
//! - Each party publishes pk_{i,e}^{(2)} = g2^{sk_{i,e}^{(2)}} signed with long-term key
//! - No secret sharing; keys are individual, not distributed
//!
//! ```text
//! Key invariant: Σ_{j∈J} λ_j^J · sk_j^(e+1) = Σ_{j∈J} λ_j^J · sk_j^(e)
//!             = SK  (collective secret unchanged)
//! Therefore: pk_J^(e+1) = pk_J^(e)  — epoch-invariant!
//! ```

mod error;
pub use error::RefreshError;

use sigimora_crypto::pedersen::{PedersenSetup, VssPublic, VssShare, PrivatePoly};
use sigimora_math::{G1Point, G2Point, Scalar};
use zeroize::Zeroize;

pub type ParticipantId = u16;

/// A contribution to the proactive refresh protocol.
///
/// # Security
/// - `shares` contain secret values that are zeroized on drop
pub struct RefreshContribution {
    pub from: ParticipantId,
    pub epoch: u64,
    pub vss_public: VssPublic,
    pub shares: Vec<VssShare>,
}

impl std::fmt::Debug for RefreshContribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshContribution")
            .field("from", &self.from)
            .field("epoch", &self.epoch)
            .field("vss_public", &self.vss_public)
            .field("shares", &format_args!("Vec<VssShare>({} entries, contents REDACTED)", self.shares.len()))
            .finish()
    }
}

impl Zeroize for RefreshContribution {
    fn zeroize(&mut self) {
        for share in &mut self.shares {
            share.zeroize();
        }
    }
}

impl Drop for RefreshContribution {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Clone for RefreshContribution {
    fn clone(&self) -> Self {
        RefreshContribution {
            from: self.from,
            epoch: self.epoch,
            vss_public: self.vss_public.clone(),
            shares: self.shares.clone(),
        }
    }
}

impl RefreshContribution {
    pub fn new(from: ParticipantId, epoch: u64, vss_public: VssPublic, shares: Vec<VssShare>) -> Self {
        RefreshContribution { from, epoch, vss_public, shares }
    }
}

/// State machine for the proactive refresh protocol.
///
/// # Security
/// - `my_key` is zeroized on drop
/// - `Debug` redacts secret fields
pub struct RefreshState {
    pub epoch: u64,
    pub n: usize,
    pub t: usize,
    pub my_id: ParticipantId,
    pub my_key: Option<Scalar>,
    pub my_poly: Option<PrivatePoly>,
    pub pedersen: PedersenSetup,
    pub contributions: Vec<RefreshContribution>,
    pub round: RefreshRound,
}

impl std::fmt::Debug for RefreshState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshState")
            .field("epoch", &self.epoch)
            .field("n", &self.n)
            .field("t", &self.t)
            .field("my_id", &self.my_id)
            .field("my_key", &self.my_key.as_ref().map(|_| "[REDACTED]"))
            .field("my_poly", &self.my_poly.as_ref().map(|_| "[REDACTED]"))
            .field("round", &self.round)
            .finish()
    }
}

impl Zeroize for RefreshState {
    fn zeroize(&mut self) {
        if let Some(ref mut k) = self.my_key {
            k.zeroize();
        }
        if let Some(ref mut p) = self.my_poly {
            p.zeroize();
        }
    }
}

impl Drop for RefreshState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Clone is safe with manual zeroize (copy-out semantics)
impl Clone for RefreshState {
    fn clone(&self) -> Self {
        RefreshState {
            epoch: self.epoch,
            n: self.n,
            t: self.t,
            my_id: self.my_id,
            my_key: self.my_key.clone(),
            my_poly: self.my_poly.clone(),
            pedersen: self.pedersen.clone(),
            contributions: self.contributions.clone(),
            round: self.round.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshRound {
    Idle,
    Committed,
    DeltasVerified,
    Complete,
}

impl RefreshState {
    pub fn new(
        epoch: u64,
        my_key: Scalar,
        n: usize,
        t: usize,
        my_id: ParticipantId,
        pedersen: PedersenSetup,
    ) -> Self {
        RefreshState {
            epoch,
            n,
            t,
            my_id,
            my_key: Some(my_key),
            my_poly: None,
            pedersen,
            contributions: Vec::new(),
            round: RefreshRound::Idle,
        }
    }

    pub fn start(&mut self) {
        self.my_poly = Some(PrivatePoly::random_with_zero_constant(self.t, &self.pedersen));
        self.round = RefreshRound::Idle;
    }

    pub fn my_contribution(&self) -> Option<RefreshContribution> {
        self.my_poly.as_ref().map(|poly| {
            let vss_public = poly.commit();
            let shares: Vec<VssShare> = (1..=self.n as u16)
                .map(|i| poly.eval(i))
                .collect();
            RefreshContribution::new(self.my_id, self.epoch, vss_public, shares)
        })
    }

    pub fn verify_contribution(&self, contrib: &RefreshContribution) -> Result<(), RefreshError> {
        let shares_for_me: Vec<&VssShare> = contrib.shares.iter()
            .filter(|s| s.index == self.my_id)
            .collect();

        if shares_for_me.is_empty() {
            return Err(RefreshError::MissingShare);
        }

        let share = shares_for_me[0];
        if !contrib.vss_public.verify_share(self.my_id, &share.value, &share.blinding, &self.pedersen) {
            return Err(RefreshError::VerificationFailed(contrib.from));
        }

        let first_commit = &contrib.vss_public.commitments[0];
        if first_commit != &G1Point::identity() {
            return Err(RefreshError::InvalidCommitment(
                "C_0 must be identity for zero-polynomial VSS".to_string()
            ));
        }

        Ok(())
    }

    pub fn add_contribution(&mut self, contrib: RefreshContribution) -> Result<(), RefreshError> {
        self.verify_contribution(&contrib)?;
        self.contributions.push(contrib);
        self.round = RefreshRound::Committed;
        Ok(())
    }

    pub fn all_contributions_received(&self) -> bool {
        self.contributions.len() == self.n - 1
    }

    pub fn compute_new_key(&self) -> Result<Scalar, RefreshError> {
        if self.contributions.len() < self.n - 1 {
            return Err(RefreshError::InsufficientContributions {
                expected: self.n - 1,
                got: self.contributions.len(),
            });
        }

        let mut delta_sum = Scalar::zero();

        for contrib in &self.contributions {
            let shares_for_me: Vec<&VssShare> = contrib.shares.iter()
                .filter(|s| s.index == self.my_id)
                .collect();

            if shares_for_me.is_empty() {
                continue;
            }

            delta_sum = delta_sum.add(&shares_for_me[0].value);
        }

        if let Some(current_key) = &self.my_key {
            Ok(current_key.add(&delta_sum))
        } else {
            Err(RefreshError::NoKey)
        }
    }

    pub fn apply_refresh(&mut self, new_key: Scalar) {
        self.my_key = Some(new_key);
        self.my_poly = None;
        self.round = RefreshRound::Complete;
    }

    pub fn is_complete(&self) -> bool {
        self.round == RefreshRound::Complete
    }
}

pub struct RefreshManager {
    pub n: usize,
    pub t: usize,
    pub pedersen: PedersenSetup,
}

impl RefreshManager {
    pub fn new(n: usize, t: usize) -> Self {
        RefreshManager {
            n,
            t,
            pedersen: PedersenSetup::deterministic(),
        }
    }

    pub fn generate_contribution(&self, party: ParticipantId) -> RefreshContribution {
        let poly = PrivatePoly::random_with_zero_constant(self.t, &self.pedersen);
        let vss_public = poly.commit();
        let shares: Vec<VssShare> = (1..=self.n as u16)
            .map(|i| poly.eval(i))
            .collect();
        RefreshContribution::new(party, 0, vss_public, shares)
    }

    pub fn apply_contributions(
        current_key: &Scalar,
        party_id: ParticipantId,
        contributions: &[RefreshContribution],
    ) -> Result<Scalar, RefreshError> {
        let mut delta_sum = Scalar::zero();

        for contrib in contributions {
            if let Some(share) = contrib.shares.iter().find(|s| s.index == party_id) {
                delta_sum = delta_sum.add(&share.value);
            }
        }

        Ok(current_key.add(&delta_sum))
    }

    pub fn verify_collective_key_invariant(
        old_pks: &[G2Point],
        new_pks: &[G2Point],
        quorum: &[ParticipantId],
    ) -> bool {
        let mut old_sum = G2Point::identity();
        let mut new_sum = G2Point::identity();

        let lambdas = sigimora_crypto::shamir::ShamirSSS::lagrange_coefficients(quorum);

        for (idx, lambda) in quorum.iter().zip(lambdas.iter()) {
            let pk_idx = (*idx as usize) - 1;
            if pk_idx < old_pks.len() && pk_idx < new_pks.len() {
                old_sum = old_sum.add(&old_pks[pk_idx].mul(lambda));
                new_sum = new_sum.add(&new_pks[pk_idx].mul(lambda));
            }
        }

        old_sum == new_sum
    }

    pub fn additive_refresh(
        n: usize,
        my_id: ParticipantId,
        rng: &mut impl rand_core::RngCore,
    ) -> (Vec<Scalar>, Scalar) {
        let mut shares_to_send: Vec<Scalar> = Vec::with_capacity(n);
        let my_delta = Scalar::random(rng);
        
        let mut sum_of_shares = Scalar::zero();
        for i in 1..=n as u16 {
            if i == my_id {
                shares_to_send.push(Scalar::zero());
            } else {
                let share = Scalar::random(rng);
                sum_of_shares = sum_of_shares.add(&share);
                shares_to_send.push(share);
            }
        }
        
        let my_share_for_self = my_delta.negate().add(&sum_of_shares);
        shares_to_send[(my_id as usize) - 1] = my_share_for_self;
        
        (shares_to_send, my_delta)
    }

    pub fn apply_additive_refresh(
        current_key: &Scalar,
        received_shares: &[Scalar],
    ) -> Scalar {
        let mut delta_sum = Scalar::zero();
        for share in received_shares {
            delta_sum = delta_sum.add(share);
        }
        current_key.add(&delta_sum)
    }

    pub fn verify_additive_invariant(
        old_keys: &[Scalar],
        new_keys: &[Scalar],
    ) -> bool {
        if old_keys.len() != new_keys.len() {
            return false;
        }
        
        let mut old_sum = Scalar::zero();
        let mut new_sum = Scalar::zero();
        
        for (old, new) in old_keys.iter().zip(new_keys.iter()) {
            old_sum = old_sum.add(old);
            new_sum = new_sum.add(new);
        }
        
        old_sum == new_sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_poly_commitment_identity() {
        let ped = PedersenSetup::deterministic();
        let _n = 5;
        let t = 3;

        let poly = PrivatePoly::random_with_zero_constant(t, &ped);
        let vss_public = poly.commit();

        assert_eq!(vss_public.commitments[0], G1Point::identity(), 
            "C_0 should be identity for zero-polynomial");
    }

    #[test]
    fn test_refresh_preserves_collective_key() {
        let n = 5;
        let t = 3;
        let manager = RefreshManager::new(n, t);

        let keys_before: Vec<Scalar> = (1..=n as u16)
            .map(|_| Scalar::random(&mut rand::thread_rng()))
            .collect();

        let pks_before: Vec<G2Point> = keys_before.iter()
            .map(|k| G2Point::generator().mul(k))
            .collect();

        let contributions: Vec<RefreshContribution> = (1..=n as u16)
            .map(|i| manager.generate_contribution(i))
            .collect();

        let keys_after: Vec<Scalar> = keys_before.iter().enumerate()
            .map(|(i, k)| {
                let party_id = (i + 1) as ParticipantId;
                RefreshManager::apply_contributions(k, party_id, &contributions).unwrap()
            })
            .collect();

        let pks_after: Vec<G2Point> = keys_after.iter()
            .map(|k| G2Point::generator().mul(k))
            .collect();

        let quorum = vec![1u16, 3, 5];
        let invariant = RefreshManager::verify_collective_key_invariant(
            &pks_before, &pks_after, &quorum
        );

        assert!(invariant, "Collective key should be invariant after refresh");
    }

    #[test]
    fn test_all_signers_different_after_refresh() {
        let n = 5;
        let manager = RefreshManager::new(n, 3);

        let keys: Vec<Scalar> = (1..=n as u16)
            .map(|_| Scalar::random(&mut rand::thread_rng()))
            .collect();

        let contributions: Vec<RefreshContribution> = (1..=n as u16)
            .map(|i| manager.generate_contribution(i))
            .collect();

        let new_keys: Vec<Scalar> = keys.iter().enumerate()
            .map(|(i, k)| {
                let party_id = (i + 1) as ParticipantId;
                RefreshManager::apply_contributions(k, party_id, &contributions).unwrap()
            })
            .collect();

        for i in 0..n {
            assert_ne!(keys[i], new_keys[i], "Each signer should have a different key");
        }
    }

    #[test]
    fn test_refresh_state_workflow() {
        let my_key = Scalar::random(&mut rand::thread_rng());
        let ped = PedersenSetup::deterministic();
        let n = 5;
        let t = 3;
        let my_id = 2;

        let mut state = RefreshState::new(0, my_key, n, t, my_id, ped.clone());

        state.start();
        let _my_contrib = state.my_contribution().unwrap();

        let mut other_contribs: Vec<RefreshContribution> = Vec::new();
        for i in 1..=n as u16 {
            if i != my_id {
                other_contribs.push(manager_generate_contribution(i, t, &ped));
            }
        }

        for contrib in other_contribs.iter() {
            state.add_contribution(contrib.clone()).unwrap();
        }

        let new_key = state.compute_new_key().unwrap();
        state.apply_refresh(new_key);

        assert!(state.is_complete());
    }

    fn manager_generate_contribution(party: ParticipantId, t: usize, ped: &PedersenSetup) -> RefreshContribution {
        let poly = PrivatePoly::random_with_zero_constant(t, ped);
        let vss_public = poly.commit();
        let shares: Vec<VssShare> = (1..=5u16)
            .map(|i| poly.eval(i))
            .collect();
        RefreshContribution::new(party, 0, vss_public, shares)
    }

    #[test]
    fn test_verify_contribution_rejects_invalid() {
        let ped = PedersenSetup::deterministic();
        let n = 5;
        let t = 3;

        let mut state = RefreshState::new(0, Scalar::random(&mut rand::thread_rng()), n, t, 2, ped.clone());
        state.start();

        let mut bad_contrib = state.my_contribution().unwrap();
        bad_contrib.vss_public.commitments[0] = G1Point::generator();

        let result = state.add_contribution(bad_contrib);
        assert!(result.is_err());
    }
}