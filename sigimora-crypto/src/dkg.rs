//! New-DKG (Gennaro et al.) with QUAL set handling and complaint mechanism.
//!
//! ## Mathematical Specification
//!
//! ### Phase 1 - Commit
//! Each P_i selects random z_i ∈ Z_q and runs Pedersen VSS to share z_i.
//! All commitments broadcast and recorded via BFT consensus.
//!
//! ### Phase 2 - Disqualify
//! If P_j receives an invalid share from P_i, it broadcasts a complaint.
//! If >f parties complain about P_i, then P_i is disqualified.
//! The remaining parties form the QUAL set.
//!
//! ### Phase 3 - Reveal
//! Each P_i ∈ QUAL broadcasts Feldman commitments g_1^{a_(i,k)} for their polynomial.
//!
//! ### Output
//! Global public key: PK = ∏_{i∈QUAL} y_i = g_2^{∑_{i∈QUAL} z_i} = g_2^{SK}
//! Party P_j's secret share: sk_j = ∑_{i∈QUAL} s_(i,j) mod q
//!
//! Property: ∑_{j∈QUAL} sk_j · λ_j^QUAL(0) = SK via Lagrange interpolation.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use sigimora_math::{G2Point, G1Point, Scalar};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::pedersen::{PedersenSetup, VssPublic, VssShare, PrivatePoly as PedersenPrivatePoly};

pub type ParticipantId = u16;

#[derive(Clone, Debug)]
pub enum DkgMessage {
    Commit {
        from: ParticipantId,
        public_key: G2Point,
        vss_public: VssPublic,
    },
    Share {
        from: ParticipantId,
        to: ParticipantId,
        encrypted_share: Vec<u8>,
    },
    Complaint {
        from: ParticipantId,
        against: ParticipantId,
    },
    Ack {
        from: ParticipantId,
    },
    Disqualify {
        from: ParticipantId,
        disqualified: ParticipantId,
    },
    QualReveal {
        from: ParticipantId,
        public_key: G2Point,
    },
}

impl DkgMessage {
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            DkgMessage::Commit { from, public_key, vss_public } => {
                let mut bytes = vec![0u8; 2];
                bytes[0..2].copy_from_slice(&from.to_le_bytes());
                bytes.push(1u8);
                bytes.extend_from_slice(&public_key.to_bytes());
                let vss_bytes = serialize_vss_public(vss_public);
                bytes.extend_from_slice(&vss_bytes);
                Ok(bytes)
            }
            DkgMessage::Share { from, to, encrypted_share } => {
                let mut bytes = vec![0u8; 2];
                bytes[0..2].copy_from_slice(&from.to_le_bytes());
                bytes.extend_from_slice(&to.to_le_bytes());
                bytes.push(2u8);
                let len = (encrypted_share.len() as u32).to_le_bytes();
                bytes.extend_from_slice(&len);
                bytes.extend_from_slice(encrypted_share);
                Ok(bytes)
            }
            DkgMessage::Complaint { from, against } => {
                let mut bytes = vec![0u8; 2];
                bytes[0..2].copy_from_slice(&from.to_le_bytes());
                bytes.extend_from_slice(&against.to_le_bytes());
                bytes.push(3u8);
                Ok(bytes)
            }
            DkgMessage::Ack { from } => {
                let mut bytes = vec![0u8; 2];
                bytes[0..2].copy_from_slice(&from.to_le_bytes());
                bytes.push(4u8);
                Ok(bytes)
            }
            DkgMessage::Disqualify { from, disqualified } => {
                let mut bytes = vec![0u8; 2];
                bytes[0..2].copy_from_slice(&from.to_le_bytes());
                bytes.extend_from_slice(&disqualified.to_le_bytes());
                bytes.push(5u8);
                Ok(bytes)
            }
            DkgMessage::QualReveal { from, public_key } => {
                let mut bytes = vec![0u8; 2];
                bytes[0..2].copy_from_slice(&from.to_le_bytes());
                bytes.push(6u8);
                bytes.extend_from_slice(&public_key.to_bytes());
                Ok(bytes)
            }
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 3 {
            return Err(CryptoError::InvalidParameter("invalid message".to_string()));
        }
        let msg_type = data[2];
        match msg_type {
            1 => {
                let from = u16::from_le_bytes([data[0], data[1]]);
                let mut pk_bytes = [0u8; 96];
                pk_bytes.copy_from_slice(&data[3..99]);
                let public_key = G2Point::from_bytes(&pk_bytes).map_err(|_| CryptoError::InvalidParameter("invalid pk".to_string()))?;
                let vss_public = deserialize_vss_public(&data[99..]);
                Ok(DkgMessage::Commit { from, public_key, vss_public })
            }
            2 => {
                let from = u16::from_le_bytes([data[0], data[1]]);
                let to = u16::from_le_bytes([data[2], data[3]]);
                let len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
                let encrypted = data[8..8 + len].to_vec();
                Ok(DkgMessage::Share { from, to, encrypted_share: encrypted })
            }
            3 => {
                let from = u16::from_le_bytes([data[0], data[1]]);
                let against = u16::from_le_bytes([data[2], data[3]]);
                Ok(DkgMessage::Complaint { from, against })
            }
            4 => {
                let from = u16::from_le_bytes([data[0], data[1]]);
                Ok(DkgMessage::Ack { from })
            }
            5 => {
                let from = u16::from_le_bytes([data[0], data[1]]);
                let disqualified = u16::from_le_bytes([data[2], data[3]]);
                Ok(DkgMessage::Disqualify { from, disqualified })
            }
            6 => {
                let from = u16::from_le_bytes([data[0], data[1]]);
                let mut pk_bytes = [0u8; 96];
                pk_bytes.copy_from_slice(&data[3..99]);
                let public_key = G2Point::from_bytes(&pk_bytes).map_err(|_| CryptoError::InvalidParameter("invalid pk".to_string()))?;
                Ok(DkgMessage::QualReveal { from, public_key })
            }
            _ => Err(CryptoError::InvalidParameter("unknown message type".to_string()))
        }
    }
}

fn serialize_vss_public(vss: &VssPublic) -> Vec<u8> {
    let mut bytes = Vec::new();
    let n = vss.commitments.len() as u32;
    bytes.extend_from_slice(&n.to_le_bytes());
    for c in &vss.commitments {
        bytes.extend_from_slice(&c.to_bytes());
    }
    bytes
}

fn deserialize_vss_public(data: &[u8]) -> VssPublic {
    let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut commitments = Vec::with_capacity(n);
    for i in 0..n {
        let mut c_bytes = [0u8; 48];
        c_bytes.copy_from_slice(&data[4 + i * 48 .. 4 + (i + 1) * 48]);
        commitments.push(G1Point::from_bytes(&c_bytes).unwrap());
    }
    VssPublic { commitments }
}

pub struct DkgState {
    pub n: usize,
    pub f: usize,
    pub t: usize,
    pub my_id: ParticipantId,
    pub my_secret: Option<Scalar>,
    pub my_public_key: Option<G2Point>,
    pub my_vss_poly: Option<PedersenPrivatePoly>,
    pub pedersen: PedersenSetup,
    pub received_public_keys: Vec<(ParticipantId, G2Point)>,
    pub received_vss_publics: Vec<(ParticipantId, VssPublic)>,
    pub received_shares: Vec<(ParticipantId, VssShare)>,
    pub complaints_received: Vec<(ParticipantId, ParticipantId)>,
    pub disqualifications: Vec<ParticipantId>,
    pub qual_set: Vec<ParticipantId>,
    pub qual_public_keys: Vec<(ParticipantId, G2Point)>,
    pub round: DkgRound,
}

impl std::fmt::Debug for DkgState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkgState")
            .field("n", &self.n)
            .field("t", &self.t)
            .field("my_id", &self.my_id)
            .field("my_secret", &self.my_secret.as_ref().map(|_| "[REDACTED]"))
            .field("my_public_key", &self.my_public_key)
            .field("my_vss_poly", &self.my_vss_poly.as_ref().map(|_| "[REDACTED]"))
            .field("received_public_keys", &self.received_public_keys.len())
            .field("received_vss_publics", &self.received_vss_publics.len())
            .field("received_shares", &self.received_shares.len())
            .field("qual_set", &self.qual_set)
            .field("round", &self.round)
            .finish()
    }
}

// Manual Clone: fields with Drop/Zeroize are cloned explicitly
impl Clone for DkgState {
    fn clone(&self) -> Self {
        DkgState {
            n: self.n,
            f: self.f,
            t: self.t,
            my_id: self.my_id,
            my_secret: self.my_secret.clone(),
            my_public_key: self.my_public_key.clone(),
            my_vss_poly: self.my_vss_poly.clone(),
            pedersen: self.pedersen.clone(),
            received_public_keys: self.received_public_keys.clone(),
            received_vss_publics: self.received_vss_publics.clone(),
            received_shares: self.received_shares.clone(),
            complaints_received: self.complaints_received.clone(),
            disqualifications: self.disqualifications.clone(),
            qual_set: self.qual_set.clone(),
            qual_public_keys: self.qual_public_keys.clone(),
            round: self.round.clone(),
        }
    }
}

impl Zeroize for DkgState {
    fn zeroize(&mut self) {
        if let Some(ref mut s) = self.my_secret {
            s.zeroize();
        }
        if let Some(ref mut p) = self.my_vss_poly {
            p.zeroize();
        }
        // Zeroize received shares (contain VssShare with value + blinding)
        for (_, ref mut share) in &mut self.received_shares {
            share.zeroize();
        }
    }
}

impl Drop for DkgState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgRound {
    Idle,
    Round1Commit,
    Round2Complaint,
    Round3QualReveal,
    Round4ShareDistribution,
    Round5Verification,
    Complete,
}

impl DkgRound {
    pub fn phase_name(&self) -> &'static str {
        match self {
            DkgRound::Idle => "Idle",
            DkgRound::Round1Commit => "Phase 1: Commit (Pedersen VSS)",
            DkgRound::Round2Complaint => "Phase 2: Complaint/Disqualify",
            DkgRound::Round3QualReveal => "Phase 3: QUAL Reveal",
            DkgRound::Round4ShareDistribution => "Phase 4: Share Distribution",
            DkgRound::Round5Verification => "Phase 5: Verification",
            DkgRound::Complete => "Complete",
        }
    }
}

impl DkgState {
    pub fn new(n: usize, t: usize, my_id: ParticipantId, pedersen: PedersenSetup) -> Self {
        assert!(t <= n, "threshold must be <= total participants");
        assert!(my_id >= 1 && my_id <= n as u16, "invalid participant id");
        let f = (n - 1) / 3;

        DkgState {
            n,
            f,
            t,
            my_id,
            my_secret: None,
            my_public_key: None,
            my_vss_poly: None,
            pedersen,
            received_public_keys: Vec::new(),
            received_vss_publics: Vec::new(),
            received_shares: Vec::new(),
            complaints_received: Vec::new(),
            disqualifications: Vec::new(),
            qual_set: Vec::new(),
            qual_public_keys: Vec::new(),
            round: DkgRound::Idle,
        }
    }

    pub fn add_complaint(&mut self, complainer: ParticipantId, accused: ParticipantId) {
        self.complaints_received.push((complainer, accused));
        self.check_disqualification();
    }

    fn check_disqualification(&mut self) {
        let mut complaint_count: std::collections::HashMap<ParticipantId, usize> = std::collections::HashMap::new();
        
        for (_, accused) in &self.complaints_received {
            *complaint_count.entry(*accused).or_insert(0) += 1;
        }

        for (accused, count) in complaint_count.iter() {
            if *count > self.f && !self.disqualifications.contains(accused) {
                self.disqualifications.push(*accused);
            }
        }
    }

    pub fn build_qual_set(&mut self) {
        self.qual_set = (1..=self.n as u16)
            .filter(|id| !self.disqualifications.contains(id))
            .collect();
    }

    pub fn add_qual_reveal(&mut self, from: ParticipantId, public_key: G2Point) {
        if self.qual_set.contains(&from) {
            self.qual_public_keys.push((from, public_key));
        }
    }

    pub fn add_disqualification(&mut self, participant: ParticipantId) {
        if !self.disqualifications.contains(&participant) {
            self.disqualifications.push(participant);
            self.build_qual_set();
        }
    }

    pub fn get_complaint_count(&self, participant: ParticipantId) -> usize {
        self.complaints_received.iter()
            .filter(|(_, accused)| *accused == participant)
            .count()
    }

    pub fn is_disqualified(&self, participant: ParticipantId) -> bool {
        self.disqualifications.contains(&participant)
    }

    /// Compute collective public key: PK = Σ_{i∈QUAL} y_i  (simple sum).
    ///
    /// This is NOT Lagrange-weighted. Each y_i = g₂^{z_i} is the contribution
    /// public key, and PK = g₂^{Σ z_i} = g₂^{SK}.
    pub fn compute_collective_public_key(&self) -> Option<G2Point> {
        let mut pk = G2Point::identity();
        let mut count = 0;

        // Add my own contribution public key y_{my_id}
        if self.qual_set.contains(&self.my_id) {
            if let Some(ref my_pk) = self.my_public_key {
                pk = pk.add(my_pk);
                count += 1;
            }
        }

        // Add all other QUAL members' contribution public keys (from commit phase)
        for (from, y_i) in &self.received_public_keys {
            if self.qual_set.contains(from) {
                pk = pk.add(y_i);
                count += 1;
            }
        }

        if count == 0 { None } else { Some(pk) }
    }

    /// Compute this party's secret share: sk_j = Σ_{i∈QUAL} f_i(j).
    ///
    /// - For each sender i∈QUAL (i ≠ my_id): use the share f_i(my_id) received.
    /// - For self (i = my_id): evaluate own polynomial f_{my_id}(my_id).
    pub fn compute_secret_share(&self) -> Option<Scalar> {
        let mut sk_j = Scalar::zero();

        // Sum shares received FROM each party i∈QUAL
        for (from, share) in &self.received_shares {
            if self.qual_set.contains(from) {
                sk_j = sk_j.add(&share.value);
            }
        }

        // Add own contribution: f_{my_id}(my_id)
        if self.qual_set.contains(&self.my_id) {
            if let Some(ref poly) = self.my_vss_poly {
                let my_own_share = poly.eval(self.my_id);
                sk_j = sk_j.add(&my_own_share.value);
            }
        }

        Some(sk_j)
    }

    pub fn start(&mut self, rng: &mut impl RngCore) {
        self.my_secret = Some(Scalar::random(rng));
        self.my_public_key = Some(G2Point::generator().mul(self.my_secret.as_ref().unwrap()));
        self.my_vss_poly = Some(PedersenPrivatePoly::random_with_secret(
            self.my_secret.as_ref().unwrap().clone(),
            self.t,
            &self.pedersen,
        ));
        self.round = DkgRound::Round1Commit;
    }

    pub fn my_public_key(&self) -> Option<G2Point> {
        self.my_public_key.clone()
    }

    pub fn my_vss_public(&self) -> Option<VssPublic> {
        self.my_vss_poly.as_ref().map(|p| p.commit())
    }

    pub fn process_participant_commit(
        &mut self,
        from: ParticipantId,
        public_key: G2Point,
        vss_public: VssPublic,
    ) -> Result<(), CryptoError> {
        self.received_public_keys.push((from, public_key));
        self.received_vss_publics.push((from, vss_public));
        Ok(())
    }

    pub fn shares_for(&self, recipient: ParticipantId) -> Option<VssShare> {
        self.my_vss_poly.as_ref().map(|p| p.eval(recipient))
    }

    pub fn process_received_share(
        &mut self,
        from: ParticipantId,
        share: VssShare,
    ) -> Result<(), CryptoError> {
        if let Some((_, vss_pub)) = self.received_vss_publics.iter().find(|(id, _)| *id == from) {
            if !vss_pub.verify_share(share.index, &share.value, &share.blinding, &self.pedersen) {
                return Err(CryptoError::ShareVerificationFailed(share.index));
            }
        }
        self.received_shares.push((from, share));
        Ok(())
    }

    pub fn my_key(&self) -> Option<Scalar> {
        self.my_secret.clone()
    }

    pub fn is_complete(&self) -> bool {
        self.round == DkgRound::Complete
    }

    pub fn finalize(&mut self) -> Result<DkgOutput, CryptoError> {
        self.build_qual_set();

        let qual_size = self.qual_set.len();
        if qual_size == 0 {
            return Err(CryptoError::DkgError("QUAL set is empty".to_string()));
        }

        // Count shares from QUAL members only
        let qual_shares: usize = self.received_shares.iter()
            .filter(|(from, _)| self.qual_set.contains(from))
            .count();
        let needed = qual_size.saturating_sub(1); // we need shares from everyone else in QUAL
        if qual_shares < needed {
            return Err(CryptoError::DkgError(format!(
                "insufficient shares from QUAL members: got {}, need {}",
                qual_shares,
                needed
            )));
        }

        // 1. Compute aggregated secret share: sk_j = Σ_{i∈QUAL} f_i(j)
        let my_share = self.compute_secret_share()
            .ok_or_else(|| CryptoError::DkgError("failed to compute secret share".to_string()))?;
        let my_share_pk = G2Point::generator().mul(&my_share);

        // 2. Compute collective public key: PK = Σ_{i∈QUAL} y_i  (simple sum)
        let collective_pk = self.compute_collective_public_key()
            .ok_or_else(|| CryptoError::DkgError("failed to compute collective PK".to_string()))?;

        // 3. Build contribution PK list (y_i = g₂^{z_i}) sorted by ID
        let mut contribution_pks: Vec<(ParticipantId, G2Point)> = Vec::new();
        if let Some(ref my_pk) = self.my_public_key {
            contribution_pks.push((self.my_id, my_pk.clone()));
        }
        contribution_pks.extend(self.received_public_keys.iter().cloned());
        contribution_pks.sort_by_key(|(id, _)| *id);

        // Store contribution PKs indexed by party ID (1-based → index 0)
        let all_pks: Vec<G2Point> = contribution_pks.into_iter().map(|(_, pk)| pk).collect();

        let qual_set = self.qual_set.clone();
        self.round = DkgRound::Complete;

        Ok(DkgOutput {
            my_secret: my_share,       // aggregated share sk_j, NOT raw z_i
            my_public_key: my_share_pk, // g₂^{sk_j}
            all_public_keys: all_pks,   // contribution PKs y_i
            n: self.n,
            f: self.f,
            t: self.t,
            qual_set,
            collective_pk,              // PK = Σ y_i (simple sum)
        })
    }
}

pub struct DkgOutput {
    pub my_secret: Scalar,
    pub my_public_key: G2Point,
    pub all_public_keys: Vec<G2Point>,
    pub n: usize,
    pub f: usize,
    pub t: usize,
    pub qual_set: Vec<ParticipantId>,
    pub collective_pk: G2Point,
}

impl std::fmt::Debug for DkgOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkgOutput")
            .field("my_secret", &"[REDACTED]")
            .field("my_public_key", &self.my_public_key)
            .field("n", &self.n)
            .field("t", &self.t)
            .field("qual_set", &self.qual_set)
            .field("collective_pk", &self.collective_pk)
            .finish()
    }
}

impl Zeroize for DkgOutput {
    fn zeroize(&mut self) {
        self.my_secret.zeroize();
    }
}

impl Drop for DkgOutput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl DkgOutput {
    /// Returns the collective public key PK = Σ y_i.
    ///
    /// After proper Shamir DKG, this is quorum-independent: any valid quorum
    /// of ≥ t+1 signers yields the same combined signature verifiable against PK.
    pub fn collective_public_key(&self, _quorum: &[u16]) -> G2Point {
        // In proper Shamir DKG, the collective PK is the same for all quorums.
        // PK = g₂^{SK} = g₂^{Σ z_i}
        self.collective_pk.clone()
    }

    pub fn threshold(&self) -> usize {
        self.t
    }

    pub fn byzantine_tolerance(&self) -> usize {
        self.f
    }

    pub fn total_nodes(&self) -> usize {
        self.n
    }

    pub fn quorum_size(&self) -> usize {
        self.t + 1
    }

    pub fn is_in_qual(&self, participant_id: u16) -> bool {
        self.qual_set.contains(&participant_id)
    }
}

pub fn encrypt_share(share: &VssShare, recipient_pk: &G2Point, rng: &mut impl RngCore) -> Vec<u8> {
    let ephemeral_sk = Scalar::random(rng);
    let ephemeral_pk = G2Point::generator().mul(&ephemeral_sk);

    let shared = recipient_pk.mul(&ephemeral_sk);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut key = [0u8; 32];
    let _ = hk.expand(b"sigimora-ecies", &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    let rng_u64 = rng.next_u64();
    nonce_bytes[..8].copy_from_slice(&rng_u64.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut share_bytes = Vec::with_capacity(2 + 32 + 32);
    share_bytes.extend_from_slice(&share.index.to_le_bytes());
    share_bytes.extend_from_slice(&share.value.to_bytes());
    share_bytes.extend_from_slice(&share.blinding.to_bytes());

    let ciphertext = cipher.encrypt(nonce, share_bytes.as_ref()).unwrap();

    let mut result = ephemeral_pk.to_bytes().to_vec();
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);
    result
}

pub fn decrypt_share(encrypted: &[u8], my_sk: &Scalar) -> Result<VssShare, CryptoError> {
    if encrypted.len() < 96 + 12 + 16 {
        return Err(CryptoError::EncryptionError("invalid ciphertext".to_string()));
    }

    let mut epk_bytes = [0u8; 96];
    epk_bytes.copy_from_slice(&encrypted[..96]);
    let ephemeral_pk = G2Point::from_bytes(&epk_bytes).map_err(|_| CryptoError::EncryptionError("invalid ephemeral pk".to_string()))?;

    let nonce = Nonce::from_slice(&encrypted[96..108]);
    let ciphertext = &encrypted[108..];

    let shared = ephemeral_pk.mul(my_sk);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut key = [0u8; 32];
    let _ = hk.expand(b"sigimora-ecies", &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::EncryptionError("decryption failed".to_string()))?;

    if plaintext.len() < 66 {
        return Err(CryptoError::InvalidParameter("invalid share".to_string()));
    }
    let index = u16::from_le_bytes([plaintext[0], plaintext[1]]);
    let mut value_bytes = [0u8; 32];
    value_bytes.copy_from_slice(&plaintext[2..34]);
    let mut blinding_bytes = [0u8; 32];
    blinding_bytes.copy_from_slice(&plaintext[34..66]);
    let value = Scalar::from_bytes(&value_bytes).map_err(|_| CryptoError::InvalidParameter("invalid scalar".to_string()))?;
    let blinding = Scalar::from_bytes(&blinding_bytes).map_err(|_| CryptoError::InvalidParameter("invalid blinding".to_string()))?;
    Ok(VssShare { index, value, blinding })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_dkg() {
        let mut rng = rand::thread_rng();
        let n = 5usize;
        let t = 3usize;
        let ped = PedersenSetup::deterministic();

        // Each party generates secret z_i, polynomial f_i(x), and commitments
        let mut states: Vec<DkgState> = (1..=n as u16)
            .map(|id| {
                let mut state = DkgState::new(n, t, id, ped.clone());
                state.start(&mut rng);
                state
            })
            .collect();

        // Collect contribution PKs y_i = g₂^{z_i} and VSS commitments
        let mut all_pks: Vec<G2Point> = Vec::new();
        let mut all_vss: Vec<VssPublic> = Vec::new();
        for i in 0..n {
            all_pks.push(states[i].my_public_key().unwrap());
            all_vss.push(states[i].my_vss_public().unwrap());
        }

        // Phase 1: Broadcast commits (each party sends its PK + VSS to all others)
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    let vss_pub = VssPublic { commitments: all_vss[i].commitments.clone() };
                    states[j].process_participant_commit(
                        i as u16 + 1, all_pks[i].clone(), vss_pub,
                    ).unwrap();
                }
            }
        }

        // Phase 2: Exchange shares — party i sends f_i(j) to party j
        // CRITICAL: each recipient gets a DIFFERENT share evaluated at their index
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    let share_for_j = states[i].shares_for((j + 1) as u16).unwrap();
                    states[j].process_received_share(i as u16 + 1, share_for_j).unwrap();
                }
            }
        }

        // Phase 3: Finalize — each party computes sk_j = Σ f_i(j) and PK = Σ y_i
        let outputs: Vec<DkgOutput> = states.iter_mut()
            .map(|s| s.finalize().unwrap())
            .collect();

        // Verify: all parties agree on the SAME collective PK
        let pk = outputs[0].collective_pk.clone();
        for output in &outputs {
            assert_eq!(pk, output.collective_pk,
                "All parties must agree on collective PK");
        }

        // Verify: collective_public_key(quorum) is quorum-independent
        let q1 = vec![1u16, 3, 5];
        let q2 = vec![1u16, 2, 4];
        let q3 = vec![2u16, 3, 4, 5];
        assert_eq!(pk, outputs[0].collective_public_key(&q1));
        assert_eq!(pk, outputs[0].collective_public_key(&q2));
        assert_eq!(pk, outputs[0].collective_public_key(&q3));

        // Verify: Lagrange interpolation of share PKs reconstructs PK
        let lambdas = crate::shamir::lagrange_at_zero(&q1);
        let mut reconstructed_pk = G2Point::identity();
        for (&id, lambda) in q1.iter().zip(lambdas.iter()) {
            let share_pk = &outputs[(id - 1) as usize].my_public_key;
            reconstructed_pk = reconstructed_pk.add(&share_pk.mul(lambda));
        }
        assert_eq!(pk, reconstructed_pk,
            "Lagrange interpolation of share PKs must yield collective PK");

        // Verify: threshold signing works
        let msg = b"test DKG threshold signing";
        let h = sigimora_math::hash_to_g1(msg, b"BLS_ATS");
        let mut combined_sig = G1Point::identity();
        for (&id, lambda) in q1.iter().zip(lambdas.iter()) {
            let sk_j = &outputs[(id - 1) as usize].my_secret;
            let sigma_j = h.mul(sk_j);
            combined_sig = combined_sig.add(&sigma_j.mul(lambda));
        }

        // e(σ, g₂) == e(H(m), PK)
        assert!(
            bool::from(sigimora_math::pairing::ct_verify_bls_signature(&combined_sig, &h, &pk)),
            "Threshold signature must verify against collective PK (constant-time)"
        );

        println!("  All {} parties completed Pedersen DKG ✓", n);
        println!("  Collective PK is quorum-independent ✓");
        println!("  Threshold signing verifies correctly ✓");
    }

    #[test]
    fn test_share_encryption() {
        let mut rng = rand::thread_rng();

        let sk = Scalar::random(&mut rng);
        let pk = G2Point::generator().mul(&sk);

        let share = VssShare {
            index: 1,
            value: Scalar::random(&mut rng),
            blinding: Scalar::random(&mut rng),
        };

        let encrypted = encrypt_share(&share, &pk, &mut rng);
        let decrypted = decrypt_share(&encrypted, &sk).unwrap();

        assert_eq!(share.index, decrypted.index);
        assert_eq!(share.value, decrypted.value);
        assert_eq!(share.blinding, decrypted.blinding);
    }
}