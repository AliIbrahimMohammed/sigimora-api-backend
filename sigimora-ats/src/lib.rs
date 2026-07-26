//! # sigimora-ats
//!
//! Accountable Threshold Signatures (ATS) for the SIGIMORA BFT Network.
//!
//! ## Design
//!
//! - **DKG-Derived Shares**: Signing keys come from Pedersen DKG
//! - **Public-Key-Only Verification**: Only the collective PK is needed
//! - **Tracking Key**: Only the network creator can identify signers
//! - **Encrypted Tags**: ECIES-encrypted under tracking public key
//!
//! ## Protocol
//!
//! 1. Network creator generates tracking key pair (tk_sk, tk_pk)
//! 2. All parties run Pedersen DKG → each gets share sk_i, collective PK
//! 3. Each signer creates σ_i = H(m)^{sk_i} + encrypted accountability tag
//! 4. Aggregator combines via Lagrange: σ = Σ λ_j · σ_j
//! 5. Verify: e(σ, g₂) == e(H(m), PK) — public keys only
//! 6. Trace: tracking key holder decrypts tags to identify signers

mod error;
pub use error::AtsError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sigimora_math::{hash_to_g1, pairing, G1Point, G2Point, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type ParticipantId = u16;

// ══════════════════════════════════════════════════════════════════════
//  Tracking Key — only network creator has the secret
// ══════════════════════════════════════════════════════════════════════

/// Tracking key pair. The network creator generates this at `sigimora create`.
/// - `public`: shared with all members, embedded in network config
/// - `secret`: kept ONLY by the creator, used for tracing
///
/// # Security
/// - `secret` is zeroized on drop
/// - `Debug` redacts the secret field
pub struct TrackingKeyPair {
    pub secret: Scalar,
    pub public: G2Point,
}

impl std::fmt::Debug for TrackingKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackingKeyPair")
            .field("secret", &"[REDACTED]")
            .field("public", &self.public)
            .finish()
    }
}

impl Zeroize for TrackingKeyPair {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl ZeroizeOnDrop for TrackingKeyPair {}

impl TrackingKeyPair {
    pub fn generate(rng: &mut impl RngCore) -> Self {
        let secret = Scalar::random(rng);
        let public = G2Point::generator().mul(&secret);
        TrackingKeyPair { secret, public }
    }

    pub fn from_secret(secret: Scalar) -> Self {
        let public = G2Point::generator().mul(&secret);
        TrackingKeyPair { secret, public }
    }

    pub fn public_key(&self) -> G2Point {
        self.public.clone()
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Network Public Parameters — no secrets here
// ══════════════════════════════════════════════════════════════════════

/// Public parameters for the ATS network. Available to all verifiers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkPublicParams {
    pub n: usize,
    pub threshold: usize,
    pub collective_pk: G2Point,
    pub tracking_pk: G2Point,
    /// DKG share public keys: pk_i = g₂^{sk_i} for each party i
    pub member_pks: Vec<(ParticipantId, G2Point)>,
    /// Long-term identity public keys: ltpk_i = g₂^{ltsk_i}
    pub member_lt_pks: Vec<(ParticipantId, G2Point)>,
}

// ══════════════════════════════════════════════════════════════════════
//  Signer Configuration — each node holds one of these
// ══════════════════════════════════════════════════════════════════════

/// Per-node signing configuration derived from DKG output.
///
/// # Security
/// - `dkg_share` and `lt_sk` are zeroized on drop
/// - `Debug` redacts secret fields
pub struct SignerConfig {
    pub node_id: ParticipantId,
    pub dkg_share: Scalar,
    pub dkg_share_pk: G2Point,
    pub lt_sk: Scalar,
    pub lt_pk: G2Point,
}

impl std::fmt::Debug for SignerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerConfig")
            .field("node_id", &self.node_id)
            .field("dkg_share", &"[REDACTED]")
            .field("dkg_share_pk", &self.dkg_share_pk)
            .field("lt_sk", &"[REDACTED]")
            .field("lt_pk", &self.lt_pk)
            .finish()
    }
}

impl Zeroize for SignerConfig {
    fn zeroize(&mut self) {
        self.dkg_share.zeroize();
        self.lt_sk.zeroize();
    }
}

impl ZeroizeOnDrop for SignerConfig {}

impl Clone for SignerConfig {
    fn clone(&self) -> Self {
        SignerConfig {
            node_id: self.node_id,
            dkg_share: self.dkg_share.clone(),
            dkg_share_pk: self.dkg_share_pk.clone(),
            lt_sk: self.lt_sk.clone(),
            lt_pk: self.lt_pk.clone(),
        }
    }
}

impl SignerConfig {
    pub fn new(
        node_id: ParticipantId,
        dkg_share: Scalar,
        lt_sk: Scalar,
    ) -> Self {
        let dkg_share_pk = G2Point::generator().mul(&dkg_share);
        let lt_pk = G2Point::generator().mul(&lt_sk);
        SignerConfig {
            node_id,
            dkg_share,
            dkg_share_pk,
            lt_sk,
            lt_pk,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Partial Signature + Encrypted Accountability Tag
// ══════════════════════════════════════════════════════════════════════

/// Partial signature from one signer, with encrypted accountability tag.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    pub node_id: ParticipantId,
    pub sigma: G1Point,
    pub encrypted_tag: EncryptedTag,
}

/// Encrypted accountability tag. Contains identity info encrypted under
/// the tracking public key using ECIES. Only the tracking key holder
/// can decrypt and identify the signer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedTag {
    pub node_id: ParticipantId,
    /// Ephemeral public key for ECIES: g₂^r
    pub ephemeral_pk: G2Point,
    /// ECIES ciphertext: encrypted(σ_i || tag_i || ltpk_i)
    pub ciphertext: Vec<u8>,
    /// Nonce for AES-GCM
    pub nonce: [u8; 12],
}

/// Decrypted tag contents — only visible to tracking key holder.
#[derive(Clone, Debug)]
pub struct DecryptedTag {
    pub node_id: ParticipantId,
    pub sigma_i: G1Point,
    pub tag_i: G1Point,
    pub lt_pk: G2Point,
}

// ══════════════════════════════════════════════════════════════════════
//  Combined ATS Signature
// ══════════════════════════════════════════════════════════════════════

/// Combined ATS signature with accountability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtsSignature {
    /// Combined threshold signature: σ = Σ λ_j · σ_j
    pub combined_sig: G1Point,
    /// Quorum: which node IDs signed (visible, but identity hidden)
    pub quorum: Vec<ParticipantId>,
    /// Bitmap commitment binding aggregator to the quorum
    pub bitmap_commitment: G1Point,
    /// Encrypted accountability tags (one per signer)
    pub encrypted_tags: Vec<EncryptedTag>,
    /// Membership proof: individual PKs for quorum members
    pub membership_proof: MembershipProof,
    /// Epoch number
    pub epoch: u64,
}

/// Membership proof: proves the signature came from valid members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipProof {
    /// Quorum public key: PK_J = Σ λ_j · pk_j
    pub quorum_pk: G2Point,
    /// Individual DKG share PKs for each signer in the quorum
    pub individual_pks: Vec<(ParticipantId, G2Point)>,
}

// ══════════════════════════════════════════════════════════════════════
//  Core ATS Operations
// ══════════════════════════════════════════════════════════════════════

/// Lagrange coefficients at x=0 — delegates to canonical implementation.
pub fn lagrange_coefficients_at_zero(quorum: &[ParticipantId]) -> Vec<Scalar> {
    sigimora_crypto::lagrange_at_zero(quorum)
}

/// Create a partial signature with encrypted accountability tag.
pub fn sign_partial(
    signer: &SignerConfig,
    msg: &[u8],
    tracking_pk: &G2Point,
    rng: &mut impl RngCore,
) -> PartialSignature {
    let h = hash_to_g1(msg, b"SIGIMORA_ATS");
    let sigma_i = h.mul(&signer.dkg_share);
    let tag_i = sigma_i.mul(&signer.lt_sk);

    let encrypted_tag = encrypt_tag(
        signer.node_id,
        &sigma_i,
        &tag_i,
        &signer.lt_pk,
        tracking_pk,
        rng,
    );

    PartialSignature {
        node_id: signer.node_id,
        sigma: sigma_i,
        encrypted_tag,
    }
}

/// Aggregate partial signatures into a combined ATS signature.
pub fn aggregate(
    partials: &[PartialSignature],
    params: &NetworkPublicParams,
    epoch: u64,
    aggregator_id: ParticipantId,
) -> Result<AtsSignature, AtsError> {
    if partials.len() < params.threshold {
        return Err(AtsError::InsufficientPartials {
            threshold: params.threshold,
            got: partials.len(),
        });
    }

    let quorum: Vec<ParticipantId> = partials.iter().map(|p| p.node_id).collect();
    let lambdas = lagrange_coefficients_at_zero(&quorum);

    // Combine: σ = Σ λ_j · σ_j
    let mut combined = G1Point::identity();
    for (partial, lambda) in partials.iter().zip(lambdas.iter()) {
        combined = combined.add(&partial.sigma.mul(lambda));
    }

    // Bitmap commitment
    let bitmap_commitment = create_bitmap_commitment(&quorum, aggregator_id);

    // Membership proof
    let individual_pks: Vec<(ParticipantId, G2Point)> = quorum
        .iter()
        .filter_map(|id| {
            params
                .member_pks
                .iter()
                .find(|(mid, _)| mid == id)
                .cloned()
        })
        .collect();

    let mut quorum_pk = G2Point::identity();
    for ((_, pk), lambda) in individual_pks.iter().zip(lambdas.iter()) {
        quorum_pk = quorum_pk.add(&pk.mul(lambda));
    }

    let membership_proof = MembershipProof {
        quorum_pk,
        individual_pks,
    };

    let encrypted_tags: Vec<EncryptedTag> = partials
        .iter()
        .map(|p| p.encrypted_tag.clone())
        .collect();

    Ok(AtsSignature {
        combined_sig: combined,
        quorum,
        bitmap_commitment,
        encrypted_tags,
        membership_proof,
        epoch,
    })
}

/// Verify an ATS signature using ONLY public keys.
/// No private keys or tracking key needed.
pub fn verify(
    params: &NetworkPublicParams,
    msg: &[u8],
    sig: &AtsSignature,
) -> bool {
    // 1. Check quorum size
    if sig.quorum.len() < params.threshold {
        return false;
    }

    // 2. Verify all signers are valid members
    for (id, pk) in &sig.membership_proof.individual_pks {
        let valid = params
            .member_pks
            .iter()
            .any(|(mid, mpk)| mid == id && *mpk == *pk);
        if !valid {
            return false;
        }
    }

    // 3. Verify combined signature: e(σ, g₂) == e(H(m), PK)
    let h = hash_to_g1(msg, b"SIGIMORA_ATS");
    if !bool::from(pairing::ct_verify_bls_signature(&sig.combined_sig, &h, &params.collective_pk)) {
        return false;
    }

    true
}

/// Trace signers — requires the tracking SECRET key.
/// Returns list of (node_id, long-term public key) for identified signers.
pub fn trace(
    tracking_sk: &Scalar,
    params: &NetworkPublicParams,
    msg: &[u8],
    sig: &AtsSignature,
) -> Vec<(ParticipantId, G2Point)> {
    let h = hash_to_g1(msg, b"SIGIMORA_ATS");
    let mut traced = Vec::new();

    for enc_tag in &sig.encrypted_tags {
        if let Some(decrypted) = decrypt_tag(tracking_sk, enc_tag) {
            // Verify partial sig: e(σ_i, g₂) == e(H(m), pk_i)
            let pk_i = params
                .member_pks
                .iter()
                .find(|(mid, _)| *mid == decrypted.node_id)
                .map(|(_, pk)| pk);

            if let Some(pk_i) = pk_i {
                if !bool::from(pairing::ct_verify_bls_signature(&decrypted.sigma_i, &h, pk_i)) {
                    continue;
                }
            }

            // Verify tag: e(tag_i, g₂) == e(σ_i, ltpk)
            // Use ct_pairing_check: ct_pairing_check(tag_i, g2, -sigma_i, ltpk)
            let neg_sigma = decrypted.sigma_i.negate();
            if !bool::from(pairing::ct_pairing_check(
                &decrypted.tag_i, &G2Point::generator(),
                &neg_sigma, &decrypted.lt_pk,
            )) {
                continue;
            }

            // Match ltpk against known members
            let matched = params
                .member_lt_pks
                .iter()
                .find(|(_, mltpk)| *mltpk == decrypted.lt_pk);

            if let Some((mid, ltpk)) = matched {
                traced.push((*mid, ltpk.clone()));
            }
        }
    }

    traced
}

// ══════════════════════════════════════════════════════════════════════
//  ECIES Encryption / Decryption for Tags
// ══════════════════════════════════════════════════════════════════════

fn encrypt_tag(
    node_id: ParticipantId,
    sigma_i: &G1Point,
    tag_i: &G1Point,
    lt_pk: &G2Point,
    tracking_pk: &G2Point,
    rng: &mut impl RngCore,
) -> EncryptedTag {
    // ECIES: ephemeral key + shared secret
    let r = Scalar::random(rng);
    let ephemeral_pk = G2Point::generator().mul(&r);
    let shared = tracking_pk.mul(&r);

    // Derive symmetric key
    let shared_bytes = shared.to_bytes();
    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut key = [0u8; 32];
    let _ = hk.expand(b"sigimora-ats-tag", &mut key);

    // Plaintext: node_id(2) + sigma_i(48) + tag_i(48) + ltpk(96)
    let mut plaintext = Vec::with_capacity(2 + 48 + 48 + 96);
    plaintext.extend_from_slice(&node_id.to_le_bytes());
    plaintext.extend_from_slice(&sigma_i.to_bytes());
    plaintext.extend_from_slice(&tag_i.to_bytes());
    plaintext.extend_from_slice(&lt_pk.to_bytes());

    // AES-GCM encrypt
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    let rng_u64 = rng.next_u64();
    nonce_bytes[..8].copy_from_slice(&rng_u64.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

    EncryptedTag {
        node_id,
        ephemeral_pk,
        ciphertext,
        nonce: nonce_bytes,
    }
}

fn decrypt_tag(tracking_sk: &Scalar, enc: &EncryptedTag) -> Option<DecryptedTag> {
    // Reconstruct shared secret
    let shared = enc.ephemeral_pk.mul(tracking_sk);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut key = [0u8; 32];
    let _ = hk.expand(b"sigimora-ats-tag", &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let nonce = Nonce::from_slice(&enc.nonce);
    let plaintext = cipher.decrypt(nonce, enc.ciphertext.as_ref()).ok()?;

    if plaintext.len() < 2 + 48 + 48 + 96 {
        return None;
    }

    let node_id = u16::from_le_bytes([plaintext[0], plaintext[1]]);
    let mut sigma_bytes = [0u8; 48];
    sigma_bytes.copy_from_slice(&plaintext[2..50]);
    let mut tag_bytes = [0u8; 48];
    tag_bytes.copy_from_slice(&plaintext[50..98]);
    let mut ltpk_bytes = [0u8; 96];
    ltpk_bytes.copy_from_slice(&plaintext[98..194]);

    let sigma_i = G1Point::from_bytes(&sigma_bytes).ok()?;
    let tag_i = G1Point::from_bytes(&tag_bytes).ok()?;
    let lt_pk = G2Point::from_bytes(&ltpk_bytes).ok()?;

    Some(DecryptedTag {
        node_id,
        sigma_i,
        tag_i,
        lt_pk,
    })
}

/// Create a bitmap commitment binding the aggregator to the quorum.
pub fn create_bitmap_commitment(
    quorum: &[ParticipantId],
    aggregator_id: ParticipantId,
) -> G1Point {
    let mut bytes = Vec::new();
    let mut sorted = quorum.to_vec();
    sorted.sort();
    for id in sorted {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes.extend_from_slice(&aggregator_id.to_le_bytes());
    hash_to_g1(&bytes, b"SIGIMORA_BITMAP_COMMIT")
}

// ══════════════════════════════════════════════════════════════════════
//  Legacy Compatibility — used by existing BFT/CLI code
// ══════════════════════════════════════════════════════════════════════

/// Signature share (legacy compatibility type).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigShare {
    pub index: ParticipantId,
    pub value: G1Point,
}

// ══════════════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_network(n: usize, t: usize) -> (
        NetworkPublicParams,
        Vec<SignerConfig>,
        TrackingKeyPair,
    ) {
        let mut rng = rand::thread_rng();
        let tracking = TrackingKeyPair::generate(&mut rng);

        // Run DKG
        let ped = sigimora_crypto::pedersen::PedersenSetup::deterministic();
        let mut states: Vec<sigimora_crypto::dkg::DkgState> = (1..=n as u16)
            .map(|id| {
                let mut s = sigimora_crypto::dkg::DkgState::new(n, t, id, ped.clone());
                s.start(&mut rand::thread_rng());
                s
            })
            .collect();

        let mut all_pks = Vec::new();
        let mut all_pops = Vec::new();
        let mut all_vss = Vec::new();
        for i in 0..n {
            all_pks.push(states[i].my_public_key().unwrap());
            all_pops.push(states[i].my_pop().unwrap());
            all_vss.push(states[i].my_vss_public().unwrap());
        }

        for i in 0..n {
            for j in 0..n {
                if i != j {
                    let vss = sigimora_crypto::pedersen::VssPublic {
                        commitments: all_vss[i].commitments.clone(),
                    };
                    states[j]
                        .process_participant_commit(i as u16 + 1, all_pks[i].clone(), all_pops[i].clone(), vss)
                        .unwrap();
                }
            }
        }

        for i in 0..n {
            for j in 0..n {
                if i != j {
                    let share = states[i].shares_for((j + 1) as u16).unwrap();
                    states[j]
                        .process_received_share(i as u16 + 1, share)
                        .unwrap();
                }
            }
        }

        let outputs: Vec<sigimora_crypto::dkg::DkgOutput> =
            states.iter_mut().map(|s| s.finalize().unwrap()).collect();

        let collective_pk = outputs[0].collective_pk.clone();

        // Create signer configs with long-term keys
        let mut signers = Vec::new();
        let mut member_pks = Vec::new();
        let mut member_lt_pks = Vec::new();

        for (i, output) in outputs.iter().enumerate() {
            let id = (i + 1) as u16;
            let lt_sk = Scalar::random(&mut rng);
            let lt_pk = G2Point::generator().mul(&lt_sk);

            signers.push(SignerConfig::new(id, output.my_secret.clone(), lt_sk));
            member_pks.push((id, output.my_public_key.clone()));
            member_lt_pks.push((id, lt_pk));
        }

        let params = NetworkPublicParams {
            n,
            threshold: t + 1, // t+1 needed to sign
            collective_pk,
            tracking_pk: tracking.public.clone(),
            member_pks,
            member_lt_pks,
        };

        (params, signers, tracking)
    }

    #[test]
    fn test_ats_sign_verify() {
        let (params, signers, _tracking) = setup_test_network(5, 3);
        let msg = b"Authorize: Alice -> Bob, 100 ETH";
        let mut rng = rand::thread_rng();

        // Quorum of t+1 = 4 signers
        let quorum_signers: Vec<&SignerConfig> =
            signers.iter().take(params.threshold).collect();

        let partials: Vec<PartialSignature> = quorum_signers
            .iter()
            .map(|s| sign_partial(s, msg, &params.tracking_pk, &mut rng))
            .collect();

        let sig = aggregate(&partials, &params, 0, 1).unwrap();

        assert!(verify(&params, msg, &sig), "ATS signature must verify");
    }

    #[test]
    fn test_ats_different_quorums() {
        let (params, signers, _tracking) = setup_test_network(5, 3);
        let msg = b"Test different quorums";
        let mut rng = rand::thread_rng();

        // Quorum 1: signers 1,2,3,4
        let partials1: Vec<PartialSignature> = signers[0..4]
            .iter()
            .map(|s| sign_partial(s, msg, &params.tracking_pk, &mut rng))
            .collect();
        let sig1 = aggregate(&partials1, &params, 0, 1).unwrap();

        // Quorum 2: signers 2,3,4,5
        let partials2: Vec<PartialSignature> = signers[1..5]
            .iter()
            .map(|s| sign_partial(s, msg, &params.tracking_pk, &mut rng))
            .collect();
        let sig2 = aggregate(&partials2, &params, 0, 2).unwrap();

        // Both must verify against the SAME collective PK
        assert!(verify(&params, msg, &sig1));
        assert!(verify(&params, msg, &sig2));

        // Combined sigs are the same (Shamir property)
        assert_eq!(
            sig1.combined_sig, sig2.combined_sig,
            "Different quorums must produce same combined signature"
        );
    }

    #[test]
    fn test_ats_trace_with_tracking_key() {
        let (params, signers, tracking) = setup_test_network(5, 3);
        let msg = b"Trace test";
        let mut rng = rand::thread_rng();

        let quorum = &signers[0..4]; // signers 1,2,3,4
        let partials: Vec<PartialSignature> = quorum
            .iter()
            .map(|s| sign_partial(s, msg, &params.tracking_pk, &mut rng))
            .collect();
        let sig = aggregate(&partials, &params, 0, 1).unwrap();

        // Trace with tracking key — must identify all 4 signers
        let traced = trace(&tracking.secret, &params, msg, &sig);
        assert_eq!(traced.len(), 4, "Should trace all 4 signers");

        let traced_ids: Vec<ParticipantId> = traced.iter().map(|(id, _)| *id).collect();
        assert!(traced_ids.contains(&1));
        assert!(traced_ids.contains(&2));
        assert!(traced_ids.contains(&3));
        assert!(traced_ids.contains(&4));
    }

    #[test]
    fn test_ats_trace_fails_without_tracking_key() {
        let (params, signers, _tracking) = setup_test_network(4, 2);
        let msg = b"No trace without key";
        let mut rng = rand::thread_rng();

        let partials: Vec<PartialSignature> = signers[0..3]
            .iter()
            .map(|s| sign_partial(s, msg, &params.tracking_pk, &mut rng))
            .collect();
        let sig = aggregate(&partials, &params, 0, 1).unwrap();

        // Wrong tracking key — trace must fail
        let wrong_key = Scalar::random(&mut rng);
        let traced = trace(&wrong_key, &params, msg, &sig);
        assert_eq!(traced.len(), 0, "Wrong key must not trace any signers");
    }

    #[test]
    fn test_ats_insufficient_signers() {
        let (params, signers, _tracking) = setup_test_network(5, 3);
        let msg = b"Not enough";
        let mut rng = rand::thread_rng();

        // Only 2 signers, but threshold is 4
        let partials: Vec<PartialSignature> = signers[0..2]
            .iter()
            .map(|s| sign_partial(s, msg, &params.tracking_pk, &mut rng))
            .collect();

        let result = aggregate(&partials, &params, 0, 1);
        assert!(result.is_err(), "Must fail with insufficient signers");
    }

    #[test]
    fn test_verify_uses_no_private_keys() {
        let (params, signers, _tracking) = setup_test_network(4, 2);
        let msg = b"Public key only verification";
        let mut rng = rand::thread_rng();

        let partials: Vec<PartialSignature> = signers[0..3]
            .iter()
            .map(|s| sign_partial(s, msg, &params.tracking_pk, &mut rng))
            .collect();
        let sig = aggregate(&partials, &params, 0, 1).unwrap();

        // verify() takes only NetworkPublicParams (public keys) — no secrets
        assert!(verify(&params, msg, &sig));
    }

    #[test]
    fn test_lagrange_sum_equals_one() {
        let quorum = vec![1u16, 3, 5];
        let lambdas = lagrange_coefficients_at_zero(&quorum);
        let sum: Scalar = lambdas.iter().fold(Scalar::zero(), |a, x| a.add(x));
        assert_eq!(sum, Scalar::one());
    }

    #[test]
    fn test_bitmap_commitment() {
        let q1 = vec![1u16, 2, 3];
        let q2 = vec![3u16, 2, 1]; // same members, different order
        let c1 = create_bitmap_commitment(&q1, 1);
        let c2 = create_bitmap_commitment(&q2, 1);
        assert_eq!(c1, c2, "Bitmap commitment must be order-independent");

        let c3 = create_bitmap_commitment(&q1, 2);
        assert_ne!(c1, c3, "Different aggregator = different commitment");
    }
}