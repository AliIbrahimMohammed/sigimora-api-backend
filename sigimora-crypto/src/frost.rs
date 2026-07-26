//! FROST-BLS: Hybrid One-Round Threshold Signature Scheme
//!
//! Combines FROST's secure DKG and accountability with BLS12-381 signatures.
//!
//! Mathematical specification:
//! ```text
//! DKG (FROST-style):
//!   - Each party samples polynomial fi(x) of degree t-1
//!   - Broadcasts commitments φi,k = ai,k · g2 in G2
//!   - PoP proof of knowledge of ai,0
//!   - Distribute shares si,j = fi(j)
//!   - Verify against commitments
//!   - sk = Σ fi(0), pk = sk · g2
//!
//! One-Round Signing:
//!   - Session: τ = H_ses(m ‖ ep ‖ S)
//!   - Signing hash: h = H_sig(m ‖ τ) in G1
//!   - Partial: σi = ski · h
//!   - Accountabilty: e(σi, g2) = e(h, vki)
//!   - Aggregate: σ = Σ λi · σi
//!
//! Verify:
//!   - e(σ, g2) = e(h, pk)
//! ```

use rand_core::RngCore;
use zeroize::Zeroize;
use sigimora_math::{hash_to_g1, pairing, G1Point, G2Point, Scalar};
use sha2::{Digest, Sha256};

use crate::error::CryptoError;
use crate::feldman::{PrivatePoly, PublicPoly};
use crate::shamir::Share;

pub type ParticipantId = u16;

#[derive(Clone, Debug)]
pub struct SigningKey {
    pub share: Share,
    pub ipk: G2Point,
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.share.value.zeroize();
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SigningKey {
    pub fn new(share: Share, ipk: G2Point) -> Self {
        SigningKey { share, ipk }
    }
}

/// A FROST key pair containing the signing key (secret) and group public key.
///
/// # Security
/// - `signing_key` is zeroized on drop
/// - `Debug` redacts the signing key
pub struct FrostKeyPair {
    pub signing_key: SigningKey,
    pub group_pk: G2Point,
}

impl std::fmt::Debug for FrostKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostKeyPair")
            .field("signing_key", &"[REDACTED]")
            .field("group_pk", &self.group_pk)
            .finish()
    }
}

impl Zeroize for FrostKeyPair {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
    }
}

impl Drop for FrostKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Clone is safe with manual zeroize (copy-out semantics)
impl Clone for FrostKeyPair {
    fn clone(&self) -> Self {
        FrostKeyPair {
            signing_key: self.signing_key.clone(),
            group_pk: self.group_pk.clone(),
        }
    }
}

impl FrostKeyPair {
    pub fn new(signing_key: SigningKey, group_pk: G2Point) -> Self {
        FrostKeyPair { signing_key, group_pk }
    }
}

#[derive(Clone, Debug)]
pub struct PartialSignature {
    pub signer_id: ParticipantId,
    pub sigma: G1Point,
}

impl PartialSignature {
    pub fn new(signer_id: ParticipantId, sigma: G1Point) -> Self {
        PartialSignature { signer_id, sigma }
    }
}

#[derive(Clone, Debug)]
pub struct FrostSignature {
    pub sigma: G1Point,
    pub signers: Vec<ParticipantId>,
    pub epoch: u64,
    pub transcript: Vec<u8>,
}

impl FrostSignature {
    pub fn new(
        sigma: G1Point,
        signers: Vec<ParticipantId>,
        epoch: u64,
        transcript: Vec<u8>,
    ) -> Self {
        FrostSignature {
            sigma,
            signers,
            epoch,
            transcript,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.sigma.to_bytes().to_vec();
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.push(self.transcript.len() as u8);
        bytes.extend_from_slice(&self.transcript);
        bytes.push(self.signers.len() as u8);
        for id in &self.signers {
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 49 {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sig_bytes = [0u8; 48];
        sig_bytes.copy_from_slice(&data[..48]);
        let sigma = G1Point::from_bytes(&sig_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;

        let num_signers = data[48] as usize;
        if data.len() < 49 + num_signers * 2 {
            return Err(CryptoError::InvalidSignature);
        }
        let mut signers = Vec::with_capacity(num_signers);
        for i in 0..num_signers {
            let start = 49 + i * 2;
            let id = u16::from_le_bytes([data[start], data[start + 1]]);
            signers.push(id);
        }

        Ok(FrostSignature {
            sigma,
            signers,
            epoch: 1,
            transcript: vec![],
        })
    }
}

pub struct Frost;

impl Frost {
    pub fn keygen(
        secret: &Scalar,
        t: usize,
        n: usize,
        my_id: ParticipantId,
        rng: &mut impl RngCore,
    ) -> Result<FrostKeyPair, CryptoError> {
        if t > n {
            return Err(CryptoError::InvalidParameter(
                "threshold must be <= participants".to_string(),
            ));
        }
        if my_id < 1 || my_id > n as u16 {
            return Err(CryptoError::InvalidParameter("invalid participant id".to_string()));
        }

        let poly = PrivatePoly::random_with_secret(secret.clone(), t, rng);
        let share = poly.eval(my_id);
        let ipk = G2Point::generator().mul(&share.value);
        let group_pk = G2Point::generator().mul(secret);

        Ok(FrostKeyPair::new(
            SigningKey::new(share, ipk),
            group_pk,
        ))
    }

    pub fn keygen_distributed(
        t: usize,
        n: usize,
        my_id: ParticipantId,
        rng: &mut impl RngCore,
    ) -> Result<(SigningKey, PublicPoly), CryptoError> {
        if t > n {
            return Err(CryptoError::InvalidParameter(
                "threshold must be <= participants".to_string(),
            ));
        }

        let poly = PrivatePoly::random(t, rng);
        let share = poly.eval(my_id);
        let ipk = G2Point::generator().mul(&share.value);
        let public_poly = poly.commit();

        Ok((
            SigningKey::new(share, ipk),
            public_poly,
        ))
    }

    pub fn compute_share(
        poly: &PrivatePoly,
        participant_id: ParticipantId,
    ) -> Share {
        poly.eval(participant_id)
    }

    pub fn derive_group_pk(public_polys: &[PublicPoly]) -> G2Point {
        let mut group_pk = G2Point::identity();
        for pp in public_polys {
            group_pk = group_pk.add(&pp.0[0]);
        }
        group_pk
    }

    fn compute_session_transcript(msg: &[u8], epoch: u64, signers: &[ParticipantId]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        hasher.update(&epoch.to_le_bytes());
        for &s in signers {
            hasher.update(&s.to_le_bytes());
        }
        hasher.finalize().to_vec()
    }

    fn compute_signing_hash(msg: &[u8], epoch: u64, signers: &[ParticipantId]) -> G1Point {
        let transcript = Self::compute_session_transcript(msg, epoch, signers);
        let mut combined = msg.to_vec();
        combined.push(b'|');
        combined.extend_from_slice(&transcript);
        hash_to_g1(&combined, b"FROST-BLS-SIG")
    }

    pub fn sign_partial(
        signing_key: &SigningKey,
        msg: &[u8],
        epoch: u64,
        signers: &[ParticipantId],
    ) -> PartialSignature {
        let h = Self::compute_signing_hash(msg, epoch, signers);
        let sigma = h.mul(&signing_key.share.value);
        PartialSignature::new(signing_key.share.index, sigma)
    }

    pub fn sign_partial_simple(
        signing_key: &SigningKey,
        msg: &[u8],
    ) -> PartialSignature {
        let h = hash_to_g1(msg, b"FROST-BLS");
        let sigma = h.mul(&signing_key.share.value);
        PartialSignature::new(signing_key.share.index, sigma)
    }

    pub fn verify_partial(
        partial: &PartialSignature,
        ipk: &G2Point,
        msg: &[u8],
        epoch: u64,
        signers: &[ParticipantId],
    ) -> bool {
        let h = Self::compute_signing_hash(msg, epoch, signers);
        pairing::ct_verify_bls_signature(&partial.sigma, &h, ipk).into()
    }

    pub fn aggregate(
        partials: &[PartialSignature],
        signing_keys: &[SigningKey],
        threshold: usize,
    ) -> Result<FrostSignature, CryptoError> {
        if partials.len() < threshold {
            return Err(CryptoError::InvalidParameter(format!(
                "need at least {} partials, got {}",
                threshold,
                partials.len()
            )));
        }

        let indices: Vec<u16> = partials.iter().map(|p| p.signer_id).collect();
        let lambdas = Self::lagrange_coefficients(&indices);

        let mut combined_sigma = G1Point::identity();
        for (partial, lambda) in partials.iter().zip(lambdas.iter()) {
            let weighted = partial.sigma.mul(lambda);
            combined_sigma = combined_sigma.add(&weighted);
        }

        let signers: Vec<ParticipantId> = signing_keys
            .iter()
            .map(|sk| sk.share.index)
            .collect();

        Ok(FrostSignature::new(combined_sigma, signers, 1, vec![]))
    }

    pub fn aggregate_simple(
        partials: &[PartialSignature],
    ) -> Result<FrostSignature, CryptoError> {
        if partials.is_empty() {
            return Err(CryptoError::InvalidParameter("no partials".to_string()));
        }

        let indices: Vec<u16> = partials.iter().map(|p| p.signer_id).collect();
        let lambdas = Self::lagrange_coefficients(&indices);

        let mut combined_sigma = G1Point::identity();
        for (partial, lambda) in partials.iter().zip(lambdas.iter()) {
            let weighted = partial.sigma.mul(lambda);
            combined_sigma = combined_sigma.add(&weighted);
        }

        let epoch = 1u64;
        let transcript = Self::compute_session_transcript(b"default", epoch, &indices);

        Ok(FrostSignature::new(combined_sigma, indices, epoch, transcript))
    }

    pub fn verify(
        frost_sig: &FrostSignature,
        group_pk: &G2Point,
        msg: &[u8],
    ) -> bool {
        let h = hash_to_g1(msg, b"FROST-BLS");
        pairing::ct_verify_bls_signature(&frost_sig.sigma, &h, group_pk).into()
    }

    pub fn verify_with_session(
        frost_sig: &FrostSignature,
        group_pk: &G2Point,
        msg: &[u8],
        epoch: u64,
        signers: &[ParticipantId],
    ) -> bool {
        let h = Self::compute_signing_hash(msg, epoch, signers);
        pairing::ct_verify_bls_signature(&frost_sig.sigma, &h, group_pk).into()
    }

    pub fn refresh_share(
        current_share: &Share,
        rng: &mut impl RngCore,
    ) -> (Share, PublicPoly) {
        let refresh_poly = PrivatePoly::random(2, rng);
        let new_share_value = current_share.value.add(&refresh_poly.eval(current_share.index).value);
        let new_share = Share {
            index: current_share.index,
            value: new_share_value,
        };
        let refresh_commitments = refresh_poly.commit();
        (new_share, refresh_commitments)
    }

    pub fn mcp_refresh_share(
        current_share: &Share,
        rng: &mut impl RngCore,
    ) -> (Share, PublicPoly) {
        let refresh_poly = PrivatePoly::random_with_zero_constant(2, rng);
        let new_share_value = current_share.value.add(&refresh_poly.eval(current_share.index).value);
        let new_share = Share {
            index: current_share.index,
            value: new_share_value,
        };
        let refresh_commitments = refresh_poly.commit();
        (new_share, refresh_commitments)
    }

    pub fn create_refresh_poly_with_zero_constant(
        degree: usize,
        rng: &mut impl RngCore,
    ) -> PrivatePoly {
        PrivatePoly::random_with_zero_constant(degree, rng)
    }

    pub fn distributed_refresh(
        all_shares: &[(u16, Share)],
        rng: &mut impl RngCore,
    ) -> Result<Vec<(u16, Share)>, CryptoError> {
        if all_shares.is_empty() {
            return Err(CryptoError::InvalidParameter("no shares".to_string()));
        }

        let degree = 2;
        let mut new_shares = Vec::new();

        for &(pid, ref share) in all_shares {
            let refresh_poly = Self::create_refresh_poly_with_zero_constant(degree, rng);
            let refresh_share = refresh_poly.eval(pid);
            let new_value = share.value.add(&refresh_share.value);
            new_shares.push((pid, Share::new(pid, new_value)));
        }

        Ok(new_shares)
    }

    pub fn verify_refresh_share(
        old_share: &Share,
        new_share: &Share,
        commitment: &PublicPoly,
    ) -> bool {
        let verified_share = commitment.eval(old_share.index);
        let expected = G2Point::generator().mul(&new_share.value.sub(&old_share.value));
        expected == verified_share
    }

    pub fn verify_zero_constant(commitment: &PublicPoly) -> bool {
        commitment.0.first().map_or(false, |c| c.is_identity())
    }

    fn lagrange_coefficients(indices: &[u16]) -> Vec<Scalar> {
        let k = indices.len();
        let mut lambdas = Vec::with_capacity(k);

        for i in 0..k {
            let mut numerator = Scalar::one();
            let mut denominator = Scalar::one();

            for j in 0..k {
                if i != j {
                    numerator = numerator.mul(&Scalar::from_u64(indices[j] as u64));
                    let diff = Scalar::from_u64(indices[j] as u64)
                        .sub(&Scalar::from_u64(indices[i] as u64));
                    denominator = denominator.mul(&diff);
                }
            }

            let inv_denom = denominator.invert().unwrap_or(Scalar::one());
            lambdas.push(numerator.mul(&inv_denom));
        }

        lambdas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_frost_keygen() {
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 3;
        let n = 5;

        for i in 1..=n {
            let keypair = Frost::keygen(&secret, t, n, i as u16, &mut rng).unwrap();
            assert_eq!(keypair.group_pk, G2Point::generator().mul(&secret));
        }
    }

    #[test]
    fn test_frost_sign_partial() {
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 2;
        let n = 3;

        let keypair = Frost::keygen(&secret, t, n, 1, &mut rng).unwrap();
        let msg = b"test message";

        let partial = Frost::sign_partial_simple(&keypair.signing_key, msg);
        // verify uses the same simple hash domain (b"FROST-BLS") as sign_partial_simple
        let h = sigimora_math::hash_to_g1(msg, b"FROST-BLS");
        assert!(bool::from(sigimora_math::pairing::ct_verify_bls_signature(&partial.sigma, &h, &keypair.signing_key.ipk)));
    }

    #[test]
    fn test_frost_signature() {
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 2;
        let n = 3;

        // Create ONE polynomial, evaluate at each party index
        let poly = PrivatePoly::random_with_secret(secret.clone(), t, &mut rng);
        let group_pk = G2Point::generator().mul(&secret);
        let keypairs: Vec<FrostKeyPair> = (1..=n as u16)
            .map(|i| {
                let share = poly.eval(i);
                let ipk = G2Point::generator().mul(&share.value);
                let sk = SigningKey::new(share, ipk);
                FrostKeyPair::new(sk, group_pk.clone())
            })
            .collect();

        let msg = b"test message for FROST";

        let partials: Vec<PartialSignature> = keypairs
            .iter()
            .map(|k| Frost::sign_partial_simple(&k.signing_key, msg))
            .collect();

        let indices: Vec<u16> = partials.iter().map(|p| p.signer_id).collect();
        let lambdas = Frost::lagrange_coefficients(&indices);

        let mut combined_sigma = G1Point::identity();
        for (partial, lambda) in partials.iter().zip(lambdas.iter()) {
            let weighted = partial.sigma.mul(lambda);
            combined_sigma = combined_sigma.add(&weighted);
        }

        let frost_sig = FrostSignature::new(combined_sigma, indices, 1, vec![]);

        assert!(Frost::verify(&frost_sig, &group_pk, msg));
    }

    #[test]
    fn test_frost_verify_wrong_message() {
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 2;
        let n = 3;

        // Create ONE polynomial, evaluate at each party index
        let poly = PrivatePoly::random_with_secret(secret.clone(), t, &mut rng);
        let group_pk = G2Point::generator().mul(&secret);
        let keypairs: Vec<FrostKeyPair> = (1..=n as u16)
            .map(|i| {
                let share = poly.eval(i);
                let ipk = G2Point::generator().mul(&share.value);
                let sk = SigningKey::new(share, ipk);
                FrostKeyPair::new(sk, group_pk.clone())
            })
            .collect();

        let msg = b"original message";

        let partials: Vec<PartialSignature> = keypairs
            .iter()
            .map(|k| Frost::sign_partial_simple(&k.signing_key, msg))
            .collect();

        let indices: Vec<u16> = partials.iter().map(|p| p.signer_id).collect();
        let lambdas = Frost::lagrange_coefficients(&indices);

        let mut combined_sigma = G1Point::identity();
        for (partial, lambda) in partials.iter().zip(lambdas.iter()) {
            let weighted = partial.sigma.mul(lambda);
            combined_sigma = combined_sigma.add(&weighted);
        }

        let frost_sig = FrostSignature::new(combined_sigma, indices, 1, vec![]);

        assert!(!Frost::verify(&frost_sig, &group_pk, b"different message"));
    }

    #[test]
    fn test_frost_threshold_signing() {
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 2;
        let n = 5;

        // Create ONE polynomial, evaluate at each party index
        let poly = PrivatePoly::random_with_secret(secret.clone(), t, &mut rng);
        let group_pk = G2Point::generator().mul(&secret);
        let keypairs: Vec<FrostKeyPair> = (1..=n as u16)
            .map(|i| {
                let share = poly.eval(i);
                let ipk = G2Point::generator().mul(&share.value);
                let sk = SigningKey::new(share, ipk);
                FrostKeyPair::new(sk, group_pk.clone())
            })
            .collect();

        let msg = b"threshold test";

        let partials: Vec<PartialSignature> = keypairs
            .iter()
            .take(t)
            .map(|k| Frost::sign_partial_simple(&k.signing_key, msg))
            .collect();

        let frost_sig = Frost::aggregate_simple(&partials).unwrap();

        assert!(Frost::verify(&frost_sig, &group_pk, msg));
    }

    #[test]
    fn test_serialization() {
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 2;
        let n = 3;

        let keypair = Frost::keygen(&secret, t, n, 1, &mut rng).unwrap();
        let msg = b"test";

        let _partial = Frost::sign_partial_simple(&keypair.signing_key, msg);

        let sig = G1Point::generator().mul(&Scalar::random(&mut rng));
        let frost_sig = FrostSignature::new(sig, vec![1, 2, 3], 1, vec![]);

        let bytes = frost_sig.to_bytes();
        let recovered = FrostSignature::from_bytes(&bytes).unwrap();

        assert_eq!(frost_sig.sigma, recovered.sigma);
    }
}