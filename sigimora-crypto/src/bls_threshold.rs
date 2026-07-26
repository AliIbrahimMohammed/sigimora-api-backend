//! Accountable Threshold BLS (ATS-BLS)
//!
//! A threshold signature scheme with accountability where exactly which signers
//! participated can be determined from the final signature.
//!
//! ## Independent Keys Model
//!
//! Unlike traditional threshold schemes where shares of a single secret are
//! distributed, here each signer has an INDEPENDENT key (x_i, X_i = g_2^{x_i}).
//!
//! Collective key for quorum J (|J| ≥ t):
//! - x_J = Σ_{j∈J} λ_j^J · x_j
//! - pk_J = g_2^{x_J} = ∏_{j∈J} pk_j^{λ_j^J}
//!
//! Sign:    σ_i = H(m)^{x_i}
//! Combine: Y = ∏ σ_j^{λ_j^J} = H(m)^{x_J}
//! Verify:  e(Y, g_2) = e(H(m), pk_J)
//!
//! Proactive refresh: zero polynomial keeps collective key invariant

use sigimora_math::{hash_to_g1, pairing, G1Point, G2Point};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::pedersen::{PedersenSetup, VssPublic, PrivatePoly as PedersenPrivatePoly};
use crate::shamir::Share;

pub type ParticipantId = u16;

/// A threshold signing key with one share of the group secret.
///
/// # Security
/// - `share` is zeroized on drop
/// - `Debug` redacts secret fields
pub struct ThresholdSigningKey {
    pub share: Share,
    pub individual_pk: G2Point,
}

impl std::fmt::Debug for ThresholdSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdSigningKey")
            .field("share", &"[REDACTED]")
            .field("individual_pk", &self.individual_pk)
            .finish()
    }
}

impl Zeroize for ThresholdSigningKey {
    fn zeroize(&mut self) {
        self.share.zeroize();
    }
}

impl Drop for ThresholdSigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Clone is safe with manual zeroize (copy-out semantics)
impl Clone for ThresholdSigningKey {
    fn clone(&self) -> Self {
        ThresholdSigningKey {
            share: self.share.clone(),
            individual_pk: self.individual_pk.clone(),
        }
    }
}

impl ThresholdSigningKey {
    pub fn new(share: Share, individual_pk: G2Point) -> Self {
        ThresholdSigningKey { share, individual_pk }
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
pub struct ThresholdSignature {
    pub sigma: G1Point,
    pub signers: Vec<ParticipantId>,
    pub threshold: usize,
}

impl ThresholdSignature {
    pub fn new(sigma: G1Point, signers: Vec<ParticipantId>, threshold: usize) -> Self {
        ThresholdSignature { sigma, signers, threshold }
    }

    pub fn verify(&self, msg: &[u8], group_pk: &G2Point) -> bool {
        let h = hash_to_g1(msg, b"BLS_ATS");
        pairing::ct_verify_bls_signature(&self.sigma, &h, group_pk).into()
    }

    pub fn who_signed(&self) -> &[ParticipantId] {
        &self.signers
    }
}

pub struct AtsBls;

impl AtsBls {
    pub fn sign_partial(sk: &ThresholdSigningKey, msg: &[u8]) -> PartialSignature {
        let h = hash_to_g1(msg, b"BLS_ATS");
        let sigma = h.mul(&sk.share.value);
        PartialSignature::new(sk.share.index, sigma)
    }

    pub fn verify_partial(
        partial: &PartialSignature,
        ipk: &G2Point,
        msg: &[u8],
    ) -> bool {
        let h = hash_to_g1(msg, b"BLS_ATS");
        pairing::ct_verify_bls_signature(&partial.sigma, &h, ipk).into()
    }

    pub fn aggregate(
        partials: &[PartialSignature],
        threshold: usize,
    ) -> Result<ThresholdSignature, CryptoError> {
        if partials.len() < threshold {
            return Err(CryptoError::InvalidParameter(
                format!("need at least {} partials, got {}", threshold, partials.len())
            ));
        }

        let signers: Vec<ParticipantId> = partials.iter().map(|p| p.signer_id).collect();
        let lambdas = crate::shamir::lagrange_at_zero(&signers);

        let mut combined_sigma = G1Point::identity();
        for (partial, lambda) in partials.iter().zip(lambdas.iter()) {
            let weighted = partial.sigma.mul(lambda);
            combined_sigma = combined_sigma.add(&weighted);
        }

        Ok(ThresholdSignature::new(combined_sigma, signers, threshold))
    }

    pub fn proactive_refresh(
        current_share: &Share,
        ped: &PedersenSetup,
    ) -> (Share, VssPublic) {
        let refresh_poly = PedersenPrivatePoly::random_with_zero_constant(2, ped);
        let new_share_value = current_share.value.add(&refresh_poly.eval(current_share.index).value);
        let new_share = Share {
            index: current_share.index,
            value: new_share_value,
        };
        let refresh_commitments = refresh_poly.commit();

        (new_share, refresh_commitments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use sigimora_math::Scalar;
    use crate::pedersen::PedersenSetup;

    #[test]
    fn test_ats_signing() {
        let n = 3;
        let threshold = 2;
        let _ped = PedersenSetup::deterministic();

        let mut signing_keys: Vec<ThresholdSigningKey> = Vec::new();
        for i in 1..=n {
            let sk = Scalar::random(&mut thread_rng());
            let pk = G2Point::generator().mul(&sk);
            let share = Share { index: i, value: sk };
            signing_keys.push(ThresholdSigningKey::new(share, pk));
        }

        let msg = b"ATS test message";
        let partials: Vec<PartialSignature> = signing_keys.iter()
            .map(|sk| AtsBls::sign_partial(sk, msg))
            .collect();

        let sig = AtsBls::aggregate(&partials, threshold).unwrap();

        let signers: Vec<u16> = sig.who_signed().to_vec();
        let lambdas = crate::shamir::lagrange_at_zero(&signers);
        let mut collective_pk = G2Point::identity();
        for (i, lambda) in signers.iter().zip(lambdas.iter()) {
            let pk = G2Point::generator().mul(&signing_keys[(*i as usize) - 1].share.value);
            collective_pk = collective_pk.add(&pk.mul(lambda));
        }

        assert!(sig.verify(msg, &collective_pk));
    }

    #[test]
    fn test_ats_threshold_2_of_3() {
        let n = 3;
        let threshold = 2;
        let _ped = PedersenSetup::deterministic();

        let mut signing_keys: Vec<ThresholdSigningKey> = Vec::new();
        for i in 1..=n {
            let sk = Scalar::random(&mut thread_rng());
            let pk = G2Point::generator().mul(&sk);
            let share = Share { index: i, value: sk };
            signing_keys.push(ThresholdSigningKey::new(share, pk));
        }

        let msg = b"threshold test";
        let partials: Vec<PartialSignature> = signing_keys.iter()
            .take(2)
            .map(|sk| AtsBls::sign_partial(sk, msg))
            .collect();

        let sig = AtsBls::aggregate(&partials, threshold).unwrap();

        let signers: Vec<u16> = sig.who_signed().to_vec();
        let lambdas = crate::shamir::lagrange_at_zero(&signers);
        let mut collective_pk = G2Point::identity();
        for (i, lambda) in signers.iter().zip(lambdas.iter()) {
            let pk = G2Point::generator().mul(&signing_keys[(*i as usize) - 1].share.value);
            collective_pk = collective_pk.add(&pk.mul(lambda));
        }

        assert!(sig.verify(msg, &collective_pk));
        assert_eq!(sig.who_signed().len(), 2);
    }

    #[test]
    fn test_proactive_refresh() {
        let ped = PedersenSetup::deterministic();

        let share = Share {
            index: 1,
            value: Scalar::random(&mut thread_rng()),
        };

        let (new_share, _commitments) = AtsBls::proactive_refresh(&share, &ped);

        assert_eq!(new_share.index, share.index);
        assert!(!new_share.value.is_zero());
    }
}