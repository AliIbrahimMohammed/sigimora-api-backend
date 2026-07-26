//! BLS signature scheme: key generation, signing, verification, aggregation.
//!
//! Mathematical specification:
//! ```text
//! KeyGen:  sk ∈ Z_r (random);  pk = [sk]·g₂ ∈ G₂
//! Sign:    σ = [sk]·H(m) ∈ G₁      where H = hash_to_g1
//! Verify:  e(σ, g₂) == e(H(m), pk)
//! Aggregate: σ_agg = σ₁ + σ₂ + … ∈ G₁
//! AggVerify: e(σ_agg, g₂) == e(H(m), pk₁ + pk₂ + …)
//! ProofOfPossession: pop = [sk]·H(pk)  (rogue-key resistance)
//! ```

use rand_core::RngCore;
use zeroize::Zeroize;
use sigimora_math::{hash_to_g1, G1Point, G2Point, Scalar};

use crate::error::CryptoError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(pub Scalar);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretKey {
    pub fn new(scalar: Scalar) -> Self {
        SecretKey(scalar)
    }

    pub fn random(rng: &mut impl RngCore) -> Self {
        SecretKey(Scalar::random(rng))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(G2Point::generator().mul(&self.0))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let h = hash_to_g1(msg, b"SIGIMORA-BLS");
        Signature(h.mul(&self.0))
    }

    pub fn proof_of_possession(&self) -> Signature {
        let h = hash_to_g1(&self.public_key().to_bytes(), b"SIGIMORA-POP");
        Signature(h.mul(&self.0))
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub G2Point);

impl PublicKey {
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        use sigimora_math::pairing::ct_verify_bls_signature;
        let h = hash_to_g1(msg, b"SIGIMORA-BLS");
        ct_verify_bls_signature(&sig.0, &h, &self.0).into()
    }

    pub fn verify_pop(&self, pop: &Signature) -> bool {
        use sigimora_math::pairing::ct_verify_bls_signature;
        let h = hash_to_g1(&self.to_bytes(), b"SIGIMORA-POP");
        ct_verify_bls_signature(&pop.0, &h, &self.0).into()
    }

    pub fn aggregate(keys: &[PublicKey]) -> PublicKey {
        let mut agg = G2Point::identity();
        for key in keys {
            agg = agg.add(&key.0);
        }
        PublicKey(agg)
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    pub fn from_bytes(b: &[u8; 96]) -> Result<Self, CryptoError> {
        G2Point::from_bytes(b).map(PublicKey).map_err(|_| CryptoError::InvalidPublicKey)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub G1Point);

impl Signature {
    pub fn new(point: G1Point) -> Self {
        Signature(point)
    }

    pub fn aggregate(sigs: &[Signature]) -> Signature {
        let mut agg = G1Point::identity();
        for sig in sigs {
            agg = agg.add(&sig.0);
        }
        Signature(agg)
    }

    pub fn verify_aggregate(agg_pk: &PublicKey, msg: &[u8], agg_sig: &Signature) -> bool {
        use sigimora_math::pairing::ct_verify_bls_signature;
        let h = hash_to_g1(msg, b"SIGIMORA-BLS");
        ct_verify_bls_signature(&agg_sig.0, &h, &agg_pk.0).into()
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }

    pub fn from_bytes(b: &[u8; 48]) -> Result<Self, CryptoError> {
        G1Point::from_bytes(b).map(Signature).map_err(|_| CryptoError::InvalidSignature)
    }
}