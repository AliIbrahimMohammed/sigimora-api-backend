//! G₁ group element wrapper over `blstrs::G1Projective`.
//!
//! Elements of G₁ live on the curve E(𝔽_q): y² = x³ + 4 over the base field
//! of BLS12-381. This is the "short" group used for signatures in the
//! BLS signature scheme.
//!
//! Points are stored in projective coordinates for efficient computation
//! and serialized in compressed form (48 bytes).

use blstrs::{G1Affine, G1Projective};
use group::{Curve, Group};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::error::MathError;
use crate::scalar::Scalar;

extern "C" {
    fn blst_hash_to_g1(
        output: *mut blst::blst_p1,
        msg: *const u8,
        msg_len: usize,
        DST: *const u8,
        DST_len: usize,
        aug: *const u8,
        aug_len: usize,
    );
}

/// An element of G₁, the group on E(𝔽_q) of BLS12-381.
///
/// Compressed serialization is 48 bytes. The generator g₁ is the
/// standard BLS12-381 generator point.
#[derive(Clone, Debug)]
pub struct G1Point(pub(crate) G1Projective);

impl Serialize for G1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for G1Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8> as serde::Deserialize>::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom("expected 48 bytes"));
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        G1Point::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

// ── Equality ─────────────────────────────────────────────────────────
impl PartialEq for G1Point {
    fn eq(&self, other: &Self) -> bool {
        // Convert to affine for reliable comparison
        self.0.to_affine() == other.0.to_affine()
    }
}

impl Eq for G1Point {}

// ── Constructors ─────────────────────────────────────────────────────
impl G1Point {
    /// The standard generator g₁ ∈ G₁ of BLS12-381.
    pub fn generator() -> Self {
        G1Point(G1Projective::generator())
    }

    /// The identity element (point at infinity) in G₁.
    pub fn identity() -> Self {
        G1Point(G1Projective::identity())
    }

    /// Check if this point is the identity (point at infinity).
    pub fn is_identity(&self) -> bool {
        bool::from(self.0.is_identity())
    }
}

// ── Group operations ─────────────────────────────────────────────────
impl G1Point {
    /// Scalar multiplication: [s]·P ∈ G₁.
    ///
    /// This is the fundamental operation for BLS signatures:
    /// σ = [sk]·H(m) is computed via this method.
    pub fn mul(&self, s: &Scalar) -> G1Point {
        // blstrs implements constant-time scalar multiplication via assembly
        G1Point(self.0 * s.0)
    }

    /// Point addition: P + Q ∈ G₁.
    ///
    /// Used for aggregating signatures: σ_agg = σ₁ + σ₂ + …
    pub fn add(&self, rhs: &G1Point) -> G1Point {
        G1Point(self.0 + rhs.0)
    }

    /// Point subtraction: P - Q ∈ G₁.
    pub fn sub(&self, rhs: &G1Point) -> G1Point {
        G1Point(self.0 - rhs.0)
    }

    /// Point negation: -P ∈ G₁.
    pub fn negate(&self) -> G1Point {
        G1Point(-self.0)
    }
}

// ── Serialization (compressed, 48 bytes) ─────────────────────────────
impl G1Point {
    /// Serialize to 48 bytes (compressed big-endian format).
    ///
    /// The compressed format stores the x-coordinate and a sign bit
    /// for the y-coordinate, following the ZCash serialization convention.
    pub fn to_bytes(&self) -> [u8; 48] {
        let affine = self.0.to_affine();
        use group::GroupEncoding;
        let repr = affine.to_bytes();
        let mut out = [0u8; 48];
        out.copy_from_slice(repr.as_ref());
        out
    }

    /// Deserialize from 48 bytes (compressed big-endian format).
    ///
    /// Validates that the point is on the curve and in the correct subgroup.
    pub fn from_bytes(b: &[u8; 48]) -> Result<G1Point, MathError> {
        use group::GroupEncoding;
        let mut repr = <G1Affine as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(b);
        let affine = G1Affine::from_bytes(&repr);
        if affine.is_some().into() {
            Ok(G1Point(G1Projective::from(affine.unwrap())))
        } else {
            Err(MathError::InvalidG1Point)
        }
    }
}

// ── Hash-to-curve ────────────────────────────────────────────────────

/// Hash an arbitrary message to a point on G₁.
///
/// Uses the IETF RFC 9380 suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`.
/// This is the H(m) function in the BLS signature scheme:
///   σ = [sk]·H(m)
///
/// The `dst` parameter is the domain separation tag, which must be unique
/// per application to prevent cross-protocol attacks.
pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1Point {
    let mut point = unsafe { std::mem::zeroed::<blst::blst_p1>() };
    unsafe {
        blst_hash_to_g1(
            &mut point,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            std::ptr::null(),
            0,
        );
    }
    unsafe {
        G1Point(std::mem::transmute::<blst::blst_p1, blstrs::G1Projective>(point))
    }
}

pub fn hash_to_g1_with_epoch(msg: &[u8], dst: &[u8], epoch: u64) -> G1Point {
    let mut msg_with_epoch = msg.to_vec();
    msg_with_epoch.extend_from_slice(&epoch.to_le_bytes());
    hash_to_g1(&msg_with_epoch, dst)
}

// ── Operator overloads ───────────────────────────────────────────────
impl std::ops::Add for &G1Point {
    type Output = G1Point;
    fn add(self, rhs: Self) -> G1Point {
        G1Point::add(self, rhs)
    }
}

impl std::ops::Sub for &G1Point {
    type Output = G1Point;
    fn sub(self, rhs: Self) -> G1Point {
        G1Point::sub(self, rhs)
    }
}

impl std::ops::Neg for &G1Point {
    type Output = G1Point;
    fn neg(self) -> G1Point {
        G1Point::negate(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_not_identity() {
        let g = G1Point::generator();
        assert!(!g.is_identity());
    }

    #[test]
    fn test_identity() {
        let id = G1Point::identity();
        assert!(id.is_identity());
    }

    #[test]
    fn test_add_identity() {
        let g = G1Point::generator();
        let sum = g.add(&G1Point::identity());
        assert_eq!(g, sum);
    }

    #[test]
    fn test_add_inverse() {
        let g = G1Point::generator();
        let neg_g = g.negate();
        let sum = g.add(&neg_g);
        assert!(sum.is_identity());
    }

    #[test]
    fn test_scalar_mul_identity() {
        // [1]·G = G
        let g = G1Point::generator();
        let result = g.mul(&Scalar::one());
        assert_eq!(g, result);
    }

    #[test]
    fn test_scalar_mul_zero() {
        // [0]·G = identity
        let g = G1Point::generator();
        let result = g.mul(&Scalar::zero());
        assert!(result.is_identity());
    }

    #[test]
    fn test_linearity() {
        // [a]G + [b]G == [a+b]G
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g = G1Point::generator();

        let lhs = g.mul(&a).add(&g.mul(&b));
        let rhs = g.mul(&a.add(&b));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_scalar_mul_associativity() {
        // [a]([b]G) == [a*b]G
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g = G1Point::generator();

        let lhs = g.mul(&b).mul(&a);
        let rhs = g.mul(&a.mul(&b));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let s = Scalar::random(&mut rng);
        let p = G1Point::generator().mul(&s);

        let bytes = p.to_bytes();
        let recovered = G1Point::from_bytes(&bytes).unwrap();
        assert_eq!(p, recovered);
    }

    #[test]
    fn test_identity_serialization() {
        let id = G1Point::identity();
        let bytes = id.to_bytes();
        let recovered = G1Point::from_bytes(&bytes).unwrap();
        assert!(recovered.is_identity());
    }

    #[test]
    fn test_hash_to_g1_non_identity() {
        let h = hash_to_g1(b"test message", b"SIGIMORA-V1");
        assert!(!h.is_identity());
    }

    #[test]
    fn test_hash_to_g1_deterministic() {
        let h1 = hash_to_g1(b"test message", b"SIGIMORA-V1");
        let h2 = hash_to_g1(b"test message", b"SIGIMORA-V1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_to_g1_different_messages() {
        let h1 = hash_to_g1(b"message 1", b"SIGIMORA-V1");
        let h2 = hash_to_g1(b"message 2", b"SIGIMORA-V1");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_to_g1_different_dst() {
        let h1 = hash_to_g1(b"same message", b"DST-1");
        let h2 = hash_to_g1(b"same message", b"DST-2");
        assert_ne!(h1, h2);
    }
}
