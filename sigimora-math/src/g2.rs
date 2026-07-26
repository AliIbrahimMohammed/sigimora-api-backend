//! G₂ group element wrapper over `blstrs::G2Projective`.
//!
//! Elements of G₂ live on the twisted curve E'(𝔽_q²) of BLS12-381.
//! This is the "long" group used for public keys in the BLS signature scheme.
//!
//! Points are stored in projective coordinates for efficient computation
//! and serialized in compressed form (96 bytes).

use blstrs::{G2Affine, G2Projective};
use group::{Curve, Group};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::error::MathError;
use crate::scalar::Scalar;

/// An element of G₂, the group on E'(𝔽_q²) of BLS12-381.
///
/// Compressed serialization is 96 bytes. The generator g₂ is the
/// standard BLS12-381 generator point for the twist curve.
#[derive(Clone, Debug)]
pub struct G2Point(pub(crate) G2Projective);

impl Serialize for G2Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for G2Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8> as serde::Deserialize>::deserialize(deserializer)?;
        if bytes.len() != 96 {
            return Err(serde::de::Error::custom("expected 96 bytes"));
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        G2Point::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

// ── Equality ─────────────────────────────────────────────────────────
impl PartialEq for G2Point {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_affine() == other.0.to_affine()
    }
}

impl Eq for G2Point {}

// ── Constructors ─────────────────────────────────────────────────────
impl G2Point {
    /// Number of bytes for compressed G2 point (96 bytes for BLS12-381).
    pub const BYTE_SIZE: usize = 96;

    /// The standard generator g₂ ∈ G₂ of BLS12-381.
    pub fn generator() -> Self {
        G2Point(G2Projective::generator())
    }

    /// The identity element (point at infinity) in G₂.
    pub fn identity() -> Self {
        G2Point(G2Projective::identity())
    }

    /// Check if this point is the identity (point at infinity).
    pub fn is_identity(&self) -> bool {
        bool::from(self.0.is_identity())
    }
}

// ── Group operations ─────────────────────────────────────────────────
impl G2Point {
    /// Scalar multiplication: [s]·P ∈ G₂.
    ///
    /// For BLS, the public key is pk = [sk]·g₂, computed via this method.
    pub fn mul(&self, s: &Scalar) -> G2Point {
        G2Point(self.0 * s.0)
    }

    /// Point addition: P + Q ∈ G₂.
    ///
    /// Used for combining public keys: pk_agg = pk₁ + pk₂ + …
    pub fn add(&self, rhs: &G2Point) -> G2Point {
        G2Point(self.0 + rhs.0)
    }

    /// Point subtraction: P - Q ∈ G₂.
    pub fn sub(&self, rhs: &G2Point) -> G2Point {
        G2Point(self.0 - rhs.0)
    }

    /// Point negation: -P ∈ G₂.
    pub fn negate(&self) -> G2Point {
        G2Point(-self.0)
    }
}

// ── Serialization (compressed, 96 bytes) ─────────────────────────────
impl G2Point {
    /// Serialize to 96 bytes (compressed big-endian format).
    pub fn to_bytes(&self) -> [u8; 96] {
        let affine = self.0.to_affine();
        use group::GroupEncoding;
        let repr = affine.to_bytes();
        let mut out = [0u8; 96];
        out.copy_from_slice(repr.as_ref());
        out
    }

    /// Deserialize from 96 bytes (compressed big-endian format).
    ///
    /// Validates that the point is on the curve and in the correct subgroup.
    pub fn from_bytes(b: &[u8; 96]) -> Result<G2Point, MathError> {
        use group::GroupEncoding;
        let mut repr = <G2Affine as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(b);
        let affine = G2Affine::from_bytes(&repr);
        if affine.is_some().into() {
            Ok(G2Point(G2Projective::from(affine.unwrap())))
        } else {
            Err(MathError::InvalidG2Point)
        }
    }
}

// ── Operator overloads ───────────────────────────────────────────────
impl std::ops::Add for &G2Point {
    type Output = G2Point;
    fn add(self, rhs: Self) -> G2Point {
        G2Point::add(self, rhs)
    }
}

impl std::ops::Sub for &G2Point {
    type Output = G2Point;
    fn sub(self, rhs: Self) -> G2Point {
        G2Point::sub(self, rhs)
    }
}

impl std::ops::Neg for &G2Point {
    type Output = G2Point;
    fn neg(self) -> G2Point {
        G2Point::negate(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_not_identity() {
        let g = G2Point::generator();
        assert!(!g.is_identity());
    }

    #[test]
    fn test_identity() {
        let id = G2Point::identity();
        assert!(id.is_identity());
    }

    #[test]
    fn test_add_identity() {
        let g = G2Point::generator();
        let sum = g.add(&G2Point::identity());
        assert_eq!(g, sum);
    }

    #[test]
    fn test_add_inverse() {
        let g = G2Point::generator();
        let neg_g = g.negate();
        let sum = g.add(&neg_g);
        assert!(sum.is_identity());
    }

    #[test]
    fn test_scalar_mul_identity() {
        let g = G2Point::generator();
        let result = g.mul(&Scalar::one());
        assert_eq!(g, result);
    }

    #[test]
    fn test_scalar_mul_zero() {
        let g = G2Point::generator();
        let result = g.mul(&Scalar::zero());
        assert!(result.is_identity());
    }

    #[test]
    fn test_linearity() {
        // [a]g₂ + [b]g₂ == [a+b]g₂
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g = G2Point::generator();

        let lhs = g.mul(&a).add(&g.mul(&b));
        let rhs = g.mul(&a.add(&b));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let s = Scalar::random(&mut rng);
        let p = G2Point::generator().mul(&s);

        let bytes = p.to_bytes();
        let recovered = G2Point::from_bytes(&bytes).unwrap();
        assert_eq!(p, recovered);
    }

    #[test]
    fn test_identity_serialization() {
        let id = G2Point::identity();
        let bytes = id.to_bytes();
        let recovered = G2Point::from_bytes(&bytes).unwrap();
        assert!(recovered.is_identity());
    }
}
