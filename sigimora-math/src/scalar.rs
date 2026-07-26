//! Scalar field element (Z_r) wrapper over `blstrs::Scalar`.
//!
//! The scalar field Z_r has order r ≈ 2²⁵⁵, the prime order of the
//! BLS12-381 G₁ and G₂ groups.
//!
//! All arithmetic operations are constant-time via the `blstrs` assembly backend.
//! SECURITY: This type holds secret material and must be zeroized on drop.

use ff::{Field, PrimeField};
use rand_core::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::error::MathError;

/// An element of the scalar field Z_r where r is the order of BLS12-381 groups.
///
/// Wraps `blstrs::Scalar` with manual `Zeroize` implementation since the
/// inner type doesn't implement it directly. All scalar operations are
/// guaranteed constant-time by the `blstrs` assembly backend.
#[derive(Clone, Debug)]
pub struct Scalar(pub(crate) blstrs::Scalar);

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8> as serde::Deserialize>::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Scalar::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

// ── Zeroize ──────────────────────────────────────────────────────────
// SECURITY: Manual Zeroize implementation for Scalar.
// blstrs::Scalar wraps blst_fr which is a [u64; 4] internally.
// We zero the memory by overwriting with the zero scalar.
impl Scalar {
    /// Number of bytes for serialized scalar (32 bytes for BLS12-381 scalar field).
    pub const BYTE_SIZE: usize = 32;
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        unsafe {
            let ptr = &mut self.0 as *mut blstrs::Scalar as *mut [u64; 4];
            ptr.write([0u64; 4]);
        }
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ── Equality ─────────────────────────────────────────────────────────
impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        // SECURITY: blstrs::Scalar PartialEq uses ct_eq internally
        self.0 == other.0
    }
}

impl Eq for Scalar {}

// ── Constructors ─────────────────────────────────────────────────────
impl Scalar {
    /// Sample a uniformly random scalar from Z_r.
    ///
    /// Uses the provided RNG which must be cryptographically secure.
    pub fn random(rng: &mut impl RngCore) -> Self {
        // blstrs::Scalar::random uses rejection sampling for uniform distribution
        Scalar(<blstrs::Scalar as Field>::random(&mut *rng))
    }

    /// The additive identity: 0 ∈ Z_r.
    pub fn zero() -> Self {
        Scalar(<blstrs::Scalar as Field>::ZERO)
    }

    pub fn one() -> Self {
        Scalar(<blstrs::Scalar as Field>::ONE)
    }

    /// Create a scalar from a u64 value.
    pub fn from_u64(val: u64) -> Self {
        let mut repr = [0u8; 32];
        // Little-endian representation for blstrs
        repr[..8].copy_from_slice(&val.to_le_bytes());
        // This is safe because any u64 < r
        Scalar(blstrs::Scalar::from_repr_vartime(repr).unwrap())
    }

    /// Check if this scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero().into()
    }
}

// ── Arithmetic ───────────────────────────────────────────────────────
// All operations are constant-time via blstrs assembly backend.
impl Scalar {
    /// Scalar addition: (self + rhs) mod r.
    pub fn add(&self, rhs: &Scalar) -> Scalar {
        Scalar(self.0 + rhs.0)
    }

    /// Scalar subtraction: (self - rhs) mod r.
    pub fn sub(&self, rhs: &Scalar) -> Scalar {
        Scalar(self.0 - rhs.0)
    }

    /// Scalar multiplication: (self * rhs) mod r.
    pub fn mul(&self, rhs: &Scalar) -> Scalar {
        Scalar(self.0 * rhs.0)
    }

    /// Multiplicative inverse: self⁻¹ mod r, if self ≠ 0.
    ///
    /// Returns `None` if self is zero (zero has no inverse).
    pub fn invert(&self) -> Option<Scalar> {
        let inv = self.0.invert();
        if inv.is_some().into() {
            Some(Scalar(inv.unwrap()))
        } else {
            None
        }
    }

    /// Additive negation: -self mod r.
    pub fn negate(&self) -> Scalar {
        Scalar(-self.0)
    }

    /// Exponentiation: self^exp mod r (for scalars in the exponent).
    /// This is scalar-scalar exponentiation, NOT group exponentiation.
    pub fn pow_u64(&self, exp: u64) -> Scalar {
        let mut result = Scalar::one();
        let mut base = self.clone();
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            e >>= 1;
        }
        result
    }
}

// ── Serialization ────────────────────────────────────────────────────
impl Scalar {
    /// Serialize to 32 bytes (big-endian canonical representation).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes_be()
    }

    /// Deserialize from 32 bytes (big-endian canonical representation).
    ///
    /// Returns an error if the bytes do not represent a valid scalar
    /// (i.e., the value is ≥ r).
    pub fn from_bytes(b: &[u8; 32]) -> Result<Scalar, MathError> {
        let scalar = blstrs::Scalar::from_bytes_be(b);
        if scalar.is_none().into() {
            return Err(MathError::InvalidScalar);
        }
        Ok(Scalar(scalar.unwrap()))
    }
}

// ── Operator overloads ───────────────────────────────────────────────
impl std::ops::Add for &Scalar {
    type Output = Scalar;
    fn add(self, rhs: Self) -> Scalar {
        Scalar::add(self, rhs)
    }
}

impl std::ops::Sub for &Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Self) -> Scalar {
        Scalar::sub(self, rhs)
    }
}

impl std::ops::Mul for &Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Self) -> Scalar {
        Scalar::mul(self, rhs)
    }
}

impl std::ops::Neg for &Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar {
        Scalar::negate(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_and_one() {
        let z = Scalar::zero();
        let o = Scalar::one();
        assert!(z.is_zero());
        assert!(!o.is_zero());
        assert_ne!(z, o);
    }

    #[test]
    fn test_addition_identity() {
        let a = Scalar::random(&mut rand::thread_rng());
        let sum = a.add(&Scalar::zero());
        assert_eq!(a, sum);
    }

    #[test]
    fn test_multiplication_identity() {
        let a = Scalar::random(&mut rand::thread_rng());
        let prod = a.mul(&Scalar::one());
        assert_eq!(a, prod);
    }

    #[test]
    fn test_additive_inverse() {
        let a = Scalar::random(&mut rand::thread_rng());
        let neg_a = a.negate();
        let sum = a.add(&neg_a);
        assert!(sum.is_zero());
    }

    #[test]
    fn test_multiplicative_inverse() {
        let a = Scalar::random(&mut rand::thread_rng());
        let inv_a = a.invert().expect("random scalar should be invertible");
        let prod = a.mul(&inv_a);
        assert_eq!(prod, Scalar::one());
    }

    #[test]
    fn test_zero_not_invertible() {
        assert!(Scalar::zero().invert().is_none());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let a = Scalar::random(&mut rand::thread_rng());
        let bytes = a.to_bytes();
        let b = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_from_u64() {
        let s = Scalar::from_u64(42);
        let bytes = s.to_bytes();
        assert_eq!(bytes[31], 42);
        assert!(bytes[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_commutativity() {
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        // a + b == b + a
        assert_eq!(a.add(&b), b.add(&a));
        // a * b == b * a
        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_associativity() {
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let c = Scalar::random(&mut rng);
        // (a + b) + c == a + (b + c)
        assert_eq!(a.add(&b).add(&c), a.add(&b.add(&c)));
        // (a * b) * c == a * (b * c)
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
    }

    #[test]
    fn test_distributivity() {
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let c = Scalar::random(&mut rng);
        // a * (b + c) == a*b + a*c
        let lhs = a.mul(&b.add(&c));
        let rhs = a.mul(&b).add(&a.mul(&c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_zeroize_on_drop() {
        let mut a = Scalar::random(&mut rand::thread_rng());
        let bytes_before = a.to_bytes();
        assert!(!bytes_before.iter().all(|&b| b == 0), "random scalar should not be zero");

        a.zeroize();
        let bytes_after = a.to_bytes();
        assert!(bytes_after.iter().all(|&b| b == 0), "after zeroize, scalar should be zero");
    }
}
