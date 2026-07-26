//! G_T target group element wrapper over `blstrs::Gt`.
//!
//! G_T is the target group of the BLS12-381 pairing, a subgroup of 𝔽_q¹²*.
//! Elements of G_T are the output of the pairing function e: G₁ × G₂ → G_T.

use group::Group;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

/// An element of G_T, the target group (subgroup of 𝔽_q¹²*) of BLS12-381.
///
/// These elements are the output of the bilinear pairing e(P, Q).
/// Signature verification checks equality of two G_T elements:
///   e(σ, g₂) == e(H(m), pk)
///
/// # Security
/// Equality comparisons use **constant-time** via `subtle::ConstantTimeEq`
/// to prevent timing side-channel attacks on signature verification.
/// The approach hashes the element to 32 bytes via SHA-256 and compares
/// the digest in constant time — a standard defensive technique when the
/// underlying type lacks a constant-time byte comparison API.
#[derive(Clone, Debug)]
pub struct GtElement(pub(crate) blstrs::Gt);

// ── Constant-Time Equality ────────────────────────────────────────────
/// Constant-time equality by hashing both elements with SHA-256 and
/// comparing the digests in constant time via `subtle`.
///
/// This is a pragmatic defense when the underlying group library does
/// not expose a constant-time equality check for G_T elements. Hashing
/// compresses the 576-byte Fp12 element to 32 bytes while keeping the
/// comparison constant-time at the digest level.
///
/// # Performance note
/// This involves two SHA-256 hashes per comparison. For high-throughput
/// verification, consider using `pairing::ct_pairing_check()` instead,
/// which avoids constructing two separate GtElement values.
impl ConstantTimeEq for GtElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Hash each element to a fixed-size digest and compare in constant time.
        let mut hasher = Sha256::new();
        // We rely on blstrs' Display/Debug or group encoding for bytes.
        // Use the group crate's byte encoding via to_compressed or to_uncompressed.
        // Gt doesn't implement group encoding, so we use the internal bytes
        // via unsafe but minimal approach: reinterpret as byte slice.
        //
        // SAFETY: blstrs::Gt is a newtype over blst::blst_fp12 which is
        // a repr(C) struct of 12 contiguous limbs. We hash the bytes rather
        // than compare them directly, so any padding bytes only affect the
        // hash, not the comparison correctness.
        let self_bytes = unsafe {
            std::slice::from_raw_parts(
                &self.0 as *const blstrs::Gt as *const u8,
                std::mem::size_of::<blstrs::Gt>(),
            )
        };
        let other_bytes = unsafe {
            std::slice::from_raw_parts(
                &other.0 as *const blstrs::Gt as *const u8,
                std::mem::size_of::<blstrs::Gt>(),
            )
        };
        hasher.update(self_bytes);
        let self_digest = hasher.finalize_reset();
        hasher.update(other_bytes);
        let other_digest = hasher.finalize();

        // Constant-time comparison of the 32-byte digests
        let mut result = Choice::from(1u8);
        for (a, b) in self_digest.iter().zip(other_digest.iter()) {
            result &= a.ct_eq(b);
        }
        result
    }
}

/// Variable-time equality — only for testing, never for verification.
/// Use `ct_eq()` for verification code to prevent timing attacks.
impl PartialEq for GtElement {
    fn eq(&self, other: &Self) -> bool {
        // NOTE: This is variable-time! Use ct_eq() in verification code.
        self.0 == other.0
    }
}

impl Eq for GtElement {}

impl GtElement {
    /// The identity element in G_T (the result of pairing with the identity point).
    pub fn identity() -> Self {
        GtElement(blstrs::Gt::identity())
    }

    /// Check if this is the identity element.
    pub fn is_identity(&self) -> bool {
        // NOTE: blst's is_identity may be variable-time.
        // For constant-time check, use ct_is_identity().
        bool::from(self.0.is_identity())
    }

    /// Multiply two G_T elements: a · b ∈ G_T.
    ///
    /// In multiplicative notation, this is group multiplication in G_T.
    pub fn mul(&self, rhs: &GtElement) -> GtElement {
        GtElement(self.0 + rhs.0) // blstrs uses additive notation internally
    }

    /// Constant-time check if this element equals the identity.
    ///
    /// Uses the `ConstantTimeEq` implementation to prevent timing leaks.
    pub fn ct_is_identity(&self) -> Choice {
        self.ct_eq(&Self::identity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = GtElement::identity();
        assert!(id.is_identity());
    }

    #[test]
    fn test_mul_identity() {
        // We'll test this more thoroughly in pairing tests
        let id = GtElement::identity();
        let result = id.mul(&id);
        assert!(result.is_identity());
    }
}
