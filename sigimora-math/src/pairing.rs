//! Bilinear pairing operations: e: G₁ × G₂ → G_T.
//!
//! The BLS12-381 pairing satisfies the bilinearity property:
//!   e([a]P, [b]Q) = e(P, Q)^{ab}  for all a, b ∈ Z_r
//!
//! This is the mathematical foundation of BLS signatures:
//!   Verify: e(σ, g₂) == e(H(m), pk)
//!   where σ = [sk]·H(m) and pk = [sk]·g₂
//!   ⟹ e([sk]·H(m), g₂) = e(H(m), [sk]·g₂)  ✓ by bilinearity

use blstrs::{Bls12, G1Affine, G2Prepared};
use group::Curve;
use pairing::{MillerLoopResult, MultiMillerLoop};
use subtle::Choice;

use crate::g1::G1Point;
use crate::g2::G2Point;
use crate::gt::GtElement;

/// Compute the optimal Ate pairing e(p, q) → G_T.
///
/// This is the core operation for BLS signature verification:
///   e(σ, g₂) == e(H(m), pk)
pub fn pairing(p: &G1Point, q: &G2Point) -> GtElement {
    // Convert to affine for the pairing computation
    let p_affine = p.0.to_affine();
    let q_affine = q.0.to_affine();

    // Compute the optimal Ate pairing via multi-Miller loop + final exponentiation
    let result = Bls12::multi_miller_loop(&[(&p_affine, &G2Prepared::from(q_affine))])
        .final_exponentiation();
    GtElement(result)
}

/// Compute a multi-pairing (product of pairings) efficiently.
///
/// Computes: ∏ᵢ e(pᵢ, qᵢ) using a single multi-Miller loop followed
/// by one final exponentiation. This is significantly faster than
/// computing individual pairings and multiplying.
///
/// Used for batch verification and pairing equality checks.
pub fn multi_pairing(pairs: &[(&G1Point, &G2Point)]) -> GtElement {
    if pairs.is_empty() {
        return GtElement::identity();
    }

    // Convert all points to affine
    let affine_pairs: Vec<(G1Affine, G2Prepared)> = pairs
        .iter()
        .map(|(p, q)| {
            (p.0.to_affine(), G2Prepared::from(q.0.to_affine()))
        })
        .collect();

    // Build references for the multi_miller_loop call
    let refs: Vec<(&G1Affine, &G2Prepared)> = affine_pairs
        .iter()
        .map(|(p, q)| (p, q))
        .collect();

    let result = Bls12::multi_miller_loop(&refs).final_exponentiation();
    GtElement(result)
}

/// Check a pairing product equation efficiently.
///
/// Returns true if: e(a1, b1) · e(a2, b2) == G_T::identity
///
/// This is useful for signature verification where we check:
///   e(σ, g₂) · e(-H(m), pk) == 1
/// which is equivalent to e(σ, g₂) == e(H(m), pk).
///
/// # Security
/// This function uses variable-time `is_identity()`. For constant-time
/// verification, use `ct_pairing_check` instead.
pub fn pairing_check(a1: &G1Point, b1: &G2Point, a2: &G1Point, b2: &G2Point) -> bool {
    let result = multi_pairing(&[(a1, b1), (a2, b2)]);
    result.is_identity()
}

/// Constant-time pairing product equation check.
///
/// Returns a `subtle::Choice` indicating whether:
///   e(a1, b1) · e(a2, b2) == G_T::identity
///
/// This is the constant-time equivalent of `pairing_check`, suitable for
/// signature verification where timing side-channels must be avoided.
///
/// # Usage
/// ```ignore
/// use subtle::ConstantTimeEq;
/// // Verify BLS signature: e(σ, g₂) == e(H(m), pk)
/// // Equivalent to: e(σ, g₂) · e(-H(m), pk) == 1
/// if ct_pairing_check(&sigma, &G2Point::generator(), &neg_hash, &pk).into() {
///     // signature valid
/// }
/// ```
pub fn ct_pairing_check(a1: &G1Point, b1: &G2Point, a2: &G1Point, b2: &G2Point) -> Choice {
    let result = multi_pairing(&[(a1, b1), (a2, b2)]);
    result.ct_is_identity()
}

/// Convenience function for the standard BLS signature verification equation:
///   e(sig, g₂) == e(H(m), pk)
///
/// Returns a `Choice` for constant-time use. Equivalent to:
/// ```ignore
/// ct_pairing_check(sig, &G2Point::generator(), &hash.negate(), &pk)
/// ```
pub fn ct_verify_bls_signature(sig: &G1Point, hash: &G1Point, pk: &G2Point) -> Choice {
    let neg_hash = hash.negate();
    ct_pairing_check(sig, &G2Point::generator(), &neg_hash, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::Scalar;
    use crate::g1::hash_to_g1;

    #[test]
    fn test_pairing_non_degenerate() {
        // e(g₁, g₂) ≠ 1 (non-degenerate pairing)
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let result = pairing(&g1, &g2);
        assert!(!result.is_identity());
    }

    #[test]
    fn test_pairing_identity_g1() {
        // e(O, g₂) == 1 (pairing with identity gives identity)
        let id = G1Point::identity();
        let g2 = G2Point::generator();
        let result = pairing(&id, &g2);
        assert!(result.is_identity());
    }

    #[test]
    fn test_pairing_identity_g2() {
        // e(g₁, O) == 1
        let g1 = G1Point::generator();
        let id = G2Point::identity();
        let result = pairing(&g1, &id);
        assert!(result.is_identity());
    }

    #[test]
    fn test_bilinearity() {
        // Core bilinearity test:
        // e([a]g₁, [b]g₂) == e(g₁, g₂)^{ab}
        //
        // We verify this by checking the equivalent form:
        // e([a]g₁, [b]g₂) == e([ab]g₁, g₂)
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        // LHS: e([a]g₁, [b]g₂)
        let lhs = pairing(&g1.mul(&a), &g2.mul(&b));

        // RHS: e([a·b]g₁, g₂)
        let ab = a.mul(&b);
        let rhs = pairing(&g1.mul(&ab), &g2);

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_bilinearity_symmetric() {
        // Another bilinearity form:
        // e([a]g₁, [b]g₂) == e(g₁, [ab]g₂)
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let lhs = pairing(&g1.mul(&a), &g2.mul(&b));
        let ab = a.mul(&b);
        let rhs = pairing(&g1, &g2.mul(&ab));

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_bls_signature_equation() {
        // Simulate BLS signature verification:
        //   sk ∈ Z_r, pk = [sk]g₂, σ = [sk]H(m)
        //   Verify: e(σ, g₂) == e(H(m), pk)
        let mut rng = rand::thread_rng();
        let sk = Scalar::random(&mut rng);
        let pk = G2Point::generator().mul(&sk);
        let msg = b"test message for BLS";
        let h = hash_to_g1(msg, b"SIGIMORA-BLS-SIG");
        let sigma = h.mul(&sk); // σ = [sk]·H(m)

        let lhs = pairing(&sigma, &G2Point::generator());
        let rhs = pairing(&h, &pk);
        assert_eq!(lhs, rhs, "BLS signature equation must hold");
    }

    #[test]
    fn test_multi_pairing_matches_individual() {
        let mut rng = rand::thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let p1 = g1.mul(&a);
        let p2 = g1.mul(&b);
        let q1 = g2.mul(&b);
        let q2 = g2.mul(&a);

        // Multi-pairing: e(p1, q1) · e(p2, q2)
        let multi = multi_pairing(&[(&p1, &q1), (&p2, &q2)]);

        // Individual: e(p1, q1) · e(p2, q2)
        let e1 = pairing(&p1, &q1);
        let e2 = pairing(&p2, &q2);
        let individual = e1.mul(&e2);

        assert_eq!(multi, individual);
    }

    #[test]
    fn test_pairing_check() {
        // e(σ, g₂) · e(-H(m), pk) == 1  iff  e(σ, g₂) == e(H(m), pk)
        let mut rng = rand::thread_rng();
        let sk = Scalar::random(&mut rng);
        let pk = G2Point::generator().mul(&sk);
        let h = hash_to_g1(b"pairing check test", b"SIGIMORA-BLS-SIG");
        let sigma = h.mul(&sk);

        // This should be true (valid signature)
        let neg_h = h.negate();
        assert!(pairing_check(&sigma, &G2Point::generator(), &neg_h, &pk));

        // With wrong message, should fail
        let h_wrong = hash_to_g1(b"wrong message", b"SIGIMORA-BLS-SIG");
        let neg_h_wrong = h_wrong.negate();
        assert!(!pairing_check(&sigma, &G2Point::generator(), &neg_h_wrong, &pk));
    }

    #[test]
    fn test_multi_pairing_empty() {
        let result = multi_pairing(&[]);
        assert!(result.is_identity());
    }

    #[test]
    fn test_bilinearity_numerical() {
        // Numerical test: e([3]g₁, [5]g₂) == e([15]g₁, g₂)
        let three = Scalar::from_u64(3);
        let five = Scalar::from_u64(5);
        let fifteen = Scalar::from_u64(15);
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let lhs = pairing(&g1.mul(&three), &g2.mul(&five));
        let rhs = pairing(&g1.mul(&fifteen), &g2);
        assert_eq!(lhs, rhs, "e([3]g₁, [5]g₂) must equal e([15]g₁, g₂)");
    }
}
