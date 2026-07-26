//! Shamir Secret Sharing over Z_r.
//!
//! Mathematical specification:
//! ```text
//! Share:      polynomial f(x) = a₀ + a₁x + … + a_{t-1}·x^{t-1}
//!             secret = f(0) = a₀ = sk
//!             share_i = (i, f(i))  for i = 1..n
//!
//! Reconstruct: Lagrange coefficients for subset S ⊆ {1..n}, |S| = t
//!             λ_i = ∏_{j∈S, j≠i}  j · (j−i)⁻¹  mod r
//!             secret = Σ_{i∈S} λ_i · share_i  mod r
//! ```

use rand_core::RngCore;
use zeroize::Zeroize;
use sigimora_math::Scalar;

use crate::error::CryptoError;

// ── Canonical Lagrange Coefficients ──────────────────────────────────
// Single source of truth for the entire workspace.

/// Compute Lagrange basis coefficients evaluated at x = 0.
///
/// For indices {x₁, x₂, …, xₖ}, computes:
///   λᵢ(0) = ∏_{j≠i} (0 - xⱼ) / (xᵢ - xⱼ)
///         = ∏_{j≠i} (-xⱼ) / (xᵢ - xⱼ)
///
/// Property: Σᵢ λᵢ(0) = 1  (partition of unity at 0).
/// Used for secret reconstruction and threshold signature aggregation.
pub fn lagrange_at_zero(indices: &[u16]) -> Vec<Scalar> {
    let k = indices.len();
    let mut lambdas = Vec::with_capacity(k);

    for i in 0..k {
        let mut num = Scalar::one();
        let mut den = Scalar::one();
        let xi = Scalar::from_u64(indices[i] as u64);

        for j in 0..k {
            if i == j { continue; }
            let xj = Scalar::from_u64(indices[j] as u64);
            // numerator: ∏ (-xⱼ)
            num = num.mul(&xj.negate());
            // denominator: ∏ (xᵢ - xⱼ)
            den = den.mul(&xi.sub(&xj));
        }

        let inv_den = den.invert().expect("Lagrange denominator must be invertible (indices must be distinct)");
        lambdas.push(num.mul(&inv_den));
    }

    lambdas
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub index: u16,
    pub value: Scalar,
}

impl Share {
    pub fn new(index: u16, value: Scalar) -> Self {
        Share { index, value }
    }
}

impl Zeroize for Share {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct ShamirSSS;

impl ShamirSSS {
    pub fn split(secret: &Scalar, t: usize, n: usize, rng: &mut impl RngCore) -> Vec<Share> {
        assert!(t <= n, "threshold must be <= total participants");
        assert!(t > 0, "threshold must be > 0");

        let mut coefficients = Vec::with_capacity(t);
        coefficients.push(secret.clone());
        for _ in 1..t {
            coefficients.push(Scalar::random(rng));
        }

        let mut shares = Vec::with_capacity(n);
        for i in 1..=n as u16 {
            let mut value = coefficients[0].clone();
            for (power, coeff) in coefficients.iter().enumerate().skip(1) {
                let mut term = coeff.clone();
                for _ in 0..power {
                    term = term.mul(&Scalar::from_u64(i as u64));
                }
                value = value.add(&term);
            }
            shares.push(Share { index: i, value });
        }
        shares
    }

    pub fn reconstruct(shares: &[Share]) -> Result<Scalar, CryptoError> {
        if shares.is_empty() {
            return Err(CryptoError::InvalidShares);
        }

        let indices: Vec<u16> = shares.iter().map(|s| s.index).collect();
        let lambdas = lagrange_at_zero(&indices);

        let mut secret = Scalar::zero();
        for (share, lambda) in shares.iter().zip(lambdas.iter()) {
            let term = share.value.mul(lambda);
            secret = secret.add(&term);
        }

        Ok(secret)
    }

    /// Wrapper around the canonical `lagrange_at_zero` for backward compatibility.
    pub fn lagrange_coefficients(indices: &[u16]) -> Vec<Scalar> {
        lagrange_at_zero(indices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reconstruct() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 3;
        let n = 5;

        let shares = ShamirSSS::split(&secret, t, n, &mut rng);
        assert_eq!(shares.len(), n);

        let reconstructed = ShamirSSS::reconstruct(&shares[..t]).unwrap();
        assert_eq!(secret, reconstructed);
    }

    #[test]
    fn test_reconstruct_different_subsets() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 3;
        let n = 5;

        let shares = ShamirSSS::split(&secret, t, n, &mut rng);

        let recon1 = ShamirSSS::reconstruct(&shares[0..3]).unwrap();
        let recon2 = ShamirSSS::reconstruct(&shares[1..4]).unwrap();
        let recon3 = ShamirSSS::reconstruct(&shares[2..5]).unwrap();

        assert_eq!(secret, recon1);
        assert_eq!(secret, recon2);
        assert_eq!(secret, recon3);
    }

    #[test]
    fn test_reconstruct_with_insufficient_shares_gives_wrong_result() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 3;
        let n = 5;

        let shares = ShamirSSS::split(&secret, t, n, &mut rng);
        let reconstructed = ShamirSSS::reconstruct(&shares[0..2]).unwrap();
        assert_ne!(secret, reconstructed);
    }

    #[test]
    fn test_lagrange_coefficients() {
        let indices = [1u16, 2, 3];
        let coeffs = ShamirSSS::lagrange_coefficients(&indices);

        assert_eq!(coeffs.len(), 3);
    }
}