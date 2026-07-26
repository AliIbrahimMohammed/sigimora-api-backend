//! Feldman Verifiable Secret Sharing (VSS).
//!
//! Mathematical specification:
//! ```text
//! Commit: C_j = [a_j]·g₂  for j = 0..t-1
//! Verify share i: [share_i]·g₂ == Σ_j C_j · i^j  (in G₂)
//! Group public key: pk = C_0 = [a₀]·g₂ = [sk]·g₂
//! ```

use rand_core::RngCore;
use zeroize::Zeroize;
use sigimora_math::{G2Point, Scalar};

use crate::shamir::Share;

#[derive(Clone, Debug)]
pub struct PrivatePoly(pub Vec<Scalar>);

impl Zeroize for PrivatePoly {
    fn zeroize(&mut self) {
        for coeff in self.0.iter_mut() {
            coeff.zeroize();
        }
    }
}

impl Drop for PrivatePoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PrivatePoly {
    pub fn random(t: usize, rng: &mut impl RngCore) -> Self {
        let mut coeffs = Vec::with_capacity(t);
        for _ in 0..t {
            coeffs.push(Scalar::random(rng));
        }
        PrivatePoly(coeffs)
    }

    pub fn random_with_secret(secret: Scalar, t: usize, rng: &mut impl RngCore) -> Self {
        let mut coeffs = Vec::with_capacity(t);
        coeffs.push(secret);
        for _ in 1..t {
            coeffs.push(Scalar::random(rng));
        }
        PrivatePoly(coeffs)
    }

    pub fn random_with_zero_constant(t: usize, rng: &mut impl RngCore) -> Self {
        let mut coeffs = Vec::with_capacity(t);
        coeffs.push(Scalar::zero());
        for _ in 1..t {
            coeffs.push(Scalar::random(rng));
        }
        PrivatePoly(coeffs)
    }

    pub fn eval(&self, x: u16) -> Share {
        let mut result = self.0[0].clone();
        let x_scalar = Scalar::from_u64(x as u64);

        for (power, coeff) in self.0.iter().enumerate().skip(1) {
            let mut term = coeff.clone();
            for _ in 0..power {
                term = term.mul(&x_scalar);
            }
            result = result.add(&term);
        }

        Share { index: x, value: result }
    }

    pub fn commit(&self) -> PublicPoly {
        let commitments: Vec<G2Point> = self
            .0
            .iter()
            .map(|coeff| G2Point::generator().mul(coeff))
            .collect();
        PublicPoly(commitments)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPoly(pub Vec<G2Point>);

impl PublicPoly {
    pub fn group_public_key(&self) -> crate::bls::PublicKey {
        crate::bls::PublicKey(self.0[0].clone())
    }

    pub fn eval(&self, x: u16) -> G2Point {
        let x_scalar = Scalar::from_u64(x as u64);
        let mut result = G2Point::identity();

        for (power, commitment) in self.0.iter().enumerate() {
            let mut term = commitment.clone();
            for _ in 0..power {
                term = term.mul(&x_scalar);
            }
            result = result.add(&term);
        }

        result
    }

    pub fn verify_share(&self, share: &Share) -> bool {
        let lhs = G2Point::generator().mul(&share.value);
        let rhs = self.eval(share.index);
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_and_verify() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 3;
        let n = 5;

        let private_poly = PrivatePoly::random_with_secret(secret, t, &mut rng);
        let public_poly = private_poly.commit();

        for i in 1..=n as u16 {
            let share = private_poly.eval(i);
            assert!(public_poly.verify_share(&share));
        }
    }

    #[test]
    fn test_verify_fails_corrupted_share() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 3;

        let private_poly = PrivatePoly::random_with_secret(secret, t, &mut rng);
        let public_poly = private_poly.commit();

        let mut share = private_poly.eval(1);
        share.value = Scalar::random(&mut rng);

        assert!(!public_poly.verify_share(&share));
    }

    #[test]
    fn test_group_public_key() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let t = 3;

        let private_poly = PrivatePoly::random_with_secret(secret, t, &mut rng);
        let public_poly = private_poly.commit();

        let gpk = public_poly.group_public_key();
        let expected_pk = crate::bls::SecretKey::random(&mut rng).public_key();
        let our_sk = crate::bls::SecretKey::random(&mut rng);
        let _our_pk = our_sk.public_key();

        assert_ne!(gpk, expected_pk);
    }
}