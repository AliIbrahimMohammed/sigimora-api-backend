//! Pedersen Verifiable Secret Sharing (VSS) on G1.
//!
//! Uses TWO generators g and h to provide statistical hiding of the secret.
//! Commitment: C(v, r) = g^v · h^r (commits to value v with blinding r)
//!
//! Mathematical specification:
//! ```text
//! Share secret s with threshold t among n parties:
//!   f(x) = s + a₁x + … + a_{t-1}x^{t-1}   (secret poly)
//!   r(x) = r₀ + b₁x + … + b_{t-1}x^{t-1}  (blinding poly)
//!   C_k   = g^{a_k} · h^{b_k}    for k = 0..t-1  (broadcast)
//!   send i: (f(i), r(i))  (private to party i)
//!
//! Verify share i: g^{s_i} · h^{ρ_i} == ∏_{k=0}^{t-1} C_k^{i^k}
//!
//! Reconstruct: s = Σ λ_j(0) · s_j  (Lagrange at 0, any t shares)
//! ```

use rand::rngs::OsRng;
use std::fmt::{Debug, Formatter};
use zeroize::Zeroize;
use sigimora_math::{G1Point, Scalar};

pub struct PedersenSetup {
    pub g: G1Point,
    pub h: G1Point,
}

impl Clone for PedersenSetup {
    fn clone(&self) -> Self {
        Self { g: self.g.clone(), h: self.h.clone() }
    }
}

impl Debug for PedersenSetup {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PedersenSetup").finish()
    }
}

impl PedersenSetup {
    pub fn new() -> Self {
        let alpha = Scalar::random(&mut OsRng);
        Self {
            g: G1Point::generator(),
            h: G1Point::generator().mul(&alpha),
        }
    }

    pub fn deterministic() -> Self {
        use sigimora_math::hash_to_g1;
        let h = hash_to_g1(b"BLS_PEDERSEN_H_NUMS_2024", b"SIGIMORA");
        Self {
            g: G1Point::generator(),
            h,
        }
    }

    pub fn commit(&self, v: &Scalar, r: &Scalar) -> G1Point {
        self.g.mul(v).add(&self.h.mul(r))
    }
}

impl Default for PedersenSetup {
    fn default() -> Self {
        Self::deterministic()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VssPublic {
    pub commitments: Vec<G1Point>,
}

impl VssPublic {
    pub fn verify_share(&self, index: u16, value: &Scalar, blinding: &Scalar, ped: &PedersenSetup) -> bool {
        let lhs = ped.commit(value, blinding);
        let x = Scalar::from_u64(index as u64);
        let mut rhs = G1Point::identity();
        let mut xpow = Scalar::one();
        for ck in &self.commitments {
            rhs = rhs.add(&ck.mul(&xpow));
            xpow = xpow.mul(&x);
        }
        lhs == rhs
    }

    pub fn secret_commitment(&self) -> &G1Point {
        &self.commitments[0]
    }
}

/// A verifiable secret share with a blinding factor.
///
/// # Security
/// - `value` and `blinding` are zeroized on drop
/// - `Debug` redacts secret fields
pub struct VssShare {
    pub index: u16,
    pub value: Scalar,
    pub blinding: Scalar,
}

impl std::fmt::Debug for VssShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VssShare")
            .field("index", &self.index)
            .field("value", &"[REDACTED]")
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

// Custom Serialize/Deserialize that still serialize the fields (needed for DKG)
impl serde::Serialize for VssShare {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("VssShare", 3)?;
        s.serialize_field("index", &self.index)?;
        s.serialize_field("value", &self.value)?;
        s.serialize_field("blinding", &self.blinding)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for VssShare {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};
        struct VssShareVisitor;
        impl<'de> Visitor<'de> for VssShareVisitor {
            type Value = VssShare;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("struct VssShare")
            }
            fn visit_map<V: MapAccess<'de>>(self, mut map: V) -> Result<VssShare, V::Error> {
                let mut index = None;
                let mut value = None;
                let mut blinding = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "index" => index = Some(map.next_value()?),
                        "value" => value = Some(map.next_value()?),
                        "blinding" => blinding = Some(map.next_value()?),
                        _ => { let _: serde::de::IgnoredAny = map.next_value()?; }
                    }
                }
                Ok(VssShare {
                    index: index.ok_or_else(|| de::Error::missing_field("index"))?,
                    value: value.ok_or_else(|| de::Error::missing_field("value"))?,
                    blinding: blinding.ok_or_else(|| de::Error::missing_field("blinding"))?,
                })
            }
        }
        deserializer.deserialize_struct("VssShare", &["index", "value", "blinding"], VssShareVisitor)
    }
}

impl Zeroize for VssShare {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.blinding.zeroize();
    }
}

impl Drop for VssShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Clone is safe because we implement manual Zeroize + Drop (copy-out semantics)
impl Clone for VssShare {
    fn clone(&self) -> Self {
        VssShare {
            index: self.index,
            value: self.value.clone(),
            blinding: self.blinding.clone(),
        }
    }
}

pub struct Vss;

impl Vss {
    pub fn share(
        ped: &PedersenSetup,
        secret: &Scalar,
        t: usize,
        n: usize,
    ) -> (VssPublic, Vec<VssShare>) {
        let mut f = vec![secret.clone()];
        let mut r = vec![Scalar::random(&mut OsRng)];
        for _ in 1..t {
            f.push(Scalar::random(&mut OsRng));
            r.push(Scalar::random(&mut OsRng));
        }

        let commitments: Vec<G1Point> = f.iter()
            .zip(r.iter())
            .map(|(fv, rv)| ped.commit(fv, rv))
            .collect();

        let public = VssPublic { commitments };
        let shares: Vec<VssShare> = (1..=n as u16)
            .map(|i| {
                let xi = Scalar::from_u64(i as u64);
                let mut fv = Scalar::zero();
                let mut rv = Scalar::zero();
                let mut xpow = Scalar::one();
                for (fk, rk) in f.iter().zip(r.iter()) {
                    fv = fv.add(&fk.mul(&xpow));
                    rv = rv.add(&rk.mul(&xpow));
                    xpow = xpow.mul(&xi);
                }
                VssShare { index: i, value: fv, blinding: rv }
            })
            .collect();

        (public, shares)
    }

    pub fn share_zero(
        ped: &PedersenSetup,
        t: usize,
        n: usize,
    ) -> (VssPublic, Vec<VssShare>) {
        Self::share(ped, &Scalar::zero(), t, n)
    }

    pub fn reconstruct(shares: &[VssShare]) -> Scalar {
        let indices: Vec<u16> = shares.iter().map(|s| s.index).collect();
        let lambdas = lagrange_at_zero(&indices);
        shares.iter()
            .zip(lambdas.iter())
            .map(|(s, l)| s.value.mul(l))
            .fold(Scalar::zero(), |a, x| a.add(&x))
    }
}

fn lagrange_at_zero(quorum: &[u16]) -> Vec<Scalar> {
    let k = quorum.len();
    let mut lambdas = Vec::with_capacity(k);

    for i in 0..k {
        let mut num = Scalar::one();
        let mut den = Scalar::one();
        let xi = Scalar::from_u64(quorum[i] as u64);

        for j in 0..k {
            if i == j { continue; }
            let xj = Scalar::from_u64(quorum[j] as u64);
            num = num.mul(&xj.negate());
            den = den.mul(&xi.sub(&xj));
        }

        let inv_den = den.invert().unwrap();
        lambdas.push(num.mul(&inv_den));
    }

    lambdas
}

#[derive(Clone, Debug)]
pub struct PrivatePoly {
    pub coeffs_f: Vec<Scalar>,
    pub coeffs_r: Vec<Scalar>,
    pub pedersen: PedersenSetup,
}

impl Zeroize for PrivatePoly {
    fn zeroize(&mut self) {
        for c in self.coeffs_f.iter_mut() { c.zeroize(); }
        for c in self.coeffs_r.iter_mut() { c.zeroize(); }
    }
}

impl Drop for PrivatePoly {
    fn drop(&mut self) { self.zeroize(); }
}

impl PrivatePoly {
    pub fn random(t: usize, ped: &PedersenSetup) -> Self {
        let mut f = vec![Scalar::random(&mut OsRng)];
        let mut r = vec![Scalar::random(&mut OsRng)];
        for _ in 1..t {
            f.push(Scalar::random(&mut OsRng));
            r.push(Scalar::random(&mut OsRng));
        }
        PrivatePoly { coeffs_f: f, coeffs_r: r, pedersen: ped.clone() }
    }

    pub fn random_with_secret(secret: Scalar, t: usize, ped: &PedersenSetup) -> Self {
        let mut f = vec![secret];
        let mut r = vec![Scalar::random(&mut OsRng)];
        for _ in 1..t {
            f.push(Scalar::random(&mut OsRng));
            r.push(Scalar::random(&mut OsRng));
        }
        PrivatePoly { coeffs_f: f, coeffs_r: r, pedersen: ped.clone() }
    }

    pub fn random_with_zero_constant(t: usize, ped: &PedersenSetup) -> Self {
        let mut f = vec![Scalar::zero()];
        let mut r = vec![Scalar::zero()];
        for _ in 1..t {
            f.push(Scalar::random(&mut OsRng));
            r.push(Scalar::random(&mut OsRng));
        }
        PrivatePoly { coeffs_f: f, coeffs_r: r, pedersen: ped.clone() }
    }

    pub fn eval(&self, x: u16) -> VssShare {
        let xi = Scalar::from_u64(x as u64);
        let mut fv = Scalar::zero();
        let mut rv = Scalar::zero();
        let mut xpow = Scalar::one();

        for (fk, rk) in self.coeffs_f.iter().zip(self.coeffs_r.iter()) {
            fv = fv.add(&fk.mul(&xpow));
            rv = rv.add(&rk.mul(&xpow));
            xpow = xpow.mul(&xi);
        }

        VssShare { index: x, value: fv, blinding: rv }
    }

    pub fn commit(&self) -> VssPublic {
        let commitments: Vec<G1Point> = self.coeffs_f.iter()
            .zip(self.coeffs_r.iter())
            .map(|(fk, rk)| self.pedersen.commit(fk, rk))
            .collect();
        VssPublic { commitments }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commit() {
        let ped = PedersenSetup::deterministic();
        let v = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);

        let c1 = ped.commit(&v, &r);
        let c2 = ped.commit(&v, &r);
        assert_eq!(c1, c2, "same (v,r) should give same commitment");
    }

    #[test]
    fn test_pedersen_different_r_same_v() {
        let ped = PedersenSetup::deterministic();
        let v = Scalar::random(&mut OsRng);
        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);

        let c1 = ped.commit(&v, &r1);
        let c2 = ped.commit(&v, &r2);
        assert_ne!(c1, c2, "different blinding should give different commitment");
    }

    #[test]
    fn test_vss_share_and_verify() {
        let ped = PedersenSetup::deterministic();
        let secret = Scalar::random(&mut OsRng);
        let t = 3;
        let n = 5;

        let (public, shares) = Vss::share(&ped, &secret, t, n);

        for share in shares.iter() {
            assert!(public.verify_share(share.index, &share.value, &share.blinding, &ped));
        }
    }

    #[test]
    fn test_vss_verify_fails_corrupted_share() {
        let ped = PedersenSetup::deterministic();
        let secret = Scalar::random(&mut OsRng);
        let t = 3;
        let n = 5;

        let (public, shares) = Vss::share(&ped, &secret, t, n);

        let mut corrupted = shares[0].clone();
        corrupted.value = Scalar::random(&mut OsRng);
        assert!(!public.verify_share(corrupted.index, &corrupted.value, &corrupted.blinding, &ped));
    }

    #[test]
    fn test_vss_reconstruct() {
        let ped = PedersenSetup::deterministic();
        let secret = Scalar::random(&mut OsRng);
        let t = 3;
        let n = 5;

        let (_, shares) = Vss::share(&ped, &secret, t, n);

        let reconstructed = Vss::reconstruct(&shares[..t as usize]);
        assert_eq!(secret, reconstructed);
    }

    #[test]
    fn test_vss_share_zero() {
        let ped = PedersenSetup::deterministic();
        let t = 3;
        let n = 5;

        let (public, shares) = Vss::share_zero(&ped, t, n);

        assert!(public.commitments[0] == G1Point::identity() ||
                public.verify_share(shares[0].index, &shares[0].value, &shares[0].blinding, &ped));

        for share in shares.iter() {
            assert!(public.verify_share(share.index, &share.value, &share.blinding, &ped));
        }
    }

    #[test]
    fn test_private_poly_share_and_verify() {
        let ped = PedersenSetup::deterministic();
        let secret = Scalar::random(&mut OsRng);
        let t = 3;
        let n = 5;

        let private = PrivatePoly::random_with_secret(secret.clone(), t, &ped);
        let public = private.commit();

        for i in 1..=n as u16 {
            let share = private.eval(i);
            assert!(public.verify_share(share.index, &share.value, &share.blinding, &ped));
        }

        let reconstructed = Vss::reconstruct(
            &(1..=t as u16).map(|i| private.eval(i)).collect::<Vec<_>>()
        );
        assert_eq!(secret, reconstructed);
    }

    #[test]
    fn test_lagrange_at_zero() {
        let indices = vec![1u16, 3, 5];
        let lambdas = lagrange_at_zero(&indices);

        assert_eq!(lambdas.len(), 3);

        let mut sum = Scalar::zero();
        for l in &lambdas {
            sum = sum.add(l);
        }
        assert_eq!(sum, Scalar::one(), "sum of Lagrange coeffs at 0 should be 1");
    }
}