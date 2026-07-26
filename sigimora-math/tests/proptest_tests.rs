//! Property-based tests for sigimora-math using proptest.

use proptest::prelude::*;
use sigimora_math::{G1Point, G2Point, Scalar};

/// Strategy for generating random scalars.
fn scalar_strategy() -> impl Strategy<Value = Scalar> {
    any::<[u8; 32]>()
        .prop_filter("must be valid scalar", |b| Scalar::from_bytes(b).is_ok())
        .prop_map(|b| Scalar::from_bytes(&b).unwrap())
}

fn scalar_pair() -> impl Strategy<Value = (Scalar, Scalar)> {
    (scalar_strategy(), scalar_strategy())
}

fn scalar_triple() -> impl Strategy<Value = (Scalar, Scalar, Scalar)> {
    (scalar_strategy(), scalar_strategy(), scalar_strategy())
}

proptest! {
    #[test]
    fn scalar_add_commutative((a, b) in scalar_pair()) {
        assert_eq!(a.add(&b), b.add(&a));
    }

    #[test]
    fn scalar_mul_commutative((a, b) in scalar_pair()) {
        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn scalar_add_associative((a, b, c) in scalar_triple()) {
        assert_eq!(a.add(&b).add(&c), a.add(&b.add(&c)));
    }

    #[test]
    fn scalar_mul_associative((a, b, c) in scalar_triple()) {
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
    }

    #[test]
    fn scalar_distributive((a, b, c) in scalar_triple()) {
        let lhs = a.mul(&b.add(&c));
        let rhs = a.mul(&b).add(&a.mul(&c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn scalar_negation_additive_inverse(a in scalar_strategy()) {
        let sum = a.add(&a.negate());
        assert!(sum.is_zero());
    }

    #[test]
    fn scalar_multiplicative_inverse(a in scalar_strategy()) {
        prop_assume!(!a.is_zero());
        let inv = a.invert().unwrap();
        assert_eq!(a.mul(&inv), Scalar::one());
    }

    #[test]
    fn scalar_serialization_roundtrip(a in scalar_strategy()) {
        let bytes = a.to_bytes();
        let b = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn g1_scalar_mul_identity(a in scalar_strategy()) {
        let g = G1Point::generator();
        assert_eq!(g.mul(&Scalar::one()), g);
    }

    #[test]
    fn g1_scalar_mul_zero(a in scalar_strategy()) {
        let g = G1Point::generator();
        assert!(g.mul(&Scalar::zero()).is_identity());
    }

    #[test]
    fn g1_linearity((a, b) in scalar_pair()) {
        let g = G1Point::generator();
        let lhs = g.mul(&a).add(&g.mul(&b));
        let rhs = g.mul(&a.add(&b));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn g2_linearity((a, b) in scalar_pair()) {
        let g = G2Point::generator();
        let lhs = g.mul(&a).add(&g.mul(&b));
        let rhs = g.mul(&a.add(&b));
        assert_eq!(lhs, rhs);
    }
}
