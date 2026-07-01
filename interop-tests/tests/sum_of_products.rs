//! Proves `elliptic_curve_tools`'s `legacy` feature lets `sum_of_products` run on curve
//! crates still on the group/ff 0.13 ecosystem — calling the ergonomic trait directly on
//! the native point types, no manual wrapping.
//!
//! Pairs and the reference sum are built with each curve's own 0.13 arithmetic, so a
//! mismatch would catch a bridge bug or an algorithm bug.

use elliptic_curve_tools::legacy::{Scratch, SumOfProducts};
use ff_013::Field;
use group_013::Group;
use subtle::ConditionallySelectable;

fn check<P>(label: &str)
where
    P: Group + ConditionallySelectable + SumOfProducts,
{
    for &n in &[2usize, 5, 33, 130] {
        let generator = P::generator();
        let one = <P::Scalar as Field>::ONE;
        let mut acc = one;
        let mut pairs: Vec<(P::Scalar, P)> = Vec::with_capacity(n);
        for _ in 0..n {
            acc += one;
            let scalar = acc + acc; // some varied scalar
            let point = generator * acc; // distinct public point
            pairs.push((scalar, point));
        }

        // Reference computed with the curve's own arithmetic, independent of the bridge.
        let native: P = pairs.iter().map(|(s, p)| *p * *s).sum();

        assert_eq!(P::sum_of_products(&pairs), native, "constant-time {label} n={n}");
        assert_eq!(
            P::sum_of_products_vartime(&pairs),
            native,
            "variable-time {label} n={n}"
        );
        assert_eq!(
            P::sum_of_products_iter(pairs.iter().copied()),
            native,
            "iter {label} n={n}"
        );

        let mut scratch = Scratch::<P>::new(n);
        assert_eq!(
            P::sum_of_products_inplace(&pairs, &mut scratch),
            Ok(native),
            "inplace {label} n={n}"
        );
        assert_eq!(
            P::sum_of_products_vartime_inplace(&pairs, &mut scratch),
            Ok(native),
            "vartime inplace {label} n={n}"
        );
    }
}

#[test]
fn curve25519_dalek_ml_ristretto() {
    check::<curve25519_dalek_ml::RistrettoPoint>("ristretto");
}

#[test]
fn curve25519_dalek_ml_edwards() {
    check::<curve25519_dalek_ml::EdwardsPoint>("ed25519 edwards");
}

// Upstream curve25519-dalek 4.1.3 is still on the group/ff 0.13 ecosystem, so it goes
// through the same `legacy` bridge as the `-ml` fork above.
#[test]
fn curve25519_dalek_v4_ristretto() {
    check::<dalek4::RistrettoPoint>("dalek 4.1.3 ristretto");
}

#[test]
fn curve25519_dalek_v4_edwards() {
    check::<dalek4::EdwardsPoint>("dalek 4.1.3 ed25519 edwards");
}

#[test]
fn ed448_goldilocks_plus_edwards() {
    check::<ed448_goldilocks_plus::EdwardsPoint>("ed448 edwards");
}

#[test]
fn ed448_goldilocks_plus_decaf() {
    check::<ed448_goldilocks_plus::DecafPoint>("ed448 decaf");
}

#[test]
fn bls12_381_plus_g1() {
    check::<bls12_381_plus::G1Projective>("bls12_381 G1");
}

#[test]
fn bls12_381_plus_g2() {
    check::<bls12_381_plus::G2Projective>("bls12_381 G2");
}

// Big-endian control: a big-endian `to_repr` curve through the same bridge.
#[test]
fn k256_big_endian_control() {
    check::<k256::ProjectivePoint>("k256");
}
