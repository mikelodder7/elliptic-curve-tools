//! Proves `elliptic_curve_tools::SumOfProducts::sum_of_products` produces correct
//! results for curve crates still on the group/ff 0.13 ecosystem, via the 0.13->0.14
//! [`adapter`].
//!
//! The pairs and the reference sum are built with each curve's *native* 0.13 arithmetic,
//! then wrapped; only the multiexp itself runs through the adapter. So a mismatch would
//! catch either an adapter delegation bug or an algorithm bug.

use adapter::{G14, S14};
use elliptic_curve_tools::SumOfProducts;
use ff_013::Field;
use group_013::Group;
use subtle::ConditionallySelectable;

fn check<P>(label: &str)
where
    P: Group + ConditionallySelectable,
{
    for &n in &[2usize, 5, 33, 130] {
        let generator = P::generator();
        let one = <P::Scalar as Field>::ONE;
        let mut acc = one;
        let mut pairs: Vec<(S14<P::Scalar>, G14<P>)> = Vec::with_capacity(n);
        for _ in 0..n {
            acc += one;
            let scalar = acc + acc; // some varied scalar
            let point = generator * acc; // distinct public point
            pairs.push((S14(scalar), G14(point)));
        }

        // Reference computed with the curve's own arithmetic, independent of the adapter.
        let native: P = pairs.iter().map(|(s, p)| p.0 * s.0).sum();

        assert_eq!(
            <G14<P> as SumOfProducts>::sum_of_products(&pairs).0,
            native,
            "constant-time {label} n={n}"
        );
        assert_eq!(
            <G14<P> as SumOfProducts>::sum_of_products_vartime(&pairs).0,
            native,
            "variable-time {label} n={n}"
        );
    }
}

#[test]
fn curve25519_dalek_ml_ristretto() {
    check::<curve25519_dalek_ml::RistrettoPoint>("ristretto");
}

#[test]
fn ed448_goldilocks_plus_edwards() {
    check::<ed448_goldilocks_plus::EdwardsPoint>("ed448");
}

#[test]
fn bls12_381_plus_g1() {
    check::<bls12_381_plus::G1Projective>("bls12_381 G1");
}

#[test]
fn bls12_381_plus_g2() {
    check::<bls12_381_plus::G2Projective>("bls12_381 G2");
}

// Big-endian control: proves the adapter (and the endianness handling) is correct for a
// big-endian `to_repr` curve too, routed through the same 0.13->0.14 bridge.
#[test]
fn k256_big_endian_control() {
    check::<k256::ProjectivePoint>("k256");
}
