//! dudect-style timing leakage test for the constant-time `sum_of_products`.
//!
//! Times `G::sum_of_products` over two classes of secret scalars — a fixed input
//! (all zero) versus uniformly random — and applies Welch's t-test to the timing
//! distributions. A constant-time implementation keeps `|t|` small (conventionally
//! `< 10`) however many samples are collected; a value that grows with the sample
//! count indicates the running time depends on the secret scalars.
//!
//! Run with an optimized build (a single pass, or `--continuous` to keep sampling):
//!   cargo run --release --bin dudect
//!   cargo run --release --bin dudect -- --continuous sum_of_products

use dudect_bencher::rand::RngExt;
use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use elliptic_curve::{Group, PrimeField};
use elliptic_curve_tools::SumOfProducts;
use k256::ProjectivePoint as G;

type Scalar = <G as Group>::Scalar;

const N: usize = 16;
const SAMPLES: usize = 100_000;

fn random_scalar(rng: &mut BenchRng) -> Scalar {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    let bytes: &mut [u8] = repr.as_mut();
    rng.fill(&mut *bytes);
    bytes[0] = 0; // keep the value below the group order
    Option::<Scalar>::from(Scalar::from_repr(repr)).unwrap_or(Scalar::ONE)
}

fn sum_of_products(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Public, distinct basis points (not secret, identical across both classes).
    let generator = G::generator();
    let mut point = generator;
    let mut points = Vec::with_capacity(N);
    for _ in 0..N {
        points.push(point);
        point += generator;
    }

    // Pre-generate every input so only the multiexp itself is timed.
    let mut classes = Vec::with_capacity(SAMPLES);
    let mut inputs = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (scalars, class) = if rng.random::<bool>() {
            (vec![Scalar::ZERO; N], Class::Left)
        } else {
            (
                (0..N).map(|_| random_scalar(rng)).collect::<Vec<_>>(),
                Class::Right,
            )
        };
        inputs.push(
            scalars
                .into_iter()
                .zip(points.iter().copied())
                .collect::<Vec<(Scalar, G)>>(),
        );
        classes.push(class);
    }

    for (class, pairs) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || G::sum_of_products(&pairs));
    }
}

ctbench_main!(sum_of_products);
