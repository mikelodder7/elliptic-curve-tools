use elliptic_curve::{Group, subtle::ConditionallySelectable};

/// A trait for a group that can compute the sum of products
/// of a slice of group elements and a slice of scalars.
/// The length of the slices must be equal.
pub trait SumOfProducts: Group {
    /// Compute the sum of products of a slice of group elements and a slice of scalars
    /// as `group[0] * scalar[0] + group[1] * scalar[1] + ... + group[n] * scalar[n]`.
    ///
    /// Avoids scalar-dependent table lookups by scanning each table and selecting
    /// entries with constant-time conditional selection. Use when any scalar
    /// is secret.
    fn sum_of_products(pairs: &[(Self::Scalar, Self)]) -> Self
    where
        Self: ConditionallySelectable;

    /// Compute the sum of products using variable-time table lookups.
    ///
    /// Uses scalar-derived window values as table indexes, which is faster
    /// than [`SumOfProducts::sum_of_products`] but potentially leaks scalar
    /// information through memory access patterns. Use only when every scalar
    /// is public, such as many verification-style workloads.
    fn sum_of_products_vartime(pairs: &[(Self::Scalar, Self)]) -> Self;

    /// Constant-time [`SumOfProducts::sum_of_products`] that reuses caller-owned
    /// scratch instead of allocating.
    ///
    /// Allocate `scratch` once with [`Scratch::new`](crate::Scratch::new) and reuse it
    /// across calls to avoid per-call heap traffic. The buffer sizes are validated at the
    /// start of the call; if `scratch` is too small for `pairs`, returns
    /// [`InsufficientScratch`](crate::InsufficientScratch) without mutating it.
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn sum_of_products_inplace(
        pairs: &[(Self::Scalar, Self)],
        scratch: &mut crate::Scratch<Self>,
    ) -> Result<Self, crate::InsufficientScratch>
    where
        Self: ConditionallySelectable;

    /// Variable-time [`SumOfProducts::sum_of_products_vartime`] that reuses
    /// caller-owned scratch instead of allocating.
    ///
    /// Allocate `scratch` once with [`Scratch::new`](crate::Scratch::new) and reuse it
    /// across calls to avoid per-call heap traffic. The buffer sizes are validated at the
    /// start of the call; if `scratch` is too small for `pairs`, returns
    /// [`InsufficientScratch`](crate::InsufficientScratch) without mutating it.
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn sum_of_products_vartime_inplace(
        pairs: &[(Self::Scalar, Self)],
        scratch: &mut crate::Scratch<Self>,
    ) -> Result<Self, crate::InsufficientScratch>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G> SumOfProducts for G
where
    G: Group,
{
    fn sum_of_products(pairs: &[(Self::Scalar, Self)]) -> Self
    where
        Self: ConditionallySelectable,
    {
        crate::multiexp::multiexp(pairs)
    }

    fn sum_of_products_vartime(pairs: &[(Self::Scalar, Self)]) -> Self {
        crate::multiexp::multiexp_vartime(pairs)
    }

    fn sum_of_products_inplace(
        pairs: &[(Self::Scalar, Self)],
        scratch: &mut crate::Scratch<Self>,
    ) -> Result<Self, crate::InsufficientScratch>
    where
        Self: ConditionallySelectable,
    {
        crate::multiexp::multiexp_inplace(pairs, scratch)
    }

    fn sum_of_products_vartime_inplace(
        pairs: &[(Self::Scalar, Self)],
        scratch: &mut crate::Scratch<Self>,
    ) -> Result<Self, crate::InsufficientScratch> {
        crate::multiexp::multiexp_vartime_inplace(pairs, scratch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Scratch, ScratchBuffer};
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    use alloc::vec::Vec;
    use elliptic_curve::{Field, PrimeField};
    #[cfg(feature = "std")]
    use std::vec::Vec;

    fn varied_pairs<G>(n: usize) -> Vec<(G::Scalar, G)>
    where
        G: Group,
        G::Scalar: Field,
    {
        let mut acc = <G::Scalar as Field>::ONE;
        (0..n)
            .map(|_| {
                acc = acc.double() + <G::Scalar as Field>::ONE;
                (acc, G::generator())
            })
            .collect()
    }

    // High-entropy (deterministic) scalars to stress the signed-digit recoder across
    // many bit patterns. Clearing the top byte keeps each value below the group order.
    fn pseudo_random_pairs<G>(n: usize, seed: u64) -> Vec<(G::Scalar, G)>
    where
        G: Group,
    {
        let g = G::generator();
        let mut state = seed | 1;
        (0..n)
            .map(|_| {
                let mut repr = <G::Scalar as PrimeField>::Repr::default();
                let bytes: &mut [u8] = repr.as_mut();
                for b in bytes.iter_mut() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *b = (state & 0xff) as u8;
                }
                bytes[0] = 0; // guarantee value < group order
                let scalar =
                    Option::<G::Scalar>::from(G::Scalar::from_repr(repr)).unwrap_or(G::Scalar::ONE);
                (scalar, g)
            })
            .collect()
    }

    fn assert_random_matches_naive<G>(sizes: &[usize])
    where
        G: ConditionallySelectable + Group + SumOfProducts,
    {
        for (i, &n) in sizes.iter().enumerate() {
            let pairs = pseudo_random_pairs::<G>(n, 0x9E37_79B9_7F4A_7C15 ^ (n as u64) ^ i as u64);
            let naive: G = pairs.iter().map(|(scalar, point)| *point * scalar).sum();
            assert_eq!(G::sum_of_products(&pairs), naive, "ct n={n}");
            assert_eq!(G::sum_of_products_vartime(&pairs), naive, "vartime n={n}");
        }
    }

    fn assert_inplace_matches_allocating<G>()
    where
        G: ConditionallySelectable + Group + SumOfProducts,
        G::Scalar: Field,
    {
        // One scratch sized for the largest case, reused for every size and for both
        // the constant- and variable-time paths, exercising the capacity contract.
        let mut scratch = Scratch::<G>::new(200);

        for &n in &[2usize, 5, 64, 130, 200] {
            let pairs = varied_pairs::<G>(n);
            let naive: G = pairs.iter().map(|(scalar, point)| *point * scalar).sum();

            assert_eq!(G::sum_of_products_inplace(&pairs, &mut scratch), Ok(naive));
            assert_eq!(
                G::sum_of_products_vartime_inplace(&pairs, &mut scratch),
                Ok(naive)
            );
        }
    }

    fn assert_undersized_scratch_errors<G>()
    where
        G: ConditionallySelectable + Group + SumOfProducts,
        G::Scalar: Field,
    {
        let pairs = varied_pairs::<G>(64);
        let mut tiny = Scratch::<G>::new(2);

        assert!(matches!(
            G::sum_of_products_inplace(&pairs, &mut tiny),
            Err(e) if e.buffer == ScratchBuffer::Digits && e.provided < e.required
        ));
        assert!(matches!(
            G::sum_of_products_vartime_inplace(&pairs, &mut tiny),
            Err(e) if e.buffer == ScratchBuffer::Digits && e.provided < e.required
        ));
    }

    fn assert_straus_sums_scalar_products<G>()
    where
        G: ConditionallySelectable + Group + SumOfProducts,
        G::Scalar: Field,
    {
        let pairs = [
            (<G::Scalar as Field>::ONE, G::generator()),
            (<G::Scalar as Field>::ONE.double(), G::generator()),
        ];

        let expected = G::generator() + G::generator().double();

        assert_eq!(G::sum_of_products(&pairs), expected);
    }

    fn assert_pippenger_sums_scalar_products<G>()
    where
        G: ConditionallySelectable + Group + SumOfProducts,
        G::Scalar: Field,
    {
        let scalar = <G::Scalar as Field>::ONE.double();
        let point = G::generator();
        let pairs = vec![(scalar, point); 130];
        let expected: G = pairs.iter().map(|(scalar, point)| *point * scalar).sum();

        assert_eq!(G::sum_of_products(&pairs), expected);
    }

    fn assert_variable_time_matches_constant_time<G>()
    where
        G: ConditionallySelectable + Group + SumOfProducts,
        G::Scalar: Field,
    {
        let scalar = <G::Scalar as Field>::ONE.double();
        let point = G::generator();
        let pairs = vec![(scalar, point); 130];

        assert_eq!(
            G::sum_of_products_vartime(&pairs),
            G::sum_of_products(&pairs)
        );
    }

    #[test]
    fn straus_sums_scalar_products() {
        assert_straus_sums_scalar_products::<k256::ProjectivePoint>();
        assert_straus_sums_scalar_products::<p256::ProjectivePoint>();
        assert_straus_sums_scalar_products::<p384::ProjectivePoint>();
        assert_straus_sums_scalar_products::<p521::ProjectivePoint>();
        assert_straus_sums_scalar_products::<bp256::r1::ProjectivePoint>();
        assert_straus_sums_scalar_products::<bp256::t1::ProjectivePoint>();
        assert_straus_sums_scalar_products::<bp384::r1::ProjectivePoint>();
        assert_straus_sums_scalar_products::<bp384::t1::ProjectivePoint>();
    }

    #[test]
    fn pippenger_sums_scalar_products() {
        assert_pippenger_sums_scalar_products::<k256::ProjectivePoint>();
        assert_pippenger_sums_scalar_products::<p256::ProjectivePoint>();
        assert_pippenger_sums_scalar_products::<p384::ProjectivePoint>();
        assert_pippenger_sums_scalar_products::<p521::ProjectivePoint>();
        assert_pippenger_sums_scalar_products::<bp256::r1::ProjectivePoint>();
        assert_pippenger_sums_scalar_products::<bp256::t1::ProjectivePoint>();
        assert_pippenger_sums_scalar_products::<bp384::r1::ProjectivePoint>();
        assert_pippenger_sums_scalar_products::<bp384::t1::ProjectivePoint>();
    }

    #[test]
    fn random_matches_naive() {
        // Small/medium sizes across every curve (different bit lengths exercise the
        // recoder's window count and carry differently).
        let small = [2usize, 3, 7, 31, 63, 127, 130, 200];
        assert_random_matches_naive::<k256::ProjectivePoint>(&small);
        assert_random_matches_naive::<p256::ProjectivePoint>(&small);
        assert_random_matches_naive::<p384::ProjectivePoint>(&small);
        assert_random_matches_naive::<p521::ProjectivePoint>(&small);
        assert_random_matches_naive::<bp256::r1::ProjectivePoint>(&small);
        assert_random_matches_naive::<bp256::t1::ProjectivePoint>(&small);
        assert_random_matches_naive::<bp384::r1::ProjectivePoint>(&small);
        assert_random_matches_naive::<bp384::t1::ProjectivePoint>(&small);
        // Larger sizes (one representative curve) to cover every Pippenger window.
        assert_random_matches_naive::<k256::ProjectivePoint>(&[401, 801]);
    }

    #[test]
    fn variable_time_matches_constant_time() {
        assert_variable_time_matches_constant_time::<k256::ProjectivePoint>();
        assert_variable_time_matches_constant_time::<p256::ProjectivePoint>();
        assert_variable_time_matches_constant_time::<p384::ProjectivePoint>();
        assert_variable_time_matches_constant_time::<p521::ProjectivePoint>();
        assert_variable_time_matches_constant_time::<bp256::r1::ProjectivePoint>();
        assert_variable_time_matches_constant_time::<bp256::t1::ProjectivePoint>();
        assert_variable_time_matches_constant_time::<bp384::r1::ProjectivePoint>();
        assert_variable_time_matches_constant_time::<bp384::t1::ProjectivePoint>();
    }

    #[test]
    fn inplace_matches_allocating() {
        assert_inplace_matches_allocating::<k256::ProjectivePoint>();
        assert_inplace_matches_allocating::<p256::ProjectivePoint>();
        assert_inplace_matches_allocating::<p384::ProjectivePoint>();
        assert_inplace_matches_allocating::<p521::ProjectivePoint>();
        assert_inplace_matches_allocating::<bp256::r1::ProjectivePoint>();
        assert_inplace_matches_allocating::<bp256::t1::ProjectivePoint>();
        assert_inplace_matches_allocating::<bp384::r1::ProjectivePoint>();
        assert_inplace_matches_allocating::<bp384::t1::ProjectivePoint>();
    }

    #[test]
    fn undersized_scratch_errors() {
        assert_undersized_scratch_errors::<k256::ProjectivePoint>();
        assert_undersized_scratch_errors::<p256::ProjectivePoint>();
        assert_undersized_scratch_errors::<p384::ProjectivePoint>();
        assert_undersized_scratch_errors::<p521::ProjectivePoint>();
        assert_undersized_scratch_errors::<bp256::r1::ProjectivePoint>();
        assert_undersized_scratch_errors::<bp256::t1::ProjectivePoint>();
        assert_undersized_scratch_errors::<bp384::r1::ProjectivePoint>();
        assert_undersized_scratch_errors::<bp384::t1::ProjectivePoint>();
    }
}
