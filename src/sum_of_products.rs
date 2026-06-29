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
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::Field;

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
}
