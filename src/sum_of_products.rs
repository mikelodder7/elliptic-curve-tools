use elliptic_curve::{ff::PrimeFieldBits, Group};

/// A trait for a group that can compute the sum of products
/// of a slice of group elements and a slice of scalars.
/// The length of the slices must be equal.
pub trait SumOfProducts: Group<Scalar: PrimeFieldBits> {
    /// Compute the sum of products of a slice of group elements and a slice of scalars
    /// as group[0]^field[0] * group[1]^field[1] * ... * group[n]^field[n]
    fn sum_of_products(pairs: &[(Self::Scalar, Self)]) -> Self;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G> SumOfProducts for G
where
    G: Group,
    G::Scalar: PrimeFieldBits + zeroize::Zeroize,
{
    fn sum_of_products(pairs: &[(Self::Scalar, Self)]) -> Self {
        multiexp::multiexp::<Self>(pairs)
    }
}
