//! Bridge for curves still on the `group`/`ff` **0.13** traits.
//!
//! `elliptic-curve-tools` is built on `group`/`ff` 0.14. Many curve crates have not
//! migrated yet (curve25519-dalek, ed448-goldilocks, bls12-381 forks, ...). Enable the
//! `legacy` feature and this module bridges them: [`Group013`] wraps any 0.13 group
//! element as a 0.14 [`Group`], [`Scalar013`] wraps its scalar as a 0.14 [`PrimeField`],
//! by delegating every operation to the inner 0.13 type. Both ecosystems share `subtle`,
//! so the constant-time machinery passes straight through.
//!
//! The ergonomic entry point is the [`SumOfProducts`] trait, implemented directly for any
//! 0.13 group element:
//!
//! ```ignore
//! use elliptic_curve_tools::legacy::SumOfProducts;
//! // `point` is a group-0.13 type (e.g. curve25519_dalek::RistrettoPoint)
//! let result = MyPoint::sum_of_products(&pairs); // pairs: &[(Scalar, MyPoint)]
//! ```
//!
//! For the full API ([`Scratch`](crate::Scratch), [`Precomputed`](crate::Precomputed),
//! the `_inplace`/`_iter` methods) wrap values in [`Group013`]/[`Scalar013`] yourself and
//! use the regular [`SumOfProducts`](crate::SumOfProducts) trait.

use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use elliptic_curve::{
    Field, Group, PrimeField,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
};
use ff_013::PrimeField as PrimeField013;
use group_013::Group as Group013Trait;
use rand_core::TryRng;

/// Wraps a `group` 0.13 element so it satisfies the `group` 0.14 [`Group`] trait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group013<P>(
    /// The wrapped 0.13 group element.
    pub P,
);

/// Wraps an `ff` 0.13 element so it satisfies the `ff` 0.14 [`PrimeField`] trait.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scalar013<F>(
    /// The wrapped 0.13 field element.
    pub F,
);

// ----- scalar (Scalar013) operator delegation -----------------------------------

macro_rules! scalar_binop {
    ($trait:ident, $method:ident) => {
        impl<F: PrimeField013> $trait for Scalar013<F> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: Self) -> Self {
                Scalar013($trait::$method(self.0, rhs.0))
            }
        }
        impl<F: PrimeField013> $trait<&Scalar013<F>> for Scalar013<F> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: &Scalar013<F>) -> Self {
                Scalar013($trait::$method(self.0, rhs.0))
            }
        }
    };
}

macro_rules! scalar_assign {
    ($trait:ident, $method:ident) => {
        impl<F: PrimeField013> $trait for Scalar013<F> {
            #[inline]
            fn $method(&mut self, rhs: Self) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
        impl<F: PrimeField013> $trait<&Scalar013<F>> for Scalar013<F> {
            #[inline]
            fn $method(&mut self, rhs: &Scalar013<F>) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
    };
}

scalar_binop!(Add, add);
scalar_binop!(Sub, sub);
scalar_binop!(Mul, mul);
scalar_assign!(AddAssign, add_assign);
scalar_assign!(SubAssign, sub_assign);
scalar_assign!(MulAssign, mul_assign);

impl<F: PrimeField013> Neg for Scalar013<F> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Scalar013(-self.0)
    }
}

impl<F: PrimeField013> Sum for Scalar013<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Scalar013(F::ZERO), Add::add)
    }
}

impl<'a, F: PrimeField013> Sum<&'a Self> for Scalar013<F> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Scalar013(F::ZERO), |acc, x| acc + *x)
    }
}

impl<F: PrimeField013> Product for Scalar013<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Scalar013(F::ONE), Mul::mul)
    }
}

impl<'a, F: PrimeField013> Product<&'a Self> for Scalar013<F> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Scalar013(F::ONE), |acc, x| acc * *x)
    }
}

impl<F: PrimeField013> ConstantTimeEq for Scalar013<F> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<F: PrimeField013> ConditionallySelectable for Scalar013<F> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar013(F::conditional_select(&a.0, &b.0, choice))
    }
}

impl<F: PrimeField013> From<u64> for Scalar013<F> {
    fn from(value: u64) -> Self {
        Scalar013(F::from(value))
    }
}

impl<F: PrimeField013> Field for Scalar013<F> {
    const ZERO: Self = Scalar013(F::ZERO);
    const ONE: Self = Scalar013(F::ONE);

    fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        // Rejection-sample a canonical representation; the 0.13 RNG API differs, so we
        // sample bytes through the 0.14 RNG and reduce via the inner `from_repr`.
        loop {
            let mut repr = F::Repr::default();
            let bytes: &mut [u8] = repr.as_mut();
            rng.try_fill_bytes(bytes)?;
            if let Some(value) = Option::<F>::from(F::from_repr(repr)) {
                return Ok(Scalar013(value));
            }
        }
    }

    fn square(&self) -> Self {
        Scalar013(self.0.square())
    }

    fn double(&self) -> Self {
        Scalar013(self.0.double())
    }

    fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Scalar013)
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let (choice, root) = F::sqrt_ratio(&num.0, &div.0);
        (choice, Scalar013(root))
    }
}

impl<F: PrimeField013> PrimeField for Scalar013<F> {
    type Repr = F::Repr;

    const MODULUS: &'static str = F::MODULUS;
    const NUM_BITS: u32 = F::NUM_BITS;
    const CAPACITY: u32 = F::CAPACITY;
    const TWO_INV: Self = Scalar013(F::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self = Scalar013(F::MULTIPLICATIVE_GENERATOR);
    const S: u32 = F::S;
    const ROOT_OF_UNITY: Self = Scalar013(F::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = Scalar013(F::ROOT_OF_UNITY_INV);
    const DELTA: Self = Scalar013(F::DELTA);

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        F::from_repr(repr).map(Scalar013)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_repr()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }
}

// ----- group (Group013) operator delegation -------------------------------------

macro_rules! group_binop {
    ($trait:ident, $method:ident) => {
        impl<P: Group013Trait + ConditionallySelectable> $trait for Group013<P> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: Self) -> Self {
                Group013($trait::$method(self.0, rhs.0))
            }
        }
        impl<P: Group013Trait + ConditionallySelectable> $trait<&Group013<P>> for Group013<P> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: &Group013<P>) -> Self {
                Group013($trait::$method(self.0, rhs.0))
            }
        }
    };
}

macro_rules! group_assign {
    ($trait:ident, $method:ident) => {
        impl<P: Group013Trait + ConditionallySelectable> $trait for Group013<P> {
            #[inline]
            fn $method(&mut self, rhs: Self) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
        impl<P: Group013Trait + ConditionallySelectable> $trait<&Group013<P>> for Group013<P> {
            #[inline]
            fn $method(&mut self, rhs: &Group013<P>) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
    };
}

group_binop!(Add, add);
group_binop!(Sub, sub);
group_assign!(AddAssign, add_assign);
group_assign!(SubAssign, sub_assign);

impl<P: Group013Trait + ConditionallySelectable> Neg for Group013<P> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Group013(-self.0)
    }
}

impl<P: Group013Trait + ConditionallySelectable> Mul<Scalar013<P::Scalar>> for Group013<P> {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Scalar013<P::Scalar>) -> Self {
        Group013(self.0 * rhs.0)
    }
}

impl<P: Group013Trait + ConditionallySelectable> Mul<&Scalar013<P::Scalar>> for Group013<P> {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: &Scalar013<P::Scalar>) -> Self {
        Group013(self.0 * rhs.0)
    }
}

impl<P: Group013Trait + ConditionallySelectable> MulAssign<Scalar013<P::Scalar>> for Group013<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: Scalar013<P::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<P: Group013Trait + ConditionallySelectable> MulAssign<&Scalar013<P::Scalar>> for Group013<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Scalar013<P::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<P: Group013Trait + ConditionallySelectable> Sum for Group013<P> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Group013(P::identity()), Add::add)
    }
}

impl<'a, P: Group013Trait + ConditionallySelectable> Sum<&'a Self> for Group013<P> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Group013(P::identity()), |acc, x| acc + *x)
    }
}

impl<P: Group013Trait + ConditionallySelectable> ConditionallySelectable for Group013<P> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Group013(P::conditional_select(&a.0, &b.0, choice))
    }
}

impl<P: Group013Trait + ConditionallySelectable> Group for Group013<P> {
    type Scalar = Scalar013<P::Scalar>;

    fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let scalar = <Scalar013<P::Scalar> as Field>::try_random(rng)?;
        Ok(Group013(P::generator() * scalar.0))
    }

    fn identity() -> Self {
        Group013(P::identity())
    }

    fn generator() -> Self {
        Group013(P::generator())
    }

    fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    fn double(&self) -> Self {
        Group013(self.0.double())
    }
}

// ----- ergonomic entry point ----------------------------------------------------

/// Sum of scalar products for curves still on the `group`/`ff` 0.13 traits.
///
/// Mirrors [`crate::SumOfProducts`] but is implemented directly for any 0.13 group
/// element, wrapping into [`Group013`]/[`Scalar013`] internally. Requires `alloc`/`std`.
#[cfg(any(feature = "alloc", feature = "std"))]
pub trait SumOfProducts: Group013Trait + ConditionallySelectable {
    /// Constant-time `sum(scalar_i * point_i)`. Use when any scalar may be secret.
    fn sum_of_products(pairs: &[(<Self as Group013Trait>::Scalar, Self)]) -> Self;

    /// Variable-time `sum(scalar_i * point_i)`. Use only when every scalar is public.
    fn sum_of_products_vartime(pairs: &[(<Self as Group013Trait>::Scalar, Self)]) -> Self;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<P> SumOfProducts for P
where
    P: Group013Trait + ConditionallySelectable,
    P::Scalar: PrimeField013,
{
    fn sum_of_products(pairs: &[(P::Scalar, Self)]) -> Self {
        let wrapped = wrap(pairs);
        crate::SumOfProducts::sum_of_products(wrapped.as_slice()).0
    }

    fn sum_of_products_vartime(pairs: &[(P::Scalar, Self)]) -> Self {
        let wrapped = wrap(pairs);
        crate::SumOfProducts::sum_of_products_vartime(wrapped.as_slice()).0
    }
}

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(any(feature = "alloc", feature = "std"))]
fn wrap<P>(pairs: &[(P::Scalar, P)]) -> Vec<(Scalar013<P::Scalar>, Group013<P>)>
where
    P: Group013Trait + ConditionallySelectable,
    P::Scalar: PrimeField013,
{
    pairs
        .iter()
        .map(|(scalar, point)| (Scalar013(*scalar), Group013(*point)))
        .collect()
}
