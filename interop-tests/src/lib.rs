//! Generic adapter bridging the `group`/`ff` **0.13** traits to **0.14**.
//!
//! `elliptic-curve-tools` is built on `group`/`ff` 0.14. Several curve crates still
//! implement the 0.13 traits ([`curve25519-dalek-ml`], [`ed448-goldilocks-plus`],
//! [`bls12_381_plus`], ...). [`G14`] wraps any 0.13 group element as a 0.14 `Group`, and
//! [`S14`] wraps its scalar as a 0.14 `PrimeField`, by delegating every operation to the
//! inner 0.13 type. Both ecosystems share `subtle` 2.x, so `ConditionallySelectable`
//! (which the constant-time `sum_of_products` needs) passes straight through.
//!
//! The random-sampling methods (`Group::try_random`, `Field::try_random`) bridge a newer
//! `rand_core` than the 0.13 types expose, so they are stubbed to a fixed valid element.
//! `sum_of_products` never calls them; the adapter exists solely to run that algorithm.

use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use ff_013::PrimeField as PrimeField013;
use group_013::Group as Group013;
use rand_core::TryRng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Wraps a `group` 0.13 element as a `group` 0.14 [`group::Group`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G14<P>(pub P);

/// Wraps an `ff` 0.13 element as an `ff` 0.14 [`ff::PrimeField`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct S14<F>(pub F);

// ----- scalar (S14) operator delegation -----------------------------------------

macro_rules! s14_binop {
    ($trait:ident, $method:ident) => {
        impl<F: PrimeField013> $trait for S14<F> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: Self) -> Self {
                S14($trait::$method(self.0, rhs.0))
            }
        }
        impl<F: PrimeField013> $trait<&S14<F>> for S14<F> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: &S14<F>) -> Self {
                S14($trait::$method(self.0, rhs.0))
            }
        }
    };
}

macro_rules! s14_assign {
    ($trait:ident, $method:ident) => {
        impl<F: PrimeField013> $trait for S14<F> {
            #[inline]
            fn $method(&mut self, rhs: Self) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
        impl<F: PrimeField013> $trait<&S14<F>> for S14<F> {
            #[inline]
            fn $method(&mut self, rhs: &S14<F>) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
    };
}

s14_binop!(Add, add);
s14_binop!(Sub, sub);
s14_binop!(Mul, mul);
s14_assign!(AddAssign, add_assign);
s14_assign!(SubAssign, sub_assign);
s14_assign!(MulAssign, mul_assign);

impl<F: PrimeField013> Neg for S14<F> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        S14(-self.0)
    }
}

impl<F: PrimeField013> Sum for S14<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(S14(F::ZERO), Add::add)
    }
}

impl<'a, F: PrimeField013> Sum<&'a Self> for S14<F> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(S14(F::ZERO), |acc, x| acc + *x)
    }
}

impl<F: PrimeField013> Product for S14<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(S14(F::ONE), Mul::mul)
    }
}

impl<'a, F: PrimeField013> Product<&'a Self> for S14<F> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(S14(F::ONE), |acc, x| acc * *x)
    }
}

impl<F: PrimeField013> ConstantTimeEq for S14<F> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<F: PrimeField013> ConditionallySelectable for S14<F> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        S14(F::conditional_select(&a.0, &b.0, choice))
    }
}

impl<F: PrimeField013> From<u64> for S14<F> {
    fn from(value: u64) -> Self {
        S14(F::from(value))
    }
}

impl<F: PrimeField013> ff::Field for S14<F> {
    const ZERO: Self = S14(F::ZERO);
    const ONE: Self = S14(F::ONE);

    fn try_random<R: TryRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        // Bridging rand_core versions is unnecessary: sum_of_products never samples.
        Ok(S14(F::ONE))
    }

    fn square(&self) -> Self {
        S14(self.0.square())
    }

    fn double(&self) -> Self {
        S14(self.0.double())
    }

    fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(S14)
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let (choice, root) = F::sqrt_ratio(&num.0, &div.0);
        (choice, S14(root))
    }
}

impl<F: PrimeField013> ff::PrimeField for S14<F> {
    type Repr = F::Repr;

    const MODULUS: &'static str = F::MODULUS;
    const NUM_BITS: u32 = F::NUM_BITS;
    const CAPACITY: u32 = F::CAPACITY;
    const TWO_INV: Self = S14(F::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self = S14(F::MULTIPLICATIVE_GENERATOR);
    const S: u32 = F::S;
    const ROOT_OF_UNITY: Self = S14(F::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = S14(F::ROOT_OF_UNITY_INV);
    const DELTA: Self = S14(F::DELTA);

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        F::from_repr(repr).map(S14)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_repr()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }
}

// ----- group (G14) operator delegation ------------------------------------------

macro_rules! g14_binop {
    ($trait:ident, $method:ident) => {
        impl<P: Group013 + ConditionallySelectable> $trait for G14<P> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: Self) -> Self {
                G14($trait::$method(self.0, rhs.0))
            }
        }
        impl<P: Group013 + ConditionallySelectable> $trait<&G14<P>> for G14<P> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: &G14<P>) -> Self {
                G14($trait::$method(self.0, rhs.0))
            }
        }
    };
}

macro_rules! g14_assign {
    ($trait:ident, $method:ident) => {
        impl<P: Group013 + ConditionallySelectable> $trait for G14<P> {
            #[inline]
            fn $method(&mut self, rhs: Self) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
        impl<P: Group013 + ConditionallySelectable> $trait<&G14<P>> for G14<P> {
            #[inline]
            fn $method(&mut self, rhs: &G14<P>) {
                $trait::$method(&mut self.0, rhs.0)
            }
        }
    };
}

g14_binop!(Add, add);
g14_binop!(Sub, sub);
g14_assign!(AddAssign, add_assign);
g14_assign!(SubAssign, sub_assign);

impl<P: Group013 + ConditionallySelectable> Neg for G14<P> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        G14(-self.0)
    }
}

impl<P: Group013 + ConditionallySelectable> Mul<S14<P::Scalar>> for G14<P> {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: S14<P::Scalar>) -> Self {
        G14(self.0 * rhs.0)
    }
}

impl<P: Group013 + ConditionallySelectable> Mul<&S14<P::Scalar>> for G14<P> {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: &S14<P::Scalar>) -> Self {
        G14(self.0 * rhs.0)
    }
}

impl<P: Group013 + ConditionallySelectable> MulAssign<S14<P::Scalar>> for G14<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: S14<P::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<P: Group013 + ConditionallySelectable> MulAssign<&S14<P::Scalar>> for G14<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: &S14<P::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<P: Group013 + ConditionallySelectable> Sum for G14<P> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(G14(P::identity()), Add::add)
    }
}

impl<'a, P: Group013 + ConditionallySelectable> Sum<&'a Self> for G14<P> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(G14(P::identity()), |acc, x| acc + *x)
    }
}

impl<P: Group013 + ConditionallySelectable> ConditionallySelectable for G14<P> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G14(P::conditional_select(&a.0, &b.0, choice))
    }
}

impl<P: Group013 + ConditionallySelectable> group::Group for G14<P> {
    type Scalar = S14<P::Scalar>;

    fn try_random<R: TryRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        Ok(G14(P::generator()))
    }

    fn identity() -> Self {
        G14(P::identity())
    }

    fn generator() -> Self {
        G14(P::generator())
    }

    fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    fn double(&self) -> Self {
        G14(self.0.double())
    }
}
