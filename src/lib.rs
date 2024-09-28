/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Extra Rust Crypto elliptic-curve adaptors, functions, and macros
//!
//! There are some methods that can be applied to many different elliptic curves
//! fields and groups.
//!
//! This crate provides multi-exponentiation functions
//! and serialization for different types of scalars and groups.
//! Serialization doesn't use any allocations and is no_std compliant.
//!
//! In addition with the `alloc` or `std` feature, it can
//! handle serializing Vec as well.
//!
//! To permit serializing a [`PrimeField`]
//!
//! ```
//! use elliptic_curve_tools::prime_field;
//! use elliptic_curve::PrimeField;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct PrimeFieldWrapper<F: PrimeField>( #[serde(with = "prime_field")] F);
//! ```
//!
//! To permit serializing a [`Group`]
//!
//! ```
//! use elliptic_curve_tools::group;
//! use elliptic_curve::{Group, group::GroupEncoding};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct GroupWrapper<G: Group>( #[serde(with = "group")] G);
//! ```
//!
//! Other collections can also be serialized like
//! - Fixed sized arrays like [[`PrimeField`]; 32] or [[`Group + GroupEncoding`]; 32]
//! -
//!
#![deny(
    clippy::unwrap_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    unused_parens,
    unused_lifetimes,
    unconditional_recursion,
    unused_extern_crates,
    trivial_casts,
    trivial_numeric_casts
)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod serdes;
mod sum_of_products;

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(feature = "std")]
#[cfg_attr(feature = "std", macro_use)]
extern crate std;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

pub use serdes::*;
pub use sum_of_products::*;
