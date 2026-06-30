# RustCrypto: Elliptic Curve Tools

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/elliptic-curve-tools/actions/workflows/elliptic-curve-tools.yml/badge.svg)
![MSRV][msrv-image]

Extra Rust Crypto elliptic-curve adaptors, functions, and macros, built on the
[`group`]/[`ff`]/[`elliptic-curve`] 0.14 traits.

[Documentation][docs-link]

It provides two things for any `group`/`ff` type:

1. **`serde` adaptors** for scalars and group elements (and their array/`Vec`/`Box<[_]>`
   collections).
2. **Multi-scalar multiplication** (`sum_of_products`), in constant or variable time, with
   buffer reuse and fixed-base precomputation.

Requires Rust **1.85** or higher (Edition 2024).

## Cargo features

| feature   | default | description                                                        |
|-----------|:-------:|--------------------------------------------------------------------|
| `std`     |   yes   | builds against `std`                                               |
| `alloc`   |         | `no_std` + `alloc` (the serde adaptors and multiexp live here)      |
| `legacy`  |         | bridge curves still on the `group`/`ff` **0.13** traits (see below) |

The serde adaptors and `sum_of_products` require the `alloc` or `std` feature.

## Serialization

`#[serde(with = "...")]` adaptors for scalars and group elements, plus their fixed-size
array, `Vec`, and `Box<[_]>` variants:

- scalars: `prime_field`, `prime_field_array`, `prime_field_vec`, `prime_field_boxed_slice`
- groups:  `group`, `group_array`, `group_vec`, `group_boxed_slice`

```rust
use elliptic_curve::PrimeField;
use elliptic_curve_tools::prime_field;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Share<F: PrimeField>(#[serde(with = "prime_field")] F);
```

## Sum of products (multi-scalar multiplication)

The `SumOfProducts` trait is implemented for every `Group`, computing
`scalar[0] * point[0] + ... + scalar[n] * point[n]`:

```rust
use elliptic_curve_tools::SumOfProducts;
use k256::ProjectivePoint;

// pairs: &[(Scalar, ProjectivePoint)]
let ct = ProjectivePoint::sum_of_products(&pairs);          // constant-time (secret scalars)
let vt = ProjectivePoint::sum_of_products_vartime(&pairs);  // variable-time (public scalars)
```

- `sum_of_products` is **constant-time** — use it whenever any scalar may be secret.
- `sum_of_products_vartime` is faster but leaks scalars through memory access; use it only
  when every scalar is public (e.g. verification).

### Reusing scratch space

To avoid per-call heap allocation, build a `Scratch` once and reuse it across calls. One
`Scratch::new(capacity)` is valid for any call with `capacity` or fewer pairs, in either
the constant- or variable-time path:

```rust
use elliptic_curve_tools::{Scratch, SumOfProducts};

let mut scratch = Scratch::new(pairs.len());
let result = ProjectivePoint::sum_of_products_inplace(&pairs, &mut scratch)?;
```

The buffer sizes are checked up front; an undersized `Scratch` returns
`InsufficientScratch` without panicking.

### Fixed-base precomputation

When the same basis is reused across many calls with different scalars (Pedersen and
polynomial commitments, threshold signatures over fixed generators), precompute it once:

```rust
use elliptic_curve_tools::Precomputed;

let basis = Precomputed::new(&points);
let a = basis.sum_of_products(&scalars_a)?;   // constant-time, no per-call table build
let b = basis.sum_of_products_vartime(&scalars_b)?;
```

### Iterator input

`sum_of_products_iter` consumes an `ExactSizeIterator` of `(scalar, point)` (e.g. a `zip`)
without first materializing a slice. `Precomputed` has `_iter` variants too.

## Legacy curves (`group`/`ff` 0.13)

Curves that have not migrated to `group`/`ff` 0.14 — curve25519-dalek, ed448-goldilocks,
bls12-381 forks, and others — can still use these functions via the optional `legacy`
feature. Call the bridge trait directly on the native point type:

```rust
use elliptic_curve_tools::legacy::SumOfProducts;

// RistrettoPoint, EdwardsPoint, DecafPoint, G1Projective, ...
let result = RistrettoPoint::sum_of_products(&pairs);
```

The `legacy` module also exposes `Group013<P>` / `Scalar013<F>` wrappers that present any
0.13 group element / scalar as the 0.14 traits, so the full API (`Scratch`, `Precomputed`,
the `_inplace`/`_iter` methods) works with 0.13 curves as well.

## Notes on the implementation

- The constant-time path uses signed-digit (booth-recoded) Straus; the variable-time path
  uses Pippenger with benchmark-tuned window thresholds.
- Both big-endian (RustCrypto Weierstrass) and little-endian (curve25519 / ed448 /
  bls12-381 style) scalar representations are handled.
- Constant-time behavior is checked with dudect (timing) and ctgrind (Valgrind) harnesses
  under `ct-tests/`; interop with 0.13 curves is checked under `interop-tests/`.

## Changes in 0.3

- Constant-time `sum_of_products` rewritten around signed-digit Straus; large constant-time
  inputs are dramatically faster, and the variable-time thresholds were re-tuned.
- Fixed little-endian scalar representations producing incorrect results.
- New allocation-free `Scratch`/`*_inplace` API, `Precomputed` fixed-base API, and
  `sum_of_products_iter`.
- New optional `legacy` feature bridging `group`/`ff` 0.13 curves.
- Dropped the external `multiexp` dependency; multi-scalar multiplication is now in-crate.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

All crates licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/elliptic-curve-tools.svg
[crate-link]: https://crates.io/crates/elliptic-curve-tools
[docs-image]: https://docs.rs/elliptic-curve-tools/badge.svg
[docs-link]: https://docs.rs/elliptic-curve-tools/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/elliptic-curve-tools.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[`group`]: https://docs.rs/group
[`ff`]: https://docs.rs/ff
[`elliptic-curve`]: https://docs.rs/elliptic-curve
