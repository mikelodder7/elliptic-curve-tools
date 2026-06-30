# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0
### Changed
- Upgraded to the `elliptic-curve`/`group`/`ff` 0.14 ecosystem; Edition 2024 (MSRV 1.85).
- Rewrote constant-time `sum_of_products` around signed-digit (booth) Straus; large
  constant-time inputs are dramatically faster. Re-tuned the variable-time Pippenger
  window thresholds by benchmark.

### Added
- Allocation-free `Scratch` with `sum_of_products_inplace` / `sum_of_products_vartime_inplace`.
- `Precomputed` fixed-base API for reusing a basis across many calls.
- `sum_of_products_iter` for streaming `(scalar, point)` pairs from an iterator.
- Optional `legacy` feature bridging curves still on `group`/`ff` 0.13 (curve25519-dalek,
  ed448-goldilocks, bls12-381 forks): `legacy::SumOfProducts` plus `Group013`/`Scalar013`
  wrappers.
- Constant-time verification harnesses (dudect, ctgrind) and cross-curve interop tests.

### Removed
- Dropped the external `multiexp` crate dependency; multi-scalar multiplication is now
  implemented in-crate.

### Fixed
- Little-endian scalar representations (curve25519 / ed448 / bls12-381 style) produced
  incorrect `sum_of_products` results; the recoder now handles both endiannesses.

## 0.2.0
- Updated the (since dropped) `multiexp` dependency to 0.4.

## 0.1.1
- Fixes for hex in alloc/std mode

## 0.1.0
- Initial release
