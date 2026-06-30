#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::{vec, vec::Vec};

use elliptic_curve::{
    Group, PrimeField,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Null,
    Single,
    Straus(u8),
    Pippenger(u8),
}

/// Window size for the constant-time Straus routine.
///
/// The hot cost of constant-time Straus is the accumulate loop: one point addition
/// per scalar per window, i.e. `width = ceil(bits / w)` additions per scalar. Signed
/// (booth) recoding lets a window of `w` reuse a table of only `2^(w-1)` points, so a
/// given table/select budget buys a *larger* window — fewer windows, fewer of the
/// dominant additions. Benchmarking signed windows on 256-bit scalars, `w = 5` is the
/// optimum (`w = 6` loses, its larger table/select outweighing the saved additions).
const STRAUS_CT_WINDOW: u8 = 5;

/// Smallest window any algorithm selects.
///
/// [`Scratch::new`] uses this to size the worst-case digit buffer (the smallest window
/// yields the most windows). Every window in [`vartime_algorithm`] and
/// [`STRAUS_CT_WINDOW`] must be at least this value.
const MIN_WINDOW: u8 = 4;

/// Largest window any Straus path selects.
///
/// [`Scratch::new`] uses this to size the worst-case point buffer (the largest Straus
/// window yields the largest per-scalar table). Every Straus window in
/// [`vartime_algorithm`] and [`STRAUS_CT_WINDOW`] must be at most this value.
const MAX_STRAUS_WINDOW: u8 = 5;

/// Select the variable-time algorithm and window for `len` scalar/point pairs.
///
/// Variable-time Pippenger indexes a single bucket per scalar, so it pays only one
/// point addition per scalar per window plus a bucket reduction. The optimal window
/// grows with `len`. Boundaries were tuned by benchmarking every `(algorithm, window)`
/// candidate (signed-digit) on 256-bit scalars across `len` from 2 to 2600; Straus wins
/// below the first threshold, where the bucket reduction is not yet amortized.
///
/// The constant-time path does not use this table; see [`STRAUS_CT_WINDOW`].
fn vartime_algorithm(len: usize) -> Algorithm {
    const FINAL_ALGORITHM: Algorithm = Algorithm::Pippenger(8);

    // Straus windows must lie in [MIN_WINDOW, MAX_STRAUS_WINDOW]; Pippenger windows must
    // be >= MIN_WINDOW. `Scratch::new` relies on these bounds to size its buffers.
    const THRESHOLDS: &[(usize, Algorithm)] = &[
        (128, Algorithm::Straus(5)),
        (400, Algorithm::Pippenger(6)),
        (900, Algorithm::Pippenger(7)),
    ];

    if len == 0 {
        return Algorithm::Null;
    }

    if len == 1 {
        return Algorithm::Single;
    }

    for (limit, algorithm) in THRESHOLDS {
        if len < *limit {
            return *algorithm;
        }
    }

    FINAL_ALGORITHM
}

/// Bit length of a scalar's canonical byte representation.
fn scalar_bits<G: Group>() -> usize {
    <<G as Group>::Scalar as PrimeField>::Repr::default()
        .as_ref()
        .len()
        * 8
}

/// Number of signed windowed digits a scalar produces for the given window size.
///
/// This is `ceil(bits / w) + 1`: one digit per window plus a final carry digit.
fn signed_digit_count<G: Group>(window: u8) -> usize {
    scalar_bits::<G>().div_ceil(usize::from(window)) + 1
}

/// Number of points in a signed Straus table or signed Pippenger bucket array.
///
/// Signed digits have magnitude in `0..=2^(w-1)`, so indices `0..=2^(w-1)` are needed.
fn signed_table_len(window: u8) -> usize {
    (1_usize << (window - 1)) + 1
}

/// Recode every scalar into signed windowed digits, packed into `digits`.
///
/// Each digit lies in `[-2^(w-1), 2^(w-1)-1]`, stored as an `i8` reinterpreted as `u8`.
/// `digits` must be exactly `pairs.len() * signed_digit_count::<G>(window)` long; every
/// entry is written, so the buffer may be reused. Runs in constant time: control flow
/// depends only on the window size and scalar bit length, never on scalar values.
fn recode_signed<G: Group>(pairs: &[(G::Scalar, G)], window: u8, digits: &mut [u8]) {
    let w = usize::from(window);
    let windows = scalar_bits::<G>().div_ceil(w);
    let count = windows + 1;
    let mask = (1_u32 << w) - 1;
    let half = 1_i32 << (w - 1);
    let base = 1_i32 << w;

    for (scalar_index, (scalar, _)) in pairs.iter().enumerate() {
        let repr = scalar.to_repr();
        let bytes: &[u8] = repr.as_ref();
        let offset = scalar_index * count;

        let mut accumulator = 0_u32;
        let mut available_bits = 0_usize;
        let mut produced = 0_usize;
        let mut carry = 0_i32;

        let recode = |unsigned: i32, carry: &mut i32| -> u8 {
            let t = unsigned + *carry; // 0..=2^w
            let ge = ((half - 1 - t) >> 31) & 1; // 1 if t >= half
            let signed = t - ge * base; // [-2^(w-1), 2^(w-1)-1]
            *carry = ge;
            (signed as i8) as u8
        };

        for byte in bytes.iter().rev() {
            accumulator |= u32::from(*byte) << available_bits;
            available_bits += 8;
            while available_bits >= w && produced < windows {
                let unsigned = (accumulator & mask) as i32;
                accumulator >>= w;
                available_bits -= w;
                digits[offset + produced] = recode(unsigned, &mut carry);
                produced += 1;
            }
        }
        while produced < windows {
            let unsigned = (accumulator & mask) as i32;
            accumulator >>= w;
            digits[offset + produced] = recode(unsigned, &mut carry);
            produced += 1;
        }
        digits[offset + windows] = (carry as i8) as u8;
    }
}

/// Build the signed Straus tables for every scalar into `values`.
///
/// Entry `k` of a scalar's table holds `k * point` for `k` in `0..=2^(w-1)`. `values`
/// must be exactly `pairs.len() * signed_table_len(window)` long; every entry is written
/// (entry `0` is reset to the identity), so the buffer may be reused.
fn fill_signed_tables<G: Group>(pairs: &[(G::Scalar, G)], window: u8, values: &mut [G]) {
    let len = signed_table_len(window);

    for (scalar_index, (_, point)) in pairs.iter().enumerate() {
        let offset = scalar_index * len;
        values[offset] = G::identity();
        let mut accum = G::identity();
        for entry in values[offset + 1..offset + len].iter_mut() {
            accum += point;
            *entry = accum;
        }
    }
}

/// Constant-time signed selection of `|digit| * point` from a scalar's table.
///
/// Scans the whole table with constant-time selection, then conditionally negates,
/// leaking nothing about the digit through control flow or memory access.
fn signed_select_ct<G>(table: &[G], digit: i8) -> G
where
    G: ConditionallySelectable + Group,
{
    let magnitude = digit.unsigned_abs();
    let sign = (digit as u8) >> 7; // 1 if negative

    let mut selected = G::identity();
    for (index, candidate) in table.iter().enumerate() {
        selected = G::conditional_select(&selected, candidate, (index as u8).ct_eq(&magnitude));
    }

    let negated = -selected;
    G::conditional_select(&selected, &negated, Choice::from(sign))
}

/// Constant-time Straus over caller-provided scratch buffers.
fn straus_with<G>(pairs: &[(G::Scalar, G)], window: u8, digits: &mut [u8], tables: &mut [G]) -> G
where
    G: ConditionallySelectable + Group,
{
    recode_signed(pairs, window, digits);
    fill_signed_tables(pairs, window, tables);

    let count = signed_digit_count::<G>(window);
    let len = signed_table_len(window);

    let mut result = G::identity();
    for digit_index in (0..count).rev() {
        if digit_index != count - 1 {
            for _ in 0..window {
                result = result.double();
            }
        }

        for (scalar, table) in tables.chunks_exact(len).enumerate() {
            let digit = digits[scalar * count + digit_index] as i8;
            result += signed_select_ct(table, digit);
        }
    }

    result
}

/// Variable-time Straus over caller-provided scratch buffers.
///
/// Identical to [`straus_with`] except the table lookup is digit-indexed (negating for
/// negative digits) instead of scanned; the two paths are kept separate so the
/// constant-time routine can be audited in isolation.
fn straus_vartime_with<G>(
    pairs: &[(G::Scalar, G)],
    window: u8,
    digits: &mut [u8],
    tables: &mut [G],
) -> G
where
    G: Group,
{
    recode_signed(pairs, window, digits);
    fill_signed_tables(pairs, window, tables);

    let count = signed_digit_count::<G>(window);
    let len = signed_table_len(window);

    let mut result = G::identity();
    for digit_index in (0..count).rev() {
        if digit_index != count - 1 {
            for _ in 0..window {
                result = result.double();
            }
        }

        for (scalar, table) in tables.chunks_exact(len).enumerate() {
            let digit = digits[scalar * count + digit_index] as i8;
            let magnitude = usize::from(digit.unsigned_abs());
            if magnitude != 0 {
                let point = table[magnitude];
                if digit < 0 {
                    result += -point;
                } else {
                    result += point;
                }
            }
        }
    }

    result
}

/// Variable-time Pippenger over caller-provided scratch buffers.
///
/// `buckets` must be exactly `signed_table_len(window)` long.
fn pippenger_vartime_with<G>(
    pairs: &[(G::Scalar, G)],
    window: u8,
    digits: &mut [u8],
    buckets: &mut [G],
) -> G
where
    G: Group,
{
    recode_signed(pairs, window, digits);

    let count = signed_digit_count::<G>(window);
    let identity = G::identity();
    let mut result = identity;

    for digit_index in (0..count).rev() {
        if digit_index != count - 1 {
            for _ in 0..window {
                result = result.double();
            }
        }

        buckets.fill(identity);
        for (scalar, (_, point)) in pairs.iter().enumerate() {
            let digit = digits[scalar * count + digit_index] as i8;
            let magnitude = usize::from(digit.unsigned_abs());
            if magnitude != 0 {
                if digit < 0 {
                    buckets[magnitude] += -*point;
                } else {
                    buckets[magnitude] += point;
                }
            }
        }

        let mut intermediate_sum = identity;
        for bucket in buckets.iter().skip(1).rev() {
            intermediate_sum += bucket;
            result += intermediate_sum;
        }
    }

    result
}

fn straus<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: ConditionallySelectable + Group,
{
    let n = pairs.len();
    let mut digits = vec![0u8; n * signed_digit_count::<G>(window)];
    let mut tables = vec![G::identity(); n * signed_table_len(window)];
    straus_with(pairs, window, &mut digits, &mut tables)
}

fn straus_vartime<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: Group,
{
    let n = pairs.len();
    let mut digits = vec![0u8; n * signed_digit_count::<G>(window)];
    let mut tables = vec![G::identity(); n * signed_table_len(window)];
    straus_vartime_with(pairs, window, &mut digits, &mut tables)
}

fn pippenger_vartime<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: Group,
{
    let n = pairs.len();
    let mut digits = vec![0u8; n * signed_digit_count::<G>(window)];
    let mut buckets = vec![G::identity(); signed_table_len(window)];
    pippenger_vartime_with(pairs, window, &mut digits, &mut buckets)
}

/// Compute the sum of scalar products for a set of scalar/group pairs.
pub(crate) fn multiexp<G>(pairs: &[(G::Scalar, G)]) -> G
where
    G: ConditionallySelectable + Group,
{
    match pairs.len() {
        0 => G::identity(),
        1 => pairs[0].1 * pairs[0].0,
        _ => straus(pairs, STRAUS_CT_WINDOW),
    }
}

/// Compute the sum of scalar products using variable-time table lookups.
pub(crate) fn multiexp_vartime<G>(pairs: &[(G::Scalar, G)]) -> G
where
    G: Group,
{
    match vartime_algorithm(pairs.len()) {
        Algorithm::Null => G::identity(),
        Algorithm::Single => pairs[0].1 * pairs[0].0,
        Algorithm::Straus(window) => straus_vartime(pairs, window),
        Algorithm::Pippenger(window) => pippenger_vartime(pairs, window),
    }
}

/// Identifies which buffer of a [`Scratch`] was undersized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScratchBuffer {
    /// The windowed-digit buffer.
    Digits,
    /// The point buffer (Straus tables or Pippenger buckets).
    Points,
}

/// Error returned by the in-place multiexp methods when a caller-supplied
/// [`Scratch`] is too small for the requested number of pairs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InsufficientScratch {
    /// Which buffer was undersized.
    pub buffer: ScratchBuffer,
    /// The length the caller provided.
    pub provided: usize,
    /// The minimum length required for this call.
    pub required: usize,
}

impl core::fmt::Display for InsufficientScratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let buffer = match self.buffer {
            ScratchBuffer::Digits => "digit",
            ScratchBuffer::Points => "point",
        };
        write!(
            f,
            "insufficient {buffer} scratch: provided {}, required {}",
            self.provided, self.required
        )
    }
}

impl core::error::Error for InsufficientScratch {}

/// Pre-allocated scratch space for the allocation-free multiexp methods
/// ([`SumOfProducts::sum_of_products_inplace`] and
/// [`SumOfProducts::sum_of_products_vartime_inplace`]).
///
/// Allocate once with [`Scratch::new`] and reuse it across many calls to avoid
/// per-call heap traffic. A scratch built for `capacity` pairs is valid for any
/// call with `capacity` or fewer pairs, in either the constant- or variable-time
/// path.
///
/// [`SumOfProducts::sum_of_products_inplace`]: crate::SumOfProducts::sum_of_products_inplace
/// [`SumOfProducts::sum_of_products_vartime_inplace`]: crate::SumOfProducts::sum_of_products_vartime_inplace
pub struct Scratch<G> {
    digits: Vec<u8>,
    points: Vec<G>,
}

impl<G: Group> Scratch<G> {
    /// Allocate scratch reusable for any sum-of-products over at most `capacity` pairs.
    ///
    /// Both buffers are sized for the worst case across every algorithm and window the
    /// crate may select: the most windowed digits (smallest window) and the largest
    /// per-scalar table (largest Straus window).
    pub fn new(capacity: usize) -> Self {
        Self {
            digits: vec![0u8; capacity.saturating_mul(signed_digit_count::<G>(MIN_WINDOW))],
            points: vec![
                G::identity();
                capacity.saturating_mul(signed_table_len(MAX_STRAUS_WINDOW))
            ],
        }
    }

    fn check(&self, digits: usize, points: usize) -> Result<(), InsufficientScratch> {
        if self.digits.len() < digits {
            return Err(InsufficientScratch {
                buffer: ScratchBuffer::Digits,
                provided: self.digits.len(),
                required: digits,
            });
        }
        if self.points.len() < points {
            return Err(InsufficientScratch {
                buffer: ScratchBuffer::Points,
                provided: self.points.len(),
                required: points,
            });
        }
        Ok(())
    }
}

/// Constant-time sum of scalar products into caller-provided [`Scratch`].
pub(crate) fn multiexp_inplace<G>(
    pairs: &[(G::Scalar, G)],
    scratch: &mut Scratch<G>,
) -> Result<G, InsufficientScratch>
where
    G: ConditionallySelectable + Group,
{
    let n = pairs.len();
    match n {
        0 => return Ok(G::identity()),
        1 => return Ok(pairs[0].1 * pairs[0].0),
        _ => {}
    }

    let window = STRAUS_CT_WINDOW;
    let digits = n * signed_digit_count::<G>(window);
    let points = n * signed_table_len(window);
    scratch.check(digits, points)?;

    Ok(straus_with(
        pairs,
        window,
        &mut scratch.digits[..digits],
        &mut scratch.points[..points],
    ))
}

/// Variable-time sum of scalar products into caller-provided [`Scratch`].
pub(crate) fn multiexp_vartime_inplace<G>(
    pairs: &[(G::Scalar, G)],
    scratch: &mut Scratch<G>,
) -> Result<G, InsufficientScratch>
where
    G: Group,
{
    let n = pairs.len();
    match vartime_algorithm(n) {
        Algorithm::Null => Ok(G::identity()),
        Algorithm::Single => Ok(pairs[0].1 * pairs[0].0),
        Algorithm::Straus(window) => {
            let digits = n * signed_digit_count::<G>(window);
            let points = n * signed_table_len(window);
            scratch.check(digits, points)?;
            Ok(straus_vartime_with(
                pairs,
                window,
                &mut scratch.digits[..digits],
                &mut scratch.points[..points],
            ))
        }
        Algorithm::Pippenger(window) => {
            let digits = n * signed_digit_count::<G>(window);
            let points = signed_table_len(window);
            scratch.check(digits, points)?;
            Ok(pippenger_vartime_with(
                pairs,
                window,
                &mut scratch.digits[..digits],
                &mut scratch.points[..points],
            ))
        }
    }
}
