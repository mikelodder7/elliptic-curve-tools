#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::{vec, vec::Vec};

use elliptic_curve::{
    Group, PrimeField,
    subtle::{ConditionallySelectable, ConstantTimeEq},
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
/// Constant-time selection must scan every entry of a scalar's table for each
/// window, so the dominant cost is `n * (bits / w) * 2^w` constant-time selects.
/// Across all input sizes and 256–521 bit scalars, `w = 4` minimizes this while
/// keeping the precomputed table small (`2^4` points per scalar). Unlike the
/// variable-time path, Pippenger is never used here: its constant-time form
/// performs a full point addition into *every* bucket per scalar, making it 10–80x
/// slower than Straus.
const STRAUS_CT_WINDOW: u8 = 4;

/// Smallest window any algorithm selects.
///
/// [`Scratch::new`] relies on this to size the worst-case digit buffer (the
/// smallest window yields the widest windowed-digit layout). Every window in
/// [`vartime_algorithm`] and [`STRAUS_CT_WINDOW`] must be at least this value.
const MIN_WINDOW: u8 = 4;

/// Select the variable-time algorithm and window for `len` scalar/point pairs.
///
/// Variable-time Pippenger indexes a single bucket per scalar, so it pays only one
/// point addition per scalar per window plus a `2^w` bucket reduction. The optimal
/// window therefore grows with `len`. Boundaries were tuned by benchmarking every
/// `(algorithm, window)` candidate on 256-bit scalars across `len` from 2 to 2600
/// (Straus wins below ~128, where the bucket reduction is not yet amortized).
///
/// The constant-time path does not use this table; see [`STRAUS_CT_WINDOW`].
fn vartime_algorithm(len: usize) -> Algorithm {
    const FINAL_ALGORITHM: Algorithm = Algorithm::Pippenger(8);

    // Every window here must be >= MIN_WINDOW so `Scratch::new` sizes correctly.
    const THRESHOLDS: &[(usize, Algorithm)] = &[
        (128, Algorithm::Straus(4)),
        (400, Algorithm::Pippenger(5)),
        (800, Algorithm::Pippenger(6)),
        (1600, Algorithm::Pippenger(7)),
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

/// Number of windowed digits a scalar produces for the given window size.
fn digit_width<G: Group>(window: u8) -> usize {
    let bit_len = <<G as Group>::Scalar as PrimeField>::Repr::default()
        .as_ref()
        .len()
        * 8;
    bit_len.div_ceil(usize::from(window))
}

/// A borrowed view over a packed buffer of windowed scalar digits.
struct ScalarWindows<'a> {
    values: &'a [u8],
    width: usize,
}

impl ScalarWindows<'_> {
    fn get(&self, scalar: usize, window: usize) -> u8 {
        self.values[(scalar * self.width) + window]
    }
}

/// A borrowed view over a packed buffer of per-scalar Straus tables.
struct StrausTables<'a, G> {
    values: &'a [G],
    width: usize,
}

impl<G> StrausTables<'_, G> {
    fn select(&self, scalar: usize, entry: u8) -> G
    where
        G: ConditionallySelectable + Group,
    {
        let start = scalar * self.width;
        let mut selected = G::identity();

        for (table_index, candidate) in self.values[start..start + self.width].iter().enumerate() {
            selected =
                G::conditional_select(&selected, candidate, (table_index as u8).ct_eq(&entry));
        }

        selected
    }

    fn get_vartime(&self, scalar: usize, entry: u8) -> G
    where
        G: Copy,
    {
        self.values[(scalar * self.width) + usize::from(entry)]
    }
}

/// Pack the windowed digits of every scalar into `values`.
///
/// `values` must be exactly `pairs.len() * digit_width::<G>(window)` long. Every
/// entry is written, so the buffer may contain stale data from a previous call.
fn fill_digits<G: Group>(pairs: &[(G::Scalar, G)], window: u8, values: &mut [u8]) {
    let width = digit_width::<G>(window);
    let window = usize::from(window);
    let mask = (1_u16 << window) - 1;

    for (scalar_index, (scalar, _)) in pairs.iter().enumerate() {
        let repr = scalar.to_repr();
        let offset = scalar_index * width;
        let mut accumulator = 0_u16;
        let mut available_bits = 0;
        let mut entry = offset;

        for byte in repr.as_ref().iter().rev() {
            accumulator |= u16::from(*byte) << available_bits;
            available_bits += 8;

            while available_bits >= window {
                values[entry] = (accumulator & mask) as u8;
                accumulator >>= window;
                available_bits -= window;
                entry += 1;
            }
        }

        if entry < offset + width {
            values[entry] = accumulator as u8;
        }
    }
}

/// Build the incremental Straus tables for every scalar into `values`.
///
/// `values` must be exactly `pairs.len() * (1 << window)` long. Every entry is
/// written (entry `0` is reset to the identity), so the buffer may be reused.
fn fill_tables<G: Group>(pairs: &[(G::Scalar, G)], window: u8, values: &mut [G]) {
    let width = 1_usize << window;

    for (scalar_index, (_, point)) in pairs.iter().enumerate() {
        let offset = scalar_index * width;
        values[offset] = G::identity();
        let mut accum = G::identity();
        for entry in values[offset + 1..offset + width].iter_mut() {
            accum += point;
            *entry = accum;
        }
    }
}

/// Constant-time Straus over caller-provided scratch buffers.
fn straus_with<G>(pairs: &[(G::Scalar, G)], window: u8, digits: &mut [u8], tables: &mut [G]) -> G
where
    G: ConditionallySelectable + Group,
{
    fill_digits(pairs, window, digits);
    fill_tables(pairs, window, tables);

    let groupings = ScalarWindows {
        values: digits,
        width: digit_width::<G>(window),
    };
    let tables = StrausTables {
        values: tables,
        width: 1_usize << window,
    };

    let mut result = G::identity();
    for bit_group in (0..groupings.width).rev() {
        if bit_group != groupings.width - 1 {
            for _ in 0..window {
                result = result.double();
            }
        }

        for scalar in 0..pairs.len() {
            result += tables.select(scalar, groupings.get(scalar, bit_group));
        }
    }

    result
}

/// Variable-time Straus over caller-provided scratch buffers.
///
/// Identical to [`straus_with`] except table lookups are scalar-indexed instead of
/// scanned with constant-time selection; the two paths are kept separate so the
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
    fill_digits(pairs, window, digits);
    fill_tables(pairs, window, tables);

    let groupings = ScalarWindows {
        values: digits,
        width: digit_width::<G>(window),
    };
    let tables = StrausTables {
        values: tables,
        width: 1_usize << window,
    };

    let mut result = G::identity();
    for bit_group in (0..groupings.width).rev() {
        if bit_group != groupings.width - 1 {
            for _ in 0..window {
                result = result.double();
            }
        }

        for scalar in 0..pairs.len() {
            result += tables.get_vartime(scalar, groupings.get(scalar, bit_group));
        }
    }

    result
}

/// Variable-time Pippenger over caller-provided scratch buffers.
///
/// `buckets` must be exactly `1 << window` long.
fn pippenger_vartime_with<G>(
    pairs: &[(G::Scalar, G)],
    window: u8,
    digits: &mut [u8],
    buckets: &mut [G],
) -> G
where
    G: Group,
{
    fill_digits(pairs, window, digits);

    let groupings = ScalarWindows {
        values: digits,
        width: digit_width::<G>(window),
    };

    let identity = G::identity();
    let mut result = identity;

    for bit_group in (0..groupings.width).rev() {
        if bit_group != groupings.width - 1 {
            for _ in 0..window {
                result = result.double();
            }
        }

        buckets.fill(identity);
        for (scalar, (_, point)) in pairs.iter().enumerate() {
            let digit = groupings.get(scalar, bit_group);
            if digit != 0 {
                buckets[usize::from(digit)] += point;
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
    let mut digits = vec![0u8; n * digit_width::<G>(window)];
    let mut tables = vec![G::identity(); n * (1_usize << window)];
    straus_with(pairs, window, &mut digits, &mut tables)
}

fn straus_vartime<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: Group,
{
    let n = pairs.len();
    let mut digits = vec![0u8; n * digit_width::<G>(window)];
    let mut tables = vec![G::identity(); n * (1_usize << window)];
    straus_vartime_with(pairs, window, &mut digits, &mut tables)
}

fn pippenger_vartime<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: Group,
{
    let n = pairs.len();
    let mut digits = vec![0u8; n * digit_width::<G>(window)];
    let mut buckets = vec![G::identity(); 1_usize << window];
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
    /// crate may select: the widest digit layout (smallest window) and the largest
    /// per-pair point table.
    pub fn new(capacity: usize) -> Self {
        let width = digit_width::<G>(MIN_WINDOW);
        Self {
            digits: vec![0u8; capacity.saturating_mul(width)],
            points: vec![G::identity(); capacity.saturating_mul(1_usize << STRAUS_CT_WINDOW)],
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
    let digits = n * digit_width::<G>(window);
    let points = n * (1_usize << window);
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
            let digits = n * digit_width::<G>(window);
            let points = n * (1_usize << window);
            scratch.check(digits, points)?;
            Ok(straus_vartime_with(
                pairs,
                window,
                &mut scratch.digits[..digits],
                &mut scratch.points[..points],
            ))
        }
        Algorithm::Pippenger(window) => {
            let digits = n * digit_width::<G>(window);
            let points = 1_usize << window;
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
