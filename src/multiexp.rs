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

/// Whether `F::Repr` stores the least-significant byte first (little-endian).
///
/// `PrimeField` does not fix an endianness for `to_repr`: the RustCrypto Weierstrass
/// curves are big-endian, while curve25519/ed448/bls12-381-style fields are little-endian.
/// This is decided from `ONE`'s representation — a public constant — so it depends only
/// on the field type and never on a secret scalar.
fn little_endian_repr<F: PrimeField>() -> bool {
    let repr = F::ONE.to_repr();
    repr.as_ref().first().copied() == Some(1)
}

/// Recode every scalar into signed windowed digits, packed into `digits`.
///
/// Each digit lies in `[-2^(w-1), 2^(w-1)-1]`, stored as an `i8` reinterpreted as `u8`.
/// `digits` must be exactly `pairs.len() * signed_digit_count::<G>(window)` long; every
/// entry is written, so the buffer may be reused. Handles both `to_repr` endiannesses.
/// Runs in constant time: control flow depends only on the window size, scalar bit
/// length, and (public) repr endianness, never on scalar values.
fn recode_signed<F: PrimeField>(
    scalars: impl IntoIterator<Item = F>,
    window: u8,
    digits: &mut [u8],
) {
    let w = usize::from(window);
    let windows = (F::Repr::default().as_ref().len() * 8).div_ceil(w);
    let count = windows + 1;
    let mask = (1_u32 << w) - 1;
    let half = 1_i32 << (w - 1);
    let base = 1_i32 << w;
    let little_endian = little_endian_repr::<F>();

    for (scalar_index, scalar) in scalars.into_iter().enumerate() {
        let repr = scalar.to_repr();
        let bytes: &[u8] = repr.as_ref();
        let len = bytes.len();
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

        // Walk bytes least-significant first regardless of the repr's endianness.
        for index in 0..len {
            let byte = if little_endian {
                bytes[index]
            } else {
                bytes[len - 1 - index]
            };
            accumulator |= u32::from(byte) << available_bits;
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
fn fill_signed_tables<G: Group>(points: impl IntoIterator<Item = G>, window: u8, values: &mut [G]) {
    let len = signed_table_len(window);

    for (index, point) in points.into_iter().enumerate() {
        let offset = index * len;
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

/// The Straus accumulate loop over precomputed signed digits and tables.
///
/// `digits` holds `count` signed digits per scalar; `tables` holds `len` points per
/// scalar (`len == signed_table_len(window)`). Selection is constant-time.
fn straus_accumulate_ct<G>(window: u8, count: usize, len: usize, digits: &[u8], tables: &[G]) -> G
where
    G: ConditionallySelectable + Group,
{
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

/// The Straus accumulate loop with variable-time, digit-indexed table lookups.
///
/// Kept separate from [`straus_accumulate_ct`] so the constant-time routine can be
/// audited in isolation.
fn straus_accumulate_vartime<G>(
    window: u8,
    count: usize,
    len: usize,
    digits: &[u8],
    tables: &[G],
) -> G
where
    G: Group,
{
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

/// Constant-time Straus over caller-provided scratch buffers.
fn straus_with<G>(pairs: &[(G::Scalar, G)], window: u8, digits: &mut [u8], tables: &mut [G]) -> G
where
    G: ConditionallySelectable + Group,
{
    recode_signed(pairs.iter().map(|(scalar, _)| *scalar), window, digits);
    fill_signed_tables(pairs.iter().map(|(_, point)| *point), window, tables);
    straus_accumulate_ct(
        window,
        signed_digit_count::<G>(window),
        signed_table_len(window),
        digits,
        tables,
    )
}

/// Variable-time Straus over caller-provided scratch buffers.
fn straus_vartime_with<G>(
    pairs: &[(G::Scalar, G)],
    window: u8,
    digits: &mut [u8],
    tables: &mut [G],
) -> G
where
    G: Group,
{
    recode_signed(pairs.iter().map(|(scalar, _)| *scalar), window, digits);
    fill_signed_tables(pairs.iter().map(|(_, point)| *point), window, tables);
    straus_accumulate_vartime(
        window,
        signed_digit_count::<G>(window),
        signed_table_len(window),
        digits,
        tables,
    )
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
    recode_signed(pairs.iter().map(|(scalar, _)| *scalar), window, digits);

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

/// Constant-time sum of scalar products read from an iterator of pairs.
///
/// The constant-time path is always Straus, which touches each pair exactly once (to
/// recode its scalar and build its table), so the input can be consumed as a stream.
/// The variable-time path has no streaming equivalent: Pippenger revisits every point
/// once per window, which a single-pass iterator cannot provide.
pub(crate) fn multiexp_iter<G, I>(pairs: I) -> G
where
    G: ConditionallySelectable + Group,
    I: IntoIterator<Item = (G::Scalar, G)>,
    I::IntoIter: ExactSizeIterator,
{
    let mut iter = pairs.into_iter();
    let n = iter.len();
    if n == 0 {
        return G::identity();
    }
    if n == 1 {
        if let Some((scalar, point)) = iter.next() {
            return point * scalar;
        }
        return G::identity();
    }

    let window = STRAUS_CT_WINDOW;
    let count = signed_digit_count::<G>(window);
    let len = signed_table_len(window);
    let mut digits = vec![0u8; n * count];
    let mut tables = vec![G::identity(); n * len];

    for (index, (scalar, point)) in iter.take(n).enumerate() {
        recode_signed(
            core::iter::once(scalar),
            window,
            &mut digits[index * count..index * count + count],
        );
        fill_signed_tables(
            core::iter::once(point),
            window,
            &mut tables[index * len..index * len + len],
        );
    }

    straus_accumulate_ct(window, count, len, &digits, &tables)
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

/// Default constant-time window for a precomputed basis.
///
/// Precomputation removes the per-call table build, but the constant-time accumulate
/// still scans the whole table per window, and that select cost grows with the table
/// size. Benchmarking confirms `w = 5` stays optimal even with the table build free —
/// a larger window's bigger scan outweighs its fewer additions. Variable-time callers,
/// whose lookup is a direct index, may prefer a larger window via
/// [`Precomputed::with_window`].
const PRECOMPUTE_WINDOW: u8 = 5;

/// Error returned when a [`Precomputed`] basis and the supplied scalars differ in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LengthMismatch {
    /// Number of precomputed basis points.
    pub points: usize,
    /// Number of scalars supplied.
    pub scalars: usize,
}

impl core::fmt::Display for LengthMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "length mismatch: {} basis points, {} scalars",
            self.points, self.scalars
        )
    }
}

impl core::error::Error for LengthMismatch {}

/// A fixed basis of group elements with precomputed Straus tables.
///
/// Building the per-point tables is a large share of a sum-of-products call. When the
/// same basis is reused across many calls with different scalars — Pedersen commitments,
/// polynomial commitments, threshold signatures over fixed generators — precompute it
/// once with [`Precomputed::new`] and call [`Precomputed::sum_of_products`] repeatedly to
/// skip that work every time — about 15% faster per constant-time call for a fixed basis.
pub struct Precomputed<G> {
    tables: Vec<G>,
    window: u8,
    len: usize,
}

impl<G: Group> Precomputed<G> {
    /// Precompute tables for `points` using the default window.
    pub fn new(points: &[G]) -> Self {
        Self::with_window(points, PRECOMPUTE_WINDOW)
    }

    /// Precompute tables for `points` using the given window, clamped to `2..=8`.
    ///
    /// Larger windows cost more memory (`points.len() * 2^(window-1)` group elements) but
    /// fewer additions per call.
    pub fn with_window(points: &[G], window: u8) -> Self {
        let window = window.clamp(2, 8);
        let len = points.len();
        let mut tables = vec![G::identity(); len * signed_table_len(window)];
        fill_signed_tables(points.iter().copied(), window, &mut tables);
        Self {
            tables,
            window,
            len,
        }
    }

    /// Number of basis points.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the basis is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Constant-time sum of `scalars[i] * points[i]` over the precomputed basis.
    ///
    /// Returns [`LengthMismatch`] if `scalars.len()` differs from the basis length.
    pub fn sum_of_products(&self, scalars: &[G::Scalar]) -> Result<G, LengthMismatch>
    where
        G: ConditionallySelectable,
    {
        self.sum_of_products_iter(scalars.iter().copied())
    }

    /// Constant-time [`Precomputed::sum_of_products`] reading scalars from an iterator.
    pub fn sum_of_products_iter<I>(&self, scalars: I) -> Result<G, LengthMismatch>
    where
        G: ConditionallySelectable,
        I: IntoIterator<Item = G::Scalar>,
        I::IntoIter: ExactSizeIterator,
    {
        let (count, digits) = self.recode_or_mismatch(scalars)?;
        Ok(straus_accumulate_ct(
            self.window,
            count,
            signed_table_len(self.window),
            &digits,
            &self.tables,
        ))
    }

    /// Variable-time sum of `scalars[i] * points[i]` over the precomputed basis.
    ///
    /// Returns [`LengthMismatch`] if `scalars.len()` differs from the basis length.
    pub fn sum_of_products_vartime(&self, scalars: &[G::Scalar]) -> Result<G, LengthMismatch> {
        self.sum_of_products_vartime_iter(scalars.iter().copied())
    }

    /// Variable-time [`Precomputed::sum_of_products_vartime`] reading scalars from an iterator.
    pub fn sum_of_products_vartime_iter<I>(&self, scalars: I) -> Result<G, LengthMismatch>
    where
        I: IntoIterator<Item = G::Scalar>,
        I::IntoIter: ExactSizeIterator,
    {
        let (count, digits) = self.recode_or_mismatch(scalars)?;
        Ok(straus_accumulate_vartime(
            self.window,
            count,
            signed_table_len(self.window),
            &digits,
            &self.tables,
        ))
    }

    /// Recode `scalars` into a fresh digit buffer, checking the length matches the basis.
    fn recode_or_mismatch<I>(&self, scalars: I) -> Result<(usize, Vec<u8>), LengthMismatch>
    where
        I: IntoIterator<Item = G::Scalar>,
        I::IntoIter: ExactSizeIterator,
    {
        let scalars = scalars.into_iter();
        if scalars.len() != self.len {
            return Err(LengthMismatch {
                points: self.len,
                scalars: scalars.len(),
            });
        }
        let count = signed_digit_count::<G>(self.window);
        let mut digits = vec![0u8; self.len * count];
        recode_signed(scalars, self.window, &mut digits);
        Ok((count, digits))
    }
}
