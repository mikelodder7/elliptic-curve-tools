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

struct ScalarWindows {
    values: Vec<u8>,
    width: usize,
}

impl ScalarWindows {
    fn get(&self, scalar: usize, window: usize) -> u8 {
        self.values[(scalar * self.width) + window]
    }
}

/// Select the variable-time algorithm and window for `len` scalar/point pairs.
///
/// Variable-time Pippenger indexes a single bucket per scalar, so it pays only one
/// point addition per scalar per window plus a `2^w` bucket reduction. The optimal
/// window therefore grows with `len`. Boundaries were tuned by benchmarking every
/// `(algorithm, window)` candidate on 256-bit scalars across `len` from 2 to 2600
/// (Straus wins below ~128 where the bucket reduction is not yet amortized).
///
/// The constant-time path does not use this table; see [`STRAUS_CT_WINDOW`].
fn vartime_algorithm(len: usize) -> Algorithm {
    const FINAL_ALGORITHM: Algorithm = Algorithm::Pippenger(8);

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

fn prep_bits<G>(pairs: &[(G::Scalar, G)], window: u8) -> ScalarWindows
where
    G: Group,
{
    let window = usize::from(window);
    let bit_len = pairs[0].0.to_repr().as_ref().len() * 8;
    let width = bit_len.div_ceil(window);
    let mask = (1_u16 << window) - 1;
    let mut values = vec![0; pairs.len() * width];

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

    ScalarWindows { values, width }
}

struct StrausTables<G> {
    values: Vec<G>,
    width: usize,
}

impl<G> StrausTables<G> {
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

fn prep_tables<G>(pairs: &[(G::Scalar, G)], window: u8) -> StrausTables<G>
where
    G: Group,
{
    let width = 1_usize << window;
    let mut values = vec![G::identity(); pairs.len() * width];

    for (scalar_index, (_, point)) in pairs.iter().enumerate() {
        let offset = scalar_index * width;
        let mut accum = G::identity();
        for entry in values[offset + 1..offset + width].iter_mut() {
            accum += point;
            *entry = accum;
        }
    }

    StrausTables { values, width }
}

fn straus<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: ConditionallySelectable + Group,
{
    let groupings = prep_bits(pairs, window);
    let tables = prep_tables(pairs, window);

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

fn straus_vartime<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: Group,
{
    let groupings = prep_bits(pairs, window);
    let tables = prep_tables(pairs, window);

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

fn pippenger_vartime<G>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
    G: Group,
{
    let bits = prep_bits(pairs, window);

    let identity = G::identity();
    let mut result = identity;
    let mut buckets = vec![identity; 1_usize << window];

    for bit_group in (0..bits.width).rev() {
        if bit_group != bits.width - 1 {
            for _ in 0..window {
                result = result.double();
            }
        }

        buckets.fill(identity);
        for (scalar, (_, point)) in pairs.iter().enumerate() {
            let window = bits.get(scalar, bit_group);
            if window != 0 {
                buckets[usize::from(window)] += point;
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
