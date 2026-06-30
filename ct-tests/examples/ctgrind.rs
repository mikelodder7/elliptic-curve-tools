//! ctgrind-style constant-time test using Valgrind's client requests.
//!
//! Each secret scalar's memory is marked "undefined" before calling the constant-time
//! `sum_of_products`. Valgrind's memcheck then tracks that taint through the computation
//! and reports any conditional branch or memory address that depends on it — exactly the
//! data-dependent operations a constant-time routine must avoid.
//!
//! Valgrind does not run on macOS aarch64, so this is gated to Linux. Run it as:
//!   cargo build --release --example ctgrind
//!   valgrind --error-exitcode=1 ./target/release/examples/ctgrind
//! A clean Valgrind report (no "depends on uninitialised value" errors) means no leak.

#[cfg(target_os = "linux")]
fn main() {
    use core::ffi::c_void;
    use core::mem::size_of_val;
    use crabgrind::memcheck::{MemState, mark_memory};
    use elliptic_curve::{Field, Group};
    use elliptic_curve_tools::SumOfProducts;
    use k256::ProjectivePoint as G;

    type Scalar = <G as Group>::Scalar;

    const N: usize = 16;

    // Build valid (secret scalar, public point) pairs.
    let generator = G::generator();
    let mut point = generator;
    let mut scalar = Scalar::ONE;
    let mut pairs: Vec<(Scalar, G)> = Vec::with_capacity(N);
    for _ in 0..N {
        scalar = scalar.double() + Scalar::ONE;
        pairs.push((scalar, point));
        point += generator;
    }

    // Mark each secret scalar's bytes undefined; the public points stay defined.
    for (scalar, _) in &pairs {
        let _ = mark_memory(
            (scalar as *const Scalar) as *const c_void,
            size_of_val(scalar),
            MemState::Undefined,
        );
    }

    let result = G::sum_of_products(&pairs);

    // Re-define the result so simply consuming it doesn't raise a spurious report.
    let _ = mark_memory(
        (&result as *const G) as *const c_void,
        size_of_val(&result),
        MemState::Defined,
    );
    core::hint::black_box(result);

    println!("ctgrind: computed sum_of_products over {N} secret scalars");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ctgrind requires Linux with Valgrind installed; nothing to run on this platform.");
}
