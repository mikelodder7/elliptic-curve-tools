# Constant-time tests

Standalone harnesses that verify `elliptic_curve_tools::SumOfProducts::sum_of_products`
(the constant-time multiexp) does not leak the secret scalars through timing or
data-dependent control flow.

This is a **separate workspace** on purpose: the harnesses depend on a statistics/CLI
stack (dudect) and on Valgrind bindings (ctgrind) that should not enter the main crate's
dependency graph or its CI. The parent crate never builds anything here. Run the tools
deliberately:

## dudect (timing, runs anywhere)

Statistical Welch's t-test over two classes of secret scalars (fixed vs. random). Run a
single pass, or `--continuous` to keep accumulating samples for one bench:

```sh
cargo run --release --bin dudect
cargo run --release --bin dudect -- --continuous sum_of_products
```

A constant-time implementation keeps `|t| < 10` no matter how long it runs. A `|t|` that
climbs with the sample count signals a timing leak. (A single pass over this crate's
`sum_of_products` reports `max t ≈ 2.3`.)

## ctgrind (Valgrind, Linux only)

Marks each secret scalar's memory "undefined" and runs the multiexp under Valgrind's
memcheck, which flags any branch or memory access derived from the secret. Valgrind has
no working macOS aarch64 port, so this is Linux-only and needs a C compiler + `libclang`
to build the bindings (`apt-get install build-essential libclang-dev`).

```sh
cargo build --release --example ctgrind
valgrind --error-exitcode=1 ./target/release/examples/ctgrind
```

A clean report (no "Conditional jump or move depends on uninitialised value" and no
"Use of uninitialised value") means no secret-dependent control flow or addressing.
