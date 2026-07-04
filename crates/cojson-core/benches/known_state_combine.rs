//! Isolated benchmark for the known-state combine algebra.
//!
//! Measures native `combine_known_states` throughput at realistic known-state
//! sizes (5, 50, 500 sessions). This is the "raw compute" half of the R6a
//! wiring gate: it shows how fast the port is with zero FFI/marshaling cost. The
//! decision of whether to wire it through NodeCore must be weighed against the
//! JSON-marshal + FFI-crossing floor measured on the TypeScript side
//! (see packages/cojson/src/tests/knownStateCombine.bench.ts).
//!
//! Two variants per size:
//!   - `combine_owned`  : clone the target then combine (mirrors the real
//!     `combineKnownStates(cloneKnownState(target), source)` call shape).
//!   - `combine_in_place`: combine into a pre-existing mutable target (the
//!     absolute floor — no allocation).

use cojson_core::core::known_state::{
    combine_known_states, CoValueKnownState, KnownStateSessions,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn make_state(n: usize, base: u32) -> CoValueKnownState {
    let mut sessions = KnownStateSessions::new();
    for i in 0..n {
        // realistic-looking session id strings
        sessions.insert(
            format!("co_zGroup_session_z{i:04}AbCdEfGhIjKlMnOp"),
            base + (i as u32),
        );
    }
    CoValueKnownState {
        id: "co_zBenchKnownState".to_string(),
        header: true,
        sessions,
    }
}

fn bench_combine(c: &mut Criterion) {
    let mut group = c.benchmark_group("known_state_combine");

    for &n in &[5usize, 50, 500] {
        let target = make_state(n, 100);
        // source overlaps fully but is ahead on every session (worst case: every
        // entry triggers an insert)
        let source = make_state(n, 100_000);

        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("combine_owned", n), &n, |b, _| {
            b.iter(|| {
                let mut t = target.clone();
                combine_known_states(&mut t, &source);
                std::hint::black_box(&t);
            });
        });

        group.bench_with_input(BenchmarkId::new("combine_in_place", n), &n, |b, _| {
            b.iter_batched(
                || target.clone(),
                |mut t| {
                    combine_known_states(&mut t, &source);
                    std::hint::black_box(&t);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_combine);
criterion_main!(benches);
