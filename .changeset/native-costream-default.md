---
"cojson": patch
---

Enable native (Rust-resident) CRDT materialization by default for coMap,
coStream/coFeed, and binaryCoStream. The `nativeCoMapMaterializationEnabled`,
`nativeCoStreamMaterializationEnabled`, and `nativeBinaryStreamMaterializationEnabled`
flags now default to `true` per the 100%-Rust scope goal: cojson's CRDT
materialization lives in the Rust core, consumed in TS through per-op / per-session
rich deltas instead of walking `getValidTransactions` in TS.

This is an intentional, documented behavior change. Output is byte-identical to
the TS materializers (verified by the cojson + jazz-tools suites and the coStream
content fixtures). A known absolute-performance cost exists on cold-bulk-ingest
shapes — the delta transfer can exceed the JS materialization it replaces — but
it is accepted because the goal is architectural completeness, not raw speed. The
TS `RawCoMap`/`RawCoStreamView`/`RawBinaryCoStreamView` materializers remain in
place as fallback/reference (each flag can be toggled off) pending their own
deletion phase. The React Native uniffi binding, which does not yet expose the
coStream surface, transparently keeps the TS coStream path.
