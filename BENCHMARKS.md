# Benchmarks — broadside

Measured 2026-11-27 (batch B1) on primo: 13th Gen Intel Core i7-13620H,
16 threads, 62 GiB RAM, cargo/rustc 1.100.0. The bench harness
(`benches/hot_paths.rs`, hand-rolled on `std::time`, `harness = false`)
drives the **debug** server binary over stdio; numbers are single-run
and primo is a shared machine, so treat them as orientation, not
lab-grade. Reproduce with:

```sh
cargo build --examples --benches
cargo bench --bench hot_paths
cargo run --example stdio_session   # the session the bench drives
```

## Workloads

| Workload | Definition |
| --- | --- |
| `cold_start_discover` | Spawn the server, send `server/discover` (modern era 2026-07-28), await the response; averaged over 5 spawns. |
| `tools_list` | `tools/list` on a warm session; 20 warmup calls, then 200 measured calls. |
| `tool_call` | Representative read-only call `broadside_status` on a warm session; 20 warmup calls, then 200 measured calls. |

Session setup: `BROADSIDE_SITE_ROOT` / `BROADSIDE_STATE_DIR` point into a temp dir (empty state: no receipts, no key record). `broadside_status` is comparatively expensive because it inspects the site tree's git state and the receipt chain on every call. The pre-existing `examples/make_fixtures.rs` example is unchanged and still compiles.

Tool surface seen by the example: 5 tools (broadside_status, broadside_live_check, broadside_build, broadside_verify, broadside_deploy).

## Results (2026-11-27 run)

| Workload | Result |
| --- | --- |
| cold start → discover | 48.30 ms per spawn (avg of 5) |
| tools/list | 1,957,705 ns/op (510.8 ops/s) |
| tools/call `broadside_status` | 229,251,606 ns/op (4.4 ops/s) |

## Gates at the same commit

- `cargo build --examples` — clean
- `cargo run --example stdio_session` — green (`stdio_session: ok`)
- `cargo bench --bench hot_paths` — runs to the numbers above
- `cargo test` — 74 passed, 0 failed
- `cargo clippy --examples --benches` — no errors or warnings on the added files

Base commit: `05234e0` (main). Branch: `pax/benchmarks-examples-20261127`.
