# broadside.receipt v1 — schema of record

The receipt log is broadside's memory and vongola's evidence
feed. Status never guesses: everything `broadside_status` reports
about the past comes from this log, chain-verified on read.

## Transport

- One JSON object per line, UTF-8, LF-terminated.
- Append-only. Writers append a whole line in a single write and
  sync before reporting success.
- Location: `$BROADSIDE_STATE_DIR/receipts.jsonl`
  (default `~/.local/share/broadside/receipts.jsonl`).
- Readers verify the full hash chain before trusting any entry:
  a tampered, deleted, or reordered line breaks verification and
  every reader fails closed.

## Fields

| field       | type   | meaning |
|-------------|--------|---------|
| `schema`    | string | always `"broadside.receipt"` |
| `version`   | int    | always `1` in this schema |
| `seq`       | int    | 1-based sequence number, gapless |
| `ts`        | string | RFC 3339 UTC (`...Z`), second precision |
| `actor`     | string | `"broadside-mcp/<version>"` |
| `action`    | string | `build` \| `verify` \| `deploy` \| `live_check` \| `quarantine` |
| `site_head` | string \| null | site tree git HEAD at action time |
| `inputs`    | object | the action's inputs (hashes, flags, target) |
| `outputs`   | object | the action's outputs (dist manifest, findings, read-back) |
| `gates`     | array  | `{name, result, detail}` per gate; result ∈ `pass` \| `fail` \| `skip` |
| `result`    | string | per action: `pass` \| `fail` (+ `refused` for deploy, `drift` \| `alert` for live_check, `alert` for quarantine) |
| `prev_hash` | string | previous receipt's `hash`; `""` for seq 1 |
| `hash`      | string | SHA-256 hex of this receipt's RFC 8785 canonical form with `hash` removed |

## Dist identity

Build and verify receipts carry `outputs.dist_hash` and the full
manifest at `outputs.dist`: `{tree_hash, file_count, total_bytes,
files: [{path, sha256, bytes}]}` with files byte-sorted by path.
The tree hash is SHA-256 over `"<relpath>\0<file-sha256>\n"`
lines in the same order. Deploy requires a passing verify
receipt whose `outputs.dist_hash` equals the deployed hash and
the on-disk dist's recomputed hash — all three, or no deploy.

## Action notes

- **deploy** receipts record `inputs.confirm`, `inputs.dry_run`,
  `inputs.target`, the gate list (confirmation, verify_receipt,
  dist_identity, transfer, readback), and `outputs.readback`
  (mode http / staging-rehash / dry-run + per-route hashes). A
  failed read-back yields `result: "fail"` — a deploy that cannot
  prove what is served did not happen.
- **live_check** outputs carry `pages` (route, status, sha256,
  state ∈ match/drift/missing/error-status), `canary_log`
  (state read/unavailable + hit lines), and `findings`.
- **quarantine** receipts are written when the citation pipeline
  newly blacklists a source (H3): `inputs.source`,
  `outputs.reason`. One receipt per new quarantine.
- Fixture involvement is never hidden: build/verify receipts name
  `jwks_fixture` / canary `fixture` flags from the records used.

## Consumption (vongola)

Vongola reads this log read-only: parse lines in order, verify
the chain (recompute each `hash`, compare `prev_hash`), then
consume by `action`. Any chain break is itself the finding —
report it, do not consume past it. See docs/VONGOLA-SEAM.md.
