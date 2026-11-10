# The vongola consumption seam

Vongola (the estate's serving/observation layer) is broadside's
one downstream consumer. The seam is deliberately thin:

## What broadside delivers

1. **The receipt log** at `~/.local/share/broadside/receipts.jsonl`
   (override: `BROADSIDE_STATE_DIR`), format `broadside.receipt`
   v1 — see docs/RECEIPT-SCHEMA.md. Append-only, hash-chained.
2. **The live-check cadence**: `broadside_live_check` receipts
   are the canary/JWKS/drift evidence vongola surfaces; a
   `result: "alert"` live_check is the H1/H2 escalation input
   (canary hit = HIGH by construction).
3. **The blocklist feed**: `broadside-mcp feed` renders the
   current H4 feed (30-day decay, allowlist-first) from the
   receipt chain — the file the host tarpit config consumes.

## What vongola does with it (its side of the seam)

- Read the log read-only; verify the chain before consuming;
  stop at a break and surface it (a broken chain is a finding,
  not a skip).
- Treat `deploy` receipts as the deployed-truth record: the
  `outputs.manifest` in the newest passing deploy receipt is
  what the edge is supposed to serve.
- Treat `quarantine` receipts as source-blacklist events for any
  citation surface it renders.

## Integration state (2026-11-10)

Delivered as seam + this note. Vongola's own tree
(`~/.GH/Qompass/Rust/Vongola`) was inventoried during the
broadside build; no vongola-side code was changed — its current
architecture takes observed-system inputs through its own
configuration, and the receipt log's stable path + versioned
schema is the contract it will bind to. When vongola grows the
reader, this document and RECEIPT-SCHEMA.md are the spec it
implements against; a schema change means a version bump here
first, never a silent format drift.
