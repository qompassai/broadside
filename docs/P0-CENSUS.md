# P0 — census & pin-down (2026-11-10, D-1246)

The site workflow, verified on the machine (primo), item by item.
Where October's STUDY.md and the machine disagreed, the machine
won and the discrepancy is named.

## The headline discrepancy

**The October live tree is gone from primo.** STUDY.md names
`~/qompass-site-package-wt` as the live site package and
`~/.GH/Qompass/qompass.ai` as its main repo. On 2026-11-10
neither exists: the worktree path is absent, the main repo is
absent, and four orphaned worktrees of the deleted repo survive
(`~/.local/share/pax/repos/qompass-ai-{dnh,pubs,icons}-wt`,
`~/.local/share/pax/qompass-compass-services-wt`, all Oct 13–14
vintage, none containing `src/manuscript_data.rs`), plus a
2026-10-13 source rip (`~/.local/share/pax/qompass-rip-20261013-source.tar.zst`).

The surviving source of truth is GitHub: `qompassai/qompass.ai`
HEAD `f8ecb71a42cfb2f6d3eded632929c00f65a342c0` (2026-10-31,
"pin nightly-2026-10-30 + edition 2024") contains the full
current tree, `src/manuscript_data.rs` included.

**Restoration (this census):** `~/qompass-site-package-wt` was
re-cloned from GitHub at f8ecb71 — the path every ship script
names is live again, at the newest state any surviving source
carries. The Oct-20 shipped state described in STUDY.md (68/0
tests) is not independently recoverable; f8ecb71 is eleven days
newer and is what the workflow now runs against.

## The workflow, pinned

| item | pinned value | verified |
|---|---|---|
| build command | `cargo leptos build --release` (cargo-leptos 0.3.1, /usr/bin) | hand-run 2026-11-10, exit 0 |
| toolchain | nightly-2026-10-30 + wasm32-unknown-unknown (tree's rust-toolchain.toml) | resolved during hand build |
| prerender | `bash scripts/prerender.sh` → dist/ (310 files, 21 MB) | hand-run, exit 0 |
| test command | `cargo test` (per ~/.local/share/pax/site-baseline-test.sh) | run in verify battery |
| manuscript generator | `scripts/generate-manuscript-data.py` — in-tree (STUDY said not in the site scripts/; it has since landed there) | reads `~/.GH/Qompass/Odyssey/manuscripts/rollup.json` → `src/manuscript_data.rs`; regeneration byte-identical to the committed file (11 manuscripts) |
| deploy mechanics | `rsync -az --delete dist/ → ubuntu@137.131.28.242:/var/www/qompass.ai/` via `~/.local/share/pax/site-ship.sh` | dry-run hand-run, exit 0 (536 itemized lines vs live, 59 deletions — the restored tree and the live host have drifted; see below) |
| deploy key | `~/.ssh/oci_qompass_ed25519` (present, mode 600) | ls |
| edge | Caddy (tree's deploy/Caddyfile), access log `/var/log/caddy/qompass.ai.log` on the host | Caddyfile read |
| live routes | `/`, `/research`, `/solutions`, `/solutions/mcp-servers`, per-server `/solutions/mcp/<slug>`, manuscript pages `/research/<slug>` for `ready = true` content | prerender.sh read + live fetches |
| JWKS | `/.well-known/jwks.json` on the live site: **404** — the duty has never been exercised; no key record exists anywhere on primo (pass census: no card/canary entries) | live fetch + pass name census |

## Drift named, not absorbed

The rsync dry-run against the live host itemizes 536 changes
(59 deletions, e.g. `img/versemend/*` present live, absent in
the restored tree). The live site was last deployed from the
deleted worktree, whose exact state is unrecoverable; f8ecb71
is the newest *recoverable* source state, not a proven match
for what's live. broadside's live_check exists to keep this
visible: it reports drift per route against the deployed
manifest instead of assuming the tree and the host agree. No
production deploy was performed in P0 (dry-run only).

## Key paths (names only; values never leave `pass`/the host)

- Deploy SSH key: `~/.ssh/oci_qompass_ed25519` (file, primo).
- Agent Card key record: **does not exist yet.** Its home is
  specified by broadside: `<site>/keys/agent-card-key-record.json`
  (public record, self-signed by the Owner-held card key; the
  private half never enters broadside or the site host). Placing
  the real record is an Owner act; until then build/verify fail
  the JWKS gate closed, and the pipeline is proven against a
  fixture record (`"fixture": true`, receipts surface the flag).
- Canary subkey: public half pinned in broadside's config
  (BROADSIDE_CANARY_SIGNER_PUBKEY); private half Owner-held per
  HONEYPOT H6, generated per that document at first real use.
  The signed manifest's home: `<site>/honeypot/manifest.json`.

## Receipt schema

`broadside.receipt` v1 is specified in docs/RECEIPT-SCHEMA.md
(hash-chained, append-only JSONL; the seam vongola consumes —
docs/VONGOLA-SEAM.md).

## Calibration addendum (2026-11-10, same programme)

The first live verify runs measured broadside's own heuristics
against the real site; four were miscalibrated and were corrected
in code, with the pre-fix runs preserved in the append-only
fixture receipt chain (nothing was rewritten):

1. **Citation scope.** Whole-dist extraction harvested 709 URLs
   (code samples, product copy, every link on every page). The
   citation surface is the reference sections — `research/` and
   `standards/` — per the STUDY's verifier scope; own-host URLs
   belong to the links gate. Scoped set: 327, then 301 after the
   fixture excision below.
2. **H3 pattern calibration.** The first pattern list flagged
   131 legitimate sources as hostile: API documentation
   legitimately contains "tool_calls", "call the tool", and
   "[system]" as subject matter. Patterns are now payload-shaped
   by construction (second-person instruction-override and
   credential/system-prompt lures only). Post-fix hostile count
   against the real set: 0. The unit suite pins both directions.
3. **DOI routes completed.** SICI DOIs are entity-encoded in the
   pages (`&lt;857::aid-sim777&gt;`) and carry literal angle
   brackets; the extractor decodes entities and admits the
   bracket segment only in the (SICI)-opens-on-a-digit shape.
   A third route — doi.org itself (CSL when served, redirect as
   registration proof) — sits behind Crossref and DataCite; it
   is what verifies the ResearchGate 10.13140 set.
4. **URL liveness semantics.** Three measured publisher shapes
   were absence-lookalikes: redirect loops (publons.com
   bot-wall), oversized bodies (the >4 MiB ECMA-262 page — now
   truncated-and-disclosed, scanned over the received prefix),
   and mid-body receive timeouts on slow hosts (eel.is — status
   already proved existence; partial body, truncation flagged
   in the receipt).

**The finding that remains:** three DOIs printed in the Owner's
publication record (`src/orcid_data.rs`) resolve nowhere —
`10.1136/JIM-2022-ERM.154`, `10.1136/JIM-2022-ERM.224`,
`10.1136/JIM-2022-MW.79` answer 404 at Crossref, DataCite, and
doi.org itself (independently curl-verified). Their entries
carry working Publons URLs. Correcting the scholarly record is
the Owner's call; canonical verify therefore FAILS today, by
design, and no production deploy can pass broadside's gate
until the record is corrected. For the staging deploy proof,
the three entries were excised from the FIXTURE site copy only
(`broadside-e2e-20261110/site`); the canonical tree is untouched.

**Live-check label fix:** pages answering 200 with no deploy
baseline were labeled "error-status"; they are now "observed".

**Fixture substitutions, restated:** all keys in every proof
are fixture keys (deterministic seeds in
`examples/make_fixtures.rs`, `"fixture": true` on every
artifact); the real Agent Card key record and canary manifest
do not exist yet — placing and signing them is an Owner act.
The canonical default-state runs fail the JWKS and canary gates
closed on exactly that absence, which is the designed posture.
