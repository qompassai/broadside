---
repo: broadside
updated: 2026-10-21
---

# broadside — master checklist

Derived from the broadside program documents (estate package
`broadside-20261020/`: STUDY.md, PROGRAM.md, HONEYPOT.md). Every
item traces to a stage gate in those documents. States: `[x]`
gated-closed · `[~]` delivered, ungated · `[ ]` open. The animated
tracker (assets/tracker.svg) is generated from this file only; it
moves only when an item's state changes at a gate.

## Ideation & design

- [x] Commissioned (as press, 2026-10-20): a small deterministic Rust MCP that builds, verifies, and deploys qompass.ai; vongola instruments it read-only via the receipt log (extending vongola to build was rejected — its read-only contract is load-bearing)
- [x] STUDY delivered (the existing site workflow censused on primo; the verification debt broadside absorbs named)
- [x] PROGRAM delivered (five tools, receipt schema seam, stage map P0–P4)
- [x] Renamed broadside (Owner's ruling, 2026-10-20) and the rename gated + live-verified (site, census, progress board); crate ships as broadside-mcp (bare name taken on crates.io)
- [x] JWKS duty ruled to broadside, not Volta (Owner, 2026-10-20): Agent Card JWKS published in dist from a signed key record, verify fails closed on mismatch, live check reads it back
- [x] Honeypot design complete (HONEYPOT.md H1–H6 incl. the gated-signing amendment: canary manifest signed under a dedicated canary subkey, broadside_verify checks before injection, evidence packets signed, bait never signed, no hack-back)
- [x] GitHub repo created with master checklist + animated tracker (Owner's word, 2026-10-21; Q-BROADSIDE-2)

## P0 — census & pin-down

- [ ] Site workflow run by hand once, end to end, on primo (exact build command, generator home, verifier scripts, deploy mechanics, key path, target — each verified on the machine)
- [ ] broadside.receipt v1 schema specified

## P1 — read core

- [ ] broadside_status + broadside_live_check landed, with the append-only receipt log (status reads receipts, never guesses)
- [ ] Live check covers the JWKS read-back against the deployed manifest and the canary-log read-back (H1)
- [ ] SERVERS.md entry lands; the conformance loop picks broadside up

## P2 — build + verify

- [ ] broadside_build + broadside_verify landed (the gate battery, evidence-exact: tests, generated-data freshness, link/figure checks, dist manifest hash)
- [ ] The three citation-verifier fixes absorbed as acceptance criteria (DataCite fallback for 10.48550/*, extractor dedupe + punctuation strip, citation classes verified by route)
- [ ] Honeypot manifest + canary injection at build; canary integrity checked in verify (H1 endpoints, H2 canary credentials)
- [ ] H3 injection quarantine in the fetch pipeline (hostile sources blacklisted and never citable again; citations fail closed)
- [ ] H6 manifest signing enforced (signature checked before injection; deploy refuses a dist whose canary set matches no validly signed manifest) and the JWKS artifact placed at build, verified against the signed key record

## P3 — deploy + vongola hookup

- [ ] broadside_deploy landed (one dist hash, only with a passing verify receipt for that identical hash; per-call confirm; flowguard label on the trajectory; live read-back written into the deploy receipt — a failed read-back is a failed deploy)
- [ ] Vongola consumes the receipt log — the site pipeline becomes an observed system (read-only, inside vongola's charter)
- [ ] H4 blocklist + tarpit on the site host (fail2ban fed by canary hits; entries expire at 30 days; the Owner's addresses and scanners allowlisted first)
- [ ] H5 evidence packets assembled (hash-chained to vongola receipts; broadside drafts the abuse report; sending is Owner-stamped only)

## P4 — second tenant + signed manifests

- [ ] Second tenant (ntranch.io) onboarded (Owner's word only)
- [ ] Signed-manifest deploy gating (rides the bunker/volta signed-authority chain when it lands)

## 1.0

- [ ] 1.0 — P0–P3 gated: qompass.ai builds, verifies, and deploys through broadside, with vongola observing the pipeline
- [ ] 1.0 release record: registry record ai.qompass/broadside published on Owner's word; conformance entry current

## Beyond 1.0

- [ ] Maintenance: verifier and manifest drift checks on a cadence
- [ ] Next-minor backlog (additional tenants, each by fresh pin-down)
- [ ] Conformance re-probes at each release (declared vs live diff; per-release grades on a stated basis)
