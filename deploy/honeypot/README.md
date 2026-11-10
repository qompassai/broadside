# Honeypot host configuration (H4) — repo copy, NOT applied

Everything in this directory is code + config **in the repo**.
None of it is applied to any host by broadside, by the build, or
by any automation: applying it to the qompass.ai host is an
Owner-stamped act, done by hand on the host, after review.

## Pieces

- `fail2ban/filter.d/qompass-canary.conf` — the filter: a
  *completed* HTTP request to a decoy endpoint in the Caddy
  access log is the only trigger (HONEYPOT.md H4: no
  connection-level triggers, no port-scan heuristics).
- `fail2ban/jail.d/qompass-canary.conf` — the jail: one hit =
  ban, 30-day bantime (entries decay by expiry, matching the
  feed's 30-day window), allowlist (`ignoreip`) configured
  FIRST and never inferred — the Owner writes their own
  addresses in at application time. Ships `enabled = false`.
- `tarpit/Caddyfile.tarpit` — the tarpit site block: flagged IPs
  (from broadside's feed) are served the decoy tree, never the
  real site.
- `tarpit/regenerate-tarpit.sh` — host-side, Owner-run: renders
  the current feed (`broadside-mcp feed`) into the tarpit block,
  validates with `caddy validate`, reloads. Broadside never runs
  it; it is shipped so the host step is one reviewed script, not
  an improvisation.

## The flow

1. broadside injects canaries at build (signed manifest, H6) and
   reads hits back in `broadside_live_check` (H1).
2. Hits land in receipts; `broadside-mcp feed` renders the
   blocklist (30-day decay, allowlist-first).
3. On the host (Owner-applied): fail2ban bans on the log trigger
   directly; the tarpit block consumes the feed for flagged IPs.

No hack-back exists at any step: detection, receipts, blocking,
evidence packets (H5) — that is the whole repertoire.
