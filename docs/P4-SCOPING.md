# P4 scoping (D-1249 Phase 6, 2026-11-10)

Both P4 checklist items were scoped against the live estate
state. **No code landed for either**: each is blocked on an
external precondition the item's own text names, recorded here
precisely so the block is a fact, not a drift.

## Second tenant (ntranch.io)

- Checklist state: `[ ]`, annotated "Owner's word only" in the
  checklist itself.
- Blockers: (1) the Owner's word for this tenant has not been
  given (the D-1249 programme's PROCEED covered the remainder
  list as scoped here — this item's own gate is a separate
  Owner decision); (2) ntranch.io's registration/DNS control is
  not established in estate records, and this programme makes
  no purchases or registrations.
- Code assessment: broadside is already tenant-shaped — site
  root, state dir, base URL, deploy target, SSH key, and the
  canary pin are all per-instance config (`config::from_env`,
  BROADSIDE_* variables), and receipts/state are per-site
  directories. Onboarding a second tenant is therefore a
  pin-down (a P0-style census for that tenant: build command,
  deploy mechanics, key paths) plus a second server instance —
  not a code change in this repo. Writing speculative
  multi-tenant machinery now, with no tenant to pin against,
  would violate the estate's evidence-first rule.

## Signed-manifest deploy gating

- Checklist state: `[ ]` — "rides the bunker/volta
  signed-authority chain when it lands."
- Blocker: the chain has not landed. The signed-authority
  protocol exists as a validated design (estate records,
  2026-10-18: DESIGN + adversarial battery; pilots scoped to
  bunker/Ghost/phlow) and is explicitly not yet built; Volta is
  briefed, not built, behind bunker Stage C. There is no
  chain-issued manifest format in production for
  broadside_deploy to verify against.
- What already stands in broadside: deploy requires a passing
  verify receipt for the identical dist hash, per-call Owner
  confirmation, and — once the Phase 4 signatures land — verify
  itself gates on the Owner-signed key record and canary
  manifest. The P4 item adds the *chain's* manifest on top of
  that; it unblocks the day the chain ships its first manifest
  format, and the integration point is `deploy()`'s
  verify_receipt gate in `src/deploy_live.rs`.
