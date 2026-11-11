# Signing request — the two Owner signatures broadside is waiting on

Prepared 2026-11-10 (D-1249 Phase 4). Both artifacts exist in the
canonical site tree (`~/qompass-site-package-wt` on primo, site
commit 9bf853b) as **unsigned drafts**: real content, no
`"fixture": true`, with exactly the fields empty that only the
Owner's keys can fill. broadside's build and verify fail closed
on both until the signed versions return — that is the designed
posture, and the canonical run in
`~/.local/share/pax/broadside-d1249-20261110/` shows the gates
stopping on the signatures and nothing else.

## Signer route (from estate records, not improvised)

- The Agent Card key is an Owner-held Ed25519 key (PROGRAM.md,
  JWKS duty ruled 2026-10-20/21): it signs at publish time; its
  private half never enters broadside or the site host.
- The canary subkey is a **dedicated** Ed25519 subkey (HONEYPOT.md
  H6): distinct from the card key and from the consent
  action-signing subkey; its private half lives with the Owner's
  signer setup; broadside trusts it only via a pinned public half.
- Volta is **not** the route for these two artifacts: the
  2026-10-21 ruling keeps Volta on its OpenPGP surfaces (the JOSE
  surface is broadside's; the Volta Part C was declined).
- Estate records show neither key exists yet (P0 census,
  2026-11-10: pass holds no card/canary entries; no key record
  existed anywhere on primo). Both keys are therefore born at
  this signing, inside the Owner's signer setup (the estate's
  signed-authority pattern: a local signer application, never a
  web page; one canonical manifest per act). Mechanically, any
  Ed25519 signer over the exact canonical bytes satisfies
  broadside's verifier.

## Artifact 1 — Agent Card key record

- Path: `~/qompass-site-package-wt/keys/agent-card-key-record.json`
- Draft sha256: `b73a8f8551829419f1ca12bafac72a6cb0baa4869a9652efe663daf475fa63ae`
- Owner fills: `kid` (a key id of his choosing, e.g.
  `agent-card-2026-1`) and `x` (base64url, the card key's 32-byte
  public half).
- Owner signs: the RFC 8785 canonical form of the completed
  record object **with the `signature` field removed**, using the
  card key itself (the record is self-signed). The base64url
  signature goes into `signature`.
- Return: the completed file replaces the draft at the same path.

## Artifact 2 — Canary manifest (revision 2026-11-10.1)

- Path: `~/qompass-site-package-wt/honeypot/manifest.json`
- Draft sha256: `7ed4b7dccd99cfd36dc34d7fd1a7fb19e7da9526b1e7ab1db4f50948295cb57d`
- Content (review before signing): canaries `/.env` (env),
  `/wp-login.php`, `/admin/`, `/backup.zip` (pages); credential
  slot `QOMPASS_DEPLOY_TOKEN` carrying fresh bait generated on
  primo 2026-11-10 — valid nowhere, marker-free per H6 (the
  value sits only in this manifest and, once signed and built,
  in the decoy `/.env` it plants).
- Owner fills: `signer_kid` (the canary subkey's id).
- Owner signs: the RFC 8785 canonical form of the completed
  manifest object **with the `signature` field removed**, using
  the canary subkey. Base64url signature into `signature`.
- Return: the completed file replaces the draft at the same
  path, **and** the canary subkey's public half (base64url) is
  communicated back — it becomes the
  `BROADSIDE_CANARY_SIGNER_PUBKEY` pin in broadside's server
  config. Without the pin, verify refuses to trust any manifest,
  however signed. The public half is a public value; the private
  half never leaves the signer setup.

## What happens after the signatures land

1. The signed files are committed in the site clone at the same
   paths.
2. Pax sets the `BROADSIDE_CANARY_SIGNER_PUBKEY` pin from the
   returned public half.
3. Canonical `broadside_build` + `broadside_verify` pass the
   JWKS and canary gates (the rest of the battery already passes:
   with the Phase 1 DOI correction, canonical verify's only
   remaining failures are the signature gates).
4. Pax runs the first production deploy — per-call Owner
   confirmation by design, as always.
