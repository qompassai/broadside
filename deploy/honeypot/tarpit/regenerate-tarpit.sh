#!/usr/bin/env bash
# regenerate-tarpit.sh — OWNER-RUN, on the qompass.ai host only.
#
# Renders broadside's current blocklist feed into the tarpit
# block of the host Caddyfile (between the BROADSIDE FEED
# markers), validates with `caddy validate`, and reloads Caddy.
# broadside never runs this; it ships so the host step is one
# reviewed script instead of an improvisation. The marked region
# is replaced wholesale; nothing else in the Caddyfile is
# touched. A backup lands beside the Caddyfile first.
set -euo pipefail

FEED="${BROADSIDE_FEED:-/var/lib/broadside/blocklist-feed.txt}"
CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"

[ -f "$FEED" ] || { echo "feed not found: $FEED" >&2; exit 1; }
[ -f "$CADDYFILE" ] || { echo "Caddyfile not found: $CADDYFILE" >&2; exit 1; }
grep -q "BROADSIDE FEED BEGIN" "$CADDYFILE" || {
    echo "no BROADSIDE FEED markers in $CADDYFILE; merge deploy/honeypot/tarpit/Caddyfile.tarpit first" >&2
    exit 1
}

# One `remote_ip` line per feed IP (comments/blank lines skipped).
MATCHERS="$(grep -vE '^[[:space:]]*(#|$)' "$FEED" | sed 's/^/\tremote_ip /')"
[ -n "$MATCHERS" ] || { echo "feed is empty; leaving Caddyfile untouched" >&2; exit 1; }

cp "$CADDYFILE" "$CADDYFILE.bak-$(date +%Y%m%d%H%M%S)"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
awk -v matchers="$MATCHERS" '
    /# === BROADSIDE FEED BEGIN ===/ { print; print matchers; skip = 1; next }
    /# === BROADSIDE FEED END ===/   { skip = 0; print; next }
    !skip { print }
' "$CADDYFILE" > "$TMP"
cat "$TMP" > "$CADDYFILE"

caddy validate --config "$CADDYFILE"
systemctl reload caddy
echo "tarpit regenerated from $FEED"
