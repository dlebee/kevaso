#!/usr/bin/env bash
# Stores the macOS signing + notarization secrets for the release workflow in GitHub, scoped to the
# `release` environment so only release jobs can read them. Run it yourself: it prompts for passwords
# and never prints them or passes them on a command line.
#
#   1. Keychain Access → login → My Certificates → "Developer ID Application: …" → right-click →
#      Export → save as .p12 and choose a password.
#   2. Create an app-specific password at https://account.apple.com (Sign-In and Security).
#   3. hack/release/set-signing-secrets.sh ~/Documents/developer-id.p12
#
# The `release` environment must exist first (Settings → Environments → New environment).
set -euo pipefail

REPO="${REPO:-dlebee/kevaso}"
ENVIRONMENT="${ENVIRONMENT:-release}"
P12="${1:?usage: $0 path/to/developer-id.p12}"
[ -f "$P12" ] || { echo "no such file: $P12" >&2; exit 1; }

read -r -s -p "Password you chose when exporting the .p12: " P12_PASSWORD; echo
export P12_PASSWORD

# Prove the file holds a usable Developer ID identity before uploading anything. openssl reads the
# password from the environment, so it never appears in `ps`.
IDENTITY="$(openssl pkcs12 -in "$P12" -passin env:P12_PASSWORD -nokeys -clcerts 2>/dev/null \
  | openssl x509 -noout -subject -nameopt multiline 2>/dev/null \
  | sed -nE 's/^ *commonName *= *(Developer ID Application: .*)$/\1/p' | head -1 || true)"
if [ -n "$IDENTITY" ]; then
  openssl pkcs12 -in "$P12" -passin env:P12_PASSWORD -nocerts -nodes 2>/dev/null | grep -q 'PRIVATE KEY' \
    || { echo "The .p12 has no private key — export the certificate with its key." >&2; exit 1; }
else
  # Some exports use algorithms the system openssl can't read; check with a throwaway keychain.
  TMPDIR_KC="$(mktemp -d)"
  KC="$TMPDIR_KC/check.keychain-db"
  KC_PW="$(openssl rand -hex 16)"
  trap 'security delete-keychain "$KC" 2>/dev/null || true; rm -rf "$TMPDIR_KC"' EXIT
  security create-keychain -p "$KC_PW" "$KC" >/dev/null
  security unlock-keychain -p "$KC_PW" "$KC"
  if ! security import "$P12" -k "$KC" -P "$P12_PASSWORD" -f pkcs12 >/dev/null 2>&1; then
    echo "Couldn't open the .p12 — wrong password?" >&2; exit 1
  fi
  IDENTITY="$(security find-identity -v -p codesigning "$KC" | sed -nE 's/.*"(Developer ID Application: [^"]+)".*/\1/p' | head -1)"
fi
[ -n "$IDENTITY" ] || { echo "The .p12 has no Developer ID Application identity (or the password is wrong)." >&2; exit 1; }
echo "Found: $IDENTITY"

base64 -i "$P12" | gh secret set MACOS_CERT_P12_BASE64 -R "$REPO" --env "$ENVIRONMENT"
printf '%s' "$P12_PASSWORD" | gh secret set MACOS_CERT_PASSWORD -R "$REPO" --env "$ENVIRONMENT"
gh variable set MACOS_SIGNING_IDENTITY -R "$REPO" -b "$IDENTITY"
unset P12_PASSWORD

read -r -p "Apple ID email (for notarization): " APPLE_ID
read -r -s -p "App-specific password: " APP_PASSWORD; echo
printf '%s' "$APPLE_ID" | gh secret set AC_APPLE_ID -R "$REPO" --env "$ENVIRONMENT"
printf '%s' "$APP_PASSWORD" | gh secret set AC_APP_PASSWORD -R "$REPO" --env "$ENVIRONMENT"
unset APP_PASSWORD
read -r -p "Apple Team ID (10 characters, shown in the identity above in parentheses): " TEAM_ID
gh variable set AC_TEAM_ID -R "$REPO" -b "$TEAM_ID"

echo "Done. Secrets in the '$ENVIRONMENT' environment of $REPO:"
gh secret list -R "$REPO" --env "$ENVIRONMENT"
if gh secret list -R "$REPO" | grep -qE '^(MACOS_CERT_|AC_)'; then
  echo "Repository-level copies still exist; remove them so only release jobs can read the secrets:"
  echo "  for s in MACOS_CERT_P12_BASE64 MACOS_CERT_PASSWORD AC_APPLE_ID AC_APP_PASSWORD; do gh secret delete \$s -R $REPO; done"
fi

read -r -p "Delete $P12 now? [Y/n] " ans
case "$ans" in n|N) echo "Kept $P12 — delete it when you're done." ;; *) rm -P "$P12" 2>/dev/null || rm -f "$P12"; echo "Deleted." ;; esac
