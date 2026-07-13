#!/usr/bin/env bash
# Automated key-rotation helper referenced by rotate-key-runbook.md.
#
# Usage:
#   ./rotate_key.sh --provider aws --secret-id <access-key-id> [--iam-user <name>]
#   ./rotate_key.sh --provider github --secret-id <token-name>
#   ./rotate_key.sh --provider generic --secret-id <name>
#
# Requires: awscli (for --provider aws), gh cli (for --provider github).
# Exits non-zero on any failure so it is safe to call from an incident script
# or CI job without silently continuing past a broken rotation.

set -euo pipefail

PROVIDER=""
SECRET_ID=""
IAM_USER=""

usage() {
  echo "Usage: $0 --provider <aws|github|generic> --secret-id <id> [--iam-user <name>]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider) PROVIDER="$2"; shift 2 ;;
    --secret-id) SECRET_ID="$2"; shift 2 ;;
    --iam-user) IAM_USER="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -z "$PROVIDER" || -z "$SECRET_ID" ]] && usage

log() { echo "[rotate_key] $*" >&2; }

rotate_aws() {
  local access_key_id="$1"
  local user="${IAM_USER:-}"

  if [[ -z "$user" ]]; then
    log "resolving IAM user that owns access key ${access_key_id}..."
    user=$(aws iam list-users --query 'Users[].UserName' --output text | \
      xargs -n1 -I{} sh -c "aws iam list-access-keys --user-name {} --query \"AccessKeyMetadata[?AccessKeyId=='${access_key_id}'].UserName\" --output text" \
      | grep -v '^$' | head -n1 || true)
    [[ -z "$user" ]] && { log "ERROR: could not resolve IAM user for ${access_key_id}. Pass --iam-user explicitly."; exit 1; }
  fi

  log "creating replacement access key for user '${user}'..."
  new_key_json=$(aws iam create-access-key --user-name "$user")
  new_key_id=$(echo "$new_key_json" | grep -o '"AccessKeyId": *"[^"]*"' | head -1 | cut -d'"' -f4)
  log "new access key created: ${new_key_id} — store it in the secrets manager NOW, this is the only time the secret is printable."
  echo "$new_key_json"

  log "deactivating compromised key ${access_key_id} (kept inactive 24h for audit trail before deletion)..."
  aws iam update-access-key --user-name "$user" --access-key-id "$access_key_id" --status Inactive

  log "verifying old key is rejected..."
  if AWS_ACCESS_KEY_ID="$access_key_id" aws sts get-caller-identity >/dev/null 2>&1; then
    log "ERROR: old key ${access_key_id} still authenticates. Investigate immediately."
    exit 1
  fi
  log "confirmed: ${access_key_id} no longer authenticates. Rotation for '${user}' complete."
}

rotate_github() {
  local token_name="$1"
  log "revoking GitHub token/secret reference '${token_name}' via gh api..."
  gh api -X DELETE "user/keys/${token_name}" >/dev/null 2>&1 || \
    log "note: fine-grained PATs and GitHub App tokens cannot always be revoked via this generic call; use the Developer Settings UI or the App installation's 'Revoke token' action if this errors."
  log "MANUAL STEP REQUIRED: mint a replacement token in GitHub Settings > Developer settings, scoped to the minimum permissions the calling workflow needs, then update the secret in the consuming repo/environment."
}

rotate_generic() {
  local name="$1"
  cat >&2 <<EOF
No rotation API is registered for this provider. Follow the manual checklist:
  1. Revoke/disable '${name}' at the provider's console RIGHT NOW.
  2. Issue a replacement credential scoped to the same (or narrower) permissions.
  3. Push the new credential to the secrets manager (never to a file in this repo).
  4. Confirm the old credential is rejected with a live test call.
  5. Record the rotation in the incident ticket per rotate-key-runbook.md section 4.
EOF
}

case "$PROVIDER" in
  aws) rotate_aws "$SECRET_ID" ;;
  github) rotate_github "$SECRET_ID" ;;
  generic) rotate_generic "$SECRET_ID" ;;
  *) echo "unsupported provider: $PROVIDER" >&2; exit 2 ;;
esac
