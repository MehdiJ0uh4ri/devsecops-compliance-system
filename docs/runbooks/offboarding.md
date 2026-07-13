# Access Offboarding

Referenced by SOC2 control CC6.3 — access removed or modified in a timely
manner. Current process is manual (tracked as remediation item R-6 in
[remediation-roadmap.md](../../compliance/soc2/remediation-roadmap.md) to move
detection of *stale* access to monthly automation; offboarding itself
triggered by an HR event stays a checklist).

## Trigger

HR offboarding ticket, or a role change that removes the need for an
existing grant.

## Checklist (complete within 24 hours of last working day)

1. Revoke IdP/SSO session and disable the account (blocks everything
   downstream immediately even if later steps take longer).
2. Remove from all GitHub teams / CODEOWNERS entries.
3. Deactivate any IAM roles/keys generated for that person via
   [`iam/generator`](../../iam/generator/) — check
   `trusted_principals` across recent role requests for their ARN.
4. Rotate any shared credential they had access to (treat as a precaution,
   not proof of compromise) using
   [`rotate_key.sh`](../../security/secrets/rotate_key.sh).
5. Confirm removal in the next monthly evidence package
   (`compliance/evidence-collector`) — this is the audit trail entry.

## Quarterly access review (until R-6 automates this)

Platform Security reviews all active IAM roles/users and GitHub team
membership against current headcount, flags anything unused > 90 days.
