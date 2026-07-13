# Runbook: Leaked Secret Response & Automatic Key Rotation

**Trigger:** GitHub secret scanning alert, gitleaks CI job failure, or a manual
report of a credential exposed in source control, logs, or a build artifact.

**Severity:** P1 if the key is active and scoped to production. Page on-call
(security channel + PagerDuty) immediately; do not wait for the next standup.

## 1. Contain (target: < 15 minutes from detection)

1. **Do not** just delete the commit/branch — assume the secret is compromised
   the moment it's pushed, even to a private repo. History rewrite alone is not
   remediation.
2. Identify the credential type and owning system from the match (gitleaks
   `RuleID` / GitHub secret-scanning provider tag: `aws-access-key-id`,
   `github-pat`, `slack-bot-token`, `generic-api-key`, ...).
3. Run the automated rotation script for the matching provider:
   ```bash
   ./security/secrets/rotate_key.sh --provider aws --secret-id <access-key-id>
   ./security/secrets/rotate_key.sh --provider github --secret-id <token-name>
   ```
   The script (§ below) revokes the old credential and issues a new one — it
   does **not** just disable and leave the old key dangling.
4. Confirm the old credential no longer authenticates:
   ```bash
   aws sts get-caller-identity --profile <revoked-key-profile>   # should fail
   ```

## 2. Eradicate

1. Purge the secret from git history if it's reachable in any ref (`git filter-repo`
   or the [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)) —
   this is cleanup for hygiene, done *after* rotation, never a substitute for it.
2. Force-push the cleaned history only after confirming with repo admins and
   notifying all contributors to re-clone (coordinate — this rewrites shared
   history; get explicit sign-off before doing it).
3. Check downstream systems that may have cached the old key: CI secret stores,
   deployed container images/config maps, teammates' local `.env` files.

## 3. Recover

1. Deploy the new credential via the normal secrets pipeline (Vault / AWS
   Secrets Manager / GitHub Environments) — never re-paste it into a file.
2. Re-run the affected pipeline/service to confirm it authenticates with the
   new credential.
3. Re-enable branch protection / merge blocks if they were temporarily loosened
   for the incident.

## 4. Post-incident (within 3 business days)

1. File the incident in the tracker with: detection method, time-to-revoke,
   blast radius (what could the key have accessed), root cause.
2. Add or tighten a gitleaks/semgrep rule if the pattern wasn't caught pre-merge.
3. Feed the incident into `compliance/evidence-collector` — SOC2 CC7.2/CC7.3
   (incident response) requires this be evidenced, not just fixed silently.
4. If the key had broad IAM permissions, open a follow-up to scope it down via
   `iam/generator/generate_policy.py` instead of reissuing the same broad grant.

## Rotation SLAs

| Credential class | Time to revoke | Time to fully rotate & verify |
|---|---|---|
| Cloud provider root/admin key | 15 min | 1 hour |
| Scoped IAM user/service-account key | 30 min | 4 hours |
| CI/CD PAT or deploy token | 30 min | 4 hours |
| Third-party SaaS API key (non-prod impact) | 4 hours | 1 business day |

## Automated rotation script

[`rotate_key.sh`](rotate_key.sh) wraps the provider CLIs so rotation is a
single command instead of a sequence of manual steps someone has to remember
correctly during an incident:

- `--provider aws`: creates a new access key, waits for propagation, then
  deactivates (not deletes, for 24h audit trail) the old one via
  `aws iam update-access-key --status Inactive`.
- `--provider github`: calls the GitHub API to revoke the PAT/App
  installation token and prints the manual step to mint a replacement
  (fine-grained PATs cannot be created headlessly without a prior device flow).
- `--provider generic`: prints the checklist for providers without a rotation
  API, so the human doing it still gets a consistent runbook instead of tribal
  knowledge.
