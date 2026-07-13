# Escalation & On-Call

Referenced by SOC2 control CC1.3 (control-matrix.csv) — management
establishes structures, reporting lines, and authority for security events.

## Reporting lines

| Role | Responsible for | Escalates to |
|---|---|---|
| On-call engineer | First response to pipeline/prod alerts | Platform Security lead |
| Platform Security lead | Triage severity, invoke runbooks (e.g. [key rotation](../../security/secrets/rotate-key-runbook.md)) | CTO |
| CTO | Business-impact decisions, customer/legal notification | CEO / Board (for material incidents) |

## When to escalate immediately (skip the queue)

- Any live secret confirmed exposed with production scope
  (→ [rotate-key-runbook.md](../../security/secrets/rotate-key-runbook.md))
- Any CRITICAL finding in `security/triage/*-report.json` affecting a
  production-deployed image that cannot be patched within 4 hours
- Any policy-gate bypass (a merge that skipped `policy-gate` via admin
  override) — this itself is a control failure and must be logged

## Escalation channel

Security incidents: page via the on-call rotation, not just a Slack message —
Slack messages get missed; pages don't.
