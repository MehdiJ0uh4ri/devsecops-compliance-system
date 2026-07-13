# SOC2 Remediation Roadmap

Tracks the 6 gaps identified in [gap-analysis.md](gap-analysis.md) through to
closure. Each item's `status` should be updated in place as work progresses —
this file itself becomes part of the audit evidence trail showing gaps were
tracked and closed, not just identified once and forgotten.

| ID | Gap | Control(s) | Owner | Target quarter | Status | Definition of done |
|---|---|---|---|---|---|---|
| R-1 | No continuous runtime security monitoring | CC7.2 | platform-security | 2026-Q4 | Not started | CloudWatch/SIEM (or equivalent) ingesting runtime security-relevant logs (auth failures, IMDS calls, security-group changes) with alerting wired to on-call; documented in docs/architecture.md |
| R-2 | No tested DR / failover plan | CC7.5, A1.3 | platform-eng | 2026-Q4 | Not started | Written DR runbook + at least one executed game-day exercise with results logged in evidence package |
| R-3 | No business continuity plan | CC9.1 | eng-leadership | 2027-Q1 | Not started | BCP document covering infra, staffing, and critical-vendor-outage scenarios, reviewed by leadership |
| R-4 | No formal vendor risk assessment | CC9.2 | legal-procurement | 2027-Q1 | Not started | Vendor questionnaire template + completed assessments for all SaaS scanners/providers in the pipeline |
| R-5 | No automated data retention/deletion | C1.2 | legal-platform-security | 2027-Q1 | Not started | Scheduled job enforcing documented retention windows, with deletion events logged as evidence |
| R-6 | Stale IAM credential detection is manual/quarterly | CC6.3 | platform-security | 2026-Q3 | In progress | Automated report (extend compliance/evidence-collector) flagging IAM credentials unused > 90 days, run monthly instead of quarterly |

## Sequencing rationale

- **R-6 first (2026-Q3, in progress):** smallest scope, builds directly on
  `compliance/evidence-collector/collect_evidence.py`, which already has an
  AWS IAM evidence hook to extend — see the `TODO` in that script.
- **R-1 and R-2 next (2026-Q4):** highest residual risk per the gap analysis;
  both require infra work outside this repo's current scope (SIEM deployment,
  DR environment) so they're scheduled with a full quarter of lead time.
- **R-3, R-4, R-5 (2027-Q1):** lower technical risk, more process/legal work.
  Batched together because they share stakeholders (legal/procurement) and
  can reasonably be worked in parallel with R-1/R-2.

## Review cadence

This roadmap is reviewed at the same monthly cadence as evidence collection
(`.github/workflows/compliance-evidence.yml`). Any item still "Not started"
two quarters after its target should be escalated to eng-leadership rather
than silently slipping — a remediation roadmap that only ever pushes dates
back is itself a control failure (CC4.2, monitoring/communicating
deficiencies timely).
