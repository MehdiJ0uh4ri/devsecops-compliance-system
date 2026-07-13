# SOC2 Gap Analysis

Derived from [control-matrix.csv](control-matrix.csv) (40 controls across the
Trust Services Criteria: Security/Common Criteria, Availability,
Confidentiality, Processing Integrity). Regenerate the summary counts below
with:

```bash
python -c "
import csv, collections
rows = list(csv.DictReader(open('control-matrix.csv', encoding='utf-8')))
print(collections.Counter(r['status'] for r in rows))
"
```

## Current state (as of this evidence period)

| Status | Count | % of 40 |
|---|---:|---:|
| Implemented | 23 | 57.5% |
| Partial | 9 | 22.5% |
| Gap | 8 | 20.0% |

## Where the pipeline earns its keep

The controls that are **fully automated** (`automation_level = automated` or
`tool`) map directly onto artifacts in this repo, which is the point of
"compliance-as-code" — the evidence isn't a screenshot, it's a CI job:

- **CC5.1 / CC6.6** — `policy/opa/**/*.rego` (root containers, IMDSv2, open
  security groups) blocks the PR, it doesn't just flag it.
- **CC6.1 / CC6.9** — `iam/generator/generate_policy.py` refuses wildcard
  actions and encodes MFA + time-limited sessions into the trust policy itself.
- **CC6.8 / CC7.1** — Trivy, Semgrep, gitleaks, and Syft run on every PR
  (`.github/workflows/pipeline.yml`).
- **CC4.1 / CC4.2** — the monthly evidence package
  (`.github/workflows/compliance-evidence.yml`) and PR-comment triage summary
  mean "show me the control operating" is a `workflow_dispatch` away, not a
  week of screenshotting before an audit.

## The 8 gaps, ranked by risk

1. **CC7.2 — No continuous runtime security monitoring (SIEM/anomaly
   detection).** Everything in this pipeline is point-in-time (runs at PR/push
   time). There is no detection for a compromise that happens *after*
   deployment between scans. This is the highest-risk gap: it is the
   difference between "we scan before shipping" and "we'd notice if something
   bad happened at 3am." → **R-1**.
2. **CC7.5 / A1.3 — No tested disaster recovery plan.** A DR runbook that has
   never been exercised is a hypothesis, not a control. → **R-2**.
3. **CC9.1 — No business continuity plan for this workload.** Related to R-2
   but broader than infra failover (staffing, vendor outage, etc). → **R-3**.
4. **CC9.2 — No formal vendor risk assessment process.** We depend on several
   SaaS scanners (Semgrep, potentially Snyk) and cloud providers; there's no
   repeatable vendor questionnaire. → **R-4**.
5. **C1.2 — No automated data retention/deletion enforcement.** Policy is
   drafted but nothing deletes data on schedule. → **R-5**.
6. **CC6.3 — Stale credential detection is manual (quarterly review only).**
   A leaked or orphaned key can live for up to a quarter before anyone notices
   it's unused. → **R-6**.
7. **CC1.4 — Security training isn't tracked in a system this pipeline can
   read.** Low technical risk, but an auditor will ask for it and today the
   answer is "ask HR."
8. **CC2.3 — No customer-facing trust/security page or gated SOC2 report
   distribution.** Business/sales blocker more than a security one, but it's
   in scope for the audit itself.

## What "partial" means in practice

`partial` controls are not failing — they're implemented for the systems this
repo directly owns (the sample app / this pipeline) but not yet extended
org-wide (e.g. **CC6.7** mTLS is enforced for the sample-app mesh but not
every legacy service; **CC3.1** threat modeling exists for one service, not
all of them). The remediation roadmap treats "partial → implemented" as
lower priority than closing true gaps, since the control mechanism is proven
and this is a rollout/scope problem, not a design problem.
