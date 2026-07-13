# Architecture

## Pipeline flow

```
                 ┌────────────────────────────────────────────────────────────┐
                 │                     Pull Request opened                     │
                 └───────────────────────────┬────────────────────────────────┘
                                              │
        ┌──────────────┬──────────────┬──────┴───────┬──────────────────┐
        ▼              ▼              ▼              ▼                  ▼
  secrets-scan   sast-semgrep   sca-sbom-container   policy-gate    (dast-zap runs
   (gitleaks)     (Semgrep)         -scan            (OPA/         after sca job,
                                (Trivy + Syft)       Conftest)        needs image)
        │              │              │              │                  │
        │              │              ▼              │                  │
        │              │      security/triage/        │                  │
        │              │      triage.py (noise-        │                  │
        │              │      reduced CVE gate)         │                  │
        │              │              │              │                  │
        └──────┬───────┴──────┬───────┴──────┬───────┴──────────────────┘
               ▼              ▼              ▼
        any live secret   any CRITICAL,   any policy
        found -> FAIL     non-allowlisted  violation (root
                           finding -> FAIL  container, IMDSv1,
                                            open SG) -> FAIL
               │
               ▼
     triage-summary-comment posts a single PR comment
     summarizing all four jobs + the triage report
               │
               ▼
          Merge allowed only if all gating jobs pass
```

Monthly (and on-demand via `workflow_dispatch`),
[`compliance-evidence.yml`](../.github/workflows/compliance-evidence.yml) runs
[`collect_evidence.py`](../compliance/evidence-collector/collect_evidence.py)
independently of the PR pipeline, producing a timestamped, auditor-ready
evidence package from [`control-matrix.csv`](../compliance/soc2/control-matrix.csv).

## Why noise reduction, not zero-tolerance

A pipeline that fails the build on every MEDIUM-severity transitive
dependency finding trains engineers to stop reading the output and merge with
`--no-verify` energy even when they can't actually bypass CI. Two mechanisms
keep the signal-to-noise ratio high enough that a red build is trusted:

1. **[`security/triage/triage.py`](../security/triage/triage.py)** only fails
   on a CRITICAL finding that is unpatched AND not allowlisted. HIGH/MEDIUM
   findings and anything covered by a live (non-expired)
   [`cve-allowlist.yml`](../security/triage/cve-allowlist.yml) entry are
   reported, not blocking.
2. **[`security/dast/zap-rules.tsv`](../security/dast/zap-rules.tsv)** applies
   the same idea to DAST: only findings with a clear exploitable impact
   (XSS, SQLi, command injection, missing transport-security headers) are
   `FAIL`; informational findings are `WARN` or `IGNORE`.

Policy-as-code (`policy/opa/`) is the one place this project does NOT
noise-reduce — see [policy/README.md](../policy/README.md) for why root
containers, IMDSv1, and open security groups are deny-only with no warn tier.

## Threat model (sample-app, STRIDE-based)

| Threat | Relevant control in this repo |
|---|---|
| **Spoofing** — forged service-to-service calls | mTLS between meshed services (see below); IAM roles use OIDC federation, not long-lived keys ([iam/generator](../iam/generator/)) |
| **Tampering** — modified image between build and deploy | SBOM ([Syft](../.github/workflows/pipeline.yml)) + image digest pinning at deploy time (not tag-based) |
| **Repudiation** — no record of who deployed what | Every merge is gated by a CI run whose artifacts (triage report, SBOM, policy-gate result) are retained 365 days as evidence |
| **Information disclosure** — secret leakage | gitleaks pre-commit + CI hook, with [rotation runbook](../security/secrets/rotate-key-runbook.md) as the response path |
| **Denial of service** — resource exhaustion | Kubernetes resource requests/limits in [k8s/deployment.yaml](../k8s/deployment.yaml); out of scope: rate limiting at the edge (tracked as CC7.2 gap, not yet implemented for sample-app) |
| **Elevation of privilege** — container escape / over-permissioned role | `no_root.rego` blocks privileged/root containers; IAM generator refuses wildcard actions and enforces time-limited, MFA-gated sessions |

This table covers `sample-app` only — see
[`compliance/soc2/gap-analysis.md`](../compliance/soc2/gap-analysis.md) (CC3.1)
for the rollout status across other services.

## mTLS (zero-trust networking)

Service-to-service traffic between meshed services is encrypted and mutually
authenticated at the transport layer (mesh sidecar terminates and verifies
both ends' certificates) rather than relying solely on network-layer
segmentation. In practice this means:

- A workload's identity is its certificate, not its IP/security-group
  membership — the same posture the IAM generator applies to human/CI
  identity (short-lived, scoped, verifiable) extended to network identity.
- `policy/opa/network/no_open_sg.rego` still matters *in addition to* mTLS:
  security groups are the coarse-grained network boundary; mTLS is the
  fine-grained one. Neither replaces the other (defense in depth).
- **Current coverage (CC6.7, partial):** enforced for `sample-app`'s mesh
  traffic. Not yet extended to legacy services outside this repo's scope —
  tracked in the gap analysis, not a remediation item on its own since it's a
  rollout gap rather than a missing mechanism.

## Directory map

| Path | What it is |
|---|---|
| [`.github/workflows/`](../.github/workflows/) | CI pipeline + scheduled evidence collection |
| [`policy/`](../policy/) | OPA/Rego policy-as-code + tests, Conftest wiring |
| [`security/`](../security/) | Triage engine, secrets scanning config + rotation runbook, custom Semgrep rules, ZAP rules |
| [`iam/`](../iam/) | Least-privilege IAM policy generator |
| [`compliance/`](../compliance/) | SOC2 control matrix, gap analysis, remediation roadmap, evidence collector |
| [`sample-app/`](../sample-app/) | Minimal Flask app used as the scan target |
| [`k8s/`](../k8s/), [`infra/`](../infra/) | Example manifests the policy gate evaluates |
