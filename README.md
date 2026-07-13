# DevSecOps Pipeline & Compliance System

Shift-left security and compliance-as-code: every PR is scanned for secrets,
SAST, SCA, container vulnerabilities, and IaC misconfiguration before it can
merge — and every control that backs a SOC2 audit generates its own evidence
automatically, instead of someone assembling screenshots the week before an
auditor asks.

## What's here

| Area | Path | Highlights |
|---|---|---|
| **CI pipeline** | [`.github/workflows/pipeline.yml`](.github/workflows/pipeline.yml) | Semgrep (SAST), Trivy + Syft (SCA/SBOM/container scan), OWASP ZAP (DAST), OPA/Conftest (policy gate), gitleaks (secrets) — all on every PR |
| **Noise-reduced triage** | [`security/triage/`](security/triage/) | [`triage.py`](security/triage/triage.py) + [`cve-allowlist.yml`](security/triage/cve-allowlist.yml) — fails the build only on a CRITICAL, unpatched, non-allowlisted finding |
| **Secrets** | [`security/secrets/`](security/secrets/) | Pre-commit + CI gitleaks scanning, plus an automated [key-rotation runbook and script](security/secrets/rotate-key-runbook.md) |
| **Policy-as-code** | [`policy/opa/`](policy/opa/) | No root containers, IMDSv2 enforced, no `0.0.0.0/0` security groups — deny-only, enforced at PR review, each rule has unit tests |
| **Least-privilege IAM** | [`iam/generator/`](iam/generator/) | [`generate_policy.py`](iam/generator/generate_policy.py) turns a declarative request into a scoped policy + MFA-gated, time-limited trust policy — refuses wildcard actions |
| **SOC2 compliance** | [`compliance/soc2/`](compliance/soc2/) | 40 controls mapped to the tool/process that implements them, a [gap analysis](compliance/soc2/gap-analysis.md), and a [remediation roadmap](compliance/soc2/remediation-roadmap.md) |
| **Evidence automation** | [`compliance/evidence-collector/`](compliance/evidence-collector/) | [`collect_evidence.py`](compliance/evidence-collector/collect_evidence.py) verifies each control's evidence artifact still exists and produces an audit-ready package in minutes |
| **Scan target** | [`sample-app/`](sample-app/), [`k8s/`](k8s/), [`infra/`](infra/) | Minimal Flask app + Kubernetes/Terraform manifests the pipeline actually runs against |

See [`docs/architecture.md`](docs/architecture.md) for the full pipeline
diagram, the threat model, and the mTLS/zero-trust networking notes.

## Quickstart

```bash
# Local pre-commit hooks (mirrors the CI gate)
pip install pre-commit
pre-commit install
pre-commit run --all-files

# Run the CVE triage engine against a Trivy scan
pip install pyyaml
trivy image --format json -o trivy-results.json sample-app:local
python security/triage/triage.py --allowlist security/triage/cve-allowlist.yml \
  --report-out triage-report.json trivy-results.json

# Generate a least-privilege IAM role
pip install pyyaml jsonschema
python iam/generator/generate_policy.py \
  iam/generator/examples/ci-deploy-role-request.yml --out-dir out/

# Run the policy-as-code unit tests
opa test policy/opa -v

# Generate a SOC2 evidence package
pip install pyyaml requests
python compliance/evidence-collector/collect_evidence.py \
  --control-matrix compliance/soc2/control-matrix.csv --output-dir evidence-package/
```

## Design principles

1. **Fail loud on what matters, stay quiet on what doesn't.** A CRITICAL,
   unpatched, unallowlisted vulnerability blocks the merge. A MEDIUM finding
   in a transitive dependency does not — it's reported, not a build-breaker.
   Same logic applies to DAST (`security/dast/zap-rules.tsv`). Policy-as-code
   is the deliberate exception: root containers, IMDSv1, and open security
   groups are always blocking (see [`policy/README.md`](policy/README.md)).
2. **The allowlist is itself audited.** Every entry in
   [`cve-allowlist.yml`](security/triage/cve-allowlist.yml) has an owner and
   an expiry date; an expired entry reverts to blocking severity instead of
   silently suppressing forever.
3. **Compliance evidence is generated, not curated.** The SOC2 control matrix
   isn't a spreadsheet someone updates before an audit — the evidence
   collector checks that the file/policy/workflow backing each automated
   control still exists, every time it runs.
4. **Least privilege is enforced by construction.** The IAM generator refuses
   wildcard actions outright and encodes session time-limits + MFA into the
   trust policy itself, rather than documenting "please scope this down" in
   a wiki page nobody reads.
