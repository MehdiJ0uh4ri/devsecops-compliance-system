# Vendor / Third-Party Risk Review (ad hoc, pre-R-4)

Referenced by SOC2 control CC9.2. Today this is an ad hoc check before
adopting a new SaaS tool in the pipeline; item R-4 in
[remediation-roadmap.md](../../compliance/soc2/remediation-roadmap.md)
formalizes this into a repeatable questionnaire.

## Current pipeline third-party dependencies

| Vendor/tool | Function | Data exposure | Notes |
|---|---|---|---|
| Semgrep (OSS rules + Semgrep Registry) | SAST | Source code patterns sent to Semgrep Cloud if using `semgrep ci` with an org token | This repo pins to local + OSS registry rules; no Semgrep Cloud account configured |
| GitHub Advanced Security (secret scanning, code scanning) | Secrets/SARIF ingestion | Findings only, within GitHub's existing data boundary for the repo | Covered under GitHub's own SOC2 report |
| Trivy / Syft / OPA / Conftest / gitleaks | SCA, SBOM, policy, secrets | None — all run locally in the CI runner, no external API calls | Preferred posture: no data leaves the build |
| OWASP ZAP | DAST | Scans the ephemeral CI container only, not production | No external service |

## Before adding a new scanner/SaaS dependency

1. Does it need to send source code, secrets, or customer data off our
   infrastructure? If yes, get a signed DPA before enabling it.
2. Does it have its own SOC2/ISO27001 report? Request it and file alongside
   this doc.
3. Prefer tools that run entirely within the CI runner (like the four above)
   over hosted SaaS equivalents when the trade-off is close.
