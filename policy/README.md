# Policy-as-Code (OPA / Conftest)

Rego policies enforced **as a PR gate**, not just a dashboard. A PR that violates
any rule below fails the `policy-gate` job in
[`.github/workflows/pipeline.yml`](../.github/workflows/pipeline.yml) and cannot merge.

| Package | File | Enforces | Evaluated against |
|---|---|---|---|
| `containers.no_root` | [opa/containers/no_root.rego](opa/containers/no_root.rego) | No privileged containers, no `runAsUser: 0`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true` | Kubernetes manifests (YAML) |
| `iam.imdsv2` | [opa/iam/imdsv2.rego](opa/iam/imdsv2.rego) | EC2 instances / launch templates must set `metadata_options.http_tokens = "required"` (IMDSv2) | `terraform show -json` plan |
| `network.no_open_sg` | [opa/network/no_open_sg.rego](opa/network/no_open_sg.rego) | No security group ingress from `0.0.0.0/0` or `::/0`, except port 80/443 for public load balancers | `terraform show -json` plan |

## Running locally

```bash
# unit tests for the policies themselves
opa test policy/opa -v

# evaluate against a real Kubernetes manifest
conftest test --config policy/conftest/conftest.toml k8s/deployment.yaml

# evaluate against a Terraform plan
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json
conftest test --config policy/conftest/conftest.toml plan.json
```

## Design notes

- **Deny-only, no warn tier for these three rules.** Anything in `deny` blocks the
  merge; there is deliberately no "soft fail" for root containers, IMDSv1, or open
  security groups — these map directly to SOC2 CC6.1/CC6.6 controls (see
  [compliance/soc2/control-matrix.csv](../compliance/soc2/control-matrix.csv)) and a
  warning that nobody reads is not a control.
- **Port 80/443 to `0.0.0.0/0` is allowed** for public ingress/load-balancer security
  groups — the goal is eliminating *accidental* exposure (SSH, RDP, databases,
  management ports), not blocking legitimate public web endpoints. Adjust
  `allowed_public_ports` in `no_open_sg.rego` if your threat model is stricter.
- Each policy has a same-named `_test.rego` file with both allow and deny fixtures.
  Add a failing fixture before writing new policy logic (TDD) — `opa test` is wired
  into CI so a policy change without a matching test won't silently regress.
