#!/usr/bin/env python3
"""Least-privilege IAM policy generator with time-limited sessions.

Takes a declarative role request (see templates/role-request.schema.json) -
what actions/resources are needed, by whom, and why - and emits:

  1. A scoped IAM permission policy (no wildcard actions unless the action
     genuinely has no resource-level ARN grammar, and only then with an
     explicit opt-in).
  2. A trust policy requiring MFA and (optionally) a source-IP condition.
  3. The `aws iam` CLI commands to actually create the role, including
     --max-session-duration so "time-limited" is enforced by IAM itself,
     not just documented.

This turns "someone hand-writes an IAM policy with Effect: Allow, Action: *"
into a reviewable, auditable, least-privilege-by-construction artifact -
the generated JSON is what gets committed and code-reviewed, not the request.

Usage:
    generate_policy.py request.yml --out-dir out/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import validate, ValidationError

SCHEMA_PATH = Path(__file__).parent / "templates" / "role-request.schema.json"

# Actions that AWS defines as only supporting Resource: "*" (no ARN grammar
# to scope down further). Anything NOT in this list must come with a
# concrete resource ARN, or generation fails.
NO_ARN_ACTIONS = {
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeRegions",
    "s3:ListAllMyBuckets",
    "iam:ListRoles",
    "iam:ListUsers",
    "cloudwatch:ListMetrics",
    "sts:GetCallerIdentity",
    "ecr:GetAuthorizationToken",
}


def load_request(path: Path) -> dict:
    text = path.read_text()
    data = yaml.safe_load(text) if path.suffix in (".yml", ".yaml") else json.loads(text)
    schema = json.loads(SCHEMA_PATH.read_text())
    try:
        validate(instance=data, schema=schema)
    except ValidationError as e:
        print(f"error: role request failed schema validation: {e.message}", file=sys.stderr)
        sys.exit(2)
    return data


def build_permission_policy(req: dict) -> dict:
    actions = req["actions"]
    resources = req["resources"]
    allow_wildcard = req.get("allow_wildcard_resource", False)

    wildcard_actions = {a for a in actions if a == "*" or a.endswith(":*")}
    if wildcard_actions:
        raise ValueError(
            f"wildcard actions are not allowed: {sorted(wildcard_actions)}. "
            "List each action explicitly (e.g. s3:GetObject, not s3:*)."
        )

    no_arn_requested = [a for a in actions if a in NO_ARN_ACTIONS]
    if no_arn_requested and not allow_wildcard:
        raise ValueError(
            f"actions {no_arn_requested} only support Resource: \"*\" in IAM; "
            "set allow_wildcard_resource: true in the request to acknowledge this."
        )

    statements = []

    scoped_actions = [a for a in actions if a not in NO_ARN_ACTIONS]
    if scoped_actions:
        statements.append({
            "Sid": "ScopedLeastPrivilegeAccess",
            "Effect": "Allow",
            "Action": sorted(scoped_actions),
            "Resource": sorted(resources),
        })

    if no_arn_requested:
        statements.append({
            "Sid": "AccountLevelReadOnlyActionsNoArnSupport",
            "Effect": "Allow",
            "Action": sorted(no_arn_requested),
            "Resource": "*",
        })

    return {"Version": "2012-10-17", "Statement": statements}


def build_trust_policy(req: dict) -> dict:
    principals = req["trusted_principals"]
    require_mfa = req.get("require_mfa", True)
    source_ips = req.get("source_ip_allowlist")
    max_minutes = req.get("max_session_duration_minutes", 60)

    conditions: dict[str, Any] = {}
    if require_mfa:
        conditions.setdefault("Bool", {})["aws:MultiFactorAuthPresent"] = "true"
    if source_ips:
        conditions.setdefault("IpAddress", {})["aws:SourceIp"] = source_ips
    # Belt-and-suspenders: even if a caller tries to request a longer STS
    # session than the role allows, IAM caps it at the role's
    # MaxSessionDuration - this condition just makes the intent explicit
    # and auditable in the policy document itself.
    conditions.setdefault("NumericLessThanEquals", {})["aws:MaxSessionDuration"] = str(max_minutes * 60)

    statement = {
        "Sid": "TimeLimitedAssumeRoleWithMFA",
        "Effect": "Allow",
        "Principal": {"AWS": principals},
        "Action": "sts:AssumeRole",
    }
    if conditions:
        statement["Condition"] = conditions

    return {"Version": "2012-10-17", "Statement": [statement]}


def build_cli_commands(req: dict, role_policy_file: str, trust_policy_file: str) -> list[str]:
    role = req["role_name"]
    max_seconds = req.get("max_session_duration_minutes", 60) * 60
    return [
        f"aws iam create-role \\\n"
        f"  --role-name {role} \\\n"
        f"  --assume-role-policy-document file://{trust_policy_file} \\\n"
        f"  --max-session-duration {max_seconds} \\\n"
        f'  --description "Least-privilege role for {req.get("requester", "unknown")}: '
        f'{req.get("justification", "no justification provided")}"',
        f"aws iam put-role-policy \\\n"
        f"  --role-name {role} \\\n"
        f"  --policy-name {role}-least-privilege \\\n"
        f"  --policy-document file://{role_policy_file}",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("request", type=Path, help="Role request YAML/JSON file")
    parser.add_argument("--out-dir", type=Path, default=Path("out"))
    args = parser.parse_args(argv)

    req = load_request(args.request)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    try:
        permission_policy = build_permission_policy(req)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    trust_policy = build_trust_policy(req)

    role = req["role_name"]
    policy_file = args.out_dir / f"{role}.policy.json"
    trust_file = args.out_dir / f"{role}.trust-policy.json"
    cli_file = args.out_dir / f"{role}.create-role.sh"

    policy_file.write_text(json.dumps(permission_policy, indent=2) + "\n")
    trust_file.write_text(json.dumps(trust_policy, indent=2) + "\n")

    commands = build_cli_commands(req, policy_file.name, trust_file.name)
    cli_file.write_text("#!/usr/bin/env bash\nset -euo pipefail\n\n" + "\n\n".join(commands) + "\n")

    print(f"wrote {policy_file}")
    print(f"wrote {trust_file}")
    print(f"wrote {cli_file}")
    print(
        f"\nSession is time-limited to {req.get('max_session_duration_minutes', 60)} minutes "
        f"(MaxSessionDuration + policy condition), MFA required: {req.get('require_mfa', True)}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
