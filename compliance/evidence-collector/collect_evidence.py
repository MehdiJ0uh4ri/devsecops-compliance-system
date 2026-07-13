#!/usr/bin/env python3
"""Automated SOC2 compliance evidence collector.

Turns compliance/soc2/control-matrix.csv into an audit-ready evidence
package: for every control, verify the evidence artifact actually exists
(file in-repo, or a live GitHub Actions run) and produce a timestamped
manifest + human-readable summary. This is the difference between "the
control matrix says CC6.8 is implemented" and "here is proof, generated
minutes ago, that it's still true" - the thing an auditor actually wants.

Design goals:
  - Works fully offline (repo-relative file checks) so it's useful in local
    dev, not just CI.
  - Optionally enriches with live GitHub Actions run status when
    GITHUB_TOKEN + GITHUB_REPOSITORY are set (as they are in
    .github/workflows/compliance-evidence.yml) - degrades gracefully to
    "not checked (offline)" otherwise rather than failing.
  - Every run is timestamped and self-contained so re-running it monthly
    builds a historical trail, not just a single snapshot.

Usage:
    collect_evidence.py --control-matrix ../soc2/control-matrix.csv \\
                         --output-dir evidence-package --period 2026-Q3
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import shutil
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:
    requests = None  # live GitHub checks are skipped if requests isn't installed

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_controls(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def resolve_evidence_paths(evidence_source: str) -> list[str]:
    """Extract plausible repo-relative file path tokens (posix-style, as
    written in the CSV) out of a free-text evidence_source cell, e.g.
    'policy/opa/network/no_open_sg.rego' or
    '.github/workflows/pipeline.yml (policy-gate job)'."""
    candidates = []
    for token in evidence_source.replace(",", " ").split():
        token = token.strip("()")
        if "/" in token or token.startswith("."):
            candidates.append(token)
    return candidates


def verify_file_evidence(evidence_source: str) -> dict:
    tokens = resolve_evidence_paths(evidence_source)
    if not tokens:
        return {"checked": False, "reason": "no repo-relative file path found in evidence_source"}
    results = []
    for token in tokens:
        if "**" in token:
            # glob pattern (e.g. policy/opa/**/*.rego) - verify at least one match
            base_part, _, pattern = token.partition("**/")
            base = REPO_ROOT / base_part.rstrip("/")
            matches = list(base.rglob(pattern)) if base.exists() else []
            results.append({"path": token, "exists": len(matches) > 0, "match_count": len(matches)})
        else:
            p = REPO_ROOT / token
            results.append({"path": token, "exists": p.exists()})
    return {"checked": True, "files": results, "all_present": all(r.get("exists") or r.get("match_count", 0) > 0 for r in results)}


def check_live_github_status(repo: str, token: str) -> dict:
    """Latest run conclusion for the two workflows that back most automated
    controls in the matrix. Best-effort: any HTTP/network failure degrades
    to 'unavailable' rather than crashing the whole evidence run."""
    if requests is None:
        return {"checked": False, "reason": "requests library not installed"}

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    result: dict[str, Any] = {"checked": True, "workflows": {}}
    for workflow_file in ("pipeline.yml", "compliance-evidence.yml"):
        url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/runs"
        try:
            resp = requests.get(url, headers=headers, params={"per_page": 1}, timeout=10)
            resp.raise_for_status()
            runs = resp.json().get("workflow_runs", [])
            if runs:
                latest = runs[0]
                result["workflows"][workflow_file] = {
                    "run_id": latest["id"],
                    "status": latest["status"],
                    "conclusion": latest["conclusion"],
                    "run_started_at": latest["run_started_at"],
                    "html_url": latest["html_url"],
                }
            else:
                result["workflows"][workflow_file] = {"status": "no_runs_found"}
        except Exception as e:  # noqa: BLE001 - genuinely best-effort, any failure just gets recorded
            result["workflows"][workflow_file] = {"status": "unavailable", "error": str(e)}
    return result


def get_stale_iam_credentials() -> dict:
    """Evidence hook for R-6 (compliance/soc2/remediation-roadmap.md):
    report IAM access keys unused for >90 days so CC6.3 can move from
    quarterly-manual to monthly-automated review.

    TODO(R-6): wire this up to boto3 iam.generate_credential_report() /
    get_credential_report() once this pipeline has a read-only IAM audit
    role available in CI. Left as an explicit not-yet-collected marker
    (rather than a fake success) so the evidence package accurately
    reflects the gap tracked in remediation-roadmap.md.
    """
    return {
        "checked": False,
        "reason": "not yet implemented - see remediation-roadmap.md item R-6",
    }


def build_manifest(controls: list[dict], period: str, github_repo: str | None, github_token: str | None) -> dict:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    live_github = None
    if github_repo and github_token:
        live_github = check_live_github_status(github_repo, github_token)

    control_evidence = []
    for c in controls:
        entry = {
            "control_id": c["control_id"],
            "tsc_category": c["tsc_category"],
            "status": c["status"],
            "automation_level": c["automation_level"],
            "owner": c["owner"],
        }
        if c["automation_level"] in ("automated", "tool") and c["status"] != "gap":
            entry["evidence_check"] = verify_file_evidence(c["evidence_source"])
        else:
            entry["evidence_check"] = {"checked": False, "reason": f"automation_level={c['automation_level']!r}, manual evidence not verifiable by this script"}
        control_evidence.append(entry)

    verified = sum(1 for e in control_evidence if e["evidence_check"].get("all_present"))
    checkable = sum(1 for e in control_evidence if e["evidence_check"].get("checked"))

    return {
        "generated_at": now,
        "period": period,
        "summary": {
            "total_controls": len(controls),
            "automated_evidence_checkable": checkable,
            "automated_evidence_verified_present": verified,
        },
        "live_github_status": live_github,
        "stale_iam_credentials": get_stale_iam_credentials(),
        "controls": control_evidence,
    }


def write_summary_markdown(manifest: dict, out_path: Path) -> None:
    lines = [
        f"# SOC2 Evidence Package — {manifest['period']}",
        "",
        f"Generated: {manifest['generated_at']}",
        "",
        f"- Total controls: {manifest['summary']['total_controls']}",
        f"- Controls with checkable automated evidence: {manifest['summary']['automated_evidence_checkable']}",
        f"- Verified present this run: {manifest['summary']['automated_evidence_verified_present']}",
        "",
        "## Per-control evidence check",
        "",
        "| Control | Category | Status | Evidence verified |",
        "|---|---|---|---|",
    ]
    for e in manifest["controls"]:
        check = e["evidence_check"]
        if check.get("checked"):
            verified = "yes" if check.get("all_present") else "**MISSING**"
        else:
            verified = "n/a (manual control)"
        lines.append(f"| {e['control_id']} | {e['tsc_category']} | {e['status']} | {verified} |")

    if manifest.get("live_github_status"):
        lines += ["", "## Live GitHub Actions status", "", "```json", json.dumps(manifest["live_github_status"], indent=2), "```"]

    lines += ["", "## Known open items", "", "See `remediation-roadmap.md` (bundled in this package) for gaps not yet closed."]
    out_path.write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--control-matrix", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--period", type=str, default="auto")
    args = parser.parse_args(argv)

    period = args.period
    if period == "auto":
        period = dt.date.today().isoformat()

    controls = load_controls(args.control_matrix)
    manifest = build_manifest(
        controls,
        period=period,
        github_repo=os.environ.get("GITHUB_REPOSITORY"),
        github_token=os.environ.get("GITHUB_TOKEN"),
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2))
    write_summary_markdown(manifest, args.output_dir / "summary.md")

    # Bundle the source-of-truth docs alongside the generated evidence so the
    # package is self-contained for an auditor (no need to also hand them a
    # repo checkout).
    soc2_dir = args.control_matrix.parent
    for fname in ("control-matrix.csv", "gap-analysis.md", "remediation-roadmap.md"):
        src = soc2_dir / fname
        if src.exists():
            shutil.copy(src, args.output_dir / fname)

    s = manifest["summary"]
    print(f"Evidence package written to {args.output_dir}")
    print(f"  {s['automated_evidence_verified_present']}/{s['automated_evidence_checkable']} "
          f"automated-evidence controls verified present (of {s['total_controls']} total controls).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
