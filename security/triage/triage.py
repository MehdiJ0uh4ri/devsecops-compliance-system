#!/usr/bin/env python3
"""Noise-reduced vulnerability triage.

Consumes scanner output (Trivy, Grype, or Semgrep JSON), normalizes findings
into one shape, applies the allowlist in cve-allowlist.yml, and decides
whether the build should fail.

Policy: fail the build ONLY on a CRITICAL-severity finding that is (a) not
allowlisted and (b) not expired-allowlisted. Everything else (HIGH/MEDIUM/LOW,
or anything covered by a live allowlist entry) is reported but does not block
the pipeline. This is the noise-reduction contract referenced in
policy/README.md and compliance/soc2/control-matrix.csv (CC7.1).

Usage:
    triage.py --allowlist cve-allowlist.yml --report-out triage-report.json \\
              trivy-results.json [grype-results.json ...]

Exit codes:
    0  - no blocking findings
    1  - one or more CRITICAL, non-allowlisted findings (build should fail)
    2  - usage / input error
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover
    print("error: pyyaml is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclasses.dataclass
class Finding:
    scanner: str
    id: str  # CVE / GHSA / rule id
    severity: str
    package: str  # package name, or file path for SAST
    title: str
    fixed_version: str | None = None
    installed_version: str | None = None


@dataclasses.dataclass
class AllowEntry:
    id: str
    package: str
    reason: str
    owner: str
    expires: dt.date
    scope: str
    rule_id: str | None = None

    def is_expired(self, today: dt.date) -> bool:
        return today > self.expires

    def matches(self, f: Finding, today: dt.date) -> bool:
        if self.scope not in ("any", f.scanner):
            return False
        id_match = self.id == "*" or self.id == f.id
        rule_match = self.rule_id is None or self.rule_id == f.id
        pkg_match = fnmatch.fnmatch(f.package, self.package)
        return id_match and rule_match and pkg_match


def load_allowlist(path: Path) -> list[AllowEntry]:
    data = yaml.safe_load(path.read_text()) or {}
    entries = []
    for e in data.get("entries", []):
        entries.append(
            AllowEntry(
                id=str(e["id"]),
                package=e.get("package", "*"),
                reason=e.get("reason", ""),
                owner=e["owner"],
                expires=dt.date.fromisoformat(str(e["expires"])),
                scope=e.get("scope", "any"),
                rule_id=e.get("rule_id"),
            )
        )
    return entries


def _sniff_kind(data: Any) -> str:
    if isinstance(data, dict) and "SchemaVersion" in data and "Results" in data:
        return "trivy"
    if isinstance(data, dict) and "matches" in data:
        return "grype"
    if isinstance(data, dict) and "results" in data and "errors" in data:
        return "semgrep"
    raise ValueError("unrecognized scanner output format")


def parse_trivy(data: dict) -> Iterable[Finding]:
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            yield Finding(
                scanner="trivy",
                id=v.get("VulnerabilityID", "UNKNOWN"),
                severity=v.get("Severity", "UNKNOWN").upper(),
                package=v.get("PkgName", "unknown"),
                title=v.get("Title") or v.get("VulnerabilityID", ""),
                fixed_version=v.get("FixedVersion") or None,
                installed_version=v.get("InstalledVersion"),
            )


def parse_grype(data: dict) -> Iterable[Finding]:
    for m in data.get("matches", []) or []:
        vuln = m.get("vulnerability", {})
        artifact = m.get("artifact", {})
        fix = vuln.get("fix", {}) or {}
        fixed_versions = fix.get("versions") or []
        yield Finding(
            scanner="grype",
            id=vuln.get("id", "UNKNOWN"),
            severity=(vuln.get("severity") or "UNKNOWN").upper(),
            package=artifact.get("name", "unknown"),
            title=vuln.get("description", vuln.get("id", "")),
            fixed_version=", ".join(fixed_versions) if fixed_versions else None,
            installed_version=artifact.get("version"),
        )


SEMGREP_SEVERITY_MAP = {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "LOW"}


def parse_semgrep(data: dict) -> Iterable[Finding]:
    for r in data.get("results", []) or []:
        extra = r.get("extra", {})
        sev = SEMGREP_SEVERITY_MAP.get((extra.get("severity") or "").upper(), "MEDIUM")
        yield Finding(
            scanner="semgrep",
            id=r.get("check_id", "UNKNOWN"),
            severity=sev,
            package=r.get("path", "unknown"),
            title=extra.get("message", r.get("check_id", "")),
        )


PARSERS = {"trivy": parse_trivy, "grype": parse_grype, "semgrep": parse_semgrep}


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text())
    kind = _sniff_kind(data)
    return list(PARSERS[kind](data))


def triage(
    findings: list[Finding], allowlist: list[AllowEntry], today: dt.date
) -> dict:
    blocking, allowlisted, expired_allowlisted, informational = [], [], [], []

    for f in findings:
        matched_entry = None
        for entry in allowlist:
            if entry.matches(f, today):
                matched_entry = entry
                break

        if matched_entry and not matched_entry.is_expired(today):
            allowlisted.append({"finding": dataclasses.asdict(f), "allowlist": dataclasses.asdict(matched_entry, dict_factory=_date_safe)})
            continue

        if matched_entry and matched_entry.is_expired(today):
            expired_allowlisted.append(
                {"finding": dataclasses.asdict(f), "allowlist": dataclasses.asdict(matched_entry, dict_factory=_date_safe), "expired_since": str(today - matched_entry.expires)}
            )
            # falls through: treated as NOT allowlisted below

        if f.severity == "CRITICAL":
            blocking.append(dataclasses.asdict(f))
        else:
            informational.append(dataclasses.asdict(f))

    return {
        "generated_at": today.isoformat(),
        "summary": {
            "total_findings": len(findings),
            "blocking_critical": len(blocking),
            "allowlisted": len(allowlisted),
            "expired_allowlist_entries": len(expired_allowlisted),
            "informational": len(informational),
        },
        "blocking": blocking,
        "expired_allowlist": expired_allowlisted,
        "allowlisted": allowlisted,
        "informational": informational,
    }


def _date_safe(items):
    return {k: (v.isoformat() if isinstance(v, dt.date) else v) for k, v in items}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scan_files", nargs="+", type=Path, help="Trivy/Grype/Semgrep JSON output file(s)")
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("triage-report.json"))
    parser.add_argument("--today", type=str, default=None, help="Override today's date (ISO), for testing")
    args = parser.parse_args(argv)

    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()

    allowlist = load_allowlist(args.allowlist)
    findings: list[Finding] = []
    for f in args.scan_files:
        findings.extend(load_findings(f))

    report = triage(findings, allowlist, today)
    args.report_out.write_text(json.dumps(report, indent=2))

    s = report["summary"]
    print(f"Triage: {s['total_findings']} findings | "
          f"{s['blocking_critical']} blocking CRITICAL | "
          f"{s['allowlisted']} allowlisted | "
          f"{s['expired_allowlist_entries']} expired-allowlist (now blocking) | "
          f"{s['informational']} informational")

    if report["expired_allowlist"]:
        print("\n::warning::The following allowlist entries are EXPIRED and no longer suppress findings:")
        for item in report["expired_allowlist"]:
            a = item["allowlist"]
            print(f"  - {a['id']} ({a['package']}) owned by {a['owner']}, expired {a['expires']}")

    if report["blocking"]:
        print("\n::error::Blocking CRITICAL findings (unpatched, not allowlisted):")
        for f in report["blocking"]:
            fix = f"fix available: {f['fixed_version']}" if f.get("fixed_version") else "no fix available upstream"
            print(f"  - [{f['scanner']}] {f['id']} in {f['package']} ({fix})")
        return 1

    print("\nNo blocking CRITICAL findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
