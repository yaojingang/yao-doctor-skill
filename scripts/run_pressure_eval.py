#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from render_pressure_eval_report import render_html, render_markdown
from scan_security_skills import build_payload


DISPOSITION_ORDER = {"safe": 0, "risky": 1, "suspicious": 2, "unsafe": 3, "critical": 4}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Yao Doctor Skill malicious-fixture pressure suite.")
    parser.add_argument("--fixture-root", help="Optional fixture root override")
    parser.add_argument("--case-file", help="Optional case definition file override")
    parser.add_argument("--output-dir", help="Optional report output directory override")
    return parser.parse_args(argv)


def family_sort_key(item: dict) -> tuple:
    return (-item["passed"], item["family"])


def evaluate_case(case: dict, report: dict | None) -> dict:
    actual = {
        "path": report["path"] if report else None,
        "disposition": report["disposition"] if report else "missing",
        "capability_risk_score": report["capability_risk_score"] if report else 0,
        "unsafe_behavior_score": report["unsafe_behavior_score"] if report else 0,
        "categories": sorted({item["category"] for item in report.get("findings", [])}) if report else [],
        "evidence_kinds": sorted({item.get("evidence_kind", "pattern-match") for item in report.get("findings", [])}) if report else [],
        "protected_surfaces": sorted({item.get("protected_surface") for item in report.get("findings", []) if item.get("protected_surface")}) if report else [],
        "findings": report.get("findings", []) if report else [],
    }
    failure_reasons = []
    checks = {}
    result = "fail"

    if not report:
        failure_reasons.append("fixture was not discovered as a skill target")
        return {"result": result, "checks": {"discovered": False}, "failure_reasons": failure_reasons, "actual": actual}

    actual_rank = DISPOSITION_ORDER[actual["disposition"]]
    expected_categories = set(case.get("expected_categories", []))
    expected_evidence = set(case.get("expected_evidence_kinds", []))
    expected_protected = set(case.get("expected_protected_surfaces", []))
    forbidden_categories = set(case.get("forbidden_categories", []))

    if case["mode"] in {"must_detect", "stretch"}:
        min_rank = DISPOSITION_ORDER.get(case.get("expected_min_disposition", "safe"), 0)
        checks["disposition"] = actual_rank >= min_rank
        checks["categories"] = expected_categories.issubset(set(actual["categories"]))
        checks["evidence"] = expected_evidence.issubset(set(actual["evidence_kinds"]))
        checks["protected"] = expected_protected.issubset(set(actual["protected_surfaces"]))
        if not checks["disposition"]:
            failure_reasons.append(
                f"actual disposition `{actual['disposition']}` did not reach expected minimum `{case.get('expected_min_disposition')}`"
            )
        if not checks["categories"]:
            failure_reasons.append(
                f"missing expected categories: {', '.join(sorted(expected_categories - set(actual['categories'])))}"
            )
        if not checks["evidence"]:
            failure_reasons.append(
                f"missing expected evidence kinds: {', '.join(sorted(expected_evidence - set(actual['evidence_kinds'])))}"
            )
        if not checks["protected"]:
            failure_reasons.append(
                f"missing expected protected surfaces: {', '.join(sorted(expected_protected - set(actual['protected_surfaces'])))}"
            )
        success = all(checks.values())
        result = "pass" if case["mode"] == "must_detect" and success else "hit" if success else "fail" if case["mode"] == "must_detect" else "miss"
    else:
        max_rank = DISPOSITION_ORDER.get(case.get("max_disposition", "critical"), 4)
        checks["disposition"] = actual_rank <= max_rank
        checks["required_categories"] = expected_categories.issubset(set(actual["categories"]))
        checks["forbidden_categories"] = not (forbidden_categories & set(actual["categories"]))
        if not checks["disposition"]:
            failure_reasons.append(
                f"actual disposition `{actual['disposition']}` exceeded control ceiling `{case.get('max_disposition')}`"
            )
        if not checks["required_categories"]:
            failure_reasons.append(
                f"missing required control categories: {', '.join(sorted(expected_categories - set(actual['categories'])))}"
            )
        if not checks["forbidden_categories"]:
            failure_reasons.append(
                f"control case hit forbidden categories: {', '.join(sorted(forbidden_categories & set(actual['categories'])))}"
            )
        result = "pass" if all(checks.values()) else "fail"

    return {
        "result": result,
        "checks": checks,
        "failure_reasons": failure_reasons,
        "actual": actual,
    }


def build_pressure_payload(fixture_root: Path, case_file: Path) -> dict:
    cases = json.loads(case_file.read_text(encoding="utf-8"))
    scan_payload = build_payload([fixture_root], full_scan=True)
    reports = {Path(item["path"]).name: item for item in scan_payload["skills"]}
    evaluated = []

    for case in cases:
        report = reports.get(case["fixture_dir"])
        outcome = evaluate_case(case, report)
        evaluated.append(
            {
                **case,
                **outcome,
            }
        )

    core_cases = [case for case in evaluated if case["mode"] in {"must_detect", "control"}]
    stretch_cases = [case for case in evaluated if case["mode"] == "stretch"]
    family_stats = []
    for family in sorted({case["family"] for case in evaluated}):
        group = [case for case in evaluated if case["family"] == family]
        passed = sum(1 for case in group if case["result"] in {"pass", "hit"})
        family_stats.append({"family": family, "total": len(group), "passed": passed})
    family_stats.sort(key=family_sort_key)

    aggregate = {
        "total_cases": len(evaluated),
        "core_cases": len(core_cases),
        "core_passed": sum(1 for case in core_cases if case["result"] == "pass"),
        "stretch_cases": len(stretch_cases),
        "stretch_hits": sum(1 for case in stretch_cases if case["result"] == "hit"),
        "control_cases": sum(1 for case in evaluated if case["mode"] == "control"),
        "control_passed": sum(1 for case in evaluated if case["mode"] == "control" and case["result"] == "pass"),
        "cross_file_cases": sum(1 for case in evaluated if "cross-file-inferred" in case.get("expected_evidence_kinds", [])),
        "cross_file_hits": sum(
            1
            for case in evaluated
            if "cross-file-inferred" in case.get("expected_evidence_kinds", [])
            and "cross-file-inferred" in case["actual"]["evidence_kinds"]
        ),
        "protected_surface_cases": sum(1 for case in evaluated if case.get("expected_protected_surfaces")),
        "protected_surface_hits": sum(
            1
            for case in evaluated
            if case.get("expected_protected_surfaces")
            and set(case.get("expected_protected_surfaces", [])).issubset(set(case["actual"]["protected_surfaces"]))
        ),
    }

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scanner_version": scan_payload["scanner_version"],
        "fixture_root": str(fixture_root.resolve()),
        "case_file": str(case_file.resolve()),
        "scan_summary": scan_payload["scan_summary"],
        "aggregate": aggregate,
        "family_stats": family_stats,
        "cases": evaluated,
    }


def write_outputs(payload: dict, output_root: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_dir = output_root / timestamp
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "report.json"
    md_path = report_dir / "report.md"
    html_path = report_dir / "report.html"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    html_path.write_text(render_html(payload), encoding="utf-8")

    latest_dir = output_root / "latest"
    latest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(json_path, latest_dir / "semantic-pressure-report.json")
    shutil.copyfile(md_path, latest_dir / "semantic-pressure-report.md")
    shutil.copyfile(html_path, latest_dir / "semantic-pressure-report.html")
    return html_path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    script_dir = Path(__file__).resolve().parent
    skill_root = script_dir.parent
    fixture_root = Path(args.fixture_root).expanduser().resolve() if args.fixture_root else skill_root / "evals" / "pressure_suite"
    case_file = Path(args.case_file).expanduser().resolve() if args.case_file else skill_root / "evals" / "pressure_suite_cases.json"
    output_root = Path(args.output_dir).expanduser().resolve() if args.output_dir else skill_root / "_eval_reports" / "semantic_pressure"

    payload = build_pressure_payload(fixture_root, case_file)
    html_path = write_outputs(payload, output_root)
    print(str(html_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
