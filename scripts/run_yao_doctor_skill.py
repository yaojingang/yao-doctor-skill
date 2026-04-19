#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from render_security_report import render_html, render_markdown
from scan_security_skills import build_payload, discover_roots


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Yao Doctor Skill and generate a visual security report.")
    parser.add_argument("roots", nargs="*", help="Optional root directories to scan")
    parser.add_argument("--output-dir", help="Optional output directory override")
    parser.add_argument("--full-scan", action="store_true", help="Ignore incremental cache and rescan every target")
    parser.add_argument("--changed-only", action="store_true", help="Render only targets changed from the incremental cache")
    return parser.parse_args(argv)


def sync_latest_report(base_output: Path, report_dir: Path, *, changed_only: bool) -> None:
    latest_name = "changed-only-latest" if changed_only else "full-library-latest"
    latest_dir = base_output / latest_name
    latest_dir.mkdir(parents=True, exist_ok=True)
    for name in ("report.json", "report.md", "report.html"):
        shutil.copyfile(report_dir / name, latest_dir / name)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    roots = discover_roots(Path.cwd(), args.roots)
    payload = build_payload(roots, full_scan=args.full_scan, changed_only=args.changed_only)

    script_dir = Path(__file__).resolve().parent
    skill_root = script_dir.parent
    base_output = Path(args.output_dir).expanduser().resolve() if args.output_dir else skill_root / "_yao_doctor_skill_reports"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_dir = base_output / timestamp
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "report.json"
    md_path = report_dir / "report.md"
    html_path = report_dir / "report.html"

    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    html_path.write_text(render_html(payload), encoding="utf-8")
    sync_latest_report(base_output, report_dir, changed_only=args.changed_only)

    print(str(html_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
