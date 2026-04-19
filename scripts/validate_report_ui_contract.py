#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REQUIRED_MARKERS = [
    'id="overview"',
    'id="data-analysis"',
    'id="definitions"',
    'id="module-guide"',
    'id="skills"',
    'id="lang-toggle"',
    'id="filters"',
    'id="type-filters"',
    'id="quick-links"',
    'id="footer-note"',
    "renderDataAnalysis(copy);",
    "renderTypeFilters(copy);",
    "renderFooter(copy);",
    "classifySkillType(",
    "https://x.com/yaojingang",
]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the current Yao Doctor Skill HTML report UI contract.")
    parser.add_argument("report_html", help="Path to the generated report.html file")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report_path = Path(args.report_html).expanduser().resolve()
    if not report_path.exists():
        print(f"missing report file: {report_path}", file=sys.stderr)
        return 1

    html = report_path.read_text(encoding="utf-8")
    missing = [marker for marker in REQUIRED_MARKERS if marker not in html]
    if missing:
        print(f"report UI contract failed for {report_path}", file=sys.stderr)
        for marker in missing:
            print(f"- missing: {marker}", file=sys.stderr)
        return 1

    print(f"report UI contract passed: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
