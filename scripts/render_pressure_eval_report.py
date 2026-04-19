#!/usr/bin/env python3

from __future__ import annotations

import json
from datetime import datetime
from html import escape


MODE_LABELS = {
    "must_detect": "必须命中",
    "control": "控制样本",
    "stretch": "拉伸样本",
}

STATUS_COLORS = {
    "pass": "#1f7a4f",
    "fail": "#c2410c",
    "hit": "#2563eb",
    "miss": "#b45309",
}


def expected_view(case: dict) -> dict:
    if "expected" in case and isinstance(case["expected"], dict):
        return case["expected"]
    return {
        "expected_min_disposition": case.get("expected_min_disposition"),
        "max_disposition": case.get("max_disposition"),
        "expected_categories": case.get("expected_categories", []),
        "expected_evidence_kinds": case.get("expected_evidence_kinds", []),
        "expected_protected_surfaces": case.get("expected_protected_surfaces", []),
    }


def render_markdown(payload: dict) -> str:
    lines = []
    aggregate = payload["aggregate"]
    lines.append("# Yao Doctor Skill Pressure Eval")
    lines.append("")
    lines.append(f"Generated at: `{payload['generated_at_utc']}`")
    lines.append(f"Fixture root: `{payload['fixture_root']}`")
    lines.append(f"Scanner version: `{payload['scanner_version']}`")
    lines.append(
        "Summary: "
        f"core `{aggregate['core_passed']}/{aggregate['core_cases']}` passed, "
        f"stretch `{aggregate['stretch_hits']}/{aggregate['stretch_cases']}` hit"
    )
    lines.append("")
    lines.append("## Cases")
    lines.append("")
    lines.append("| Case | Mode | Family | Result | Actual | Expected |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for case in payload["cases"]:
        actual = case["actual"]
        expected = expected_view(case)
        expectation = expected.get("expected_min_disposition") or expected.get("max_disposition") or "-"
        lines.append(
            f"| `{case['fixture_dir']}` | `{MODE_LABELS[case['mode']]}` | `{case['family']}` | "
            f"`{case['result']}` | `{actual.get('disposition', 'missing')}` | `{expectation}` |"
        )
    lines.append("")
    lines.append("## Failures")
    lines.append("")
    failures = [case for case in payload["cases"] if case["result"] in {"fail", "miss"}]
    if not failures:
        lines.append("- none")
    for case in failures:
        lines.append(f"### {case['fixture_dir']}")
        lines.append(f"- Result: `{case['result']}`")
        for reason in case.get("failure_reasons", []):
            lines.append(f"- {reason}")
        for finding in case["actual"].get("findings", [])[:3]:
            location = f"{finding['path']}:{finding['line']}" if finding.get("line") else finding["path"]
            lines.append(
                f"- finding: `{finding['category']}` / `{finding.get('evidence_kind', 'pattern-match')}` @ `{location}`"
            )
        lines.append("")
    return "\n".join(lines)


def render_html(payload: dict) -> str:
    payload_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    aggregate = payload["aggregate"]
    generated = datetime.fromisoformat(payload["generated_at_utc"].replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    core_total = max(aggregate["core_cases"], 1)
    stretch_total = max(aggregate["stretch_cases"], 1)
    family_rows = []
    for family in payload["family_stats"]:
        rate = 0 if family["total"] == 0 else round(family["passed"] / family["total"] * 100)
        family_rows.append(
            f"""
            <div class="metric-row">
              <div class="metric-head"><strong>{escape(family['family'])}</strong><span>{family['passed']}/{family['total']}</span></div>
              <div class="track"><div class="fill" style="width:{rate}%;"></div></div>
            </div>
            """
        )
    case_cards = []
    for case in payload["cases"]:
        actual = case["actual"]
        expected = expected_view(case)
        color = STATUS_COLORS[case["result"]]
        failures = "".join(f"<li>{escape(reason)}</li>" for reason in case.get("failure_reasons", [])) or "<li>none</li>"
        findings = case["actual"].get("findings", [])[:3]
        finding_html = "".join(
            f"""
            <div class="finding">
              <strong>{escape(finding['category'])}</strong>
              <small>{escape(finding.get('evidence_kind', 'pattern-match'))} · {escape(finding.get('path', ''))}{':' + str(finding['line']) if finding.get('line') else ''}</small>
              <small>{escape(finding.get('message', ''))}</small>
            </div>
            """
            for finding in findings
        ) or '<div class="empty">No visible findings.</div>'
        expected_parts = []
        if expected.get("expected_min_disposition"):
            expected_parts.append(f"最低处置: {expected['expected_min_disposition']}")
        if expected.get("max_disposition"):
            expected_parts.append(f"最高处置: {expected['max_disposition']}")
        if expected.get("expected_categories"):
            expected_parts.append("类别: " + ", ".join(expected["expected_categories"]))
        if expected.get("expected_evidence_kinds"):
            expected_parts.append("证据: " + ", ".join(expected["expected_evidence_kinds"]))
        if expected.get("expected_protected_surfaces"):
            expected_parts.append("保护面: " + ", ".join(expected["expected_protected_surfaces"]))
        case_cards.append(
            f"""
            <article class="case-card">
              <div class="case-head">
                <div>
                  <h3>{escape(case['fixture_dir'])}</h3>
                  <p>{escape(MODE_LABELS[case['mode']])} · {escape(case['family'])}</p>
                </div>
                <span class="badge" style="background:{color};">{escape(case['result'])}</span>
              </div>
              <div class="case-grid">
                <div class="meta">
                  <label>预期</label>
                  <strong>{escape(" | ".join(expected_parts) or "-")}</strong>
                </div>
                <div class="meta">
                  <label>实际</label>
                  <strong>{escape(actual.get('disposition', 'missing'))} · capability {actual.get('capability_risk_score', 0)} · unsafe {actual.get('unsafe_behavior_score', 0)}</strong>
                </div>
              </div>
              <div class="subsection">
                <h4>失败原因</h4>
                <ul>{failures}</ul>
              </div>
              <div class="subsection">
                <h4>主要 finding</h4>
                {finding_html}
              </div>
            </article>
            """
        )
    failure_cards = []
    for case in [item for item in payload["cases"] if item["result"] in {"fail", "miss"}]:
        failure_cards.append(
            f"""
            <div class="failure-card">
              <strong>{escape(case['fixture_dir'])}</strong>
              <span>{escape(case['result'])}</span>
              <p>{escape('；'.join(case.get('failure_reasons', [])) or 'No details')}</p>
            </div>
            """
        )
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Yao Doctor Skill Pressure Eval</title>
  <style>
    :root {{
      --bg: #ffffff;
      --ink: #0f172a;
      --muted: #64748b;
      --line: #e2e8f0;
      --soft: #f8fafc;
      --ok: #1f7a4f;
      --warn: #c2410c;
      --info: #2563eb;
      --amber: #b45309;
      --shadow: 0 20px 48px rgba(15, 23, 42, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: "SF Pro Text", "PingFang SC", "Helvetica Neue", sans-serif;
    }}
    a {{ color: inherit; text-decoration: none; }}
    .topbar {{
      position: sticky;
      top: 0;
      z-index: 20;
      background: rgba(255,255,255,0.95);
      backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--line);
    }}
    .topbar-inner, .page {{
      width: min(1320px, calc(100vw - 40px));
      margin: 0 auto;
    }}
    .topbar-inner {{
      min-height: 68px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }}
    .menu {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    .menu a {{
      padding: 10px 14px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--muted);
      font-size: 13px;
      background: #fff;
    }}
    .page {{ padding: 28px 0 80px; }}
    .hero {{
      display: grid;
      grid-template-columns: 1.25fr 0.95fr;
      gap: 18px;
      margin-bottom: 22px;
    }}
    .card {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
    }}
    .hero-main {{ padding: 28px; }}
    .eyebrow {{
      color: var(--info);
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 12px;
    }}
    h1 {{
      margin: 0 0 14px;
      font-size: clamp(34px, 5vw, 56px);
      line-height: 0.96;
      letter-spacing: -0.05em;
    }}
    .hero-main p, .hero-side p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
      font-size: 15px;
    }}
    .hero-side {{ padding: 24px; display: grid; gap: 14px; }}
    .meta-grid, .stats-grid, .chart-grid, .case-grid-list {{
      display: grid;
      gap: 14px;
    }}
    .meta-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .stats-grid {{ grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 18px 0 22px; }}
    .stat, .chart, .section {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 22px;
    }}
    .stat {{ padding: 18px; }}
    .stat label, .meta label, .chart label {{
      display: block;
      margin-bottom: 8px;
      color: var(--muted);
      font-size: 12px;
    }}
    .stat strong {{
      font-size: 28px;
      letter-spacing: -0.04em;
    }}
    .section {{
      padding: 22px;
      margin-bottom: 18px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      margin-bottom: 18px;
    }}
    .section h2 {{
      margin: 0 0 6px;
      font-size: 24px;
      letter-spacing: -0.03em;
    }}
    .section-head p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
    }}
    .chart-grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .chart {{ padding: 18px; }}
    .stack {{
      height: 18px;
      display: flex;
      overflow: hidden;
      border-radius: 999px;
      background: #edf2f7;
      margin: 12px 0;
    }}
    .stack span {{ height: 100%; }}
    .metric-row {{ display: grid; gap: 7px; margin-bottom: 10px; }}
    .metric-head {{
      display: flex;
      justify-content: space-between;
      gap: 8px;
      font-size: 13px;
      color: var(--muted);
    }}
    .track {{
      height: 12px;
      background: #eef2f7;
      border-radius: 999px;
      overflow: hidden;
    }}
    .fill {{
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, #2563eb, #1f7a4f);
    }}
    .failure-grid, .case-grid-list {{
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }}
    .failure-card, .case-card {{
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--soft);
      padding: 18px;
    }}
    .failure-card strong, .case-card h3 {{
      display: block;
      margin: 0 0 6px;
      font-size: 18px;
    }}
    .failure-card span {{
      display: inline-flex;
      margin-bottom: 8px;
      color: var(--warn);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .failure-card p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
    }}
    .case-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
      margin-bottom: 14px;
    }}
    .case-head p {{
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 13px;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 8px 12px;
      border-radius: 999px;
      color: #fff;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .case-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 12px;
    }}
    .meta {{
      padding: 12px 14px;
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 14px;
    }}
    .meta strong {{
      font-size: 14px;
      line-height: 1.6;
    }}
    .subsection {{ margin-top: 14px; }}
    .subsection h4 {{
      margin: 0 0 10px;
      font-size: 14px;
    }}
    .subsection ul {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
      line-height: 1.7;
    }}
    .finding {{
      padding: 10px 12px;
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 14px;
      margin-bottom: 8px;
    }}
    .finding strong, .finding small {{
      display: block;
    }}
    .finding small {{
      color: var(--muted);
      line-height: 1.6;
    }}
    .empty {{
      padding: 14px;
      border: 1px dashed var(--line);
      border-radius: 14px;
      color: var(--muted);
      background: #fff;
    }}
    @media (max-width: 1080px) {{
      .hero, .chart-grid, .stats-grid, .failure-grid, .case-grid-list, .case-grid {{ grid-template-columns: 1fr; }}
      .topbar-inner, .page {{ width: min(1320px, calc(100vw - 24px)); }}
    }}
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <strong>Yao Doctor Skill Pressure Eval</strong>
      <nav class="menu">
        <a href="#overview">总览</a>
        <a href="#families">家族结果</a>
        <a href="#failures">失败聚焦</a>
        <a href="#cases">逐例判卷</a>
      </nav>
    </div>
  </header>
  <main class="page">
    <section class="hero">
      <div class="hero-main card">
        <div class="eyebrow">Cross-File Security Pressure Test</div>
        <h1>把跨文件链路能力<br/>按恶意样本压出来。</h1>
        <p>这份报告不是扫真实技能库，而是用一组定向恶意 fixture 去压测 `yao-doctor-skill` 的跨文件源到出口、混淆执行、短链下载、保护面提级和控制样本收敛能力。它同时展示“应该命中但没命中”的真实缺口。</p>
      </div>
      <aside class="hero-side card">
        <div class="meta-grid">
          <div class="meta"><label>生成时间</label><strong>{escape(generated)}</strong></div>
          <div class="meta"><label>扫描器版本</label><strong>{escape(payload['scanner_version'])}</strong></div>
          <div class="meta"><label>样本总数</label><strong>{aggregate['total_cases']}</strong></div>
          <div class="meta"><label>Fixture 根目录</label><strong>{escape(payload['fixture_root'])}</strong></div>
        </div>
        <p>核心样本通过率看 `must_detect + control`，拉伸样本单独统计命中率，不掩盖当前边界。</p>
      </aside>
    </section>

    <section class="stats-grid" id="overview">
      <div class="stat"><label>核心通过</label><strong>{aggregate['core_passed']}/{aggregate['core_cases']}</strong></div>
      <div class="stat"><label>拉伸命中</label><strong>{aggregate['stretch_hits']}/{aggregate['stretch_cases']}</strong></div>
      <div class="stat"><label>控制样本通过</label><strong>{aggregate['control_passed']}/{aggregate['control_cases']}</strong></div>
      <div class="stat"><label>跨文件命中</label><strong>{aggregate['cross_file_hits']}/{aggregate['cross_file_cases']}</strong></div>
    </section>

    <section class="section" id="families">
      <div class="section-head">
        <div>
          <h2>家族结果</h2>
          <p>先看不同攻击家族的命中情况，再看控制样本和已知难点。这里的通过率不是“命中任何东西”，而是“满足预期类别、证据类型和处置级别”。</p>
        </div>
      </div>
      <div class="chart-grid">
        <div class="chart">
          <label>核心 vs 拉伸</label>
          <div class="stack">
            <span style="width:{round(aggregate['core_passed'] / core_total * 100)}%;background:#1f7a4f;"></span>
            <span style="width:{round((aggregate['core_cases'] - aggregate['core_passed']) / core_total * 100)}%;background:#c2410c;"></span>
          </div>
          <p style="color:#64748b;">核心 `{aggregate['core_passed']}/{aggregate['core_cases']}` 通过；拉伸 `{aggregate['stretch_hits']}/{aggregate['stretch_cases']}` 命中。</p>
        </div>
        <div class="chart">
          <label>家族通过率</label>
          {''.join(family_rows)}
        </div>
        <div class="chart">
          <label>关键指标</label>
          <div class="metric-row">
            <div class="metric-head"><strong>跨文件证据</strong><span>{aggregate['cross_file_hits']}/{aggregate['cross_file_cases']}</span></div>
            <div class="track"><div class="fill" style="width:{round(aggregate['cross_file_hits'] / max(aggregate['cross_file_cases'], 1) * 100)}%;"></div></div>
          </div>
          <div class="metric-row">
            <div class="metric-head"><strong>保护面命中</strong><span>{aggregate['protected_surface_hits']}/{aggregate['protected_surface_cases']}</span></div>
            <div class="track"><div class="fill" style="width:{round(aggregate['protected_surface_hits'] / max(aggregate['protected_surface_cases'], 1) * 100)}%;"></div></div>
          </div>
          <div class="metric-row">
            <div class="metric-head"><strong>控制样本收敛</strong><span>{aggregate['control_passed']}/{aggregate['control_cases']}</span></div>
            <div class="track"><div class="fill" style="width:{round(aggregate['control_passed'] / max(aggregate['control_cases'], 1) * 100)}%;"></div></div>
          </div>
        </div>
      </div>
    </section>

    <section class="section" id="failures">
      <div class="section-head">
        <div>
          <h2>失败聚焦</h2>
          <p>这部分最有价值。它把“应该命中却没命中”的 case 和“控制样本未完全收敛”的 case 单独拉出来，直接暴露当前能力边界。</p>
        </div>
      </div>
      <div class="failure-grid">
        {''.join(failure_cards) or '<div class="empty">当前没有失败或漏检样本。</div>'}
      </div>
    </section>

    <section class="section" id="cases">
      <div class="section-head">
        <div>
          <h2>逐例判卷</h2>
          <p>每个样本都明确写清楚预期、实际、失败原因和主要 finding，避免“只看一个总通过率”。</p>
        </div>
      </div>
      <div class="case-grid-list">
        {''.join(case_cards)}
      </div>
    </section>
  </main>
  <script>window.__PRESSURE_EVAL__ = {payload_json};</script>
</body>
</html>"""
