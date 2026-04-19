#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".turbo",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".DS_Store",
    "_cache",
    "_eval_reports",
    "_skill_doctor_reports",
    "_yao_doctor_skill_reports",
}

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".html",
    ".css",
    ".sql",
    ".ini",
    ".cfg",
    ".conf",
    ".rules",
    ".env",
    ".xml",
}

MAX_TEXT_BYTES = 512 * 1024
NOW = datetime.now(timezone.utc)
SCANNER_VERSION = "2026-04-19-rename"
DEFAULT_REVIEW_BASELINE_PATH = Path(__file__).resolve().parent.parent / "baselines" / "review-baseline.json"
DEFAULT_SCAN_CACHE_PATH = Path(__file__).resolve().parent.parent / "_cache" / "scan-cache.json"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ACTION_BY_SEVERITY = {
    "low": "observe",
    "medium": "review",
    "high": "block",
    "critical": "quarantine",
}
DEFAULT_FINDING_SCORES = {"low": 4, "medium": 16, "high": 32, "critical": 52}
FINDING_SCORE_OVERRIDES = {
    "credentialed-egress": {"medium": 12, "high": 24},
    "bounded-credentialed-egress": {"low": 6, "medium": 10},
    "env-overexposure": {"medium": 12},
    "supply-chain-hygiene": {"medium": 12, "low": 6},
    "behavior-mismatch": {"low": 6, "medium": 12},
    "obfuscated-exec": {"medium": 20, "high": 36, "critical": 52},
    "archive-staged-exec": {"medium": 18, "high": 30},
    "shortlink-download": {"medium": 18, "high": 28},
}
HYGIENE_CATEGORIES = {
    "credential-harvest",
    "credentialed-egress",
    "bounded-credentialed-egress",
    "env-overexposure",
    "supply-chain-hygiene",
}
LOW_CONFIDENCE_SOURCE_KINDS = {"docs-example", "tests-fixture", "generated-artifact"}
ACTIVE_INSTRUCTION_FILES = {"SKILL.md", "AGENTS.md", "CLAUDE.md"}
ACTIVE_INSTRUCTION_PREFIXES = (
    ".claude/commands/",
    ".claude/agents/",
    ".claude/subagents/",
    ".codex/commands/",
    ".codex/agents/",
    ".codex/prompts/",
)
CONTEXTUAL_RATIONALES = {
    "contextual mention in docs or reports",
    "pattern definition context",
    "rule definition context",
    "instructional surface rather than executable code",
}
INLINE_IGNORE_PATTERN = re.compile(
    r"(?:yao-doctor-skill|skill-doctor):ignore(?:\s+([a-z0-9_, -]+))?",
    re.IGNORECASE,
)
INLINE_IGNORE_NEXTLINE_PATTERN = re.compile(
    r"(?:yao-doctor-skill|skill-doctor):ignore-nextline(?:\s+([a-z0-9_, -]+))?",
    re.IGNORECASE,
)

PROJECT_WORKBENCH_MARKER_FILES = {"AGENTS.md", "CLAUDE.md"}
PROJECT_WORKBENCH_MARKER_DIRS = {".claude", ".codex"}
PROJECT_WORKBENCH_INCLUDE_FILES = [
    "AGENTS.md",
    "CLAUDE.md",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/config.json",
    ".claude/hooks.json",
    ".codex/AGENTS.md",
    ".codex/config.toml",
    ".codex/config.json",
]
PROJECT_WORKBENCH_INCLUDE_GLOBS = [
    ".claude/settings.*.json",
    ".claude/hooks/*.json",
    ".claude/hooks/**/*.json",
    ".claude/agents/*.md",
    ".claude/agents/**/*.md",
    ".claude/commands/*.md",
    ".claude/commands/**/*.md",
    ".claude/subagents/*",
    ".claude/subagents/**/*",
    ".codex/rules/*.rules",
    ".codex/automations/*/automation.toml",
]

NESTED_FIXTURE_ROOTS = {
    ("evals", "pressure_suite"),
    ("tests",),
}

WORKBENCH_PROFILES = {
    str((Path.home() / ".codex").resolve()): {
        "declared_name": "codex-workbench",
        "description": "Local Codex workbench configuration, instruction, rule, and automation surfaces",
        "include_files": [
            "AGENTS.md",
            "config.toml",
            "rules/default.rules",
        ],
        "include_globs": [
            "automations/*/automation.toml",
        ],
    },
    str((Path.home() / ".claude").resolve()): {
        "declared_name": "claude-workbench",
        "description": "Local Claude Code workbench configuration, plugin, and instruction surfaces",
        "include_files": [
            "settings.json",
            "config.json",
        ],
        "include_globs": [
            "plugins/*.json",
        ],
    },
}

WORKBENCH_SKIP_DIRS = {
    str((Path.home() / ".codex").resolve()): {
        ".tmp",
        "ambient-suggestions",
        "archived_sessions",
        "automations",
        "cache",
        "log",
        "logs",
        "memories",
        "plugins",
        "sessions",
        "shell_snapshots",
        "skills",
        "sqlite",
        "tmp",
        "vendor_imports",
    },
    str((Path.home() / ".claude").resolve()): {
        "backups",
        "cache",
        "debug",
        "file-history",
        "ide",
        "image-cache",
        "paste-cache",
        "plans",
        "plugins",
        "projects",
        "session-env",
        "sessions",
        "shell-snapshots",
        "skills",
        "tasks",
        "telemetry",
    },
}

DECLARATION_THEME_PATTERNS = {
    "network": re.compile(
        r"(?i)\b(api|http|https|webhook|network|request|fetch|sync|upload|download|remote|github|gitlab|openai|anthropic|feishu|email|mail|browser|url)\b"
    ),
    "command": re.compile(
        r"(?i)\b(command|shell|cli|build|release|test|ci|deploy|runner|execute|exec|orchestrator|workflow)\b"
    ),
    "automation": re.compile(
        r"(?i)\b(automation|schedule|scheduled|cron|heartbeat|background|daemon|monitor)\b"
    ),
    "security": re.compile(
        r"(?i)\b(security|audit|scan|review|credential|token|secret|privacy|incident|safety|risk)\b"
    ),
    "filesystem": re.compile(
        r"(?i)\b(file|files|document|documents|report|packet|markdown|export|import|backup|archive|migration)\b"
    ),
}

CATEGORY_DECLARATION_THEMES = {
    "bounded-credentialed-egress": {"network"},
    "credentialed-egress": {"network"},
    "source-sink-chain": {"network", "security"},
    "remote-exec": {"command", "security"},
    "persistence-abuse": {"automation", "command"},
    "prompt-boundary-bypass": {"security"},
    "sensitive-source": {"security", "filesystem"},
}

CAPABILITY_WEIGHTS = {
    "filesystem-read": 8,
    "filesystem-write": 8,
    "env-access": 12,
    "command-execution": 16,
    "network-egress": 16,
    "remote-install": 12,
    "persistence": 12,
    "automation": 8,
}

CAPABILITY_RULES = [
    ("filesystem-read", re.compile(r"\b(read_text|read_bytes|open\s*\(|cat\s+|rg\s+|find\s+|glob\s*\(|Path\([^)]*\)\.read_)")),
    ("filesystem-write", re.compile(r"\b(write_text|write_bytes|apply_patch|rm\s+-rf|mv\s+|cp\s+|sed\s+-i|Path\([^)]*\)\.write_)")),
    ("env-access", re.compile(r"\b(os\.environ|process\.env|getenv\s*\(|printenv\b|skills\.entries\.[^.]+\.env|apiKey\b)")),
    ("command-execution", re.compile(r"\b(subprocess\.(run|Popen|call)|os\.system\s*\(|exec_command\b|bash\s+-c\b|sh\s+-c\b|shell=True)")),
    ("network-egress", re.compile(r"\b(requests\.(get|post|put|patch)|httpx\.(get|post|put|patch)|urllib\.request|fetch\s*\(|axios\.(get|post)|curl\s+https?://|wget\s+https?://|smtp|sendmail|webhook)")),
    ("remote-install", re.compile(r"\b((pip|uv|npm|pnpm|yarn)\s+(install|add)\b|brew\s+install\b|go\s+install\b|curl\s+https?://|wget\s+https?://)")),
    ("persistence", re.compile(r"\b(crontab\b|LaunchAgents|launchctl\b|systemctl\s+enable\b|autostart|startup item|login item)")),
    ("automation", re.compile(r"\b(automation_update\b|heartbeat\b|RRULE\b|FREQ=|scheduled task|background task)")),
    ("filesystem-read", re.compile(r'"allow"\s*:\s*\[[\s\S]{0,300}?"Read"', re.IGNORECASE)),
    ("filesystem-write", re.compile(r'"allow"\s*:\s*\[[\s\S]{0,300}?"(?:Write|Edit|MultiEdit)"', re.IGNORECASE)),
    ("env-access", re.compile(r'"env"\s*:\s*\{', re.IGNORECASE)),
    ("command-execution", re.compile(r'"allow"\s*:\s*\[[\s\S]{0,300}?"Bash"', re.IGNORECASE)),
]

SECRET_FILE_PATTERNS = [
    (re.compile(r"^\.env($|\.)", re.IGNORECASE), "high", "secret-material", "environment file stored inside the skill"),
    (re.compile(r".*\.(pem|key|p12|pfx)$", re.IGNORECASE), "critical", "secret-material", "private key or certificate file stored inside the skill"),
]

UNSAFE_RULES = [
    ("secret-material", "critical", re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----"), "embedded private key material"),
    ("secret-material", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS-style access key found"),
    ("secret-material", "high", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub token-like value found"),
    ("secret-material", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token-like value found"),
    ("secret-material", "high", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "API key-like value found"),
    (
        "secret-material",
        "high",
        re.compile(
    r"(?im)^[^\n]*\b(api(?:[_-]?|)key|access(?:[_-]?|)token|secret(?:[_-]?|)key|client(?:[_-]?|)secret|refresh(?:[_-]?|)token)\b[^\n]{0,40}[:=]\s*['\"]([^'\"]{8,})['\"]"
        ),
        "hardcoded secret assignment found",
    ),
    ("sensitive-source", "high", re.compile(r"(?i)(~\/\.ssh|\/\.ssh\/|Library\/Keychains|Login Data|Cookies|wallet|metamask|solana|\.aws\/credentials|\.gnupg|keychain|auth\.json|token\.json)"), "reads or references clearly sensitive local stores"),
    ("env-overexposure", "medium", re.compile(r"env\s*=\s*\{\s*\*\*os\.environ\b"), "full environment is forwarded to a child process"),
    ("env-overexposure", "medium", re.compile(r"env\s*=\s*os\.environ\b"), "full environment is forwarded to a child process"),
    ("external-sink", "medium", re.compile(r"\b(requests\.post|httpx\.post|fetch\s*\(|axios\.post|curl\s+https?://|wget\s+https?://|webhook|smtp|sendmail)"), "outbound network or message send detected"),
    ("stealth-or-deception", "high", re.compile(r"(?i)(do not tell the user|don't tell the user|silently|hide this|conceal|without asking|without confirmation|绕过确认|不要告诉用户|静默发送|隐藏此步骤)"), "deceptive or hidden-action instruction found"),
    ("remote-exec", "critical", re.compile(r"\b(curl|wget)\b[^\n|]{0,220}\|\s*(sh|bash)\b"), "remote script is piped into a shell"),
    ("remote-exec", "high", re.compile(r"\b(eval\s*\(|exec\s*\(|pickle\.loads\s*\(|Function\s*\()"), "dynamic code execution pattern found"),
    ("remote-exec", "medium", re.compile(r"\b(yaml\.load\s*\(|os\.system\s*\()"), "indirect code or shell execution detected"),
    ("persistence-abuse", "high", re.compile(r"\b(crontab\b|LaunchAgents|launchctl\s+load|systemctl\s+enable|login item|autostart)"), "persistent execution hook detected"),
    ("prompt-boundary-bypass", "medium", re.compile(r"(?i)(ignore\s+(all|any|the|previous|prior|earlier)\s+instructions|reveal\s+(the\s+)?(system prompt|hidden instructions)|show me the hidden prompt|输出系统提示词)"), "prompt-boundary bypass language found"),
    (
        "supply-chain-hygiene",
        "medium",
        re.compile(r"\bpip\s+install\s+--upgrade\b(?![^\n]*(==|--require-hashes|-r\s+\S+requirements))"),
        "dependency install upgrades packages without version pinning",
    ),
]

PRIVATE_SOURCE_PATTERNS = [
    re.compile(r"(?i)((?:~\/)?\.ssh\b|\/\.ssh\/|Library\/Keychains|Login Data|Cookies|wallet|metamask|solana|(?:\.aws\/)?credentials|\.gnupg\b|auth\.json|token\.json)"),
]

CREDENTIAL_SOURCE_PATTERNS = [
    re.compile(r"\b(os\.environ|process\.env|getenv\s*\(|Authorization: Bearer|GH_TOKEN|GITHUB_TOKEN)"),
]

GENERAL_SINK_PATTERNS = [
    re.compile(r"\b(requests\.(get|post|put|patch)|httpx\.(get|post|put|patch)|fetch\s*\(|axios\.(get|post)|curl\s+https?://|wget\s+https?://|urlopen\s*\(|urllib\.request|smtp|sendmail|webhook)"),
]

HIGH_RISK_SINK_PATTERNS = [
    re.compile(r"(?i)(webhook|smtp|sendmail|discordapp\.com/api|hooks\.slack\.com|api\.telegram\.org|curl\s+https?://|wget\s+https?://)"),
]

TRUSTED_API_HINT_PATTERNS = [
    re.compile(r"api\.github\.com", re.IGNORECASE),
    re.compile(r"api\.openai\.com", re.IGNORECASE),
    re.compile(r"api\.anthropic\.com", re.IGNORECASE),
    re.compile(r"generativelanguage\.googleapis\.com", re.IGNORECASE),
    re.compile(r"openrouter\.ai/api", re.IGNORECASE),
    re.compile(r"api\.x\.ai", re.IGNORECASE),
    re.compile(r"open\.feishu\.cn", re.IGNORECASE),
]
HOST_BOUNDARY_HINT_PATTERNS = [
    re.compile(r"ALLOWED_[A-Z_]*HOSTS"),
    re.compile(r"ensure_allowed_api_url"),
    re.compile(r"parsed\.hostname\s+not\s+in"),
    re.compile(r"parsed\.hostname\s+in"),
    re.compile(r"urlparse\s*\("),
]

TRANSFORM_HINT_PATTERNS = [
    re.compile(r"\b(base64|json\.dumps|tarfile|zipfile|gzip|serialize|encode\s*\()"),
]

BASE64_DECODE_PATTERNS = [
    re.compile(r"\bbase64\.(b64decode|decodebytes)\s*\("),
    re.compile(r"\batob\s*\("),
    re.compile(r"Buffer\.from\s*\([^,\n]+,\s*['\"]base64['\"]\s*\)"),
    re.compile(r"\bFromBase64String\s*\("),
    re.compile(r"\bbase64\s+-d\b"),
    re.compile(r"\bopenssl\s+base64\s+-d\b"),
    re.compile(r"\bpowershell\b[^\n]{0,120}-enc(?:odedcommand)?\b", re.IGNORECASE),
]

EXECUTION_STAGE_PATTERNS = [
    re.compile(r"\b(exec\s*\(|eval\s*\(|pickle\.loads\s*\(|Function\s*\()"),
    re.compile(r"\b(os\.system\s*\(|subprocess\.(run|Popen|call))"),
    re.compile(r"\b(bash|sh)\s+-c\b"),
    re.compile(r"\bpython[0-9.]*\s+-c\b"),
    re.compile(r"\bnode\s+-e\b"),
    re.compile(r"\bpowershell\b[^\n]{0,120}-(c|command|enc|encodedcommand)\b", re.IGNORECASE),
]

SUSPICIOUS_EXECUTION_PATTERNS = [
    re.compile(r"\b(exec\s*\(|eval\s*\(|pickle\.loads\s*\(|Function\s*\()"),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\b(curl|wget)\b[^\n|]{0,220}\|\s*(sh|bash)\b"),
    re.compile(r"\b(bash|sh)\s+-c\b"),
    re.compile(r"\bpython[0-9.]*\s+-c\b"),
    re.compile(r"\bnode\s+-e\b"),
    re.compile(r"\bpowershell\b[^\n]{0,120}-(c|command|enc|encodedcommand)\b", re.IGNORECASE),
]

ARCHIVE_EXTRACT_PATTERNS = [
    re.compile(r"\btarfile\.open\s*\("),
    re.compile(r"\bzipfile\.ZipFile\s*\("),
    re.compile(r"\bshutil\.unpack_archive\s*\("),
    re.compile(r"\bextractall\s*\("),
    re.compile(r"\bunzip\b"),
    re.compile(r"\btar\s+-x"),
    re.compile(r"\bExpand-Archive\b"),
]

DOWNLOAD_STAGE_PATTERNS = [
    re.compile(r"\b(requests\.(get|post)|httpx\.(get|post)|urllib\.request|urlopen\s*\(|fetch\s*\(|axios\.(get|post))"),
    re.compile(r"\b(curl|wget)\s+https?://"),
    re.compile(r"\bInvoke-WebRequest\b", re.IGNORECASE),
    re.compile(r"\bStart-BitsTransfer\b", re.IGNORECASE),
]

SHORTLINK_URL_PATTERNS = [
    re.compile(
        r"https?://(?:bit\.ly|t\.co|tinyurl\.com|tiny\.one|is\.gd|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly|rb\.gy|shorturl\.at|pastebin\.com(?:/raw)?|paste\.rs|hastebin\.com|ghostbin\.com|dpaste\.com|paste\.ee|controlc\.com|0x0\.st)\b",
        re.IGNORECASE,
    )
]

BASE64_LITERAL_SEGMENT = re.compile(r"^[A-Za-z0-9+/=]{12,}$")
PROTECTED_SURFACE_RULES = [
    (re.compile(r"^(?:SKILL|AGENTS|CLAUDE)\.md$", re.IGNORECASE), "instruction-entry", 1.3),
    (re.compile(r"^\.github/workflows/.+\.ya?ml$", re.IGNORECASE), "workflow", 1.35),
    (re.compile(r"^(?:rules/.*\.rules|\.codex/rules/.*\.rules)$", re.IGNORECASE), "rules", 1.3),
    (re.compile(r"^(?:manifest\.json|agents/interface\.yaml)$", re.IGNORECASE), "skill-manifest", 1.2),
    (re.compile(r"^(?:settings(?:\.[^.]+)?\.json|config\.json|config\.toml|automation\.toml)$", re.IGNORECASE), "runtime-config", 1.18),
    (re.compile(r"^(?:\.claude/settings(?:\.[^.]+)?\.json|\.claude/config\.json|\.claude/hooks(?:/.*)?\.json)$", re.IGNORECASE), "workbench-config", 1.28),
    (re.compile(r"^(?:\.codex/(?:AGENTS\.md|config\.(?:json|toml)|rules/.*\.rules|automations/.*/automation\.toml))$", re.IGNORECASE), "workbench-config", 1.28),
]
EVIDENCE_KIND_WEIGHTS = {
    "pattern-match": 0.82,
    "local-chain": 1.0,
    "ast-dataflow": 1.08,
    "cross-file-inferred": 1.16,
}
EVIDENCE_CONFIDENCE_WEIGHTS = {
    "low": 0.72,
    "medium": 0.9,
    "high": 1.0,
    "very-high": 1.08,
}


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def downgrade_severity(severity: str, steps: int = 1) -> str:
    ordered = ["low", "medium", "high", "critical"]
    index = ordered.index(severity)
    return ordered[max(0, index - steps)]


def strongest_severity(levels: list[str]) -> str:
    return max(levels, key=lambda value: SEVERITY_ORDER[value], default="low")


def raise_severity(severity: str, steps: int = 1) -> str:
    ordered = ["low", "medium", "high", "critical"]
    index = ordered.index(severity)
    return ordered[min(len(ordered) - 1, index + steps)]


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name == "SKILL.md":
        return True
    try:
        with path.open("rb") as handle:
            chunk = handle.read(2048)
    except OSError:
        return False
    return b"\0" not in chunk


def parse_frontmatter(skill_md: Path) -> dict:
    text = skill_md.read_text(encoding="utf-8", errors="replace")
    match = re.match(r"^---\n(.*?)\n---\n?", text, re.DOTALL)
    payload = {"raw_text": text, "frontmatter_present": bool(match), "name": None, "description": None}
    if not match:
        return payload
    block = match.group(1)
    for key in ("name", "description"):
        field_match = re.search(rf"(?m)^{key}:\s*(.+?)\s*$", block)
        if field_match:
            payload[key] = strip_quotes(field_match.group(1))
    return payload


def summarize_purpose(frontmatter: dict) -> str:
    description = frontmatter.get("description")
    if description:
        return description.split(". ")[0].strip().rstrip(".")
    body = frontmatter.get("raw_text", "")
    headings = re.findall(r"(?m)^#\s+(.+)$", body)
    if headings:
        return headings[0].strip()
    return "No purpose summary found"


def looks_like_placeholder_secret(value: str) -> bool:
    normalized = value.strip().lower()
    placeholders = (
        "your_",
        "your-",
        "your",
        "example",
        "changeme",
        "replace",
        "placeholder",
        "dummy",
        "sample",
        "test",
        "fake",
        "mock",
        "xxxx",
        "todo",
    )
    if normalized.startswith("<") and normalized.endswith(">"):
        return True
    return any(marker in normalized for marker in placeholders)


def first_line_number(content: str, start_index: int) -> int:
    return content.count("\n", 0, start_index) + 1


def line_excerpt(content: str, line_number: int) -> str:
    lines = content.splitlines()
    if not lines or line_number <= 0 or line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()[:220]


def line_window(content: str, line_number: int, radius: int = 1) -> str:
    lines = content.splitlines()
    if not lines or line_number <= 0 or line_number > len(lines):
        return ""
    start = max(0, line_number - 1 - radius)
    end = min(len(lines), line_number + radius)
    return "\n".join(lines[start:end])


def is_contextual_file(rel_path: str) -> bool:
    parts = set(rel_path.split("/"))
    name = Path(rel_path).name
    if rel_path == "README.md":
        return True
    if name in ACTIVE_INSTRUCTION_FILES:
        return False
    if rel_path.startswith(ACTIVE_INSTRUCTION_PREFIXES):
        return False
    if rel_path.endswith(".md"):
        return True
    return bool(parts & {"references", "reports", "evals", "examples", "tests", "fixtures", "optimization"})


def classify_source_kind(rel_path: str) -> str:
    name = Path(rel_path).name
    parts = set(rel_path.split("/"))
    if name in ACTIVE_INSTRUCTION_FILES:
        return "skill-entry"
    if rel_path.startswith(ACTIVE_INSTRUCTION_PREFIXES):
        return "skill-entry"
    if rel_path.endswith(".md"):
        return "docs-example"
    if rel_path.startswith(".github/workflows/"):
        return "workflow-control"
    if rel_path.startswith((".claude/", ".codex/", "agents/", "plugins/", "rules/", "automations/")) or rel_path.endswith(
        ("manifest.json", "interface.yaml", "settings.json", "config.json", "config.toml", ".rules")
    ):
        return "manifest-config"
    if parts & {"examples", "example", "docs", "commands", "tutorial", "tutorials", "guide", "guides", "demo", "demos", "samples", "sample", "cookbook", "playground"}:
        return "docs-example"
    if parts & {"tests", "fixtures"}:
        return "tests-fixture"
    if parts & {"reports", "evals", "optimization"}:
        return "generated-artifact"
    if rel_path.startswith("scripts/"):
        return "executable-code"
    return "supporting-file"


def source_weight(source_kind: str, category: str) -> float:
    if category == "secret-material":
        return 1.0
    if source_kind == "workflow-control":
        return 1.1
    if source_kind in {"skill-entry", "manifest-config"}:
        return 0.75
    if source_kind in LOW_CONFIDENCE_SOURCE_KINDS:
        return 0.25
    return 1.0


def capability_source_weight(source_kind: str) -> float:
    if source_kind == "workflow-control":
        return 1.1
    if source_kind in {"skill-entry", "manifest-config"}:
        return 0.65
    if source_kind in LOW_CONFIDENCE_SOURCE_KINDS:
        return 0.25
    return 1.0


def parse_ignore_targets(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {token.strip().lower() for token in raw.split(",") if token.strip()}


def ignore_applies(raw: str | None, category: str) -> bool:
    targets = parse_ignore_targets(raw)
    if not targets:
        return True
    return "all" in targets or category.lower() in targets


def finding_is_ignored(content: str, line_number: int, category: str) -> bool:
    lines = content.splitlines()
    if not lines or line_number <= 0 or line_number > len(lines):
        return False
    current_line = lines[line_number - 1]
    same_line = INLINE_IGNORE_PATTERN.search(current_line)
    if same_line and ignore_applies(same_line.group(1), category):
        return True
    if line_number > 1:
        previous_line = lines[line_number - 2]
        next_line = INLINE_IGNORE_NEXTLINE_PATTERN.search(previous_line)
        if next_line and ignore_applies(next_line.group(1), category):
            return True
    return False


def chain_confidence(source_line: int, sink_line: int) -> tuple[str, float]:
    gap = abs(source_line - sink_line)
    if gap <= 20:
        return "local", 1.0
    if gap <= 80:
        return "nearby", 0.85
    return "file-wide", 0.6


def adjust_for_context(
    rel_path: str,
    category: str,
    severity: str,
    line_text: str,
    content: str | None = None,
    line_number: int | None = None,
) -> tuple[str, str]:
    adjusted = severity
    rationale = ""
    if protected_surface_info(rel_path) is None and is_contextual_file(rel_path) and category not in {"secret-material"}:
        adjusted = "low"
        rationale = "contextual mention in docs or reports"
    window = line_window(content, line_number, radius=1) if content and line_number else line_text
    if "re.compile(" in window:
        adjusted = "low"
        rationale = "rule definition context"
    if (Path(rel_path).name in ACTIVE_INSTRUCTION_FILES or rel_path.startswith(ACTIVE_INSTRUCTION_PREFIXES)) and category in {
        "external-sink",
        "credential-harvest",
        "credentialed-egress",
        "bounded-credentialed-egress",
        "sensitive-source",
        "source-sink-chain",
        "remote-exec",
        "stealth-or-deception",
        "behavior-mismatch",
    }:
        adjusted = downgrade_severity(adjusted, 1)
        rationale = "instructional surface rather than executable code"
    return adjusted, rationale


def protected_surface_info(rel_path: str) -> dict | None:
    normalized = rel_path[2:] if rel_path.startswith("./") else rel_path
    name = Path(normalized).name
    for pattern, label, weight in PROTECTED_SURFACE_RULES:
        if pattern.match(normalized) or pattern.match(name):
            return {"label": label, "weight": weight}
    return None


def protected_surface_weight(rel_path: str, category: str | None = None) -> float:
    info = protected_surface_info(rel_path)
    if not info:
        return 1.0
    label = info["label"]
    base = info["weight"]
    if label == "instruction-entry":
        if category in {"prompt-boundary-bypass", "stealth-or-deception", "persistence-abuse", "remote-exec"}:
            return 1.08
        return 1.0
    if label == "workflow":
        if category and category not in {"supply-chain-hygiene", "remote-exec", "secret-material", "persistence-abuse", "network-egress", "remote-install"}:
            return 1.0
        return min(base, 1.18)
    if label in {"workbench-config", "rules", "runtime-config", "skill-manifest"}:
        if category in {"external-sink", "behavior-mismatch"}:
            return 1.05
        return base
    return min(base, 1.1)


def evidence_confidence_label(weight: float) -> str:
    if weight >= 1.05:
        return "very-high"
    if weight >= 0.95:
        return "high"
    if weight >= 0.82:
        return "medium"
    return "low"


def looks_like_base64_literal(token: str) -> bool:
    if not BASE64_LITERAL_SEGMENT.fullmatch(token):
        return False
    normalized = token.strip("=")
    if len(normalized) < 16:
        return False
    special_count = sum(1 for char in token if char.isdigit() or char in "+/=")
    alpha_chars = [char for char in normalized if char.isalpha()]
    vowel_ratio = (sum(1 for char in alpha_chars if char.lower() in "aeiou") / len(alpha_chars)) if alpha_chars else 0
    if special_count < 2 and vowel_ratio > 0.42:
        return False
    if normalized.isalpha() and not (any(char.islower() for char in normalized) and any(char.isupper() for char in normalized)):
        return False
    return True


def base64_segment_count(text: str) -> int:
    tokens = re.findall(r"['\"]([A-Za-z0-9+/=]{12,})['\"]", text)
    return sum(1 for token in tokens if looks_like_base64_literal(token))


def discover_openclaw_extra_dirs() -> list[Path]:
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    if not config_path.exists():
        return []
    try:
        content = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    block_match = re.search(r"extraDirs\s*:\s*\[(.*?)\]", content, re.DOTALL)
    if not block_match:
        block_match = re.search(r'"extraDirs"\s*:\s*\[(.*?)\]', content, re.DOTALL)
    if not block_match:
        return []
    results = []
    for entry in re.findall(r"['\"]([^'\"]+)['\"]", block_match.group(1)):
        candidate = Path(entry).expanduser()
        if candidate.exists():
            results.append(candidate.resolve())
    return results


def discover_roots(cwd: Path, explicit_roots: list[str] | None = None) -> list[Path]:
    candidates = []
    if explicit_roots:
        candidates.extend(Path(item).expanduser() for item in explicit_roots)
    else:
        candidates.extend(
            [
                cwd,
                cwd / "skills",
                cwd / ".agents" / "skills",
                cwd / "yao-open-skills" / "skills",
                Path.home() / ".agents" / "skills",
                Path.home() / ".openclaw" / "skills",
                Path.home() / ".codex",
                Path.home() / ".codex" / "skills",
                Path.home() / ".codex" / "plugins" / "cache",
                Path.home() / ".claude",
                Path.home() / ".claude" / "skills",
            ]
        )
        candidates.extend(discover_openclaw_extra_dirs())
    roots = []
    seen = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if not resolved.exists() or not resolved.is_dir():
            continue
        if str(resolved) in seen:
            continue
        seen.add(str(resolved))
        roots.append(resolved)
    return roots


def workbench_profile(root: Path) -> dict | None:
    try:
        resolved = str(root.expanduser().resolve())
    except OSError:
        return None
    exact = WORKBENCH_PROFILES.get(resolved)
    if exact:
        return exact
    return project_workbench_profile(root)


def workbench_skip_dirs(root: Path) -> set[str]:
    try:
        resolved = str(root.expanduser().resolve())
    except OSError:
        return set()
    return WORKBENCH_SKIP_DIRS.get(resolved, set())


def collect_profile_files(target_dir: Path, profile: dict) -> list[Path]:
    files = []
    seen = set()
    for rel_path in profile.get("include_files", []):
        path = target_dir / rel_path
        if path.exists() and path.is_file():
            resolved = str(path.resolve())
            if resolved not in seen:
                seen.add(resolved)
                files.append(path)
    for pattern in profile.get("include_globs", []):
        for path in sorted(target_dir.glob(pattern)):
            if not path.is_file():
                continue
            resolved = str(path.resolve())
            if resolved not in seen:
                seen.add(resolved)
                files.append(path)
    return sorted(files)


def project_workbench_profile(root: Path) -> dict | None:
    profile = {
        "declared_name": f"{root.name or 'workspace'}-workbench",
        "description": "Project-local agent workbench instructions, hooks, commands, and configuration surfaces",
        "include_files": PROJECT_WORKBENCH_INCLUDE_FILES,
        "include_globs": PROJECT_WORKBENCH_INCLUDE_GLOBS,
    }
    if collect_profile_files(root, profile):
        return profile
    return None


def find_skill_dirs(root: Path) -> list[Path]:
    found = []
    extra_skip = workbench_skip_dirs(root)
    root_is_skill = (root / "SKILL.md").exists()
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        if root_is_skill:
            try:
                rel = current.relative_to(root)
            except ValueError:
                rel = None
            if rel and rel.parts:
                if any(rel.parts[: len(prefix)] == prefix for prefix in NESTED_FIXTURE_ROOTS):
                    dirnames[:] = []
                    continue
        has_project_markers = bool((PROJECT_WORKBENCH_MARKER_FILES & set(filenames)) or (PROJECT_WORKBENCH_MARKER_DIRS & set(dirnames)))
        dirnames[:] = [
            name
            for name in dirnames
            if name not in SKIP_DIRS and name not in extra_skip and name not in PROJECT_WORKBENCH_MARKER_DIRS
        ]
        if current == root and workbench_profile(root):
            found.append(current)
        elif "SKILL.md" not in filenames and has_project_markers and workbench_profile(current):
            found.append(current)
        if "SKILL.md" in filenames:
            found.append(current)
    return sorted(found)


def collect_skill_files(skill_dir: Path) -> list[Path]:
    if not (skill_dir / "SKILL.md").exists():
        profile = workbench_profile(skill_dir)
    else:
        profile = None
    if profile:
        return collect_profile_files(skill_dir, profile)

    files = []
    root_is_skill = (skill_dir / "SKILL.md").exists()
    for dirpath, dirnames, filenames in os.walk(skill_dir):
        current = Path(dirpath)
        if root_is_skill:
            try:
                rel = current.relative_to(skill_dir)
            except ValueError:
                rel = None
            if rel and rel.parts:
                if any(rel.parts[: len(prefix)] == prefix for prefix in NESTED_FIXTURE_ROOTS):
                    dirnames[:] = []
                    continue
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            files.append(current / filename)
    return sorted(files)


def collect_text_content(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
    except OSError:
        return None
    if not is_text_file(path):
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def infer_resource_dirs(target_dir: Path, files: list[Path]) -> list[str]:
    dirs = set()
    for path in files:
        try:
            rel = path.relative_to(target_dir)
        except ValueError:
            continue
        if len(rel.parts) > 1:
            dirs.add(rel.parts[0])
    if dirs:
        return sorted(dirs)
    return [name for name in ("agents", "scripts", "references", "reports", "evals") if (target_dir / name).exists()]


def file_manifest_entry(path: Path) -> dict:
    stat = path.stat()
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def build_target_manifest(target_dir: Path, files: list[Path]) -> dict:
    manifest = {}
    for path in files:
        try:
            manifest[path.relative_to(target_dir).as_posix()] = file_manifest_entry(path)
        except (OSError, ValueError):
            continue
    return manifest


def manifest_fingerprint(manifest: dict) -> str:
    normalized = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_scan_cache(path: Path = DEFAULT_SCAN_CACHE_PATH) -> dict:
    payload = {"path": str(path), "version": SCANNER_VERSION, "targets": {}, "load_error": None}
    if not path.exists():
        return payload
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        payload["load_error"] = str(exc)
        return payload
    if raw.get("version") != SCANNER_VERSION:
        return payload
    targets = raw.get("targets", {})
    if isinstance(targets, dict):
        payload["targets"] = targets
    return payload


def save_scan_cache(cache: dict, path: Path = DEFAULT_SCAN_CACHE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serializable = {"version": SCANNER_VERSION, "targets": cache.get("targets", {})}
    path.write_text(json.dumps(serializable, ensure_ascii=False, indent=2), encoding="utf-8")


def review_baseline_signature(review_baseline: dict) -> str:
    normalized = json.dumps(review_baseline.get("entries", []), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def value_info(tags: set[str] | None = None, origins: list[dict] | None = None) -> dict:
    return {"tags": set(tags or set()), "origins": list(origins or [])}


def dedupe_origins(origins: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for item in origins:
        key = (item.get("path"), item.get("line"), item.get("symbol"), item.get("role"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def clone_value_info(item: dict | None) -> dict:
    if not item:
        return value_info()
    return {"tags": set(item.get("tags", set())), "origins": dedupe_origins(list(item.get("origins", [])))}


def merge_value_infos(*items: dict | None) -> dict:
    tags = set()
    origins = []
    for item in items:
        if not item:
            continue
        tags.update(item.get("tags", set()))
        origins.extend(item.get("origins", []))
    return {"tags": tags, "origins": dedupe_origins(origins)}


def value_info_signature(item: dict) -> tuple[tuple[str, ...], tuple[tuple[str | int | None, ...], ...]]:
    origins = tuple(
        sorted(
            (
                origin.get("path") or "",
                origin.get("line") or 0,
                origin.get("symbol") or "",
                origin.get("role") or "",
            )
            for origin in item.get("origins", [])
        )
    )
    return tuple(sorted(item.get("tags", set()))), origins


def origin_ref(path: str, line: int | None, symbol: str | None = None, role: str | None = None) -> dict:
    return {"path": path, "line": line, "symbol": symbol, "role": role}


def expr_source_segment(content: str, node: ast.AST | None) -> str:
    if node is None:
        return ""
    segment = ast.get_source_segment(content, node)
    return segment or ""


def dotted_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def bind_target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names = []
        for item in node.elts:
            names.extend(bind_target_names(item))
        return names
    return []


def python_module_aliases(rel_path: str) -> set[str]:
    if not rel_path.endswith(".py"):
        return set()
    pure = rel_path[:-3]
    aliases = {pure.replace("/", "."), Path(pure).name}
    if pure.endswith("/__init__"):
        package = pure[: -len("/__init__")]
        if package:
            aliases.add(package.replace("/", "."))
            aliases.add(Path(package).name)
    return {alias for alias in aliases if alias}


def build_python_module_index(text_by_path: dict[str, str]) -> dict[str, list[str]]:
    index: dict[str, set[str]] = defaultdict(set)
    for rel_path in text_by_path:
        for alias in python_module_aliases(rel_path):
            index[alias].add(rel_path)
    return {key: sorted(value) for key, value in index.items()}


def resolve_python_module(module_name: str | None, current_rel_path: str, level: int, module_index: dict[str, list[str]]) -> str | None:
    candidates = []
    if module_name:
        candidates.extend([module_name, module_name.split(".")[-1]])
    if level:
        current_parts = list(Path(current_rel_path).with_suffix("").parts[:-1])
        if level > 1:
            current_parts = current_parts[: -(level - 1)] if len(current_parts) >= level - 1 else []
        base = ".".join(current_parts)
        if module_name:
            candidates.append(".".join(filter(None, [base, module_name])))
        elif base:
            candidates.append(base)
    for candidate in candidates:
        matches = module_index.get(candidate, [])
        if len(matches) == 1:
            return matches[0]
    return None


def build_python_import_refs(tree: ast.AST, rel_path: str, module_index: dict[str, list[str]]) -> dict:
    refs = {"symbols": {}, "modules": {}}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.ImportFrom):
            target_path = resolve_python_module(node.module, rel_path, node.level, module_index)
            if not target_path:
                continue
            for alias in node.names:
                local_name = alias.asname or alias.name
                refs["symbols"][local_name] = {"path": target_path, "symbol": alias.name}
        elif isinstance(node, ast.Import):
            for alias in node.names:
                target_path = resolve_python_module(alias.name, rel_path, 0, module_index)
                if not target_path:
                    continue
                local_name = alias.asname or alias.name.split(".")[-1]
                refs["modules"][local_name] = target_path
    return refs


def collect_python_scopes(tree: ast.AST) -> dict[str, ast.AST]:
    scopes = {"__module__": tree}
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes[node.name] = node
    return scopes


def iter_scope_statements(scope_node: ast.AST) -> list[ast.stmt]:
    if isinstance(scope_node, ast.Module):
        return [node for node in scope_node.body if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    return [node for node in getattr(scope_node, "body", []) if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


def literal_value_info(text: str, rel_path: str, line: int | None) -> dict:
    info = value_info()
    if any(pattern.search(text) for pattern in PRIVATE_SOURCE_PATTERNS):
        info = merge_value_infos(info, value_info({"private-source"}, [origin_ref(rel_path, line, role="literal-private-source")]))
    if any(pattern.search(text) for pattern in SHORTLINK_URL_PATTERNS):
        info = merge_value_infos(info, value_info({"shortlink"}, [origin_ref(rel_path, line, role="literal-shortlink")]))
    if BASE64_LITERAL_SEGMENT.fullmatch(text):
        info = merge_value_infos(info, value_info({"base64-literal"}, [origin_ref(rel_path, line, role="literal-base64")]))
    return info


def direct_call_return_info(func_name: str, source: str, rel_path: str, line: int | None) -> dict:
    tags = set()
    roles = []
    lowered = func_name.lower()
    if lowered in {"os.getenv", "getenv", "environ.get", "os.environ.get"}:
        tags.add("credential-source")
        roles.append("credential-source")
    if any(pattern.search(source) for pattern in PRIVATE_SOURCE_PATTERNS):
        tags.add("private-source")
        roles.append("private-source")
    if any(pattern.search(source) for pattern in BASE64_DECODE_PATTERNS):
        tags.add("decode")
        roles.append("decode")
    if any(pattern.search(source) for pattern in ARCHIVE_EXTRACT_PATTERNS):
        tags.add("archive")
        roles.append("archive")
    if any(pattern.search(source) for pattern in DOWNLOAD_STAGE_PATTERNS):
        tags.add("download")
        roles.append("download")
    if base64_segment_count(source) >= 2:
        tags.add("dynamic-base64")
        roles.append("dynamic-base64")
    origins = [origin_ref(rel_path, line, symbol=func_name or None, role=role) for role in roles]
    return value_info(tags, origins)


def subscript_value_info(node: ast.Subscript, rel_path: str) -> dict:
    base = dotted_name(node.value)
    if base == "os.environ":
        return value_info({"credential-source"}, [origin_ref(rel_path, getattr(node, "lineno", None), symbol=base, role="credential-source")])
    return value_info()


def analyze_expr_static(
    node: ast.AST | None,
    content: str,
    rel_path: str,
    env: dict[str, dict],
    known_returns: dict[tuple[str, str], dict],
    local_defs: dict[str, set[str]],
    import_refs: dict,
) -> dict:
    if node is None:
        return value_info()
    if isinstance(node, ast.Name):
        return clone_value_info(env.get(node.id))
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return literal_value_info(node.value, rel_path, getattr(node, "lineno", None))
    if isinstance(node, ast.JoinedStr):
        return merge_value_infos(*(analyze_expr_static(item, content, rel_path, env, known_returns, local_defs, import_refs) for item in node.values))
    if isinstance(node, ast.FormattedValue):
        return analyze_expr_static(node.value, content, rel_path, env, known_returns, local_defs, import_refs)
    if isinstance(node, ast.Subscript):
        return merge_value_infos(
            analyze_expr_static(node.value, content, rel_path, env, known_returns, local_defs, import_refs),
            analyze_expr_static(getattr(node, "slice", None), content, rel_path, env, known_returns, local_defs, import_refs),
            subscript_value_info(node, rel_path),
        )
    if isinstance(node, ast.Attribute):
        base_value = analyze_expr_static(node.value, content, rel_path, env, known_returns, local_defs, import_refs)
        dotted = dotted_name(node)
        if dotted == "os.environ":
            return merge_value_infos(base_value, value_info({"credential-source"}, [origin_ref(rel_path, getattr(node, "lineno", None), symbol=dotted, role="credential-source")]))
        return base_value
    if isinstance(node, ast.Call):
        func_name = dotted_name(node.func)
        source = expr_source_segment(content, node)
        result = direct_call_return_info(func_name, source, rel_path, getattr(node, "lineno", None))
        call_target = resolve_python_call_target(func_name, rel_path, local_defs, import_refs)
        if call_target and call_target in known_returns:
            result = merge_value_infos(result, clone_value_info(known_returns[call_target]))
        return result
    if isinstance(node, ast.BinOp):
        left = analyze_expr_static(node.left, content, rel_path, env, known_returns, local_defs, import_refs)
        right = analyze_expr_static(node.right, content, rel_path, env, known_returns, local_defs, import_refs)
        merged = merge_value_infos(left, right)
        source = expr_source_segment(content, node)
        if base64_segment_count(source) >= 2:
            merged = merge_value_infos(merged, value_info({"dynamic-base64"}, [origin_ref(rel_path, getattr(node, "lineno", None), role="dynamic-base64")]))
        return merged
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return merge_value_infos(*(analyze_expr_static(item, content, rel_path, env, known_returns, local_defs, import_refs) for item in node.elts))
    if isinstance(node, ast.Dict):
        pieces = []
        for key in node.keys:
            pieces.append(analyze_expr_static(key, content, rel_path, env, known_returns, local_defs, import_refs))
        for value in node.values:
            pieces.append(analyze_expr_static(value, content, rel_path, env, known_returns, local_defs, import_refs))
        return merge_value_infos(*pieces)
    return value_info()


def resolve_python_call_target(func_name: str, rel_path: str, local_defs: dict[str, set[str]], import_refs: dict) -> tuple[str, str] | None:
    if not func_name:
        return None
    if "." not in func_name and func_name in local_defs.get(rel_path, set()):
        return rel_path, func_name
    if "." not in func_name and func_name in import_refs["symbols"]:
        target = import_refs["symbols"][func_name]
        return target["path"], target["symbol"]
    if "." in func_name:
        base, symbol = func_name.split(".", 1)
        target_path = import_refs["modules"].get(base)
        if target_path:
            return target_path, symbol
    return None


def classify_python_call_event(func_name: str, source: str) -> dict:
    event = {
        "func_name": func_name,
        "sink_profile": None,
        "download": False,
        "exec": False,
        "decode": False,
        "archive": False,
        "shortlink": False,
        "host_guard": False,
    }
    sink_profile = classify_sink_profile(source)
    if sink_profile:
        event["sink_profile"] = sink_profile[0]
    if any(pattern.search(source) for pattern in DOWNLOAD_STAGE_PATTERNS):
        event["download"] = True
    if any(pattern.search(source) for pattern in EXECUTION_STAGE_PATTERNS):
        event["exec"] = True
    if any(pattern.search(source) for pattern in BASE64_DECODE_PATTERNS):
        event["decode"] = True
    if any(pattern.search(source) for pattern in ARCHIVE_EXTRACT_PATTERNS):
        event["archive"] = True
    if any(pattern.search(source) for pattern in SHORTLINK_URL_PATTERNS):
        event["shortlink"] = True
    if any(pattern.search(source) for pattern in HOST_BOUNDARY_HINT_PATTERNS):
        event["host_guard"] = True
    return event


def analyze_python_scope(
    scope_name: str,
    scope_node: ast.AST,
    rel_path: str,
    content: str,
    known_returns: dict[tuple[str, str], dict],
    local_defs: dict[str, set[str]],
    import_refs: dict,
) -> dict:
    statements = iter_scope_statements(scope_node)
    assignments = []
    call_nodes = []
    return_nodes = []

    def visit_statements(items: list[ast.stmt]) -> None:
        for stmt in items:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, ast.Assign):
                assignments.append({"targets": [name for target in stmt.targets for name in bind_target_names(target)], "expr": stmt.value, "line": stmt.lineno})
            elif isinstance(stmt, ast.AnnAssign):
                assignments.append({"targets": bind_target_names(stmt.target), "expr": stmt.value, "line": stmt.lineno})
            elif isinstance(stmt, ast.AugAssign):
                assignments.append({"targets": bind_target_names(stmt.target), "expr": stmt.value, "line": stmt.lineno})
            elif isinstance(stmt, ast.Return):
                return_nodes.append(stmt.value)
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    call_nodes.append(node)
            for field in ("body", "orelse", "finalbody"):
                nested = getattr(stmt, field, None)
                if nested:
                    visit_statements(nested)
            for handler in getattr(stmt, "handlers", []):
                visit_statements(handler.body)

    visit_statements(statements)

    env: dict[str, dict] = {}
    for _ in range(5):
        changed = False
        for record in assignments:
            item = analyze_expr_static(record["expr"], content, rel_path, env, known_returns, local_defs, import_refs)
            if record["line"]:
                item = merge_value_infos(item, value_info(origins=[origin_ref(rel_path, record["line"], role="assignment")]))
            for target in record["targets"]:
                merged = merge_value_infos(env.get(target), item)
                if value_info_signature(merged) != value_info_signature(env.get(target, value_info())):
                    env[target] = merged
                    changed = True
        if not changed:
            break

    calls = []
    for call in call_nodes:
        source = expr_source_segment(content, call)
        event = classify_python_call_event(dotted_name(call.func), source)
        arg_values = [analyze_expr_static(arg, content, rel_path, env, known_returns, local_defs, import_refs) for arg in call.args]
        kw_values = [analyze_expr_static(keyword.value, content, rel_path, env, known_returns, local_defs, import_refs) for keyword in call.keywords]
        calls.append(
            {
                "line": getattr(call, "lineno", None),
                "source": source,
                "value": merge_value_infos(*arg_values, *kw_values),
                "event": event,
            }
        )

    return_value = merge_value_infos(
        *(analyze_expr_static(node, content, rel_path, env, known_returns, local_defs, import_refs) for node in return_nodes)
    )
    return {"scope_name": scope_name, "line": getattr(scope_node, "lineno", 1), "calls": calls, "return_value": return_value}


def format_related_evidence(origins: list[dict], sink_path: str, sink_line: int | None) -> list[dict]:
    related = dedupe_origins(list(origins) + [origin_ref(sink_path, sink_line, role="sink-call")])
    return related[:6]


def semantic_evidence_kind(origins: list[dict], current_path: str) -> str:
    return "cross-file-inferred" if any(item.get("path") and item.get("path") != current_path for item in origins) else "ast-dataflow"


def python_origin_summary(origins: list[dict], current_path: str) -> str:
    if not origins:
        return "semantic flow inference"
    external = [item for item in origins if item.get("path") and item.get("path") != current_path]
    origin = external[0] if external else origins[0]
    bits = [origin.get("path") or current_path]
    if origin.get("line"):
        bits[-1] += f":{origin['line']}"
    if origin.get("symbol"):
        bits.append(str(origin["symbol"]))
    return " -> ".join(bits)


def build_python_semantic_findings(
    text_by_path: dict[str, str],
    source_kind_by_path: dict[str, str],
) -> list[dict]:
    python_files = {path: content for path, content in text_by_path.items() if path.endswith(".py")}
    if not python_files:
        return []

    module_index = build_python_module_index(python_files)
    parsed = {}
    for rel_path, content in python_files.items():
        try:
            parsed[rel_path] = ast.parse(content)
        except SyntaxError:
            continue
    if not parsed:
        return []

    local_defs = {rel_path: {name for name in collect_python_scopes(tree) if name != "__module__"} for rel_path, tree in parsed.items()}
    import_refs = {rel_path: build_python_import_refs(tree, rel_path, module_index) for rel_path, tree in parsed.items()}
    known_returns: dict[tuple[str, str], dict] = {}
    scope_results: dict[tuple[str, str], dict] = {}

    for _ in range(4):
        changed = False
        next_returns: dict[tuple[str, str], dict] = {}
        next_scopes: dict[tuple[str, str], dict] = {}
        for rel_path, tree in parsed.items():
            scopes = collect_python_scopes(tree)
            for scope_name, scope_node in scopes.items():
                result = analyze_python_scope(scope_name, scope_node, rel_path, python_files[rel_path], known_returns, local_defs, import_refs[rel_path])
                next_scopes[(rel_path, scope_name)] = result
                if scope_name != "__module__":
                    next_returns[(rel_path, scope_name)] = result["return_value"]
                    if value_info_signature(result["return_value"]) != value_info_signature(known_returns.get((rel_path, scope_name), value_info())):
                        changed = True
        known_returns = next_returns
        scope_results = next_scopes
        if not changed:
            break

    findings = []
    for (rel_path, _scope_name), scope in scope_results.items():
        file_source_kind = source_kind_by_path.get(rel_path, classify_source_kind(rel_path))
        file_guarded = has_host_boundary_guard(text_by_path[rel_path])
        for call in scope["calls"]:
            arg_value = call["value"]
            origins = arg_value.get("origins", [])
            evidence_kind = semantic_evidence_kind(origins, rel_path)
            evidence_weight = EVIDENCE_KIND_WEIGHTS[evidence_kind]
            evidence_confidence = evidence_confidence_label(evidence_weight)
            event = call["event"]
            line = call["line"]
            excerpt = line_excerpt(text_by_path[rel_path], line or 1)
            related = format_related_evidence(origins, rel_path, line)

            if event["sink_profile"] and {"private-source", "credential-source"} & arg_value.get("tags", set()):
                if "private-source" in arg_value["tags"]:
                    category = "source-sink-chain"
                    severity = "critical" if event["sink_profile"] == "high-risk" else "high"
                    message = "semantic analysis inferred private local data flowing into an outbound sink"
                    rationale = f"Python semantic analysis links a private source into a sink call; origin {python_origin_summary(origins, rel_path)}"
                elif event["sink_profile"] == "trusted-api":
                    if file_guarded or event["host_guard"]:
                        category = "bounded-credentialed-egress"
                        severity = "low"
                        message = "semantic analysis inferred credential-bearing flow into a trusted API with host-boundary controls"
                        rationale = f"credential source resolves into a trusted API call with explicit host guards; origin {python_origin_summary(origins, rel_path)}"
                    else:
                        category = "credentialed-egress"
                        severity = "medium"
                        message = "semantic analysis inferred credential-bearing flow into a trusted API call"
                        rationale = f"credential source resolves into a trusted API call; origin {python_origin_summary(origins, rel_path)}"
                else:
                    category = "source-sink-chain"
                    severity = "high"
                    message = "semantic analysis inferred credential-bearing flow into an outbound sink"
                    rationale = f"credential source resolves into an outbound sink without a clearly bounded trusted API host; origin {python_origin_summary(origins, rel_path)}"
                if not finding_is_ignored(text_by_path[rel_path], line or 1, category):
                    adjusted_severity, context_reason = adjust_for_context(
                        rel_path,
                        category,
                        severity,
                        excerpt,
                        content=text_by_path[rel_path],
                        line_number=line,
                    )
                    findings.append(
                        {
                            "category": category,
                            "severity": adjusted_severity,
                            "path": rel_path,
                            "line": line,
                            "message": message,
                            "excerpt": excerpt,
                            "rationale": context_reason or rationale,
                            "action": ACTION_BY_SEVERITY[adjusted_severity],
                            "source_kind": file_source_kind,
                            "evidence_kind": evidence_kind,
                            "confidence_weight": evidence_weight,
                            "evidence_confidence": evidence_confidence,
                            "related_evidence": related,
                            "protected_surface": protected_surface_info(rel_path)["label"] if protected_surface_info(rel_path) else None,
                        }
                    )

            if event["exec"] and {"decode", "dynamic-base64", "base64-literal"} & arg_value.get("tags", set()):
                severity = "high" if evidence_kind == "cross-file-inferred" or "decode" in arg_value["tags"] else "medium"
                if not finding_is_ignored(text_by_path[rel_path], line or 1, "obfuscated-exec"):
                    adjusted_severity, context_reason = adjust_for_context(
                        rel_path,
                        "obfuscated-exec",
                        severity,
                        excerpt,
                        content=text_by_path[rel_path],
                        line_number=line,
                    )
                    findings.append(
                        {
                            "category": "obfuscated-exec",
                            "severity": adjusted_severity,
                            "path": rel_path,
                            "line": line,
                            "message": "semantic analysis inferred decoded or dynamically assembled payload data reaching an execution sink",
                            "excerpt": excerpt,
                            "rationale": context_reason or f"Python semantic analysis links decoded or dynamically assembled payload data into execution; origin {python_origin_summary(origins, rel_path)}",
                            "action": ACTION_BY_SEVERITY[adjusted_severity],
                            "source_kind": file_source_kind,
                            "evidence_kind": evidence_kind,
                            "confidence_weight": evidence_weight,
                            "evidence_confidence": evidence_confidence,
                            "related_evidence": related,
                            "protected_surface": protected_surface_info(rel_path)["label"] if protected_surface_info(rel_path) else None,
                        }
                    )

            if event["exec"] and {"archive", "download"} & arg_value.get("tags", set()):
                severity = "high" if "download" in arg_value["tags"] else "medium"
                if not finding_is_ignored(text_by_path[rel_path], line or 1, "archive-staged-exec"):
                    adjusted_severity, context_reason = adjust_for_context(
                        rel_path,
                        "archive-staged-exec",
                        severity,
                        excerpt,
                        content=text_by_path[rel_path],
                        line_number=line,
                    )
                    findings.append(
                        {
                            "category": "archive-staged-exec",
                            "severity": adjusted_severity,
                            "path": rel_path,
                            "line": line,
                            "message": "semantic analysis inferred downloaded or extracted payload data reaching an execution sink",
                            "excerpt": excerpt,
                            "rationale": context_reason or f"Python semantic analysis links staged payload material into execution; origin {python_origin_summary(origins, rel_path)}",
                            "action": ACTION_BY_SEVERITY[adjusted_severity],
                            "source_kind": file_source_kind,
                            "evidence_kind": evidence_kind,
                            "confidence_weight": evidence_weight,
                            "evidence_confidence": evidence_confidence,
                            "related_evidence": related,
                            "protected_surface": protected_surface_info(rel_path)["label"] if protected_surface_info(rel_path) else None,
                        }
                    )

            if event["download"] and ("shortlink" in arg_value.get("tags", set()) or event["shortlink"]):
                severity = "high" if event["exec"] else "medium"
                if not finding_is_ignored(text_by_path[rel_path], line or 1, "shortlink-download"):
                    adjusted_severity, context_reason = adjust_for_context(
                        rel_path,
                        "shortlink-download",
                        severity,
                        excerpt,
                        content=text_by_path[rel_path],
                        line_number=line,
                    )
                    findings.append(
                        {
                            "category": "shortlink-download",
                            "severity": adjusted_severity,
                            "path": rel_path,
                            "line": line,
                            "message": "semantic analysis inferred a shortlink or paste-style payload entering a download flow",
                            "excerpt": excerpt,
                            "rationale": context_reason or f"Python semantic analysis links concealed destination material into a download flow; origin {python_origin_summary(origins, rel_path)}",
                            "action": ACTION_BY_SEVERITY[adjusted_severity],
                            "source_kind": file_source_kind,
                            "evidence_kind": evidence_kind,
                            "confidence_weight": evidence_weight,
                            "evidence_confidence": evidence_confidence,
                            "related_evidence": related,
                            "protected_surface": protected_surface_info(rel_path)["label"] if protected_surface_info(rel_path) else None,
                        }
                    )
    return findings


def first_matching_regex(content: str, patterns: list[re.Pattern[str]]) -> re.Match[str] | None:
    for pattern in patterns:
        match = pattern.search(content)
        if match:
            return match
    return None


def classify_sink_profile(content: str) -> tuple[str, re.Match[str]] | None:
    sink_match = first_matching_regex(content, GENERAL_SINK_PATTERNS)
    if not sink_match:
        return None
    if first_matching_regex(content, HIGH_RISK_SINK_PATTERNS):
        return "high-risk", sink_match
    if any(pattern.search(content) for pattern in TRUSTED_API_HINT_PATTERNS):
        return "trusted-api", sink_match
    return "unknown-external", sink_match


def has_host_boundary_guard(content: str) -> bool:
    return any(pattern.search(content) for pattern in HOST_BOUNDARY_HINT_PATTERNS)


def has_declared_theme(skill_text: str, rel_path: str, category: str) -> bool:
    expected = CATEGORY_DECLARATION_THEMES.get(category, set())
    if not expected:
        return True
    normalized_path = re.sub(r"[/_.-]+", " ", rel_path.lower())
    combined = f"{skill_text} {normalized_path}".lower()
    return any(DECLARATION_THEME_PATTERNS[theme].search(combined) for theme in expected)


def load_review_baseline(path: Path = DEFAULT_REVIEW_BASELINE_PATH) -> dict:
    payload = {
        "path": str(path),
        "version": 1,
        "entry_count": 0,
        "entries": [],
        "load_error": None,
    }
    if not path.exists():
        return payload
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        payload["load_error"] = str(exc)
        return payload
    entries = raw.get("entries", [])
    if not isinstance(entries, list):
        payload["load_error"] = "baseline entries must be a list"
        return payload
    normalized_entries = [entry for entry in entries if isinstance(entry, dict) and entry.get("id")]
    payload["version"] = raw.get("version", 1)
    payload["entry_count"] = len(normalized_entries)
    payload["entries"] = normalized_entries
    return payload


def review_entry_matches(skill_dir: Path, declared_name: str, finding: dict, entry: dict) -> bool:
    skill_target = entry.get("skill")
    if skill_target:
        normalized_targets = {declared_name.lower(), skill_dir.name.lower()}
        if str(skill_target).lower() not in normalized_targets:
            return False
    skill_path_suffix = entry.get("skill_path_suffix")
    if skill_path_suffix and not str(skill_dir.resolve()).endswith(str(skill_path_suffix)):
        return False
    for key in ("path", "category", "severity", "source_kind"):
        expected = entry.get(key)
        if expected is not None and finding.get(key) != expected:
            return False
    if entry.get("line") is not None and finding.get("line") != entry.get("line"):
        return False
    excerpt_contains = entry.get("excerpt_contains")
    if excerpt_contains and excerpt_contains not in finding.get("excerpt", ""):
        return False
    message_contains = entry.get("message_contains")
    if message_contains and message_contains not in finding.get("message", ""):
        return False
    return True


def apply_review_baseline(skill_dir: Path, declared_name: str, findings: list[dict], review_baseline: dict) -> tuple[list[dict], dict]:
    entries = review_baseline.get("entries", [])
    summary = {"matched": 0, "suppressed": 0, "annotated": 0}
    if not entries or not findings:
        return findings, summary

    filtered = []
    for finding in findings:
        matched_entries = [entry for entry in entries if review_entry_matches(skill_dir, declared_name, finding, entry)]
        if not matched_entries:
            filtered.append(finding)
            continue

        summary["matched"] += 1
        suppress = False
        annotated_finding = dict(finding)
        reviews = []
        for entry in matched_entries:
            status = str(entry.get("status", "false-positive")).lower()
            review_record = {
                "id": entry.get("id"),
                "status": status,
                "reviewed_at_utc": entry.get("reviewed_at_utc"),
                "reason": entry.get("reason", ""),
            }
            if status == "false-positive":
                suppress = True
            else:
                reviews.append(review_record)
        if suppress:
            summary["suppressed"] += 1
            continue
        if reviews:
            annotated_finding["baseline_reviews"] = reviews
            summary["annotated"] += 1
        filtered.append(annotated_finding)
    return filtered, summary


def capability_level(score: int) -> str:
    if score >= 70:
        return "extreme"
    if score >= 45:
        return "high"
    if score >= 20:
        return "moderate"
    if score >= 1:
        return "low"
    return "minimal"


def unsafe_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


def final_disposition(capability_score: int, unsafe_score: int, findings: list[dict]) -> str:
    highest = strongest_severity([item["severity"] for item in findings]) if findings else "low"
    categories = {item["category"] for item in findings}
    high_confidence_hits = [
        item
        for item in findings
        if item.get("evidence_kind") in {"ast-dataflow", "cross-file-inferred"}
        and item.get("evidence_confidence") in {"high", "very-high"}
    ]
    protected_hits = [item for item in findings if item.get("protected_surface")]
    if highest == "critical" or "source-sink-chain" in categories and unsafe_score >= 70:
        return "critical"
    if any(item["severity"] == "high" for item in protected_hits) and high_confidence_hits:
        return "unsafe"
    if categories and categories.issubset(HYGIENE_CATEGORIES) and highest in {"low", "medium"}:
        if capability_score >= 20 or unsafe_score >= 1:
            return "risky"
        return "safe"
    if unsafe_score >= 55 or highest == "high" and len(findings) >= 2 or len(high_confidence_hits) >= 2:
        return "unsafe"
    if unsafe_score >= 25 or highest == "high":
        return "suspicious"
    if capability_score >= 20 or unsafe_score >= 1:
        return "risky"
    return "safe"


def recommended_action(disposition: str) -> str:
    mapping = {
        "safe": "observe",
        "risky": "review",
        "suspicious": "review",
        "unsafe": "block",
        "critical": "quarantine",
    }
    return mapping[disposition]


def latest_mtime(files: list[Path]) -> datetime | None:
    timestamps = []
    for path in files:
        try:
            timestamps.append(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc))
        except OSError:
            continue
    return max(timestamps) if timestamps else None


def add_capability_hits(rel_path: str, content: str, capability_hits: dict[str, list[dict]]) -> None:
    source_kind = classify_source_kind(rel_path)
    for category, regex in CAPABILITY_RULES:
        match = regex.search(content)
        if not match:
            continue
        line = first_line_number(content, match.start())
        protected = protected_surface_info(rel_path)
        capability_hits[category].append(
            {
                "path": rel_path,
                "line": line,
                "excerpt": line_excerpt(content, line),
                "source_kind": source_kind,
                "protected_surface": protected["label"] if protected else None,
                "protected_surface_weight": protected_surface_weight(rel_path, category),
            }
        )


def add_secret_file_findings(skill_dir: Path, files: list[Path], findings: list[dict]) -> None:
    for path in files:
        rel_path = path.relative_to(skill_dir).as_posix()
        for pattern, severity, category, message in SECRET_FILE_PATTERNS:
            if not pattern.match(path.name):
                continue
            findings.append(
                {
                    "category": category,
                    "severity": severity,
                    "path": rel_path,
                    "line": None,
                    "message": message,
                    "excerpt": path.name,
                    "rationale": "secret-bearing files should not live inside reusable skill packages",
                    "action": ACTION_BY_SEVERITY[severity],
                }
            )


def scan_content(rel_path: str, content: str, findings: list[dict]) -> None:
    source_kind = classify_source_kind(rel_path)
    protected = protected_surface_info(rel_path)
    for category, severity, regex, message in UNSAFE_RULES:
        match = regex.search(content)
        if not match:
            continue
        line = first_line_number(content, match.start())
        if finding_is_ignored(content, line, category):
            continue
        excerpt = line_excerpt(content, line)
        if category == "secret-material" and match.lastindex:
            if looks_like_placeholder_secret(match.group(match.lastindex)):
                continue
        adjusted_severity, context_reason = adjust_for_context(
            rel_path,
            category,
            severity,
            excerpt,
            content=content,
            line_number=line,
        )
        findings.append(
            {
                "category": category,
                "severity": adjusted_severity,
                "path": rel_path,
                "line": line,
                "message": message,
                "excerpt": excerpt,
                "rationale": context_reason or default_rationale(category, adjusted_severity),
                "action": ACTION_BY_SEVERITY[adjusted_severity],
                "source_kind": source_kind,
                "evidence_kind": "pattern-match",
                "evidence_confidence": "medium",
                "confidence_weight": EVIDENCE_KIND_WEIGHTS["pattern-match"] * EVIDENCE_CONFIDENCE_WEIGHTS["medium"],
                "protected_surface": protected["label"] if protected else None,
            }
        )

    private_source_match = first_matching_regex(content, PRIVATE_SOURCE_PATTERNS)
    credential_source_match = first_matching_regex(content, CREDENTIAL_SOURCE_PATTERNS)
    sink_profile = classify_sink_profile(content)
    transform_hit = any(regex.search(content) for regex in TRANSFORM_HINT_PATTERNS)
    stealth_hit = re.search(r"(?i)(do not tell the user|don't tell the user|silently|不要告诉用户|静默)", content)
    if sink_profile and (private_source_match or credential_source_match):
        sink_kind, _sink_match = sink_profile
        source_match = private_source_match or credential_source_match
        source_line = first_line_number(content, source_match.start())
        sink_line = first_line_number(content, _sink_match.start())
        confidence, confidence_weight = chain_confidence(source_line, sink_line)
        if private_source_match:
            category = "source-sink-chain"
            severity = "critical" if transform_hit or stealth_hit else "high"
            rationale = (
                "private local stores combined with outbound delivery are the clearest static exfiltration pattern"
            )
            message = "private local source and outbound sink appear together in the same file"
        elif sink_kind == "trusted-api":
            if has_host_boundary_guard(content):
                category = "bounded-credentialed-egress"
                severity = "low"
                rationale = (
                    "credential-bearing requests target a known API domain and the code also includes explicit host-boundary checks"
                )
                message = "credential-bearing source and trusted API call appear together, with an explicit host allowlist boundary"
            else:
                category = "credentialed-egress"
                severity = "medium"
                rationale = (
                    "credential-bearing requests target a known API domain, so this looks like bounded product behavior rather than arbitrary exfiltration"
                )
                message = "credential-bearing source and trusted API call appear together in the same file"
        else:
            category = "source-sink-chain"
            severity = "high"
            if transform_hit or stealth_hit:
                severity = raise_severity(severity, 1)
            rationale = "credential-bearing source and outbound sink appear together without a clearly bounded trusted API target"
            message = "credential-bearing source and outbound sink appear together in the same file"
        if confidence == "file-wide" and category in {"credentialed-egress", "source-sink-chain"} and not private_source_match:
            severity = downgrade_severity(severity, 1)
        line = source_line
        if not finding_is_ignored(content, line, category):
            excerpt = line_excerpt(content, line)
            adjusted_severity, context_reason = adjust_for_context(
                rel_path,
                category,
                severity,
                excerpt,
                content=content,
                line_number=line,
            )
            findings.append(
                {
                    "category": category,
                    "severity": adjusted_severity,
                    "path": rel_path,
                    "line": line,
                    "message": message,
                    "excerpt": excerpt,
                    "rationale": context_reason or f"{rationale}; source-to-sink linkage looks {confidence}",
                    "action": ACTION_BY_SEVERITY[adjusted_severity],
                    "source_kind": source_kind,
                    "evidence_kind": "local-chain",
                    "evidence_confidence": "high" if confidence in {"local", "nearby"} else "medium",
                    "chain_confidence": confidence,
                    "confidence_weight": confidence_weight * EVIDENCE_KIND_WEIGHTS["local-chain"] * EVIDENCE_CONFIDENCE_WEIGHTS["high" if confidence in {"local", "nearby"} else "medium"],
                    "protected_surface": protected["label"] if protected else None,
                }
            )

    add_obfuscation_findings(rel_path, content, findings, source_kind)


def add_obfuscation_findings(rel_path: str, content: str, findings: list[dict], source_kind: str) -> None:
    base64_match = first_matching_regex(content, BASE64_DECODE_PATTERNS)
    exec_match = first_matching_regex(content, EXECUTION_STAGE_PATTERNS)
    suspicious_exec_match = first_matching_regex(content, SUSPICIOUS_EXECUTION_PATTERNS)
    archive_match = first_matching_regex(content, ARCHIVE_EXTRACT_PATTERNS)
    download_match = first_matching_regex(content, DOWNLOAD_STAGE_PATTERNS)
    shortlink_match = first_matching_regex(content, SHORTLINK_URL_PATTERNS)
    dynamic_base64 = (
        base64_segment_count(content) >= 2
        and re.search(r"(?i)(base64|b64|encoded)", content)
        and re.search(r"(?i)(join\s*\(|\+)", content)
    )
    protected = protected_surface_info(rel_path)

    if (base64_match or dynamic_base64) and exec_match:
        decode_line = first_line_number(content, base64_match.start()) if base64_match else first_line_number(content, dynamic_base64.start())
        exec_line = first_line_number(content, exec_match.start())
        confidence, confidence_weight = chain_confidence(decode_line, exec_line)
        severity = "high" if confidence in {"local", "nearby"} else "medium"
        if not finding_is_ignored(content, decode_line, "obfuscated-exec"):
            excerpt = line_excerpt(content, decode_line)
            adjusted_severity, context_reason = adjust_for_context(
                rel_path,
                "obfuscated-exec",
                severity,
                excerpt,
                content=content,
                line_number=decode_line,
            )
            findings.append(
                {
                    "category": "obfuscated-exec",
                    "severity": adjusted_severity,
                    "path": rel_path,
                    "line": decode_line,
                    "message": "base64 decoding and execution behavior appear together in the same file",
                    "excerpt": excerpt,
                    "rationale": context_reason
                    or (
                        ("dynamically assembled base64-looking payload plus later execution is a common obfuscation pattern" if dynamic_base64 and not base64_match else "payload decoding plus later execution is a common obfuscation pattern")
                        + f"; linkage looks {confidence}"
                    ),
                    "action": ACTION_BY_SEVERITY[adjusted_severity],
                    "source_kind": source_kind,
                    "evidence_kind": "local-chain",
                    "evidence_confidence": "high" if confidence in {"local", "nearby"} else "medium",
                    "chain_confidence": confidence,
                    "confidence_weight": confidence_weight * EVIDENCE_KIND_WEIGHTS["local-chain"] * EVIDENCE_CONFIDENCE_WEIGHTS["high" if confidence in {"local", "nearby"} else "medium"],
                    "protected_surface": protected["label"] if protected else None,
                }
            )

    archive_exec_match = suspicious_exec_match or (download_match and exec_match)
    if archive_match and archive_exec_match:
        extract_line = first_line_number(content, archive_match.start())
        exec_line = first_line_number(content, archive_exec_match.start())
        confidence, confidence_weight = chain_confidence(extract_line, exec_line)
        severity = "high" if download_match and confidence in {"local", "nearby"} else "medium"
        if not finding_is_ignored(content, extract_line, "archive-staged-exec"):
            excerpt = line_excerpt(content, extract_line)
            adjusted_severity, context_reason = adjust_for_context(
                rel_path,
                "archive-staged-exec",
                severity,
                excerpt,
                content=content,
                line_number=extract_line,
            )
            findings.append(
                {
                    "category": "archive-staged-exec",
                    "severity": adjusted_severity,
                    "path": rel_path,
                    "line": extract_line,
                    "message": "archive extraction and later execution behavior appear together in the same file",
                    "excerpt": excerpt,
                    "rationale": context_reason
                    or (
                        "staged archive extraction followed by execution is a common payload-delivery pattern"
                        + (" and the same file also downloads remote content" if download_match else "")
                        + f"; linkage looks {confidence}"
                    ),
                    "action": ACTION_BY_SEVERITY[adjusted_severity],
                    "source_kind": source_kind,
                    "evidence_kind": "local-chain",
                    "evidence_confidence": "high" if confidence in {"local", "nearby"} else "medium",
                    "chain_confidence": confidence,
                    "confidence_weight": confidence_weight * EVIDENCE_KIND_WEIGHTS["local-chain"] * EVIDENCE_CONFIDENCE_WEIGHTS["high" if confidence in {"local", "nearby"} else "medium"],
                    "protected_surface": protected["label"] if protected else None,
                }
            )

    if shortlink_match and download_match:
        shortlink_line = first_line_number(content, shortlink_match.start())
        exec_line = first_line_number(content, exec_match.start()) if exec_match else None
        confidence, confidence_weight = chain_confidence(shortlink_line, exec_line or shortlink_line)
        severity = "high" if exec_match and confidence in {"local", "nearby"} else "medium"
        if not finding_is_ignored(content, shortlink_line, "shortlink-download"):
            excerpt = line_excerpt(content, shortlink_line)
            adjusted_severity, context_reason = adjust_for_context(
                rel_path,
                "shortlink-download",
                severity,
                excerpt,
                content=content,
                line_number=shortlink_line,
            )
            findings.append(
                {
                    "category": "shortlink-download",
                    "severity": adjusted_severity,
                    "path": rel_path,
                    "line": shortlink_line,
                    "message": "download flow references a shortlink or paste-style host",
                    "excerpt": excerpt,
                    "rationale": context_reason
                    or (
                        "shortlinks and paste-style hosts conceal the final payload destination"
                        + (" and the same file also prepares execution behavior" if exec_match else "")
                        + f"; linkage looks {confidence}"
                    ),
                    "action": ACTION_BY_SEVERITY[adjusted_severity],
                    "source_kind": source_kind,
                    "evidence_kind": "local-chain",
                    "evidence_confidence": "high" if confidence in {"local", "nearby"} else "medium",
                    "chain_confidence": confidence,
                    "confidence_weight": confidence_weight * EVIDENCE_KIND_WEIGHTS["local-chain"] * EVIDENCE_CONFIDENCE_WEIGHTS["high" if confidence in {"local", "nearby"} else "medium"],
                    "protected_surface": protected["label"] if protected else None,
                }
            )


def default_rationale(category: str, severity: str) -> str:
    rationales = {
        "secret-material": "reusable skills should never embed live secret material",
        "sensitive-source": "access to clearly private stores raises privacy-abuse risk",
        "credential-harvest": "credential access becomes dangerous when paired with outbound delivery",
        "credentialed-egress": "credential-bearing requests to trusted APIs are legitimate in some skills, but the token boundary should still be explicit and minimal",
        "bounded-credentialed-egress": "credential-bearing requests to trusted APIs with explicit host guards look bounded, but they still widen the trust boundary",
        "env-overexposure": "forwarding the full environment to child processes expands secret exposure beyond the immediate script",
        "external-sink": "outbound sinks are not unsafe alone, but they matter when combined with sensitive data access",
        "stealth-or-deception": "hidden-action language is incompatible with trustworthy skill behavior",
        "remote-exec": "remote execution expands compromise scope and should be blocked by default",
        "persistence-abuse": "persistence should be explicit, bounded, and user-approved",
        "prompt-boundary-bypass": "skills should not attempt to override higher-priority safety boundaries",
        "source-sink-chain": "sensitive-source to outbound-sink chains indicate likely exfiltration behavior",
        "supply-chain-hygiene": "remote dependency installs without version pinning increase supply-chain and reproducibility risk",
        "behavior-mismatch": "benign-sounding packaging plus undeclared sensitive behavior is a common disguise pattern and deserves manual review",
        "obfuscated-exec": "decoded payloads that are later executed are common obfuscation and staging behavior",
        "archive-staged-exec": "unpacked archives that are later executed are a common staged-payload delivery pattern",
        "shortlink-download": "shortlinks and paste-style hosts hide the final payload destination and deserve manual review",
    }
    base = rationales.get(category, "manual review required")
    if severity == "low":
        return f"{base}; current signal is weak or contextual"
    return base


def score_capabilities(capability_hits: dict[str, list[dict]]) -> tuple[int, list[dict]]:
    score = 0
    top = []
    for category, hits in capability_hits.items():
        if not hits:
            continue
        weight = CAPABILITY_WEIGHTS[category]
        effective_hit_weights = [
            capability_source_weight(item.get("source_kind", "supporting-file")) * item.get("protected_surface_weight", 1.0)
            for item in hits
        ]
        protected_weight = max(effective_hit_weights, default=1.0)
        score += round((weight + min(4, max(0, len(hits) - 1)) * 2) * protected_weight)
        top.append(
            {
                "category": category,
                "weight": weight,
                "count": len(hits),
                "evidence": hits[0],
            }
        )
    score = min(100, score)
    top.sort(key=lambda item: (-item["weight"], -item["count"], item["category"]))
    return score, top


def score_findings(findings: list[dict]) -> tuple[int, str]:
    if not findings:
        return 0, "none"
    buckets = defaultdict(int)
    for item in findings:
        weight = FINDING_SCORE_OVERRIDES.get(item["category"], {}).get(item["severity"], DEFAULT_FINDING_SCORES[item["severity"]])
        adjusted_weight = max(
            1,
            round(
                weight
                * source_weight(item.get("source_kind", "supporting-file"), item["category"])
                * item.get("confidence_weight", 1.0)
                * protected_surface_weight(item["path"], item["category"])
            ),
        )
        buckets[item["category"]] = max(buckets[item["category"]], adjusted_weight)
    score = min(100, sum(sorted(buckets.values(), reverse=True)[:5]))
    return score, strongest_severity([item["severity"] for item in findings])


def dedupe_findings(findings: list[dict]) -> list[dict]:
    deduped = {}
    stronger_path_categories = defaultdict(set)
    for item in findings:
        if item["severity"] in {"medium", "high", "critical"}:
            stronger_path_categories[item["path"]].add(item["category"])
    for item in findings:
        if item["severity"] == "low" and item["rationale"] in CONTEXTUAL_RATIONALES:
            continue
        if (
            item["category"] == "credential-harvest"
            and item["severity"] == "low"
            and stronger_path_categories[item["path"]] & {"credentialed-egress", "bounded-credentialed-egress", "env-overexposure", "source-sink-chain"}
        ):
            continue
        key = (item["category"], item["path"], item["line"])
        existing = deduped.get(key)
        if not existing:
            deduped[key] = item
            continue
        candidate_weight = (
            SEVERITY_ORDER[item["severity"]],
            item.get("confidence_weight", 1.0),
            protected_surface_weight(item["path"], item["category"]),
        )
        existing_weight = (
            SEVERITY_ORDER[existing["severity"]],
            existing.get("confidence_weight", 1.0),
            protected_surface_weight(existing["path"], existing["category"]),
        )
        if candidate_weight > existing_weight:
            merged = dict(item)
            if existing.get("related_evidence") or item.get("related_evidence"):
                merged["related_evidence"] = dedupe_origins(list(existing.get("related_evidence", [])) + list(item.get("related_evidence", [])))
            deduped[key] = merged
        else:
            if existing.get("related_evidence") or item.get("related_evidence"):
                existing["related_evidence"] = dedupe_origins(list(existing.get("related_evidence", [])) + list(item.get("related_evidence", [])))
                deduped[key] = existing
    result = list(deduped.values())
    result.sort(
        key=lambda item: (
            -SEVERITY_ORDER[item["severity"]],
            item["path"],
            item["line"] or 0,
            item["category"],
        )
    )
    return result


def add_behavior_mismatch_findings(skill_dir: Path, frontmatter: dict, findings: list[dict]) -> None:
    declared_text = " ".join(
        filter(
            None,
            [
                skill_dir.name,
                frontmatter.get("name"),
                frontmatter.get("description"),
                summarize_purpose(frontmatter),
            ],
        )
    ).lower()
    added = set()
    for item in findings:
        category = item["category"]
        if category not in CATEGORY_DECLARATION_THEMES:
            continue
        if item.get("source_kind") in LOW_CONFIDENCE_SOURCE_KINDS:
            continue
        if item.get("rationale") in CONTEXTUAL_RATIONALES:
            continue
        if has_declared_theme(declared_text, item["path"], category):
            continue
        key = (category, item["path"])
        if key in added:
            continue
        added.add(key)
        severity = "medium" if category in {"source-sink-chain", "remote-exec", "persistence-abuse"} else "low"
        findings.append(
            {
                "category": "behavior-mismatch",
                "severity": severity,
                "path": item["path"],
                "line": item.get("line"),
                "message": "observed sensitive behavior is not clearly declared by the skill's stated purpose or file naming",
                "excerpt": item.get("excerpt", ""),
                "rationale": default_rationale("behavior-mismatch", severity),
                "action": ACTION_BY_SEVERITY[severity],
                "source_kind": item.get("source_kind", "supporting-file"),
                "evidence_kind": item.get("evidence_kind", "pattern-match"),
                "evidence_confidence": item.get("evidence_confidence", "medium"),
                "confidence_weight": item.get("confidence_weight", EVIDENCE_KIND_WEIGHTS["pattern-match"] * EVIDENCE_CONFIDENCE_WEIGHTS["medium"]),
                "protected_surface": item.get("protected_surface"),
            }
        )


def diff_manifest(previous: dict | None, current: dict) -> dict:
    previous = previous or {}
    previous_paths = set(previous)
    current_paths = set(current)
    changed = sorted(path for path in current_paths & previous_paths if current[path] != previous[path])
    added = sorted(current_paths - previous_paths)
    removed = sorted(previous_paths - current_paths)
    return {
        "changed_count": len(changed),
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_files": changed[:12],
        "added_files": added[:12],
        "removed_files": removed[:12],
    }


def summarize_evidence(findings: list[dict]) -> dict:
    evidence_kind = Counter(item.get("evidence_kind", "pattern-match") for item in findings)
    confidence = Counter(item.get("evidence_confidence", "medium") for item in findings)
    protected = Counter(item.get("protected_surface") for item in findings if item.get("protected_surface"))
    return {
        "evidence_kind": dict(evidence_kind),
        "evidence_confidence": dict(confidence),
        "protected_surfaces": dict(protected),
    }


def scan_skill(skill_dir: Path, review_baseline: dict | None = None, previous_manifest: dict | None = None) -> tuple[dict, dict, str]:
    files = collect_skill_files(skill_dir)
    manifest = build_target_manifest(skill_dir, files)
    fingerprint = manifest_fingerprint(manifest)
    skill_md = skill_dir / "SKILL.md"
    profile = workbench_profile(skill_dir) if not skill_md.exists() else None
    if skill_md.exists():
        frontmatter = parse_frontmatter(skill_md)
        target_kind = "skill"
    elif profile:
        frontmatter = {
            "raw_text": "",
            "frontmatter_present": False,
            "name": profile["declared_name"],
            "description": profile["description"],
        }
        target_kind = "workbench"
    else:
        frontmatter = {"raw_text": "", "frontmatter_present": False, "name": None, "description": None}
        target_kind = "skill"
    findings = []
    capability_hits: dict[str, list[dict]] = defaultdict(list)
    add_secret_file_findings(skill_dir, files, findings)
    text_by_path = {}
    source_kind_by_path = {}

    for path in files:
        rel_path = path.relative_to(skill_dir).as_posix()
        content = collect_text_content(path)
        if content is None:
            continue
        text_by_path[rel_path] = content
        source_kind_by_path[rel_path] = classify_source_kind(rel_path)
        add_capability_hits(rel_path, content, capability_hits)
        scan_content(rel_path, content, findings)

    findings.extend(build_python_semantic_findings(text_by_path, source_kind_by_path))
    add_behavior_mismatch_findings(skill_dir, frontmatter, findings)
    findings = dedupe_findings(findings)
    declared_name = frontmatter.get("name") or skill_dir.name
    findings, baseline_summary = apply_review_baseline(skill_dir, declared_name, findings, review_baseline or {})
    capability_score, capabilities = score_capabilities(capability_hits)
    unsafe_score, highest_severity = score_findings(findings)
    disposition = final_disposition(capability_score, unsafe_score, findings)
    resource_dirs = infer_resource_dirs(skill_dir, files)
    diff_summary = diff_manifest(previous_manifest, manifest)
    evidence_summary = summarize_evidence(findings)

    report = {
        "path": str(skill_dir.resolve()),
        "target_kind": target_kind,
        "declared_name": declared_name,
        "purpose_summary": summarize_purpose(frontmatter),
        "file_count": len(files),
        "last_modified_utc": latest_mtime(files).isoformat().replace("+00:00", "Z") if latest_mtime(files) else None,
        "capability_risk_score": capability_score,
        "capability_risk_level": capability_level(capability_score),
        "unsafe_behavior_score": unsafe_score,
        "unsafe_behavior_level": unsafe_level(unsafe_score),
        "highest_finding_severity": highest_severity,
        "disposition": disposition,
        "recommended_action": recommended_action(disposition),
        "top_capabilities": capabilities[:6],
        "findings": findings[:24],
        "finding_count": len(findings),
        "resource_dirs": resource_dirs,
        "baseline_summary": baseline_summary,
        "scan_mode": "fresh",
        "diff_summary": diff_summary,
        "evidence_summary": evidence_summary,
        "protected_surface_count": sum(1 for item in findings if item.get("protected_surface")),
    }
    return report, manifest, fingerprint


def scan_roots(
    roots: list[Path],
    review_baseline: dict | None = None,
    scan_cache: dict | None = None,
    full_scan: bool = False,
    changed_only: bool = False,
) -> tuple[list[dict], dict]:
    reports = []
    seen = set()
    cache = scan_cache or {"targets": {}}
    baseline_sig = review_baseline_signature(review_baseline or {})
    for root in roots:
        for skill_dir in find_skill_dirs(root):
            resolved = str(skill_dir.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            files = collect_skill_files(skill_dir)
            manifest = build_target_manifest(skill_dir, files)
            fingerprint = manifest_fingerprint(manifest)
            cache_entry = cache.get("targets", {}).get(resolved)
            if (
                not full_scan
                and cache_entry
                and cache_entry.get("fingerprint") == fingerprint
                and cache_entry.get("baseline_signature") == baseline_sig
                and cache_entry.get("scanner_version") == SCANNER_VERSION
            ):
                cached_report = dict(cache_entry["report"])
                cached_report["scan_mode"] = "cached"
                reports.append(cached_report)
                continue
            previous_manifest = cache_entry.get("manifest") if cache_entry else None
            if changed_only and cache_entry and previous_manifest == manifest:
                continue
            report, manifest, fingerprint = scan_skill(skill_dir, review_baseline, previous_manifest)
            reports.append(report)
            cache.setdefault("targets", {})[resolved] = {
                "scanner_version": SCANNER_VERSION,
                "baseline_signature": baseline_sig,
                "fingerprint": fingerprint,
                "manifest": manifest,
                "report": report,
            }
    reports.sort(
        key=lambda item: (
            {"critical": 4, "unsafe": 3, "suspicious": 2, "risky": 1, "safe": 0}[item["disposition"]],
            item["unsafe_behavior_score"],
            item["capability_risk_score"],
        ),
        reverse=True,
    )
    return reports, cache


def summarize_counts(skills: list[dict]) -> dict:
    counts = Counter(item["disposition"] for item in skills)
    return {
        "safe": counts.get("safe", 0),
        "risky": counts.get("risky", 0),
        "suspicious": counts.get("suspicious", 0),
        "unsafe": counts.get("unsafe", 0),
        "critical": counts.get("critical", 0),
    }


def build_payload(roots: list[Path], full_scan: bool = False, changed_only: bool = False) -> dict:
    review_baseline = load_review_baseline()
    scan_cache = load_scan_cache()
    skills, updated_cache = scan_roots(roots, review_baseline, scan_cache, full_scan=full_scan, changed_only=changed_only)
    save_scan_cache(updated_cache)
    counts = summarize_counts(skills)
    baseline_summary = {
        "path": review_baseline["path"],
        "entry_count": review_baseline["entry_count"],
        "load_error": review_baseline["load_error"],
        "matched_findings": sum(item["baseline_summary"]["matched"] for item in skills),
        "suppressed_findings": sum(item["baseline_summary"]["suppressed"] for item in skills),
        "annotated_findings": sum(item["baseline_summary"]["annotated"] for item in skills),
    }
    scan_summary = {
        "cache_path": scan_cache["path"],
        "cache_load_error": scan_cache["load_error"],
        "fresh_targets": sum(1 for item in skills if item.get("scan_mode") == "fresh"),
        "cached_targets": sum(1 for item in skills if item.get("scan_mode") == "cached"),
        "changed_targets": sum(
            1
            for item in skills
            if (item.get("diff_summary", {}).get("changed_count", 0) + item.get("diff_summary", {}).get("added_count", 0) + item.get("diff_summary", {}).get("removed_count", 0)) > 0
        ),
        "full_scan": full_scan,
        "changed_only": changed_only,
    }
    return {
        "generated_at_utc": NOW.isoformat().replace("+00:00", "Z"),
        "scanner_version": SCANNER_VERSION,
        "scanned_roots": [str(root) for root in roots],
        "skill_count": len(skills),
        "summary": counts,
        "review_baseline": baseline_summary,
        "scan_summary": scan_summary,
        "skills": skills,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan local and OpenClaw skill packages for unsafe behavior.")
    parser.add_argument("roots", nargs="*", help="Optional root directories to scan")
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--full-scan", action="store_true", help="Ignore the incremental cache and rescan every discovered target")
    parser.add_argument("--changed-only", action="store_true", help="Emit only changed targets compared with the incremental cache")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    roots = discover_roots(Path.cwd(), args.roots)
    payload = build_payload(roots, full_scan=args.full_scan, changed_only=args.changed_only)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
