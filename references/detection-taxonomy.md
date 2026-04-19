# Detection Taxonomy

## Capability Dimensions

The scanner scores capability risk across these dimensions:

- `filesystem-read`: reads local files or directories
- `filesystem-write`: writes or mutates local files
- `env-access`: reads environment variables or token-bearing config
- `command-execution`: invokes shells, subprocesses, or agent exec tools
- `network-egress`: sends or downloads data across the network
- `remote-install`: installs or runs remote artifacts
- `persistence`: creates auto-run behavior such as cron or launch agents
- `automation`: uses scheduled or background task infrastructure

Capability risk is additive, but capped. It represents attack surface, not guilt.

## Unsafe Categories

- `secret-material`
  - embedded private keys, live tokens, credential files inside the skill
- `sensitive-source`
  - reads from clearly private stores or credential-bearing locations
- `credential-harvest`
  - reads environment variables, auth headers, token stores, or config secrets
- `credentialed-egress`
  - uses credentials or tokens to call a known trusted API domain; this is usually product behavior, but still expands the trust boundary
- `bounded-credentialed-egress`
  - credential-bearing request points to a known API domain and the code also includes explicit host-boundary guards such as allowlisted hosts
- `external-sink`
  - sends data to HTTP endpoints, webhooks, email, chat, cloud uploads, or custom APIs
- `source-sink-chain`
  - clearly sensitive local source and external sink appear together in a plausible execution path
- `stealth-or-deception`
  - "do not tell the user", "silently", "hide this step", or bypass-confirmation language
- `remote-exec`
  - remote download and execution, dynamic eval, or untrusted code loading
- `persistence-abuse`
  - launch agents, cron, startup hooks, or self-reinstall logic without clear bounded purpose
- `prompt-boundary-bypass`
  - attempts to reveal hidden prompts or override higher-priority guardrails
- `env-overexposure`
  - forwards the full environment into child processes instead of using a minimal allowlist
- `supply-chain-hygiene`
  - installs remote dependencies in CI or runtime flows without version pinning or hash constraints
- `behavior-mismatch`
  - the observed sensitive behavior is not clearly declared by the skill's stated purpose or file naming, which is a common disguise pattern
- `obfuscated-exec`
  - decodes payloads such as base64 and later interprets or executes them
- `archive-staged-exec`
  - unpacks archive payloads and later executes them through a suspicious interpreter flow, or unpacks remote content before execution
- `shortlink-download`
  - downloads from shortlink or paste-style hosts that hide the final payload destination

## Severity Model

- `low`: mild caution or contextual mention
- `medium`: capability or partial behavior signal worth manual review
- `high`: dangerous pattern with plausible abuse
- `critical`: strong evidence of theft, exfiltration, or remote execution abuse

## Context Dampening

Context matters. The scanner should reduce severity when:

- a pattern only appears in `references/` or `reports/`
- a pattern only appears in non-entry Markdown documentation such as flow notes or implementation docs
- the line is clearly a regex or rule-definition example
- the file is documenting an attack pattern rather than implementing it

It should not reduce severity when:

- the pattern appears in `SKILL.md`
- the pattern appears in executable scripts
- the pattern includes concrete tokens, secrets, endpoints, or auto-run commands

## Source Confidence

Not every match should carry the same weight.

- executable scripts and active workflow files should carry more weight than docs or fixtures
- docs, examples, reports, and generated artifacts should usually be downgraded unless they contain real live secrets
- source-to-sink chains should carry more weight when the source and sink are local in the same file, and less weight when they are only loosely related across a large file
- declarative manifests should be annotated as configuration surfaces, not automatically treated the same as runtime code

## Evidence Model

The scanner now labels how each finding was produced:

- `pattern-match`
  - direct regex or structural match in one file
- `local-chain`
  - source and sink, or stage and execution, appear in one file with line-distance weighting
- `ast-dataflow`
  - Python semantic analysis inferred variable or return-value flow within one file or across functions
- `cross-file-inferred`
  - Python semantic analysis inferred flow across imported local modules or helper functions

It also carries a separate confidence label:

- `low`
- `medium`
- `high`
- `very-high`

These labels do not replace severity. They explain how strong the evidence path is.

## Protected Surfaces

Some files should count more because they control how the agent or skill behaves even without normal runtime code:

- `SKILL.md`
- `AGENTS.md`
- `CLAUDE.md`
- `.github/workflows/*.yml`
- `rules/*.rules`
- `.claude/settings*.json`
- `.claude/config.json`
- `.codex/config.toml`
- `.codex/config.json`
- `.codex/rules/*.rules`
- `manifest.json`
- `agents/interface.yaml`

Findings and capability hits on these surfaces should score higher than ordinary supporting files.

## Purpose Congruence

Disguised skills often use harmless names while performing sensitive behavior.

- if a skill claims to be a formatter, title generator, or note cleaner but also reads sensitive stores, runs remote code, or sends credential-bearing traffic, the scanner should add a `behavior-mismatch` review signal
- if the skill name, description, or file name clearly declares the integration or operation, this mismatch signal should be suppressed

## Inline Review Overrides

Targeted suppression should be explicit and auditable.

- same-line ignore: `yao-doctor-skill:ignore`
- same-line category ignore: `yao-doctor-skill:ignore credentialed-egress`
- previous-line nextline ignore: `yao-doctor-skill:ignore-nextline bounded-credentialed-egress`

Backward compatibility:
- old `skill-doctor:ignore` and `skill-doctor:ignore-nextline` markers are still recognized during migration

These markers should be used sparingly and only after manual review.

## Review Baseline File

The scanner also supports a persistent review baseline at:

- `yao-doctor-skill/baselines/review-baseline.json`

Supported review statuses:

- `false-positive`
  - suppress the finding from the current report after manual confirmation
- `accepted-risk`
  - keep the finding visible, but annotate it as already reviewed

## Incremental Scan Cache

The scanner now stores an incremental cache under:

- `yao-doctor-skill/_cache/scan-cache.json`

The cache records:

- target manifest fingerprint
- scanner version
- review-baseline signature
- previous report payload for unchanged targets

This lets repeat scans reuse unchanged targets and focus review time on diffs.

Recommended matching fields:

- `skill`
- `path`
- `category`
- `line`
- optional `message_contains` or `excerpt_contains` when the rule may move slightly over time

## Trusted API Rule

Not every credential-bearing network call is exfiltration.

- credentials plus a known official API domain should usually be classified as `credentialed-egress`
- credentials plus arbitrary webhook, mail, chat, or unknown external destination should usually escalate to `source-sink-chain`
- private local stores plus any outbound sink should be treated more aggressively than environment variables plus a known API

## Recommended Actions

- `observe`: low-signal note, safe to keep scanning
- `review`: manual inspection before using the skill
- `block`: do not execute until the finding is explained or removed
- `quarantine`: isolate or delete from active search paths before any install or run
