# Open-Source Reference Scan

Date: `2026-04-19`

This note captures the external projects reviewed before tightening `yao-doctor-skill`'s detection logic.

Detailed research write-up:

- [skill-security-research-20260419.md](skill-security-research-20260419.md)

## Projects Reviewed

1. [TruffleHog](https://github.com/trufflesecurity/trufflehog)
   - high-adoption secret scanner with verified-secret flows, keyword prefilters, exclude words, and line-level ignore markers
2. [Gitleaks](https://github.com/gitleaks/gitleaks)
   - rule system with path filters, entropy gates, keywords, per-rule allowlists, stopwords, and baselines
3. [detect-secrets](https://github.com/Yelp/detect-secrets)
   - plugin-plus-filter architecture, baseline audit workflow, inline allowlisting, and heuristic false-positive filters
4. [AgentShield](https://github.com/affaan-m/agentshield)
   - agent-config and skill-focused scanner with runtime confidence, source-aware downgrade rules, and template vs active-runtime distinctions
5. [GitHub Agentic Workflows Threat Detection](https://github.github.com/gh-aw/reference/threat-detection/)
   - context-aware threat detection with protected files, safe outputs, and explicit workflow-context tuning guidance
6. [Malicious Or Not: Adding Repository Context to Agent Skill Classification](https://arxiv.org/abs/2603.16572)
   - argues that repository context and purpose congruence substantially reduce false positives in skill classification

## Borrowed Design Patterns

### 1. Source-Aware Confidence

Borrowed mainly from AgentShield.

- docs, examples, fixtures, and generated artifacts should not score like active runtime code
- executable scripts and active workflows should keep full weight
- declarative surfaces should be labeled, not blindly treated as runtime behavior

Implemented in `scan_security_skills.py` through `source_kind`, `source_weight`, and source-aware severity/scoring.

### 2. Bounded Credentialed Egress

Borrowed from the distinction seen across TruffleHog verification logic, GitHub threat-detection context, and practical secret scanners that separate product integrations from arbitrary exfiltration.

- `token + official API host` should not be treated like `token + webhook`
- explicit host-boundary checks should lower the finding further
- this is still trust-boundary expansion, but it is not the same as theft

Implemented as `credentialed-egress` and `bounded-credentialed-egress`.

### 3. Local Chain Confidence

Borrowed from context-aware scanners and verification-heavy tools.

- source and sink on nearby lines are more suspicious than two unrelated hits in the same large file
- file-wide coincidences should not score like local chains

Implemented by adding `chain_confidence` and applying a scoring discount to file-wide source-to-sink matches.

### 4. Inline Auditable Overrides

Borrowed from detect-secrets and TruffleHog.

- false positives should be suppressible at the exact line
- suppression must stay visible in source, not hidden in scanner code

Implemented via:

- `yao-doctor-skill:ignore`
- `yao-doctor-skill:ignore <category>`
- `yao-doctor-skill:ignore-nextline <category>`

### 5. Purpose-To-Behavior Congruence

Borrowed from the repository-context paper and from agent-specific scanners that separate template intent from runtime behavior.

- a harmless-sounding skill name plus undeclared sensitive behavior is a real review signal
- the goal is not to prove abuse, but to surface disguise risk early
- if the skill name, description, or file naming clearly declares the integration, the mismatch signal should be suppressed

Implemented as `behavior-mismatch`.

## What Was Deliberately Not Copied

- live secret verification against third-party APIs
  - useful for secret scanning, but too network-heavy and out of scope for an offline-first skill audit pass
- blanket allowlists
  - they suppress real findings too easily; inline or path-aware suppression is safer
- giant provider-specific detector libraries
  - good for secrets, but not the main problem here; `yao-doctor-skill` is focused on skill behavior and exfiltration logic

## Immediate Next Iteration Options

1. Add provider-aware path congruence so `github_*` or `feishu_*` scripts explain trusted API use even more precisely.
2. Add obfuscation detectors for `base64` plus `exec`, compressed payload unpacking, shortlink downloaders, and paste-site fetch flows.
3. Add a reviewed baseline file so accepted findings stay auditable across scans without mutating source files.
