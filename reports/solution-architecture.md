# Solution Architecture

## Goal

Replace the old mixed cleanup-oriented `yao-doctor-skill` with a governed security-first skill that answers:

- what a skill can access
- what a skill appears to do with that access
- whether the evidence supports `safe`, `risky`, `suspicious`, `unsafe`, or `critical`

## Why The Old Shape Was Wrong

The previous package mixed:

- usage heat
- cleanup pressure
- security

That design blurred three different decisions. A stale skill is not automatically dangerous, and an actively used skill can still be malicious. The replacement skill removes cleanup and usage from the main workflow.

## New Pipeline

1. Discover skill roots.
   - current workspace
   - `~/.agents/skills`
   - `~/.openclaw/skills`
   - `~/.codex/skills`
   - `~/.claude/skills`
   - `~/.codex/plugins/cache`
   - OpenClaw `extraDirs` when detectable
2. Discover skill packages by `SKILL.md`, discover supported workbench surfaces from local Codex and Claude roots, and infer project-level workbench surfaces from repo `AGENTS.md`, `CLAUDE.md`, or selected `.claude/.codex` files.
3. Parse frontmatter and basic package metadata.
4. Scan all text files for:
   - capability surface
   - unsafe signals
   - source-to-sink chains
   - protected-surface signals
   - Python semantic flows across functions and local imports
5. Score each skill on two axes:
   - capability risk score
   - unsafe behavior score
6. Reuse unchanged targets from the incremental cache and compute per-target diffs for changed targets.
7. Produce a final disposition and recommended action.
8. Render:
   - `report.json`
   - `report.md`
   - `report.html`

## Scoring Logic

### Axis 1: Capability Risk

Measures attack surface only. Example drivers:

- shell execution
- network egress
- env access
- file mutation
- persistence hooks

### Axis 2: Unsafe Behavior

Measures evidence of harmful behavior. Example drivers:

- hidden or deceptive instructions
- credential access paired with outbound send
- browser or wallet data access
- remote pipe-to-shell execution
- persistence abuse
- cross-file credential or private-data flow into sinks
- obfuscated decode or staged-payload execution flows inferred through Python semantics

### Evidence Layer

The scanner now also records how a finding was inferred:

- direct pattern match
- local chain
- Python AST/dataflow within one file
- Python cross-file inference through imports and helper functions

That evidence layer is used both for report explanation and for score weighting.

### Final Disposition

- `safe`: low unsafe score and low capability surface
- `risky`: capability surface is meaningful, unsafe evidence is weak
- `suspicious`: partial unsafe evidence exists
- `unsafe`: strong unsafe evidence exists
- `critical`: quarantine-worthy chains or secrets are found

## Report System

The HTML report is intentionally not a generic data grid. It uses:

- editorial hero summary with sticky navigation
- bilingual shell with Chinese default and English toggle
- overview section for global disposition and top-risk context
- data-analysis section with four runtime-oriented skill types
- linked type filters between analysis cards and module list
- per-skill casefile cards with audit-opinion summaries
- responsive layout with strong contrast and restrained motion

The report is now treated as a fixed UI contract instead of an ad hoc visual layer. The generation path must keep:

- timestamped snapshots
- `full-library-latest/report.html` for stable browsing
- `changed-only-latest/report.html` for incremental review
- a smoke validator for the current HTML contract

## Current Iteration Scope

This first rebuild includes:

- full boundary redesign
- governed metadata
- working scanner for local skill directories
- visual HTML report generation with fixed section order and interaction model

It does not yet include:

- AST-specific parsing for every language
- signed provenance or publisher reputation
- automatic quarantine actions
- full visual regression screenshot testing

## Next Iteration Directions

1. Add AST-aware flow tracing for Python, shell, JavaScript, and YAML installer metadata.
2. Add allowlist and provenance modules for known-safe publishers and signed skill bundles.
3. Add diff mode so one skill update can be reviewed against its previous version instead of rescanning the full library.
