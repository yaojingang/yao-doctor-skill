# Yao Doctor Skill Security Report

Generated at: `2026-04-20T02:15:00Z`
Scanner version: `public-example-1`
Scanned roots: `/opt/aurora-lab/demo-skills`, `/opt/aurora-lab/workbench/.codex`, `/srv/public-agent-lab/.claude/skills`
Skill count: `11`
Scan summary: `11` fresh, `0` cached, `11` changed
Review baseline: `2` entries, `0` suppressed, `0` annotated

## Summary

- `critical`: 2
- `unsafe`: 2
- `suspicious`: 1
- `risky`: 3
- `safe`: 3

## Skills

| Target | Type | Disposition | Capability | Unsafe | Action |
| --- | --- | --- | --- | --- | --- |
| `nebula-console` | `workbench` | `critical` | `78` | `96` | `quarantine` |
| `glass-archive-lifter` | `skill` | `critical` | `64` | `91` | `quarantine` |
| `orbit-mail-bridge` | `skill` | `unsafe` | `58` | `72` | `block` |
| `aurora-batch-deployer` | `skill` | `unsafe` | `67` | `66` | `block` |
| `harbor-rule-lattice` | `skill` | `suspicious` | `44` | `38` | `review` |
| `atlas-file-porter` | `skill` | `risky` | `53` | `0` | `review` |
| `mint-feed-collector` | `skill` | `risky` | `35` | `0` | `review` |
| `solstice-dataset-mixer` | `skill` | `risky` | `47` | `12` | `review` |
| `ember-release-notes` | `skill` | `safe` | `6` | `0` | `observe` |
| `lumen-brief-studio` | `skill` | `safe` | `4` | `0` | `observe` |
| `quartz-worklog-curator` | `skill` | `safe` | `18` | `0` | `observe` |

## nebula-console

- Type: `workbench`
- Path: `/opt/aurora-lab/workbench/.codex`
- Purpose: Demo workbench surface for orchestrating sandbox tasks, policy routing, and scheduled actions.
- Scores: capability `78` (extreme), unsafe `96` (critical)
- Final disposition: `critical`
- Recommended action: `quarantine`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `automation` at `.codex/automations/dawn-watch/automation.toml:8` (4 hit(s), protected `workbench-config`)
  - `persistence` at `.codex/config.toml:21` (3 hit(s), protected `workbench-config`)
  - `command-execution` at `.codex/rules/ops.rules:33` (2 hit(s), protected `rules`)
- Findings:
  - [critical] `prompt-boundary-bypass` at `.codex/rules/ops.rules:33`: instruction surface explicitly asks the runner to skip user confirmation for deployment actions -> quarantine (source `workflow-control`, evidence `pattern-match`, confidence `high`, protected `rules`)
  - [high] `persistence-abuse` at `.codex/config.toml:21`: scheduled automation rewrites shared state on every launch -> block (source `workflow-control`, evidence `pattern-match`, confidence `high`, protected `workbench-config`)
  - [high] `remote-exec` at `.codex/automations/dawn-watch/automation.toml:17`: automation shells out to a downloaded helper before integrity validation -> block (source `workflow-control`, evidence `pattern-match`, confidence `high`, protected `workbench-config`)

## glass-archive-lifter

- Type: `skill`
- Path: `/srv/demo-skills/glass-archive-lifter`
- Purpose: Processes uploaded archives and republishes extracted assets into a delivery bucket.
- Scores: capability `64` (high), unsafe `91` (critical)
- Final disposition: `critical`
- Recommended action: `quarantine`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `filesystem-read` at `scripts/unpack_assets.py:44` (11 hit(s))
  - `command-execution` at `scripts/stage_runner.py:61` (3 hit(s))
  - `network-egress` at `scripts/publish_assets.py:28` (2 hit(s))
- Findings:
  - [critical] `archive-staged-exec` at `scripts/stage_runner.py:61`: archive contents are unpacked and then executed as staged Python code -> quarantine (source `executable-code`, evidence `ast-dataflow`, confidence `very-high`)
  - [high] `obfuscated-exec` at `scripts/boot.py:19`: base64-decoded blob is executed after extraction -> block (source `executable-code`, evidence `pattern-match`, confidence `high`)

## orbit-mail-bridge

- Type: `skill`
- Path: `/srv/demo-skills/orbit-mail-bridge`
- Purpose: Routes approved status digests into external messaging destinations.
- Scores: capability `58` (high), unsafe `72` (high)
- Final disposition: `unsafe`
- Recommended action: `block`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `network-egress` at `scripts/publish_digest.py:48` (5 hit(s))
  - `env-access` at `scripts/publish_digest.py:22` (2 hit(s))
  - `filesystem-read` at `scripts/collect_summary.py:31` (4 hit(s))
- Findings:
  - [high] `source-sink-chain` at `scripts/publish_digest.py:48`: digest content and credential-bearing outbound request appear in the same dataflow chain -> block (source `executable-code`, chain `nearby`, evidence `cross-file-inferred`, confidence `high`)
  - [medium] `credentialed-egress` at `scripts/publish_digest.py:22`: service token is sent to a non-vendor endpoint -> review (source `executable-code`, evidence `pattern-match`, confidence `medium`)

## aurora-batch-deployer

- Type: `skill`
- Path: `/srv/demo-skills/aurora-batch-deployer`
- Purpose: Prepares nightly deployment bundles and promotes them through a scripted release lane.
- Scores: capability `67` (high), unsafe `66` (high)
- Final disposition: `unsafe`
- Recommended action: `block`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `command-execution` at `scripts/deploy.py:52` (7 hit(s))
  - `network-egress` at `scripts/ship.py:40` (3 hit(s))
  - `filesystem-write` at `scripts/render_manifest.py:24` (4 hit(s))
- Findings:
  - [high] `remote-exec` at `scripts/deploy.py:52`: release path executes helper scripts pulled from a mutable shared folder -> block (source `executable-code`, evidence `ast-dataflow`, confidence `high`)
  - [medium] `behavior-mismatch` at `SKILL.md:14`: the documented purpose focuses on bundle creation but the implementation also triggers promotion hooks -> review (source `skill-entry`, evidence `pattern-match`, confidence `medium`, protected `instruction-entry`)

## harbor-rule-lattice

- Type: `skill`
- Path: `/srv/demo-skills/harbor-rule-lattice`
- Purpose: Maintains approval rules for a fictional multi-tenant assistant hub.
- Scores: capability `44` (moderate), unsafe `38` (medium)
- Final disposition: `suspicious`
- Recommended action: `review`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `automation` at `rules/tenant.rules:11` (2 hit(s), protected `rules`)
  - `persistence` at `rules/tenant.rules:27` (1 hit(s), protected `rules`)
- Findings:
  - [medium] `prompt-boundary-bypass` at `rules/tenant.rules:27`: review rules mention bypassing the normal confirmation gate during escalations -> review (source `workflow-control`, evidence `pattern-match`, confidence `medium`, protected `rules`)

## atlas-file-porter

- Type: `skill`
- Path: `/srv/demo-skills/atlas-file-porter`
- Purpose: Moves approved local exports into a staging area for downstream checks.
- Scores: capability `53` (high), unsafe `0` (none)
- Final disposition: `risky`
- Recommended action: `review`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `filesystem-read` at `scripts/collect_exports.py:18` (8 hit(s))
  - `filesystem-write` at `scripts/stage_exports.py:47` (6 hit(s))
  - `command-execution` at `scripts/hash_exports.py:36` (2 hit(s))
- Findings: none

## mint-feed-collector

- Type: `skill`
- Path: `/srv/demo-skills/mint-feed-collector`
- Purpose: Fetches public feed entries from demo endpoints and produces a daily trend digest.
- Scores: capability `35` (moderate), unsafe `0` (none)
- Final disposition: `risky`
- Recommended action: `review`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `network-egress` at `scripts/fetch_feed.py:13` (6 hit(s))
  - `filesystem-write` at `scripts/render_digest.py:29` (3 hit(s))
- Findings: none

## solstice-dataset-mixer

- Type: `skill`
- Path: `/srv/demo-skills/solstice-dataset-mixer`
- Purpose: Combines several local CSV files into a unified demo warehouse snapshot.
- Scores: capability `47` (high), unsafe `12` (low)
- Final disposition: `risky`
- Recommended action: `review`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `filesystem-read` at `scripts/load_tables.py:22` (9 hit(s))
  - `filesystem-write` at `scripts/write_snapshot.py:41` (5 hit(s))
  - `env-access` at `scripts/main.py:14` (1 hit(s))
- Findings:
  - [low] `env-overexposure` at `scripts/main.py:14`: optional workspace env is inherited without an allowlist wrapper -> review (source `executable-code`, evidence `pattern-match`, confidence `low`)

## ember-release-notes

- Type: `skill`
- Path: `/srv/demo-skills/ember-release-notes`
- Purpose: Turns draft release bullets into a clean fictional changelog and rollout note.
- Scores: capability `6` (low), unsafe `0` (none)
- Final disposition: `safe`
- Recommended action: `observe`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Findings: none

## lumen-brief-studio

- Type: `skill`
- Path: `/srv/demo-skills/lumen-brief-studio`
- Purpose: Packages fictional campaign notes into a concise brief for handoff reviews.
- Scores: capability `4` (minimal), unsafe `0` (none)
- Final disposition: `safe`
- Recommended action: `observe`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Findings: none

## quartz-worklog-curator

- Type: `skill`
- Path: `/srv/demo-skills/quartz-worklog-curator`
- Purpose: Organizes local worklog fragments into a single daily summary for a demo operations team.
- Scores: capability `18` (low), unsafe `0` (none)
- Final disposition: `safe`
- Recommended action: `observe`
- Scan mode: `fresh`
- Diff: changed `0`, added `0`, removed `0`
- Top capabilities:
  - `filesystem-read` at `scripts/collect_logs.py:18` (4 hit(s))
- Findings: none