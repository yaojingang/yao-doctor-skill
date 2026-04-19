# Security Principles

This skill is built around one core distinction:

- `risk` answers: what could this skill access or do?
- `unsafe` answers: what evidence suggests this skill steals, leaks, hides, or abuses that access?

## What Counts As Risk

These are capability signals, not automatic compromise:

- broad file read access
- shell execution
- environment variable access
- network egress
- installer or dependency download behavior
- persistent automation or scheduled execution

A skill with large capability surface is powerful and deserves review, but it is not automatically malicious.

## What Counts As Unsafe

These are behavioral or chain signals:

- reading clearly sensitive paths such as `~/.ssh`, browser profiles, wallet stores, keychains, or token files
- reading environment variables or secrets and sending them to a network sink
- instructions that hide behavior from the user or bypass confirmation
- remote download and execution such as `curl | sh`
- persistence abuse such as writing launch agents, crontabs, or auto-start hooks without a legitimate declared purpose
- prompt or instruction patterns that attempt to reveal hidden prompts, ignore higher-priority rules, or conceal actions

## Final Dispositions

- `safe`: no meaningful unsafe evidence and low capability exposure
- `risky`: broad capabilities exist, but unsafe intent or behavior is not evidenced
- `suspicious`: partial unsafe evidence exists and manual review is required before any execution
- `unsafe`: concrete unsafe behavior is indicated and execution should be blocked
- `critical`: immediate quarantine recommended due to credential theft, privacy exfiltration, remote code execution chains, or comparable severity

## Source-To-Sink Rule

The strongest signal is a chain:

1. sensitive source
2. transformation or packaging
3. outbound sink

Examples:

- `os.environ` plus `requests.post(...)`
- `~/.ssh` or `Cookies` access plus `curl` or webhook send
- token file reads plus SMTP, IM send, webhook post, or cloud upload

This chain is what separates "powerful" from "unsafe."

## Trusted API Exception

Some skills legitimately call official APIs with user-provided credentials.

- `GITHUB_TOKEN` plus `api.github.com` is still a real trust-boundary expansion
- but it should not be classified the same way as secrets plus arbitrary webhook delivery
- treat these as engineering hygiene or bounded egress findings unless there is evidence of stealth, repackaging, or unbounded external delivery
- explicit host allowlists or URL guard functions should reduce severity further and move the finding toward `bounded-credentialed-egress`

## Disguise Principle

Malicious skills often hide behind normal-sounding names, file paths, or product copy.

- the scanner should compare declared purpose with observed sensitive behavior
- if a skill performs credentialed egress, remote execution, or sensitive-source access that is not clearly declared in its purpose or file naming, add a review signal
- this is not proof of abuse on its own, but it is a strong audit priority signal

## Confidence Principle

The scanner should separate strong runtime-adjacent evidence from weaker contextual evidence.

- executable scripts and active workflows should weigh more than docs, examples, tests, or generated reports
- source-to-sink patterns should be scored more aggressively when the source and sink are local to the same code block or nearby lines
- explicit inline suppressions should be possible, but only through visible markers such as `yao-doctor-skill:ignore`
- migration note: legacy `skill-doctor:ignore` markers may still be honored for backward compatibility

## Obfuscation Principle

Many malicious packages do not mention theft directly. They hide staging and execution.

- base64 decode plus later execution should be treated as an obfuscation signal
- archive extraction followed by suspicious interpreter execution, or archive extraction immediately after remote download, should be treated as staged payload delivery
- shortlinks or paste-style hosts used in download flows should be reviewed because they hide the final destination and can rotate silently

Plain documentation, design notes, or root-level Markdown examples should not be treated like active runtime unless they are the actual `SKILL.md` entry surface.

These patterns are not proof on their own, but they are materially more suspicious than plain network access.

## Review Baseline Principle

False positives should be remembered without editing the scanner every time.

- use `baselines/review-baseline.json` to persist reviewed findings
- `false-positive` entries suppress a finding from the current report
- `accepted-risk` entries keep the finding visible but annotate it as reviewed
- the baseline is an audit artifact, not a hidden magic suppression layer

## Review Posture

- read-only by default
- evidence first
- no fear-mongering from permissions alone
- no silent auto-remediation
- high-confidence findings should always point to exact files and lines
