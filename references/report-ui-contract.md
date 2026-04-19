# Report UI Contract

This document freezes the current HTML report contract for `yao-doctor-skill`.

## Stable Entry

- full-library report:
  - `_yao_doctor_skill_reports/full-library-latest/report.html`
- changed-only report:
  - `_yao_doctor_skill_reports/changed-only-latest/report.html`

`run_yao_doctor_skill.py` is responsible for updating the timestamped snapshot and the corresponding stable latest directory.

## Required Section IDs

- `overview`
- `data-analysis`
- `definitions`
- `module-guide`
- `skills`

## Required Controls

- language toggle: `#lang-toggle`
- disposition filter row: `#filters`
- type filter row: `#type-filters`
- quick links rail: `#quick-links`
- footer note: `#footer-note`

## Required Rendering Hooks

- `renderOverview(copy)`
- `renderDataAnalysis(copy)`
- `renderDefinitions(copy)`
- `renderGuide(copy)`
- `renderSkillModules(copy)`
- `renderFooter(copy)`

## Required Interaction Rules

1. Language switching must preserve the same page structure and controls.
2. Type filters from the data-analysis cards and from the module toolbar must stay synchronized.
3. Activating a type filter must update:
   - overview cards
   - overview charts
   - data-analysis emphasis state
   - module list
4. Skill cards must preserve the order:
   - metadata
   - chart row
   - audit opinion
   - evidence panels

## Validation

Use:

```bash
python3 scripts/validate_report_ui_contract.py _yao_doctor_skill_reports/full-library-latest/report.html
```

This is a smoke-level structural guard, not a full visual regression suite.
