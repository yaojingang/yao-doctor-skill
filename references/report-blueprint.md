# Report Blueprint

The report should now be treated as a fixed audit surface, not a loose visualization experiment.

## Current Section Order

1. Hero
   - bilingual shell
   - sticky top navigation
   - scan context and root inventory
2. Report Overview
   - disposition summary cards
   - disposition distribution
   - top unsafe modules
   - capability-vs-unsafe scatter
3. Data Analysis
   - four runtime-oriented skill types
   - per-type distribution, risk mix, and activity/exposure comparison
   - clickable type cards and chart rows that filter the module list
4. Definitions
   - capability, unsafe, disposition, action definitions
   - threshold and ladder charts
5. Module Guide
   - reading order and action ladder
6. Skill Modules
   - dual score chart
   - severity chart
   - capability chart
   - audit opinion card
   - findings and capability evidence panels
7. Footer
   - author credit and X profile link

## Current UX Contract

- default language is Chinese, with a top-right English toggle
- top navigation stays fixed during scroll
- every major section is anchor-addressable
- data-analysis type filters and module-area type filters must stay synchronized
- when a type filter is active:
  - the overview summary and charts switch to that type's perspective
  - the scatter keeps global coordinates but visually highlights the active type
  - the module list narrows to the active type
- every skill card must keep the order:
  - meta
  - three charts
  - audit opinion
  - evidence panels

## Current Visual Direction

- pure white primary canvas
- restrained color accents tied to disposition, not decorative gradients
- serif-forward display headings with compact supporting UI copy
- editorial casefile feel instead of admin dashboard chrome
- mobile collapse behavior is explicit, not incidental

## What Not To Regress

- do not remove the capability-vs-unsafe separation
- do not collapse the report back into a generic table
- do not drop the audit opinion card layer
- do not break the stable report entry `full-library-latest/report.html`
- do not add “usage frequency” wording without clarifying that it is currently an activity proxy, not true invocation telemetry
