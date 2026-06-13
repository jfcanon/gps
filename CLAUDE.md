# Claude Code — Project Conventions

## Workflow Protocol

All changes to this project follow a strict plan → execute → approve loop:

1. **Draft plan prompt** (caveman / user provides requirements)
2. **`/ecc:plan`** — planning agent creates inline plan, waits for confirmation
3. **`/ecc:prp-implement green light`** — orchestrator executes plan tasks
4. **User reviews** — approves or requests changes before next phase

**Never execute file edits without an approved plan. Never proceed to next scope without green light.**

## Activity Log

All progress tracked in: `ado/activity.log`

- Update after every phase completion
- Format: `- [x] Phase N: <what was done>`
- Include phase number in every entry
- File created 2026-06-12. Append only — do not rewrite history.

## Canonical Template

All 12 `features.md` domain entries must match the PA template:

**Template authority**: `memory/pa_feature_template.md` (user-provided original)
**Approved reference**: Feature 3 (PA) in `ado/features.md` — fully approved as of Phase 10

### Feature structure (in order)

| Section | Rule |
|---|---|
| Table | Keep as-is (Work Item Type, Title, Tags, Priority) |
| **Title** | "Security Domain #N: {Name} ({CODE}) Baselines" — NOT "Baseline Enforcement" |
| **Description** | 3 sentences: establishes → audit and identify WHERE deviates → assesses the following |
| **Controls List** | `[v2]` for pure-v2 controls. `[ResourceName]` or `[R1, R2]` for v3 resources. No counts, no "resource:" prefix |
| **Intended Business Outcome** | TBC |
| **Success Measures** | AC-N Theme (control IDs): 2 domain-specific assessment sentences. No % targets. No enforcement verbs. |
| **Release Notes** | N/A |
| **Architectural and Technical Outcomes** | Two subsections: Azure Policy Assessment (JSON export sync) + Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync). Pipeline-framing language. Domain-specific policy and alert gaps. |

### Forbidden in any section
- BDD Acceptance Criteria (Given/When/Then) — removed
- Enforcement verbs: "enforces", "eliminates", "mandates", "blocks", "requires", "deploys"
- % compliance targets in Success Measures
- "Baseline Enforcement" in title

## Token Cost Discipline

- Read file before editing (never edit blind)
- Edit one feature block at a time
- Validate with grep after each edit
- No speculative large writes — plan first, write only after green light
- Phase number tracked in activity.log and plan prompts

## Scope Gates

All 12 Features: **COMPLETE** — Phase 12 finished 2026-06-13
- Phase 9–10: Feature 3 (PA) — template established
- Phase 11: Feature 1 (NS) — first application
- Phase 12: Features 2, 4–12 — all remaining features rewritten

**Next scope**: ADO import and task generation from v3 Excel rows (~3,000 Tasks from 118 xlsx files) — deferred
