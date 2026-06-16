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

**Phase 16**: IM user stories — `ado/user_stories/im.md` — COMPLETE (2026-06-14)
**Phase 17**: PA user stories — `ado/user_stories/pa.md` — COMPLETE (2026-06-14)
**Phase 18**: DP user stories — `ado/user_stories/dp.md` — COMPLETE (2026-06-14)
**Phase 19**: AM user stories — `ado/user_stories/am.md` — COMPLETE (2026-06-14)
**Phase 20**: LT user stories — `ado/user_stories/lt.md` — COMPLETE (2026-06-14)
**Phase 21**: IR user stories — `ado/user_stories/ir.md` — COMPLETE (2026-06-14)
**Phase 22**: PV user stories — `ado/user_stories/pv.md` — COMPLETE (2026-06-15)
**Phase 23**: ES user stories — `ado/user_stories/es.md` — COMPLETE (2026-06-15)
**Phase 24**: BR user stories — `ado/user_stories/br.md` — COMPLETE (2026-06-15)
**Phase 25**: DS user stories — `ado/user_stories/ds.md` — COMPLETE (2026-06-15)
**Phase 26**: GS user stories — `ado/user_stories/gs.md` — COMPLETE (2026-06-15)

**ALL 12 DOMAIN USER STORY FILES COMPLETE** — Phases 13–26 done.
**Phase 27**: ADO import scripts — `scripts/parse_stories.py`, `scripts/import_to_ado.py`, `scripts/ado_config.py`, `scripts/ado_import_README.md` — COMPLETE (2026-06-15)
**Phase 28**: Code review via Qwen3 — `scripts/code-review.md` — COMPLETE (2026-06-15). 3 fixes applied: WIQL injection, CSV existence check, 429 retry.

**Phase 29**: Policy coverage audit — `scripts/audit_policy_coverage.py` — COMPLETE (2026-06-15). confirmed=22, uncertain=48, none=90.
**Phase 30**: v3 relevance — `data/outputs/v3_controls.csv` — SUPERSEDED. Used wrong source (85-row benchmark definition). Replaced by Phase 34.
**Phase 31**: Automation feasibility — `data/outputs/automation_classes.csv` — SUPERSEDED. Used wrong source. Replaced by Phase 35.
**Phase 32**: Effort estimates — `data/outputs/effort_estimates.csv` + `effort_summary.csv` — COMPLETE (2026-06-15). 581h / 72.6 days. Baseline only — superseded for v3-combined stories by Phase 36.
**Phase 33**: Industry benchmark — `docs/assessment_benchmark.md` — COMPLETE (2026-06-15). Industry norm: 600-1,000h. Our revised estimate: 581h (in range).
**Phase 34**: Download 118 v3 per-service xlsx — `scripts/download_v3_baselines.py` — COMPLETE (2026-06-15). 4,157 rows, 118 services → `data/outputs/v3_service_controls_raw.csv`. Cache: `data/inputs/v3_baselines/` (gitignored).
**Phase 35**: Applicability + automation review — `scripts/review_v3_controls.py` — COMPLETE (2026-06-15). 905 customer rows (877 script_medium, 21 manual_only, 4 script_simple). 0 newly_applicable. → `data/outputs/v3_service_controls_reviewed.csv`.
**Phase 36**: Revised effort estimates (v3) — `scripts/estimate_effort_v3.py` — COMPLETE (2026-06-15). 152 stories, 119 v3-matched, 33 fallback. **Total: 696h / 87 days** (baseline). → `data/outputs/effort_estimates_v3.csv`.
**Phase 37**: Qwen3 reclassification — `scripts/extract_unique_controls.py` + `scripts/reclassify_v3_controls.py` — COMPLETE (2026-06-15). 34 unique control IDs → Qwen3 (local, qwen3:30b-a3b). 1,398 newly_applicable flips. Automation: script_simple=1,148 / script_medium=1,154 / manual_only=1. **Revised effort: 609h / 76.1 days**. → `data/outputs/v3_control_judgments.json`, `v3_service_controls_reclassified.csv`, `effort_estimates_v3_revised.csv`.
**Phase 38**: ADO wiki — `ado/wiki/delivery-approach.md` — COMPLETE (2026-06-15). 318 lines, 10 sections, mermaid diagram, stakeholder-ready ADO markdown. Covers full approach: scope, hierarchy, mapping, estimates, delivery phases.

**Phase 39**: NS re-estimation (filtered infra) — `scripts/estimate_effort_ns_filtered.py` — COMPLETE (2026-06-16). 15 services excluded (Batch, Communication Services, Communications Gateway, Container Apps, Digital Twins, HPC Cache, Machine Learning Service, Managed Lustre, Nutanix on Azure, Remote Rendering, SignalR Service, Spring Apps, Stack Edge, VMware Solution, Web PubSub) + azure-netapp-files from CSV pool. 37 active stories (52 total). **Revised NS: 124h / 15.5 days** (↓63h from 187h). → `data/outputs/effort_estimates_ns_filtered.csv`.

**Phase 40**: Scope reduction — IR + DS features CLOSED (out of infra scope). Updated total: **485h / 60.6 days** (10 domains). ado/wiki/delivery-approach.md updated with new estimate, scope table, and mermaid Gantt (Sprint 2 Jun 18 start, projected completion mid-Sep 2026, 1 FTE sequential assumption). (2026-06-16)

**Deferred**: ADO import execution (configure ado_config.py + export ADO_PAT, then run scripts). IR + DS features already closed in ADO — import only 10 active domains.
**Deferred**: Task generation from v3 Excel rows (~4,157 rows now reclassified in v3_service_controls_reclassified.csv).
**Deferred**: Infra-filter pass for remaining 9 domains (DP, GS, ES, PV, LT, PA, IM, BR, AM) — confirm excluded services per domain, re-run estimate_effort_ns_filtered.py pattern per domain. Each pass expected to reduce total estimate further.
