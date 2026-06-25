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

**Phase 43 Part 0**: Assessment script infrastructure — COMPLETE (2026-06-16). `scripts/extract_service_controls.py` (CSV→JSON, raw+reclassified join). `scripts/assessment/redis/` folder + README + runner skeleton. `data/outputs/redis_na_research.json` template. Validation: 35 rows → `data/inputs/assessment_data/azure-cache-for-redis_controls.json`.

**Phase 43 Part 1**: Azure Cache for Redis assessment scripts — COMPLETE (2026-06-16). PATH B: 14 N/A rows researched → 4 now_applicable_native (IM-1 AAD, IM-3 MI, IM-3 SP, PA-7 RBAC — all via Entra GA Nov 2024), 7 still_not_applicable, 3 conditional. PATH A: 9 domain files (ns/dp/im/lt/br/am/pa/es/pv_redis.py), 34 check functions, all registered in CHECK_REGISTRY. 34/34 AST-validated. Output: `data/outputs/redis_rechecked_controls.csv` (35 rows: 14 implemented, 4 upgraded, 3 conditional, 14 N/A).

**ADO import**: Managed by separate AI agent on Azure-connected VM. Not in this project's scope.
**Deferred**: Task generation from v3 Excel rows (~4,157 rows now reclassified in v3_service_controls_reclassified.csv).
**Deferred**: Infra-filter pass for remaining 9 domains (DP, GS, ES, PV, LT, PA, IM, BR, AM) — confirm excluded services per domain, re-run estimate_effort_ns_filtered.py pattern per domain. Each pass expected to reduce total estimate further.

**Phase 44**: NS bastion gap assessment — Azure Bastion executor scripts. Part of v2 assessment pipeline. (2026-06-22)

**Phase 45**: IM domain CSVs — 8 services (addds, apimanagement, attestation, botservice, cloudshell, intelligentrecommendations, spatialanchors, universalprint). 292 rows. 10-col schema. All validated. `data/outputs/*_rechecked_controls.csv`. (2026-06-22)

**Phase 46**: BR domain CSVs — 2 services (backup, siterecovery). 71 rows. All validated. (2026-06-24)

**Phase 47**: PA domain CSVs — 3 services (automation, customerlockbox, lighthouse). 105 rows. All validated. Cloud Shell skipped (done Phase 45). (2026-06-24)

**Phase 48**: CSV schema fix + NS web-search verdict review — Schema upgraded 5 files to 14-col v2. Exa web research on 14 NS service CSVs: 16 `*_na_research.json` caches created. 5 rows flipped to now_applicable_native. 21 legacy bad verdicts fixed. (2026-06-24)

**Phase 49**: CSPM secondary assessment layer — `data/outputs/*_rechecked_controls_v2.csv` generation. Blast radius + risk_rank scoring added. (2026-06-24)

**Phase 50**: Housekeeping — v2 schema enforced across all 29 CSVs. Archive pass. context.md created at `data/outputs/context.md`. (2026-06-24)

**Phase 51**: data/outputs context audit — `data/outputs/context.md` updated. Inventory of all 65+ files. keyvault anomaly (10-col) flagged. (2026-06-24)

**Phase 52**: NS domain 20 remaining services assessed — output: `data/outputs/{slug}_rechecked_controls_v2.csv` (14-col v2, in data/outputs/ NOT ns/). ~700 rows. Total NS assessed: 34 services. NOTE: final.csv in ns/ NOT yet created for these 20 — that is Session 6 / Phase 57 scope. (2026-06-24). Plan prompt: `docs/phase52_plan_prompt.md`.

**Phase 55**: NS original 14 CSVs enriched to 95%+ confidence — Q1 Exa web research (47 searches), standard rationale (125+ rows), verdict corrections (6 Phase 48 cache errors reverted), Q2 supplement rows (NS-6 azurefirewall, NS-7 redis+servicebus). Quality gate: 14/14 PASS. Scripts: `scripts/phase55_*.py`. (2026-06-24)

**Phase 56**: NS 14 CSVs URL backfill + June 2026 re-search + Q2 audit — 86 bulk rows covered, 16 individual patches, 3 Q2 supplement rows (azuredns NS-1-SUPPLEMENT, appgateway NS-7-SUPPLEMENT-APPGW, frontdoor NS-2-SUPPLEMENT). azuredns PA-7 flipped conditional→now_applicable_native. Quality gate 14/14 PASS. ~95%+ confidence. (2026-06-24)

**Current state (Phase 56 complete)**:
- `data/outputs/ns/` — 14 enriched NS CSVs. Quality gate PASS. ~95%+ confidence after Phase 56 (5 residual uncovered rows are legitimate no-data-plane cases).
- `data/outputs/{slug}_rechecked_controls_v2.csv` — 20 NS Phase 52 CSVs exist but NOT in ns/ yet, NOT Exa-enriched. These are Session 6 / Phase 57 scope.
- Next: Session 6 / Phase 57 — Finalize 20 NS Phase 52 CSVs: copy to data/outputs/ns/{slug}.final.csv + Exa-enrich (same Phase 56 approach). Pivot from IM domain — IM deferred to Session 7.
- Blocked: Phase 53 IM ADO import — awaiting User Story IDs from user.
