# Phase 43 Part 2 — Azure Key Vault MCSB v3 Baseline Re-Review

## 🔴 COMPLETED 2026-06-17
Phase 43 Part 2 has been executed successfully! The deliverables created:
1. `data/outputs/keyvault_na_research_2.json`: 16 stale Path B rows fully reviewed
2. `data/outputs/keyvault_rechecked_controls_2.csv`: 36 original baseline rows regenerated fresh, Redis-style reviewed CSV
3. Verified existing Key Vault scripts (scripts/assessment/keyvault/) inspected: all 9 domain files, 34 check functions registered
4. Updated ado/activity.log with progress

## Original content below preserved for historical reference.

---

This file captures the corrected understanding of Phase 43 Part 2 as plan prompts for a planning agent.

## Confidence

Confidence in this interpretation is greater than 90%.

Why:
- The source of truth is the original Microsoft Key Vault baseline xlsx:
  `data/inputs/v3_baselines/key-vault-azure-security-benchmark-v3-latest-security-baseline.xlsx`
- Redis Phase 43 Part 1 established the pattern:
  1. inspect all service rows from the original baseline,
  2. split into `Path B` stale `False` / `Not Applicable` rows needing research and `Path A` rows needing scripts,
  3. perform row-level research for stale rows,
  4. write assessment scripts,
  5. emit a reviewed per-service CSV that reflects the re-review.
- The current `keyvault_rechecked_controls.csv` should not be treated as the source of truth for planning. It is only a derived artifact and may be incomplete or in the wrong shape.

## Core Intent

Phase 43 Part 2 is not primarily "write a CSV from a supplied table."

Phase 43 Part 2 is:
- re-analyze the original Key Vault MCSB v3 baseline rows,
- inspect every `asb_control_id` / `feature_name` row for current 2026 reality,
- focus especially on rows Microsoft marked `False` or `Not Applicable` 3+ years ago,
- determine whether those stale rows are still truly not applicable or have become newly applicable,
- mirror the same Redis review workflow for Key Vault,
- then produce scripts, research JSON, and a reviewed CSV from that re-review.

## Feedback Analogy

This phase is like reopening an old building inspection from 2021 and walking every room again in 2026:
- the Microsoft xlsx is the old inspection sheet,
- `False` / `Not Applicable` rows are rooms previously marked "not installed" or "not relevant",
- Redis proved some of those old markings became outdated as Azure capabilities evolved,
- Key Vault needs the same fresh walkthrough, room by room, before writing the final inspection summary.

## Source Of Truth

Planning agent must treat these as primary evidence inputs:
- `CLAUDE.md`
- `docs/plan_prompt.md`
- `data/inputs/v3_baselines/key-vault-azure-security-benchmark-v3-latest-security-baseline.xlsx`
- `data/inputs/assessment_data/key-vault_controls.json`
- `data/outputs/redis_na_research.json`
- `data/outputs/redis_rechecked_controls.csv`

Planning agent may inspect these as current-state artifacts, but must not assume they are already correct:
- `data/outputs/keyvault_na_research.json`
- `data/outputs/keyvault_rechecked_controls.csv`
- `scripts/assessment/keyvault/`

Fresh-start rule:
- The planner should prefer regenerating Key Vault review artifacts from scratch from the original baseline rows.
- Existing Key Vault outputs and scripts are reference material only, not the base to preserve.
- If current Key Vault artifacts disagree with source-of-truth rows or Redis-pattern expectations, source-of-truth wins.

## Global Constraints

- Project root: `/Users/nahuelavalos/Repo/NewSecGap`
- Read `CLAUDE.md` first before proposing edits.
- Plan already approved and executing; do not invent a new project scope.
- Do not perform the work yet; only produce execution-ready prompts.
- Preserve the Redis Phase 43 Part 1 pattern unless the user explicitly overrides it.
- Azure SDK is not installed in dev, so validation must use AST parsing only, not import-based compile checks.
- `data/outputs/` is gitignored and must not be staged.
- `ado/activity.log` is append-only.
- Current workspace may contain partial or mid-task Key Vault work from a prior agent; planner must inspect before assuming completion.

## What Phase 43 Part 2 Really Produces

Expected artifact chain:
1. Extracted Key Vault control rows from the original baseline
2. Fresh Path B research file rebuilt row-by-row for stale `False` / `Not Applicable` rows
3. Fresh or reconciled Key Vault assessment scripts for all rows that are implemented or newly/conditionally applicable
4. AST validation and runner registration verification
5. A fresh Redis-style reviewed CSV derived from the original row set plus the re-review
6. Documentation/log updates and commit

## Task 1 Prompt — Rebuild The Row Inventory From Source

Use this prompt with the planning agent:

> You are planning Task 1 for Phase 43 Part 2 in `/Users/nahuelavalos/Repo/NewSecGap`.  
> Goal: rebuild the Key Vault worklist from source-of-truth baseline data, not from the current Key Vault CSV.  
>  
> Inputs to inspect:
> - `CLAUDE.md`
> - `docs/plan_prompt.md`
> - `data/inputs/v3_baselines/key-vault-azure-security-benchmark-v3-latest-security-baseline.xlsx`
> - `data/inputs/assessment_data/key-vault_controls.json`
>  
> Required planning outcome:
> 1. Confirm total Key Vault row count from source.
> 2. Enumerate every row by `asb_control_id` + `feature_name`.
> 3. Split rows into:
>    - `Path A`: rows that are supported / implemented and need script coverage
>    - `Path B`: rows originally marked `False` or `Not Applicable` that need current-state re-review
> 4. Explicitly identify stale rows whose 2021-2022 classification may have changed by 2026.
> 5. Treat the current `keyvault_rechecked_controls.csv` as an output candidate to be regenerated from scratch, not as the planning input.
>  
> Output expected from the planner:
> - A source-of-truth inventory workflow
> - A rule for classifying rows into Path A vs Path B
> - Acceptance criteria: all original Key Vault rows accounted for, none silently dropped

## Task 2 Prompt — Perform Path B Re-Review Of Stale Rows

Use this prompt with the planning agent:

> You are planning Task 2 for Phase 43 Part 2 in `/Users/nahuelavalos/Repo/NewSecGap`.  
> Goal: perform the same stale-row review that Redis received, but for Azure Key Vault.  
>  
> Context:
> - Microsoft marked some Key Vault rows `False` or `Not Applicable` years ago.
> - This task is to inspect whether those rows are still truly not applicable in 2026.
> - Review must be row-by-row, not just control-by-control.
> - Web-backed research is required where current capability status is uncertain.
>  
> Primary stale rows called out in planning notes:
> - `AM-5` Defender AAC
> - `ES-1` EDR
> - `ES-2` Anti-Malware
> - `ES-3` Anti-Malware Health
> - `PV-3` Automation State Config
> - `PV-3` Guest Config Agent
> - `PV-3` Custom Containers
> - `PV-3` Custom VM Images
> - `PV-6` Update Management
> - `PV-5` Defender VA
> - `DP-2` DLP
> - `DP-1` Sensitive Data Discovery
> - `PA-8` Customer Lockbox
> - `BR-1` Azure Backup
> - `PA-1` Local Admin Accounts
> - `IM-1` Local Authentication Methods
>  
> Required research method:
> 1. Compare the Redis pattern in `data/outputs/redis_na_research.json`.
> 2. For each stale Key Vault row, determine whether the 2026 verdict is:
>    - `still_not_applicable`
>    - `now_applicable_native`
>    - `conditional`
>    - or unchanged `implemented` / supported if the original row was merely stale
> 3. Capture evidence URL, evidence date, rationale, script feasibility, Azure API property if any, and suggested check.
> 4. Rebuild `data/outputs/keyvault_na_research.json` from scratch from the reviewed stale-row set.
> 5. Do not use vague placeholders like `see script` unless no stronger evidence is available.
>  
> Output expected from the planner:
> - A row-by-row research workflow
> - Clear evidence fields to capture for every reviewed stale row
> - Acceptance criteria: every stale Key Vault row has a 2026 verdict with rationale, not just a shorthand label

## Task 3 Prompt — Build Or Correct Path A Script Coverage

Use this prompt with the planning agent:

> You are planning Task 3 for Phase 43 Part 2 in `/Users/nahuelavalos/Repo/NewSecGap`.  
> Goal: ensure Key Vault script coverage matches the re-reviewed row set after Path B research, following the Redis domain-file pattern.  
>  
> Existing location:
> - `scripts/assessment/keyvault/`
>  
> Expected domain files:
> - `ns_keyvault.py`
> - `dp_keyvault.py`
> - `im_keyvault.py`
> - `lt_keyvault.py`
> - `br_keyvault.py`
> - `am_keyvault.py`
> - `pa_keyvault.py`
> - `es_keyvault.py`
> - `pv_keyvault.py`
> - `run_keyvault_assessment.py`
>  
> Planning requirements:
> 1. Inspect current Key Vault script coverage first; do not assume missing or complete.
> 2. Compare covered checks against the source row inventory and Path B verdicts.
> 2a. If the current Key Vault scripts are inconsistent with the source-reviewed row set, prefer rebuilding the mismatched portions rather than preserving drift.
> 3. Ensure each implemented / now-applicable / conditional row has an intended assessment path:
>    - concrete script check,
>    - automatic PASS rationale,
>    - or explicit UNKNOWN/conditional rationale if ARM cannot prove it directly.
> 4. Mirror Redis grouping and runner registration conventions.
> 5. Where a stale row flipped to applicable, confirm the associated check function exists or is planned.
>  
> Output expected from the planner:
> - A reconciliation between re-reviewed rows and Key Vault check functions
> - A gap list for any rows not yet covered by code or deliberate rationale
> - Acceptance criteria: row coverage and script coverage align

## Task 4 Prompt — Validate Key Vault Scripts

Use this prompt with the planning agent:

> You are planning Task 4 for Phase 43 Part 2 in `/Users/nahuelavalos/Repo/NewSecGap`.  
> Goal: validate current Key Vault script files without relying on Azure SDK imports.  
>  
> Required validation workflow:
> 1. Read `CLAUDE.md` first.
> 2. AST-validate all Key Vault Python files in `scripts/assessment/keyvault/`.
> 3. Verify runner registration count matches the actual intended Key Vault check set.
> 4. If any syntax issue or missing registry entry exists, fix only what is needed for consistency with the reviewed row inventory.
>  
> Output expected from the planner:
> - A minimal AST validation sequence
> - A registry reconciliation step against the reviewed row set
> - Acceptance criteria: all Key Vault files parse and runner coverage matches the intended checks

## Task 5 Prompt — Regenerate `keyvault_rechecked_controls.csv` In Redis Style

Use this prompt with the planning agent:

> You are planning Task 5 for Phase 43 Part 2 in `/Users/nahuelavalos/Repo/NewSecGap`.  
> Goal: regenerate `data/outputs/keyvault_rechecked_controls.csv` so it reflects the same kind of reviewed artifact Redis produced.  
>  
> Reference artifact:
> - `data/outputs/redis_rechecked_controls.csv`
>  
> Key rule:
> - Do not treat the current Key Vault CSV as canonical; regenerate from scratch from the original Key Vault rows plus Path B verdicts plus Path A/script metadata.
>  
> Planning requirements:
> 1. Inspect the Redis reviewed CSV and identify its effective schema and meaning.
> 2. Build the Key Vault reviewed CSV from source:
>    - original row values from Key Vault baseline / extracted JSON
>    - reviewed 2026 verdicts from Key Vault Path B research
>    - script linkage for Path A rows
> 3. Ensure every original Key Vault row is represented unless there is an explicit documented reason to exclude it.
> 4. Preserve research provenance and avoid over-compressing rows into vague summary text.
> 5. Match Redis-style evidence depth better than the current simplified Key Vault CSV.
>  
> Output expected from the planner:
> - The intended reviewed CSV schema
> - The merge logic between source rows, research verdicts, and script metadata
> - Acceptance criteria: Key Vault reviewed CSV is comparable in purpose and depth to Redis, not just a summary sheet

## Task 6 Prompt — Update `CLAUDE.md` And `ado/activity.log`

Use this prompt with the planning agent:

> You are planning Task 6 for Phase 43 Part 2 in `/Users/nahuelavalos/Repo/NewSecGap`.  
> Goal: update project tracking files only after the re-review, script coverage, validation, and reviewed CSV are truly aligned.  
>  
> Files:
> - `CLAUDE.md`
> - `ado/activity.log`
>  
> Planning requirements:
> 1. Read the surrounding entries first.
> 2. Insert or append only; never rewrite history.
> 3. Ensure any completion text reflects the actual Key Vault reviewed row counts, Path B outcomes, and validation results rather than stale assumptions.
>  
> Output expected from the planner:
> - Correct insertion / append strategy
> - A reminder to update counts only after validating them from source
> - Acceptance criteria: tracking text matches the real reviewed phase outputs

## Task 7 Prompt — Stage And Commit Safely

Use this prompt with the planning agent:

> You are planning Task 7 for Phase 43 Part 2 in `/Users/nahuelavalos/Repo/NewSecGap`.  
> Goal: create a clean commit after source review, research, scripts, validation, and docs are complete.  
>  
> Constraints:
> - Do not stage `data/outputs/`
> - Review `git status` first
> - Respect a potentially dirty worktree
> - Do not revert unrelated changes
>  
> Planning requirements:
> 1. Stage only tracked source files that represent the completed Key Vault phase.
> 2. Exclude gitignored output artifacts even if they are important for local verification.
> 3. Verify staged files align with the actual phase work completed.
>  
> Output expected from the planner:
> - A safe staging order
> - A pre-commit verification checklist
> - Acceptance criteria: only intended tracked files staged, outputs left unstaged

## Dependency Summary

Recommended execution order for the eventual implementer:
1. Rebuild Key Vault row inventory from source xlsx / extracted JSON
2. Perform Path B stale-row research
3. Reconcile Path A script coverage with reviewed verdicts
4. AST-validate Key Vault scripts and runner registration
5. Regenerate Redis-style Key Vault reviewed CSV from source + research + script metadata
6. Update `CLAUDE.md` and `ado/activity.log`
7. Stage tracked files and commit

## Definition Of Done

Phase 43 Part 2 is done only when:
- every original Key Vault baseline row has been accounted for,
- every stale `False` / `Not Applicable` row has a current 2026 verdict and rationale,
- Key Vault script coverage matches the reviewed applicable rows,
- Key Vault files pass AST validation,
- `keyvault_rechecked_controls.csv` is regenerated as a true reviewed artifact comparable to Redis,
- project tracking files reflect the real counts and outcomes,
- and the git commit excludes `data/outputs/`.
