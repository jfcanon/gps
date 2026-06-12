# Project Plan — Azure Infra Security Gap Assessment

## Problem Statement

Cloud engineering team needs ADO work items covering Azure security gaps against MCSB v2 (preview).
Previous Excel consolidation approach failed (too manual, AI Copilot insufficient).
ADO items blocked on gap list. Gap list blocked on consolidation. Loop broken here.

## Strategy: Unblock ADO First, Enrich Later

### Phase 1 — Scaffold ADO (NOW, no data needed)

Create 12 ADO Epics from MCSB v2 domains.
Under each Epic: Features per control group.
Under each Feature: Placeholder User Stories for each control.
Source: MCSB v2 domain list + v3 118-control cross-reference.

**Output:** `ado/epics.md`, `ado/features_by_domain.md`, `ado/user_stories_template.md`

### Phase 2 — Build Coverage Pipeline (scripts/)

Parse all input sources programmatically. No Excel.

```
scripts/
├── parse_optive_csv.py       # load Optive CSV, extract control IDs + status
├── parse_az_policy.py        # load Az Policy JSON → control coverage map
├── parse_az_defender.py      # load Defender JSON → control coverage map
├── parse_ado_export.py       # load ADO export → fuzzy match MCSB controls
└── build_gap_matrix.py       # join all → gap_matrix.csv
```

### Phase 3 — Map Gaps to ADO Items

Read gap_matrix.csv.
Filter: controls with NO coverage across all sources = net-new gap.
Output: `data/outputs/ado_items_to_create.csv`
Update ADO placeholder items with gap details.

### Phase 4 — Prioritize and Estimate

Score gaps: severity (MCSB criticality) × coverage (0/partial/full).
Assign story points.
Sequence into sprints.
Export ADO delivery plan.

## Current Inputs Checklist

- [YES] MCSB v2 domain list (fetch from MS Learn or GitHub)
- [YES, msft organized the 118 controls differently in v2 , so this might be a challenge, cause v2 also has its own controls not 100% related to v3, so it could be a mix, we might end up with more than 118 user stories] MCSB v3 GitHub Excel (118 controls) — for cross-reference
- [No, this will be managed elsewhere, first place holders, then we clean up user stories after we get full consolidated list] Optive CSV — drop in `data/inputs/optive_parsed.csv`
- [No, idem above] Az Policy JSON — drop in `data/inputs/az_policy.json`
- [No, idem above ] Defender JSON — drop in `data/inputs/az_defender.json`
- [No idem above] ADO export — drop in `data/inputs/ado_export.json` or `.csv`

## Decision Log

| Decision | Rationale |
|----------|-----------|
| Skip Excel consolidation | Manual join of 5 sources = error-prone. Script = repeatable |
| ADO placeholder items first | Unblocks team. Enrichment can happen async |
| MCSB v2 domains as Epics | v2 is current standard. v3 controls mapped under v2 structure |
| No Azure Policy/Defender → Excel | JSON → Python direct. No intermediate format needed |
| Optive CSV keep as-is | Already in MCSB v3 format. Direct join possible |

## MCSB v2 Domain → ADO Epic Mapping

| # | Domain | Code | Epic Title |
|---|--------|------|------------|
| 1 | Network Security | NS | [SEC] Network Security Controls — MCSB v2 |
| 2 | Identity Management | IM | [SEC] Identity Management Controls — MCSB v2 |
| 3 | Privileged Access | PA | [SEC] Privileged Access Controls — MCSB v2 |
| 4 | Data Protection | DP | [SEC] Data Protection Controls — MCSB v2 |
| 5 | Asset Management | AM | [SEC] Asset Management Controls — MCSB v2 |
| 6 | Logging and Threat Detection | LT | [SEC] Logging & Threat Detection Controls — MCSB v2 |
| 7 | Incident Response | IR | [SEC] Incident Response Controls — MCSB v2 |
| 8 | Posture and Vulnerability Management | PV | [SEC] Posture & Vulnerability Management — MCSB v2 |
| 9 | Endpoint Security | ES | [SEC] Endpoint Security Controls — MCSB v2 |
| 10 | Backup and Recovery | BR | [SEC] Backup & Recovery Controls — MCSB v2 |
| 11 | DevOps Security | DS | [SEC] DevOps Security Controls — MCSB v2 |
| 12 | Governance and Strategy | GS | [SEC] Governance & Strategy Controls — MCSB v2 |

## Next Actions

1. Confirm MCSB v2 domain list complete (fetch from MS Learn)
2. Drop input files into `data/inputs/`
3. Generate ADO epic/feature/story scaffold → `ado/`
4. Build parse scripts → `scripts/`
5. Run pipeline → `data/outputs/gap_matrix.csv`
6. Push repo, share with team
