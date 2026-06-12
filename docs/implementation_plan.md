# Implementation Plan — Azure Infra Security Gap Assessment

**Repo**: `/Users/nahuelavalos/Repo/NewSecGap`  
**Complexity**: Large  
**Estimated User Stories**: 150–200+ (more than 118, see Control Unification below)

---

## Summary

Replace failed Excel consolidation with a Python pipeline that joins 5 input sources against a unified MCSB control list, outputs a gap matrix, and generates ADO work items. Primary challenge: MCSB v3 (118 controls, per-resource) and v2 (own controls, per-domain) were never officially cross-mapped — this plan defines how to resolve that. ADO scaffold created first (no data dependency), pipeline built second.

---

## Critical Design Decision — Control Unification

### The Problem

MCSB v3 organized controls **per Azure resource** (118 controls, e.g., "Azure SQL — Restrict network access").  
MCSB v2 reorganized around **12 security domains** with its own control numbering (e.g., NS-1, NS-2...).  
Microsoft never published an official v3 → v2 cross-reference map.

This means:
- v2 controls and v3 controls are **parallel lists**, not a rename
- Both sets are relevant — neither supersedes the other fully
- Some v3 controls will map cleanly to a v2 control (same intent, different scope)
- Some v3 controls have no v2 equivalent (resource-specific detail)
- Some v2 controls have no v3 equivalent (new guidance added in v2)

### Resolution Strategy — Option A (Preferred)

Build a **unified master control list** per v2 domain. Each row can have three sources:

| source value | meaning |
|---|---|
| `v2` | Control exists in MCSB v2 only — no v3 equivalent found |
| `v3` | Control from v3 mapped to this domain — no direct v2 equivalent |
| `v2+v3` | Merged: v2 control and v3 control cover same intent |

**Schema for master control list** (`data/outputs/master_controls.csv`):

```
unified_id        | String  | Canonical ID: use v2 ID (NS-1) when available, else synthetic (NS-v3-001)
domain_code       | String  | NS / IM / PA / DP / AM / LT / IR / PV / ES / BR / DS / GS
domain_name       | String  | Full domain name
control_title     | String  | Canonical title (v2 title preferred, or descriptive title for v3-only)
source            | Enum    | v2 / v3 / v2+v3
v2_control_id     | String  | MCSB v2 control ID (e.g., NS-1) — null if v3-only
v2_control_title  | String  | MCSB v2 original title — null if v3-only
v3_control_id     | String  | MCSB v3 control ID (e.g., AZ-STOR-001) — null if v2-only
v3_resource       | String  | Azure resource name from v3 (e.g., Azure Storage) — null if v2-only
v3_control_title  | String  | MCSB v3 original title — null if v2-only
severity          | Enum    | High / Medium / Low
implementation_type | Enum  | Automated / Manual / Hybrid
notes             | String  | Merge rationale or mapping decision notes
```

### v3 → v2 Domain Mapping (Deductive Rules)

Use these rules in `map_v3_to_v2_domains.py` to assign each v3 control to a v2 domain:

| v3 Control Pattern | Maps to v2 Domain |
|---|---|
| Network access restriction, firewall, private endpoint, NSG | NS — Network Security |
| Identity, authentication, MFA, service principal, managed identity | IM — Identity Management |
| Admin access, privileged role, PIM, just-in-time | PA — Privileged Access |
| Encryption at rest, encryption in transit, key management, CMK, TLS | DP — Data Protection |
| Inventory, tagging, resource classification, CMDB | AM — Asset Management |
| Audit logging, diagnostic settings, log analytics, SIEM, alerts | LT — Logging and Threat Detection |
| Incident response, alert handling, security contact | IR — Incident Response |
| Vulnerability assessment, patch management, Defender for Cloud, secure score | PV — Posture and Vulnerability Management |
| Endpoint protection, antimalware, EDR, VM agent | ES — Endpoint Security |
| Backup policy, geo-redundancy, restore testing, retention | BR — Backup and Recovery |
| CI/CD security, IaC scanning, code secrets, pipeline hardening | DS — DevOps Security |
| Policy assignment, RBAC governance, compliance reporting, security strategy | GS — Governance and Strategy |

**Ambiguous controls** (e.g., TLS + logging both relevant): assign to **primary intent** domain; add `cross_ref_domain` field pointing to secondary.

### Estimated Control Counts Post-Unification

| Domain | v2 Controls (est.) | v3 Mapped (est.) | Merged (est.) | Net Total |
|---|---|---|---|---|
| NS | 10 | 18 | 6 | ~22 |
| IM | 8 | 12 | 4 | ~16 |
| PA | 7 | 8 | 3 | ~12 |
| DP | 9 | 22 | 7 | ~24 |
| AM | 5 | 6 | 2 | ~9 |
| LT | 10 | 14 | 5 | ~19 |
| IR | 4 | 3 | 1 | ~6 |
| PV | 8 | 15 | 5 | ~18 |
| ES | 5 | 8 | 3 | ~10 |
| BR | 5 | 7 | 2 | ~10 |
| DS | 6 | 3 | 1 | ~8 |
| GS | 7 | 2 | 1 | ~8 |
| **TOTAL** | **~84** | **~118** | **~40** | **~162** |

**Result: ~162 user stories across 12 epics.** (±20 depending on actual merge decisions)

---

## Phase 0 — Fetch & Build Master Control List

**Goal**: Produce `data/outputs/master_controls.csv` — the authoritative row source for all downstream work.  
**No data inputs from customer required** (MCSB is public).

### Files

| File | Action | Description |
|---|---|---|
| `scripts/fetch_mcsb_v2.py` | CREATE | Fetch MCSB v2 controls from Microsoft GitHub |
| `scripts/load_mcsb_v3.py` | CREATE | Load MCSB v3 GitHub Excel (118 controls) |
| `scripts/map_v3_to_v2_domains.py` | CREATE | Apply domain mapping rules to v3 controls |
| `scripts/build_master_controls.py` | CREATE | Merge v2 + mapped v3 → master_controls.csv |
| `data/outputs/master_controls.csv` | GENERATED | Unified control list ~162 rows |

### Script Specs

#### `fetch_mcsb_v2.py`
```python
# Inputs:  None (fetches from public GitHub)
# Outputs: data/outputs/mcsb_v2_raw.csv
#
# Target URL: 
#   https://raw.githubusercontent.com/MicrosoftDocs/SecurityBenchmarks/master/
#   Azure%20Security%20Benchmark/3.0/azure-security-benchmark-v3-latest.xlsx
#   (v2 preview may be at a different path — confirm on first run)
#
# Key functions:
#   fetch_excel(url) -> pd.DataFrame
#   normalize_columns(df) -> df  # standardize column names
#   extract_controls(df) -> List[Control]
```

#### `load_mcsb_v3.py`
```python
# Inputs:  data/inputs/mcsb_v3.xlsx (download manually from GitHub if needed)
# Outputs: data/outputs/mcsb_v3_raw.csv
#
# Expected v3 columns (from GitHub Excel):
#   ID, Azure Service, Control Title, Description, Guidance, 
#   Responsibility, Feature, Policy/Implementation
#
# Key functions:
#   load_excel(path) -> pd.DataFrame
#   extract_v3_controls(df) -> List[V3Control]
```

#### `map_v3_to_v2_domains.py`
```python
# Inputs:  data/outputs/mcsb_v3_raw.csv
# Outputs: data/outputs/mcsb_v3_mapped.csv  (adds: domain_code, domain_name, mapping_confidence)
#
# Key functions:
#   apply_keyword_rules(control) -> (domain_code, confidence: High/Medium/Low)
#   flag_ambiguous(df) -> df  # mark Low confidence for manual review
#
# mapping_confidence:
#   High   = single keyword match, clear intent
#   Medium = multiple keywords, best-guess domain assigned
#   Low    = ambiguous, flagged for manual review in notes
```

#### `build_master_controls.py`
```python
# Inputs:  
#   data/outputs/mcsb_v2_raw.csv
#   data/outputs/mcsb_v3_mapped.csv
# Outputs: 
#   data/outputs/master_controls.csv
#
# Key functions:
#   match_v2_v3(v2_row, v3_row) -> bool  # title similarity > 0.8 = merge candidate
#   merge_controls(v2_row, v3_row) -> unified_row  # source = 'v2+v3'
#   assign_synthetic_id(domain_code, seq) -> str  # e.g., NS-v3-001
#   build_unified_list(v2_df, v3_mapped_df) -> pd.DataFrame
```

---

## Phase 1 — ADO Scaffold

**Goal**: Create placeholder ADO work items for all 12 domains now. No data required. Unblocks cloud eng team.

### Files

| File | Action | Description |
|---|---|---|
| `ado/epics.md` | CREATE | 12 epic definitions with all fields |
| `ado/features_by_domain.md` | CREATE | Features grouped under each epic |
| `ado/user_stories_template.md` | CREATE | Template + examples for user stories |
| `ado/ado_import_template.csv` | CREATE | CSV ready for ADO bulk import |

### ADO Work Item Hierarchy

```
Epic (12 total — one per MCSB v2 domain)
  └── Feature (1 per control group within domain, ~3-5 per epic)
        └── User Story (1 per unified control, ~162 total)
              └── Task (implementation sub-steps, added during sprint planning)
```

### ADO Item Field Definitions

#### Epic Template

```
Title:       [SEC] {Domain Name} Controls — MCSB v2
Tags:        MCSB-v2; security-gap; {domain_code}; azure-infra-sec
Area Path:   {team area path}
Iteration:   Backlog
Description: 
  ## MCSB v2 Domain: {Domain Name} ({domain_code})
  
  This epic tracks all security controls for the {Domain Name} domain 
  as defined in Microsoft Cloud Security Benchmark v2 (preview).
  
  Unified control count: {N} (includes MCSB v2 native + MCSB v3 resource-level controls)
  
  Reference: https://learn.microsoft.com/en-us/security/benchmark/azure/
  
  Source mapping:
  - MCSB v2 controls: {count}
  - MCSB v3 controls mapped to this domain: {count}
  - Merged (v2+v3 same intent): {count}
```

#### Feature Template

```
Title:       [SEC-{DOMAIN}] {Control Group Name}
Parent Epic: [SEC] {Domain Name} Controls — MCSB v2
Tags:        MCSB-v2; {domain_code}; {control_group_tag}
Description:
  ## Control Group: {Control Group Name}
  
  Groups related MCSB controls for {domain} domain.
  Controls in this feature: {control_id_list}
```

#### User Story Template

```
Title:       [SEC-{DOMAIN}-{ID}] {Control Title} — {Azure Resource if v3-only}
Parent:      [SEC-{DOMAIN}] {Control Group Name}
Tags:        MCSB-v2; {domain_code}; {source: v2|v3|v2+v3}; {severity}; gap-assessment
Story Points: {see estimation matrix below}

Description:
  ## Security Control: {Control Title}
  
  **Control ID**: {unified_id}
  **Domain**: {domain_name} ({domain_code})
  **Severity**: {High | Medium | Low}
  **Source**: {v2 | v3 | v2+v3}
  
  ### MCSB v2 Reference
  {v2_control_id}: {v2_control_title}
  {v2_description}
  
  ### MCSB v3 Reference (if applicable)
  Resource: {v3_resource}
  Control: {v3_control_title}
  {v3_description}
  
  ### Current State
  - Optive assessment: {covered | not_covered | partial | unknown}
  - Azure Policy: {enforced | audit | not_configured | unknown}
  - Defender for Cloud: {covered | not_covered | unknown}
  - ADO existing item: {link if found | none detected}
  
  ### Gap Status
  {GAP | PARTIAL | COVERED | UNKNOWN}
  
  ### What Needs to Be Done
  {description of implementation work — populated after gap matrix run}

Acceptance Criteria:
  - [ ] Control implementation verified in Azure environment
  - [ ] Azure Policy assigned and in Enforce mode (where applicable)
  - [ ] Defender for Cloud alert/recommendation resolved (where applicable)
  - [ ] Evidence documented (screenshot, policy export, or audit log)
  - [ ] MCSB control marked COVERED in gap_matrix.csv
  - [ ] ADO item updated with completion evidence link
```

#### Story Point Estimation Matrix

| Implementation Type | Severity | Story Points |
|---|---|---|
| Automated (Policy + Defender) | High | 3 |
| Automated (Policy + Defender) | Medium | 2 |
| Automated (Policy + Defender) | Low | 1 |
| Manual / Hybrid | High | 8 |
| Manual / Hybrid | Medium | 5 |
| Manual / Hybrid | Low | 3 |
| Requires Architecture Change | Any | 13 |

---

## Phase 2 — Python Coverage Pipeline

**Goal**: Parse all 4 customer input sources, join against master_controls.csv, produce gap_matrix.csv.

### Files

| File | Action | Description |
|---|---|---|
| `scripts/parse_optive_csv.py` | CREATE | Load Optive CSV → coverage map |
| `scripts/parse_az_policy.py` | CREATE | Parse Az Policy JSON → control coverage |
| `scripts/parse_az_defender.py` | CREATE | Parse Defender JSON → control coverage |
| `scripts/parse_ado_export.py` | CREATE | Load ADO export → fuzzy match MCSB controls |
| `scripts/build_gap_matrix.py` | CREATE | Join all → gap_matrix.csv |
| `scripts/requirements.txt` | CREATE | pandas, rapidfuzz, openpyxl, requests |

### Script Specs

#### `parse_optive_csv.py`
```python
# Inputs:  data/inputs/optive_parsed.csv
#          (already in MCSB v3 column format from docling parse)
# Outputs: data/outputs/optive_coverage.csv
#
# Expected input columns (MCSB v3 format):
#   Control ID, Azure Service, Control Title, Status, Notes, Remediation
#
# Output columns:
#   v3_control_id, optive_status, optive_notes
#   optive_status values: Covered / Partial / Not Covered / Not Assessed
#
# Key functions:
#   normalize_optive_status(raw_status: str) -> str
#   extract_coverage(df) -> pd.DataFrame
```

#### `parse_az_policy.py`
```python
# Inputs:  data/inputs/az_policy.json
# Outputs: data/outputs/az_policy_coverage.csv
#
# Az Policy JSON structure (typical export):
#   policyAssignments[].{name, displayName, policyDefinitionId, 
#                        enforcementMode, complianceState}
#
# Output columns:
#   policy_name, policy_display_name, enforcement_mode, 
#   compliance_state, mcsb_control_ref, az_policy_covered
#
# Key functions:
#   extract_assignments(json_data) -> List[PolicyAssignment]
#   map_policy_to_mcsb(assignment) -> Optional[str]  # returns unified_id or None
#   classify_coverage(assignment) -> str  # Enforced / Audit / Not Configured
#
# Note: Az Policy assignment names often contain MCSB control IDs in metadata.
#       Check policyDefinitionId for patterns like "mcsb", "azure-security-benchmark"
```

#### `parse_az_defender.py`
```python
# Inputs:  data/inputs/az_defender.json
# Outputs: data/outputs/az_defender_coverage.csv
#
# Defender JSON structure (typical export from Defender for Cloud):
#   securityAssessments[].{displayName, status.code, 
#                          resourceDetails, metadata.severity,
#                          metadata.implementationEffort}
#
# Output columns:
#   recommendation_name, status, severity, mcsb_control_ref, defender_covered
#
# Key functions:
#   extract_recommendations(json_data) -> List[Recommendation]
#   map_recommendation_to_mcsb(rec) -> Optional[str]  # unified_id
#   classify_defender_coverage(status_code) -> str  # Covered / Not Covered / N/A
#
# Note: Defender recommendations often have direct MCSB mapping in metadata.
#       Check metadata.userImpact, metadata.categories for domain hints.
```

#### `parse_ado_export.py`
```python
# Inputs:  
#   data/inputs/ado_export.json (or .csv)
#   data/outputs/master_controls.csv
# Outputs: data/outputs/ado_coverage.csv
#
# ADO item fields to extract:
#   ID, Title, State, Tags, Description, AreaPath, IterationPath
#
# Output columns:
#   ado_item_id, ado_title, ado_state, matched_unified_id, 
#   match_confidence, ado_covered
#
# Key functions:
#   load_ado_items(path) -> pd.DataFrame
#   fuzzy_match_control(ado_title, control_titles) -> (unified_id, score)
#     # Use rapidfuzz.process.extractOne, threshold=75
#   tag_match(ado_tags, domain_codes) -> Optional[str]  # check tags for MCSB refs
#   classify_ado_coverage(state, confidence) -> str  # Covered / Likely / Not Found
#
# Match confidence thresholds:
#   score >= 90 → High (mark as Covered)
#   score 75-89 → Medium (mark as Likely — needs human review)
#   score < 75  → No match
```

#### `build_gap_matrix.py`
```python
# Inputs:
#   data/outputs/master_controls.csv
#   data/outputs/optive_coverage.csv
#   data/outputs/az_policy_coverage.csv
#   data/outputs/az_defender_coverage.csv
#   data/outputs/ado_coverage.csv
# Outputs:
#   data/outputs/gap_matrix.csv
#   data/outputs/ado_items_to_create.csv  (GAP rows only)
#
# Key functions:
#   join_all_sources(master, optive, policy, defender, ado) -> pd.DataFrame
#   compute_gap_status(row) -> str  # see logic below
#   score_priority(row) -> float
#   export_gaps(df) -> pd.DataFrame
```

---

## Phase 3 — Gap Matrix Schema

### `data/outputs/gap_matrix.csv` — Full Schema

```
unified_id            | String  | Canonical control ID (v2 ID or synthetic)
domain_code           | String  | NS / IM / PA / DP / AM / LT / IR / PV / ES / BR / DS / GS
domain_name           | String  | Full domain name
control_title         | String  | Canonical control title
source                | Enum    | v2 / v3 / v2+v3
v2_control_id         | String  | MCSB v2 ID — null if v3-only
v3_control_id         | String  | MCSB v3 ID — null if v2-only
v3_resource           | String  | Azure resource — null if v2-only
severity              | Enum    | High / Medium / Low
implementation_type   | Enum    | Automated / Manual / Hybrid
optive_covered        | Enum    | Covered / Partial / Not Covered / Not Assessed / Unknown
az_policy_covered     | Enum    | Enforced / Audit / Not Configured / Unknown
defender_covered      | Enum    | Covered / Not Covered / N/A / Unknown
ado_covered           | Enum    | Covered / Likely / Not Found
ado_item_id           | String  | ADO item ID if matched — null otherwise
ado_match_confidence  | Enum    | High / Medium / None
gap_status            | Enum    | COVERED / PARTIAL / GAP / UNKNOWN
priority_score        | Float   | 0.0–10.0 (see formula below)
notes                 | String  | Manual notes, merge rationale, ambiguity flags
```

### `gap_status` Logic

```python
def compute_gap_status(row) -> str:
    covered_sources = sum([
        row['optive_covered'] == 'Covered',
        row['az_policy_covered'] == 'Enforced',
        row['defender_covered'] == 'Covered',
        row['ado_covered'] == 'Covered',
    ])
    partial_sources = sum([
        row['optive_covered'] == 'Partial',
        row['az_policy_covered'] == 'Audit',
        row['ado_covered'] == 'Likely',
    ])
    unknown_sources = sum([
        v == 'Unknown' for v in [
            row['optive_covered'], row['az_policy_covered'],
            row['defender_covered'], row['ado_covered']
        ]
    ])

    if covered_sources >= 2:
        return 'COVERED'
    elif covered_sources == 1 or partial_sources >= 1:
        return 'PARTIAL'
    elif unknown_sources == 4:
        return 'UNKNOWN'
    else:
        return 'GAP'
```

### Priority Score Formula

```python
SEVERITY_WEIGHT = {'High': 3.0, 'Medium': 2.0, 'Low': 1.0}
COVERAGE_SCORE  = {'COVERED': 1.0, 'PARTIAL': 0.5, 'UNKNOWN': 0.3, 'GAP': 0.0}

def score_priority(row) -> float:
    sev   = SEVERITY_WEIGHT.get(row['severity'], 1.0)
    cov   = COVERAGE_SCORE.get(row['gap_status'], 0.0)
    return round(sev * (1.0 - cov), 2)  # range: 0.0 (covered) to 3.0 (high/gap)
```

### `data/outputs/ado_items_to_create.csv` — Schema (subset of gap_matrix)

```
unified_id, domain_code, control_title, severity, gap_status, 
priority_score, v2_control_id, v3_resource, implementation_type,
ado_epic_title, ado_feature_title, ado_story_title, story_points,
tags, description_stub
```

---

## Phase 4 — Prioritization & Sprint Sequencing

### Sprint Sequencing Recommendation

```
Sprint 1 (setup):     Phase 0 scripts — build master_controls.csv
Sprint 2 (scaffold):  Phase 1 — generate ADO epics/features/stories (placeholders)
Sprint 3 (parse):     Phase 2 scripts — parse all 5 input sources
Sprint 4 (gap):       Phase 3 — run gap_matrix, identify GAP rows
Sprint 5 (enrich):    Enrich ADO placeholder items with gap data
Sprint 6+ (remediate):Cloud eng team executes actual security controls
```

### Domain Priority Order (recommended sequence for remediation)

Based on typical risk exposure for Azure infra:

1. **IM** — Identity Management (highest breach vector)
2. **PA** — Privileged Access (lateral movement risk)
3. **NS** — Network Security (perimeter)
4. **DP** — Data Protection (compliance driver)
5. **LT** — Logging & Threat Detection (detection gap risk)
6. **PV** — Posture & Vulnerability Management
7. **GS** — Governance & Strategy
8. **AM** — Asset Management
9. **ES** — Endpoint Security
10. **BR** — Backup & Recovery
11. **IR** — Incident Response
12. **DS** — DevOps Security

---

## Files to Create — Summary

```
NewSecGap/
├── scripts/
│   ├── requirements.txt
│   ├── fetch_mcsb_v2.py
│   ├── load_mcsb_v3.py
│   ├── map_v3_to_v2_domains.py
│   ├── build_master_controls.py
│   ├── parse_optive_csv.py
│   ├── parse_az_policy.py
│   ├── parse_az_defender.py
│   ├── parse_ado_export.py
│   └── build_gap_matrix.py
├── ado/
│   ├── epics.md
│   ├── features_by_domain.md
│   ├── user_stories_template.md
│   └── ado_import_template.csv
├── data/
│   ├── inputs/          (gitignored — drop files here)
│   └── outputs/         (gitignored — generated)
│       ├── mcsb_v2_raw.csv
│       ├── mcsb_v3_raw.csv
│       ├── mcsb_v3_mapped.csv
│       ├── master_controls.csv
│       ├── optive_coverage.csv
│       ├── az_policy_coverage.csv
│       ├── az_defender_coverage.csv
│       ├── ado_coverage.csv
│       ├── gap_matrix.csv
│       └── ado_items_to_create.csv
└── docs/
    └── implementation_plan.md  (this file)
```

---

## Open Questions / Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| MCSB v2 GitHub Excel location unknown / format differs | Medium | Confirm URL on first fetch; fallback to manual MS Learn scrape |
| Optive CSV column names differ from expected v3 format | Medium | Add column detection step in parse_optive_csv.py; log actual columns |
| Az Policy JSON has no MCSB metadata (no control ID in policy) | High | Fallback: keyword match on policy displayName against control titles |
| Defender JSON schema varies by export method (portal vs API) | Medium | Handle both schemas; detect on load |
| ADO export is XML not JSON/CSV | Low | Add XML parser branch in parse_ado_export.py |
| Fuzzy match produces false positives in ADO coverage | High | Set threshold at 85+ for auto-Covered; 75-84 = Likely (human review) |
| >162 controls = sprint overload for cloud eng team | Medium | Phase remediation — GAP + High severity first; PARTIAL and Low later |
| v3 → v2 domain mapping ambiguity for ~15% of controls | Medium | Flag as Low confidence; build manual review list in master_controls.csv |

---

## Acceptance Criteria

- [ ] `master_controls.csv` generated — all v2 + v3 controls unified, ~150-200 rows
- [ ] 12 ADO Epics defined in `ado/epics.md` with all field values
- [ ] ADO User Stories created for all controls with correct parent hierarchy
- [ ] All 5 parse scripts run without error on sample inputs
- [ ] `gap_matrix.csv` produced with all columns populated
- [ ] `ado_items_to_create.csv` contains only GAP-status rows
- [ ] Priority scores assigned to all GAP rows
- [ ] Repo pushed and shared with team

---

**WAITING FOR CONFIRMATION**: Proceed with implementation? Start with Phase 0 (build master controls) or Phase 1 (ADO scaffold first)?
