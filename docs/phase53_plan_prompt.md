# Phase 53 — IM Domain ADO Import
## Plan Prompt (Persistent — reuse in new sessions)

**Last updated**: 2026-06-24
**Status**: READY — all IM assessment complete, ADO import is next step

---

## Critical Context: IM Is Already Assessed

All 9 IM domain v2 CSVs exist and pass 14-col validation:

| CSV slug | Service | Rows | Cols | IM Control |
|---|---|---|---|---|
| addds | Active Directory Domain Services | 35 | 14 ✓ | IM-1 |
| apimanagement | API Management | 35 | 14 ✓ | IM-5 |
| attestation | Attestation | 35 | 14 ✓ | IM-4 |
| botservice | Bot Service | 35 | 14 ✓ | IM-3 |
| cloudshell | Cloud Shell | 35 | 14 ✓ | IM-* |
| intelligentrecommendations | Intelligent Recommendations | 38 | 14 ✓ | IM-* |
| spatialanchors | Spatial Anchors | 36 | 14 ✓ | IM-7 |
| trustedhardwareim | Trusted Hardware Identity Mgmt | 35 | 14 ✓ | IM-4 |
| universalprint | Universal Print | 35 | 14 ✓ | IM-3 |

**DO NOT re-assess these.** Phase 53 = ADO import only.

---

## What Phase 53 Is

Import all 9 IM CSVs to Azure DevOps as Tasks under their parent IM User Stories.

One Task per CSV row. Each Task links to a parent User Story via `--parent-id`.

---

## IM User Stories (from ado/user_stories/im.md)

10 total. 7 combined (v2+v3) + 3 pure v2.

| ADO Story | Title | Resource | CSV | ADO Parent ID |
|---|---|---|---|---|
| SEC-1 | Use Centralized Identity and Authentication System | Active Directory Domain Services | addds | **FILL IN** |
| SEC-2 | Protect Identity and Authentication Systems | (pure v2 — no resource) | — | **FILL IN** |
| SEC-3 | Manage Application Identities: Bot Service | Bot Service | botservice | **FILL IN** |
| SEC-3 | Manage Application Identities: Universal Print | Universal Print | universalprint | **FILL IN** |
| SEC-4 | Authenticate Server and Services: Attestation | Attestation | attestation | **FILL IN** |
| SEC-4 | Authenticate Server and Services: THIM | Trusted Hardware IM | trustedhardwareim | **FILL IN** |
| SEC-5 | Use Single Sign-On for Application Access | API Management | apimanagement | **FILL IN** |
| SEC-6 | Use Strong Authentication Controls | (pure v2 — no resource) | — | **FILL IN** |
| SEC-7 | Restrict Resource Access Based on Conditions | Spatial Anchors | spatialanchors | **FILL IN** |
| SEC-8 | Restrict Exposure of Credential and Secrets | (pure v2 — no resource) | — | **FILL IN** |

**Extra services** (cloudshell, intelligentrecommendations): not in im.md User Stories above — map to closest IM control or ask user before importing.

**Pure v2 stories** (SEC-2, SEC-6, SEC-8): no per-resource CSV. Create a single summary Task manually in ADO, or skip import for these 3 stories and document as manual.

---

## Files to Read First

1. `docs/avd_task_import_guide.md` — import script usage, PAT setup, dry-run commands
2. `ado/user_stories/im.md` — 10 IM User Stories with full acceptance criteria
3. `scripts/ado_config.py` — verify ADO_ORG and ADO_PROJECT are set

---

## Pipeline Steps

### Step 1 — Prerequisites

```bash
cd /Users/nahuelavalos/Repo/NewSecGap
git pull origin master

# Verify all 9 IM CSVs pass validation
python3 -c "
import csv, glob
slugs = ['addds','apimanagement','attestation','botservice','cloudshell',
         'intelligentrecommendations','spatialanchors','trustedhardwareim','universalprint']
for s in slugs:
    rows = list(csv.DictReader(open(f'data/outputs/{s}_rechecked_controls_v2.csv')))
    cols = len(rows[0]) if rows else 0
    print(f'{s:30} rows={len(rows)} cols={cols} {\"OK\" if cols==14 else \"FAIL\"}')"

# Set PAT
export ADO_PAT=<your-personal-access-token>
```

All must show `cols=14`. If any show `cols=10`: STOP — that CSV needs schema upgrade before import.

### Step 2 — Get ADO User Story IDs

In Azure DevOps, navigate to the IM Feature User Stories. Get the numeric Work Item ID for each.
Fill in the table above under "ADO Parent ID".

The Feature name in ADO: `Security Domain #2: Identity Management (IM) Baselines`

### Step 3 — Dry run each service (one at a time)

```bash
cd scripts/

# Template — replace PARENT_ID for each service
python3 import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/{slug}_rechecked_controls_v2.csv \
    --parent-id {ADO_PARENT_ID} \
    --dry-run
```

Review dry-run output: expected row count, no schema errors, correct parent ID.

### Step 4 — Live import each service

```bash
python3 import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/{slug}_rechecked_controls_v2.csv \
    --parent-id {ADO_PARENT_ID}
```

Repeat for each of 9 services. Confirm Tasks appear under User Story in ADO.

### Step 5 — Handle pure v2 User Stories (SEC-2, SEC-6, SEC-8)

Options:
- A) Create 1 placeholder Task manually in ADO per User Story: "IM-{N} cross-cutting control — see User Story acceptance criteria"
- B) Skip — leave pure v2 stories with no Tasks (document this)
- C) Create a minimal CSV with 1 row per pure v2 story → import same way

Recommended: Option A — minimal manual Tasks noting it's a tenant-wide control, not per-resource.

### Step 6 — Verify in ADO

Open ADO → Boards → Work Items → IM Feature. Expand each User Story. Confirm Tasks created.

Expected Task counts:
- addds: 35 Tasks
- apimanagement: 35 Tasks
- attestation: 35 Tasks
- botservice: 35 Tasks
- cloudshell: 35 Tasks
- intelligentrecommendations: 38 Tasks
- spatialanchors: 36 Tasks
- trustedhardwareim: 35 Tasks
- universalprint: 35 Tasks
- Total: 319 Tasks

### Step 7 — Update activity.log

Append Phase 53 entry to `ado/activity.log`.

---

## Constraints

- Do NOT re-assess or overwrite any IM CSVs
- Dry-run before every live import
- Stop on any 401/403 error (PAT issue) — refresh PAT before continuing
- cloudshell and intelligentrecommendations: confirm which User Story to parent to before importing
- Pure v2 stories: decide Option A/B/C before running script

---

## Quality Gate

After all imports:

```bash
# ADO query — count Tasks under IM Feature
# Run in ADO via Work Item Query:
# [Work Item Type] = Task AND [Parent] IN (LIST_OF_IM_USER_STORY_IDS)
# Expected: ~319 Tasks + any pure v2 placeholders
```

All 9 IM CSVs imported → Tasks visible in ADO under correct User Stories.

---

## JSON-LD Plan Prompt

```json
{
  "@context": {
    "@vocab": "https://schema.org/",
    "nsg": "https://newsecgap.internal/ontology#"
  },
  "@type": "SoftwareProject",
  "@id": "nsg:phase-53-im-ado-import",
  "name": "NewSecGap Phase 53 — IM Domain ADO Import",
  "phase": "53",
  "projectRoot": "/Users/nahuelavalos/Repo/NewSecGap",
  "description": "Import all 9 Identity Management (IM) domain v2 CSVs to Azure DevOps as Tasks under IM User Stories. Assessment is already complete — all 9 CSVs are 14-col v2 standard. This phase is ADO Task creation only.",
  "targetDomain": {"name": "Identity Management", "termCode": "IM", "adoFeature": "Security Domain #2: Identity Management (IM) Baselines"},
  "importState": "READY — all 9 IM CSVs pass 14-col validation",
  "readFirst": [
    {"order": 1, "path": "docs/avd_task_import_guide.md", "why": "Import script usage, PAT setup, dry-run commands"},
    {"order": 2, "path": "ado/user_stories/im.md", "why": "10 IM User Stories — get ADO Work Item IDs"},
    {"order": 3, "path": "scripts/ado_config.py", "why": "ADO_ORG and ADO_PROJECT config"}
  ],
  "csvScope": {
    "totalCount": 9,
    "totalRows": 319,
    "services": [
      {"slug": "addds", "file": "addds_rechecked_controls_v2.csv", "rows": 35, "imControl": "IM-1"},
      {"slug": "apimanagement", "file": "apimanagement_rechecked_controls_v2.csv", "rows": 35, "imControl": "IM-5"},
      {"slug": "attestation", "file": "attestation_rechecked_controls_v2.csv", "rows": 35, "imControl": "IM-4"},
      {"slug": "botservice", "file": "botservice_rechecked_controls_v2.csv", "rows": 35, "imControl": "IM-3"},
      {"slug": "cloudshell", "file": "cloudshell_rechecked_controls_v2.csv", "rows": 35, "imControl": "IM-*"},
      {"slug": "intelligentrecommendations", "file": "intelligentrecommendations_rechecked_controls_v2.csv", "rows": 38, "imControl": "IM-*"},
      {"slug": "spatialanchors", "file": "spatialanchors_rechecked_controls_v2.csv", "rows": 36, "imControl": "IM-7"},
      {"slug": "trustedhardwareim", "file": "trustedhardwareim_rechecked_controls_v2.csv", "rows": 35, "imControl": "IM-4"},
      {"slug": "universalprint", "file": "universalprint_rechecked_controls_v2.csv", "rows": 35, "imControl": "IM-3"}
    ]
  },
  "pureV2Stories": [
    {"control": "IM-2", "title": "Protect Identity and Authentication Systems", "action": "Create placeholder Task manually in ADO"},
    {"control": "IM-6", "title": "Use Strong Authentication Controls", "action": "Create placeholder Task manually in ADO"},
    {"control": "IM-8", "title": "Restrict Exposure of Credential and Secrets", "action": "Create placeholder Task manually in ADO"}
  ],
  "executionSteps": [
    {"position": 1, "action": "PULL latest from master"},
    {"position": 2, "action": "VERIFY all 9 IM CSVs: 14 cols, rows > 0"},
    {"position": 3, "action": "GET ADO parent User Story IDs for each IM service from ADO"},
    {"position": 4, "action": "DRY RUN import for each service: python3 import_assessment_tasks_to_ado.py --csv ... --parent-id ... --dry-run"},
    {"position": 5, "action": "LIVE IMPORT each service (one at a time, confirm before next)"},
    {"position": 6, "action": "HANDLE pure v2 User Stories: create 1 placeholder Task each in ADO manually"},
    {"position": 7, "action": "VERIFY in ADO: ~319 Tasks under IM User Stories"},
    {"position": 8, "action": "UPDATE ado/activity.log"}
  ],
  "constraints": [
    "DO NOT re-assess or overwrite any IM CSVs",
    "Dry-run before every live import",
    "Stop on 401/403 — refresh PAT before continuing",
    "cloudshell and intelligentrecommendations: confirm parent User Story before importing",
    "keyvault_rechecked_controls_v2.csv is 10-col — DO NOT import until schema fixed"
  ],
  "blockers": [
    "ADO parent User Story IDs required (numeric Work Item IDs) — user must provide",
    "ADO_PAT environment variable must be set",
    "ADO_ORG and ADO_PROJECT in scripts/ado_config.py must be configured"
  ],
  "qualityGate": {
    "expectedTaskCount": 319,
    "mustPass": [
      "All 9 CSVs dry-run clean before live import",
      "319+ Tasks visible in ADO under IM User Stories",
      "No 4xx errors during import",
      "activity.log updated"
    ]
  },
  "phaseAfter": {
    "options": [
      "Phase 54: NS ADO import (34 NS CSVs → Tasks under NS User Stories)",
      "Phase 54: PA domain ADO import (3 PA CSVs: automation, customerlockbox, lighthouse)",
      "Phase 54: BR domain ADO import (2 BR CSVs: backup, siterecovery)"
    ]
  }
}
```
