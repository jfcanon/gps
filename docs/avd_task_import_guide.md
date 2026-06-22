# AVD Task Import Guide — Phase 45 IM Domain CSVs

## What This Does

Creates ADO Tasks (children of User Stories) from `*_rechecked_controls.csv` files.
One Task per CSV row. Task is linked to parent User Story found by `asb_control_id` + service tag.

Script: `scripts/import_assessment_tasks_to_ado.py`

---

## Prerequisites (do once on AVD)

### 1. Pull latest from GitHub

```bash
cd <repo_path>
git pull origin master
```

### 2. Install dependencies

```bash
pip install requests python-dotenv
```

### 3. Configure ADO connection

Edit `scripts/ado_config.py`:
```python
ADO_ORG     = "https://dev.azure.com/YOUR_ORG"
ADO_PROJECT = "YOUR_PROJECT"
AREA_PATH       = None   # or "ProjectName\\Security"
ITERATION_PATH  = None   # or "ProjectName\\Sprint 1"
```

### 4. Set PAT environment variable

```bash
export ADO_PAT=<your-personal-access-token>
```

PAT needs: **Work Items — Read, Write, Manage**

---

## Dependency: User Stories Must Exist First

The import script finds **parent User Stories** by matching:
- `asb_control_id` (e.g. `IM-1`) in the User Story title
- `service-name` in the User Story's tags

If User Stories don't exist in ADO yet → run `import_to_ado.py` first (see `scripts/ado_import_README.md`).

IM domain User Stories source: `ado/user_stories/im.md`

---

## IM Domain — Service CSV Map

| CSV file | --service-name value |
|---|---|
| `data/outputs/addds_rechecked_controls.csv` | `active-directory-domain-services` |
| `data/outputs/attestation_rechecked_controls.csv` | `attestation` |
| `data/outputs/botservice_rechecked_controls.csv` | `bot-service` |
| `data/outputs/cloudshell_rechecked_controls.csv` | `cloud-shell` |
| `data/outputs/intelligentrecommendations_rechecked_controls.csv` | `intelligent-recommendations` |
| `data/outputs/spatialanchors_rechecked_controls.csv` | `spatial-anchors` |
| `data/outputs/trustedhardwareim_rechecked_controls.csv` | `trusted-hardware-identity-management` |
| `data/outputs/universalprint_rechecked_controls.csv` | `universal-print` |
| `data/outputs/apimanagement_rechecked_controls.csv` | `api-management` |

---

## Run Import (one service at a time)

### Step 1 — Dry run first (no changes to ADO)

```bash
cd scripts/
python import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/addds_rechecked_controls.csv \
    --service-name active-directory-domain-services \
    --dry-run
```

Check output — expect rows printed, parent stories found, no errors.

### Step 2 — Live run

```bash
python import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/addds_rechecked_controls.csv \
    --service-name active-directory-domain-services
```

Repeat for each service in the table above.

### Step 3 — Verify in ADO

Open ADO → Boards → Work Items. Filter by tag = service name. Tasks should appear under parent User Stories.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `No parent found: N` | User Story missing or tag mismatch | Check ADO for User Story with `asb_control_id` in title and service tag |
| `ADO_PAT not set` | Missing env var | `export ADO_PAT=<pat>` |
| `401 Unauthorized` | PAT expired or wrong scope | Regenerate PAT |
| `CSV schema error` | Wrong CSV format | Verify 10-col header matches expected |

---

## AVD Copilot Prompt

> **Use this prompt on AVD to run the IM domain import.**
> Paste into AI Copilot chat. It will execute commands one at a time.

```
You are running the ADO task import for Phase 45 IM domain services.
Repo is at: <REPO_PATH_ON_AVD>
ADO_PAT is already set as environment variable.

Follow these steps exactly. Do NOT skip steps. Do NOT run multiple services at once.

STEP 1: Pull latest code
  cd <REPO_PATH_ON_AVD>
  git pull origin master

STEP 2: Verify CSVs exist
  ls data/outputs/addds_rechecked_controls.csv
  ls data/outputs/attestation_rechecked_controls.csv
  ls data/outputs/botservice_rechecked_controls.csv
  ls data/outputs/cloudshell_rechecked_controls.csv
  ls data/outputs/intelligentrecommendations_rechecked_controls.csv
  ls data/outputs/spatialanchors_rechecked_controls.csv
  ls data/outputs/trustedhardwareim_rechecked_controls.csv
  ls data/outputs/universalprint_rechecked_controls.csv
  If any file missing → STOP. Report which file is missing.

STEP 3: Dry run for service 1 (addds)
  cd scripts/
  python import_assessment_tasks_to_ado.py --csv ../data/outputs/addds_rechecked_controls.csv --service-name active-directory-domain-services --dry-run
  Report: how many rows found, how many parents found, any errors.

STEP 4: If dry run OK → live run for addds
  python import_assessment_tasks_to_ado.py --csv ../data/outputs/addds_rechecked_controls.csv --service-name active-directory-domain-services
  Report: tasks created count, any failures.

STEP 5: Repeat STEP 3+4 for each service:
  attestation       → --service-name attestation
  botservice        → --service-name bot-service
  cloudshell        → --service-name cloud-shell
  intelligentrecommendations → --service-name intelligent-recommendations
  spatialanchors    → --service-name spatial-anchors
  trustedhardwareim → --service-name trusted-hardware-identity-management
  universalprint    → --service-name universal-print
  apimanagement     → --service-name api-management

STEP 6: Final report
  Print a table: service | tasks created | failures
  If any service has failures → report which rows failed and why.

IMPORTANT RULES:
- Run dry-run before each live run.
- Stop at any error and report to user before continuing.
- Do not guess at missing config values — ask user.
```

---

## Phase 45 CSVs Status

All 8 IM domain CSVs committed to GitHub master as of 2026-06-22 (commit 962e29c).
Prior-phase NS/DP CSVs also committed (commit 2c35123).
Total tracked: 23 `*_rechecked_controls.csv` files.
