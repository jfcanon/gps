# AVD Task Import Guide — rechecked_controls_v2 CSVs → ADO Tasks

## What This Does

Creates ADO Tasks (children of User Stories) from `*_rechecked_controls_v2.csv` files.
One Task per CSV row. Each Task links to a parent User Story.

> **v2 schema (Phase 50+)**: 14 cols — original 10 + `service, severity, blast_radius, risk_rank`.
> The import script reads headers dynamically; extra cols are ignored by ADO import logic.
> Original v1 CSVs are archived at `data/outputs/archive/*_rechecked_controls.csv`.

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
pip install -r requirements.txt
```

Skip if already installed. The script needs `requests` and `python-dotenv` — both are in `requirements.txt`.

### 3. Configure ADO connection

Edit `scripts/ado_config.py`:

```python
ADO_ORG     = "https://dev.azure.com/YOUR_ORG"   # your org URL
ADO_PROJECT = "YOUR_PROJECT"                       # your project name
AREA_PATH       = None   # set None if unsure — tasks go to project root
ITERATION_PATH  = None   # set None if unsure — tasks land in backlog
```

**area_path**: the folder/team path in ADO where tasks get filed. Find it in ADO under Project Settings → Teams → Area. Example: `"MyProject\\Security"`. Set `None` if you don't know — tasks will import fine without it.

**iteration_path**: the sprint or iteration bucket. Find it in ADO under Boards → Sprints. Example: `"MyProject\\Sprint 3"`. Set `None` if you don't know — tasks land in the root backlog.

### 4. Set PAT environment variable

```bash
export ADO_PAT=<your-personal-access-token>
```

All-access PAT works. No specific scope configuration needed.

---

## Run Import

### Preferred method — direct User Story ID

If you know the ADO work item ID of the parent User Story (recommended):

```bash
cd scripts/
# Dry run first
python3 import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/addds_rechecked_controls_v2.csv \
    --parent-id 12345 \
    --dry-run

# Live run
python3 import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/addds_rechecked_controls_v2.csv \
    --parent-id 12345
```

All rows in the CSV get linked to User Story #12345. Simple and reliable.

### Fallback method — service name lookup

If you don't have the ADO item ID, the script searches by service tag:

```bash
python3 import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/addds_rechecked_controls_v2.csv \
    --service-name active-directory-domain-services \
    --dry-run
```

Requires User Stories to already exist in ADO with matching tags.

### Verify in ADO

Open ADO → Boards → Work Items. Tasks appear as children under the parent User Story.

---

## All CSVs — Service Map

29 CSVs currently tracked (Phase 50+). Run `ls data/outputs/*_rechecked_controls_v2.csv` for current list.

| Service | CSV slug | Domain | `--service-name` value |
|---|---|---|---|
| Active Directory Domain Services | addds | IM | `active-directory-domain-services` |
| API Management | apimanagement | IM | `api-management` |
| Application Gateway | appgateway | NS | `application-gateway` |
| Attestation | attestation | IM | `attestation` |
| Azure Bastion | bastion | NS | `azure-bastion` |
| Azure DNS | azuredns | NS | `azure-dns` |
| Azure Firewall | azurefirewall | NS | `azure-firewall` |
| Bot Service | botservice | IM | `bot-service` |
| Cloud Shell | cloudshell | IM | `cloud-shell` |
| DDoS Protection | ddosprotection | NS | `ddos-protection` |
| Firewall Manager | firewallmanager | NS | `firewall-manager` |
| Front Door | frontdoor | NS | `front-door` |
| Intelligent Recommendations | intelligentrecommendations | IM | `intelligent-recommendations` |
| Network Watcher | networkwatcher | NS | `network-watcher` |
| Private Link | privatelink | NS | `private-link` |
| Public IP | publicip | NS | `public-ip` |
| Redis Cache | redis | NS | `azure-cache-for-redis` |
| Service Bus | servicebus | NS | `service-bus` |
| Spatial Anchors | spatialanchors | IM | `spatial-anchors` |
| Trusted Hardware IM | trustedhardwareim | IM | `trusted-hardware-identity-management` |
| Universal Print | universalprint | IM | `universal-print` |
| VPN Gateway | vpngateway | NS | `vpn-gateway` |
| Web Application Firewall | waf | NS | `web-application-firewall` |

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Provide --parent-id or --service-name` | Neither flag passed | Add `--parent-id <id>` or `--service-name <name>` |
| `No parent found: N` | WIQL search found no matching User Story | Use `--parent-id` instead |
| `ADO_PAT not set` | Missing env var | `export ADO_PAT=<pat>` |
| `ADO_ORG not configured` | Default value still in ado_config.py | Edit `scripts/ado_config.py` |
| `401 Unauthorized` | PAT expired | Regenerate PAT |
| `CSV schema error` | Wrong CSV format | Verify 14-col header in CSV (v2 schema) |

---

## AVD Copilot Prompt

Paste into AI Copilot. Fill in `<REPO_PATH>` and `<USER_STORY_ID_FOR_SERVICE>` before pasting.

```
You are running ADO task import for Phase 45 IM domain services.
Repo is at: <REPO_PATH>
ADO_PAT is already set. ado_config.py is already configured.

Follow these steps exactly. One service at a time. Stop at any error.

STEP 1: Pull latest
  cd <REPO_PATH>
  git pull origin master

STEP 2: Verify CSVs exist
  ls data/outputs/addds_rechecked_controls_v2.csv
  ls data/outputs/attestation_rechecked_controls_v2.csv
  ls data/outputs/botservice_rechecked_controls_v2.csv
  ls data/outputs/cloudshell_rechecked_controls_v2.csv
  ls data/outputs/intelligentrecommendations_rechecked_controls_v2.csv
  ls data/outputs/spatialanchors_rechecked_controls_v2.csv
  ls data/outputs/trustedhardwareim_rechecked_controls_v2.csv
  ls data/outputs/universalprint_rechecked_controls_v2.csv
  If any missing → STOP and report.

STEP 3: Dry run service 1 (addds), User Story ID = <USER_STORY_ID_FOR_ADDDS>
  cd scripts/
  python3 import_assessment_tasks_to_ado.py --csv ../data/outputs/addds_rechecked_controls_v2.csv --parent-id <USER_STORY_ID_FOR_ADDDS> --dry-run
  Report: rows found, any errors.

STEP 4: Live run addds (if dry run OK)
  python3 import_assessment_tasks_to_ado.py --csv ../data/outputs/addds_rechecked_controls_v2.csv --parent-id <USER_STORY_ID_FOR_ADDDS>
  Report: tasks created, failures.

STEP 5: Repeat STEP 3+4 for each service with its User Story ID:
  attestation         → --parent-id <ID>
  botservice          → --parent-id <ID>
  cloudshell          → --parent-id <ID>
  intelligentrecommendations → --parent-id <ID>
  spatialanchors      → --parent-id <ID>
  trustedhardwareim   → --parent-id <ID>
  universalprint      → --parent-id <ID>

STEP 6: Final report — table: service | tasks created | failures

RULES:
- Dry-run before every live run.
- Stop on any error. Report before continuing.
- Do not guess missing config. Ask user.
```
