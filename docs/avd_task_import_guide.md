# AVD Task Import Guide — Assessment CSVs → ADO Tasks

## What This Does

Creates ADO Tasks (children of User Stories) from enriched assessment CSVs.
One Task per CSV row. Each Task links to a parent User Story via `--parent-id`.

> **CSV source**: Use `data/outputs/ns/*.final.csv` for NS domain (enriched, Phase 58).
> Use `data/outputs/*_rechecked_controls_v2.csv` for IM domain until Phase 59 creates `data/outputs/im/*.final.csv`.
> Script reads headers dynamically — works with all v2 schemas.

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

Needs `requests` and `python-dotenv`.

### 3. Configure ADO connection

Edit `scripts/ado_config.py`:

```python
ADO_ORG     = "https://dev.azure.com/YOUR_ORG"   # your org URL
ADO_PROJECT = "YOUR_PROJECT"                       # your project name
AREA_PATH       = None   # optional — set if you want tasks in a specific area
ITERATION_PATH  = None   # optional — set if you want tasks in a specific sprint
```

### 4. Set PAT environment variable

```bash
export ADO_PAT=<your-personal-access-token>
```

---

## Run Import

### Preferred — direct User Story ID

```bash
cd scripts/

# Dry run first (always)
python3 import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/ns/appservice.final.csv \
    --parent-id 12345 \
    --dry-run

# Live run
python3 import_assessment_tasks_to_ado.py \
    --csv ../data/outputs/ns/appservice.final.csv \
    --parent-id 12345
```

---

## All CSVs — Full Service Map

### NS Domain — 34 services — `data/outputs/ns/*.final.csv`

| Service | `--csv` path | `--parent-id` |
|---|---|---|
| App Gateway | `data/outputs/ns/appgateway.final.csv` | `<ID>` |
| App Service | `data/outputs/ns/appservice.final.csv` | `<ID>` |
| Azure Bastion | `data/outputs/ns/bastion.final.csv` | `<ID>` |
| Azure CDN | `data/outputs/ns/azurecdn.final.csv` | `<ID>` |
| Azure DNS | `data/outputs/ns/azuredns.final.csv` | `<ID>` |
| Azure Firewall | `data/outputs/ns/azurefirewall.final.csv` | `<ID>` |
| Cognitive Search | `data/outputs/ns/cognitivesearch.final.csv` | `<ID>` |
| Cognitive Services | `data/outputs/ns/cognitiveservices.final.csv` | `<ID>` |
| Database Migration | `data/outputs/ns/databasemigration.final.csv` | `<ID>` |
| Databricks | `data/outputs/ns/databricks.final.csv` | `<ID>` |
| Data Factory | `data/outputs/ns/datafactory.final.csv` | `<ID>` |
| DDoS Protection | `data/outputs/ns/ddosprotection.final.csv` | `<ID>` |
| Event Grid | `data/outputs/ns/eventgrid.final.csv` | `<ID>` |
| Event Hubs | `data/outputs/ns/eventhubs.final.csv` | `<ID>` |
| File Sync | `data/outputs/ns/filesync.final.csv` | `<ID>` |
| Firewall Manager | `data/outputs/ns/firewallmanager.final.csv` | `<ID>` |
| Front Door | `data/outputs/ns/frontdoor.final.csv` | `<ID>` |
| Functions | `data/outputs/ns/functions.final.csv` | `<ID>` |
| Load Balancer | `data/outputs/ns/loadbalancer.final.csv` | `<ID>` |
| Logic Apps | `data/outputs/ns/logicapps.final.csv` | `<ID>` |
| NAT Gateway | `data/outputs/ns/natgateway.final.csv` | `<ID>` |
| Network Watcher | `data/outputs/ns/networkwatcher.final.csv` | `<ID>` |
| Notification Hubs | `data/outputs/ns/notificationhubs.final.csv` | `<ID>` |
| Peering Service | `data/outputs/ns/peeringservice.final.csv` | `<ID>` |
| Private Link | `data/outputs/ns/privatelink.final.csv` | `<ID>` |
| Public IP | `data/outputs/ns/publicip.final.csv` | `<ID>` |
| Redis Cache | `data/outputs/ns/redis.final.csv` | `<ID>` |
| Service Bus | `data/outputs/ns/servicebus.final.csv` | `<ID>` |
| Traffic Manager | `data/outputs/ns/trafficmanager.final.csv` | `<ID>` |
| Virtual Desktop | `data/outputs/ns/virtualdesktop.final.csv` | `<ID>` |
| Virtual Network | `data/outputs/ns/virtualnetwork.final.csv` | `<ID>` |
| Virtual WAN | `data/outputs/ns/virtualwan.final.csv` | `<ID>` |
| VPN Gateway | `data/outputs/ns/vpngateway.final.csv` | `<ID>` |
| WAF | `data/outputs/ns/waf.final.csv` | `<ID>` |

### IM Domain — 9 services

> Phase 59 not yet run. Use `data/outputs/im/*.final.csv` after Phase 59 completes.
> Until then, use `data/outputs/*_rechecked_controls_v2.csv` as fallback.

| Service | `--csv` path (post Phase 59) | `--parent-id` |
|---|---|---|
| ADDS | `data/outputs/im/addds.final.csv` | `<ID>` |
| API Management | `data/outputs/im/apimanagement.final.csv` | `<ID>` |
| Attestation | `data/outputs/im/attestation.final.csv` | `<ID>` |
| Bot Service | `data/outputs/im/botservice.final.csv` | `<ID>` |
| Cloud Shell | `data/outputs/im/cloudshell.final.csv` | `<ID>` |
| Intelligent Recommendations | `data/outputs/im/intelligentrecommendations.final.csv` | `<ID>` |
| Spatial Anchors | `data/outputs/im/spatialanchors.final.csv` | `<ID>` |
| Trusted HW IM | `data/outputs/im/trustedhardwareim.final.csv` | `<ID>` |
| Universal Print | `data/outputs/im/universalprint.final.csv` | `<ID>` |

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Provide --parent-id or --service-name` | Neither flag passed | Add `--parent-id <id>` |
| `ADO_PAT not set` | Missing env var | `export ADO_PAT=<pat>` |
| `ADO_ORG not configured` | Default in ado_config.py | Edit `scripts/ado_config.py` |
| `401 Unauthorized` | PAT expired | Regenerate PAT |
| `CSV schema error` | Wrong CSV format | Verify 14-col header in CSV |
| `No parent found: N` | WIQL search found no match | Use `--parent-id` instead |

---

## AVD Copilot Prompt — NS Domain (34 services)

Paste into AI Copilot on AVD. Fill in `<REPO_PATH>` and each `<ID_*>` before pasting.

```
You are running ADO task import for NS domain (34 services).
Repo is at: <REPO_PATH>
ADO_PAT is already set. ado_config.py is already configured.

Follow these steps exactly. One service at a time. Stop at any error.

STEP 1: Pull latest
  cd <REPO_PATH>
  git pull origin master

STEP 2: Verify NS CSVs exist
  ls data/outputs/ns/*.final.csv
  Expected: 34 files. If any missing → STOP and report.

STEP 3: For each service, dry run then live run.
  Template:
    cd scripts/
    python3 import_assessment_tasks_to_ado.py --csv ../data/outputs/ns/{SLUG}.final.csv --parent-id {ID} --dry-run
    # if dry run OK:
    python3 import_assessment_tasks_to_ado.py --csv ../data/outputs/ns/{SLUG}.final.csv --parent-id {ID}

  Services and IDs (fill in <ID_*>):
    appgateway        → --parent-id <ID_APPGATEWAY>
    appservice        → --parent-id <ID_APPSERVICE>
    azurecdn          → --parent-id <ID_AZURECDN>
    azuredns          → --parent-id <ID_AZUREDNS>
    azurefirewall     → --parent-id <ID_AZUREFIREWALL>
    bastion           → --parent-id <ID_BASTION>
    cognitivesearch   → --parent-id <ID_COGNITIVESEARCH>
    cognitiveservices → --parent-id <ID_COGNITIVESERVICES>
    databasemigration → --parent-id <ID_DATABASEMIGRATION>
    databricks        → --parent-id <ID_DATABRICKS>
    datafactory       → --parent-id <ID_DATAFACTORY>
    ddosprotection    → --parent-id <ID_DDOSPROTECTION>
    eventgrid         → --parent-id <ID_EVENTGRID>
    eventhubs         → --parent-id <ID_EVENTHUBS>
    filesync          → --parent-id <ID_FILESYNC>
    firewallmanager   → --parent-id <ID_FIREWALLMANAGER>
    frontdoor         → --parent-id <ID_FRONTDOOR>
    functions         → --parent-id <ID_FUNCTIONS>
    loadbalancer      → --parent-id <ID_LOADBALANCER>
    logicapps         → --parent-id <ID_LOGICAPPS>
    natgateway        → --parent-id <ID_NATGATEWAY>
    networkwatcher    → --parent-id <ID_NETWORKWATCHER>
    notificationhubs  → --parent-id <ID_NOTIFICATIONHUBS>
    peeringservice    → --parent-id <ID_PEERINGSERVICE>
    privatelink       → --parent-id <ID_PRIVATELINK>
    publicip          → --parent-id <ID_PUBLICIP>
    redis             → --parent-id <ID_REDIS>
    servicebus        → --parent-id <ID_SERVICEBUS>
    trafficmanager    → --parent-id <ID_TRAFFICMANAGER>
    virtualdesktop    → --parent-id <ID_VIRTUALDESKTOP>
    virtualnetwork    → --parent-id <ID_VIRTUALNETWORK>
    virtualwan        → --parent-id <ID_VIRTUALWAN>
    vpngateway        → --parent-id <ID_VPNGATEWAY>
    waf               → --parent-id <ID_WAF>

STEP 4: Final report — table: service | rows | tasks created | failures

RULES:
- Dry-run before every live run.
- Stop on any error. Report before continuing.
- Do not guess missing config. Ask user.
```

---

## AVD Copilot Prompt — IM Domain (9 services, post Phase 59)

```
You are running ADO task import for IM domain (9 services).
Repo is at: <REPO_PATH>
ADO_PAT is already set. ado_config.py is already configured.

STEP 1: Pull latest
  cd <REPO_PATH> && git pull origin master

STEP 2: Verify IM CSVs exist
  ls data/outputs/im/*.final.csv
  Expected: 9 files. If any missing → STOP.

STEP 3: For each service, dry run then live run.
  addds                    → --parent-id <ID_ADDDS>
  apimanagement            → --parent-id <ID_APIMANAGEMENT>
  attestation              → --parent-id <ID_ATTESTATION>
  botservice               → --parent-id <ID_BOTSERVICE>
  cloudshell               → --parent-id <ID_CLOUDSHELL>
  intelligentrecommendations → --parent-id <ID_INTELLIGENTRECOMMENDATIONS>
  spatialanchors           → --parent-id <ID_SPATIALANCHORS>
  trustedhardwareim        → --parent-id <ID_TRUSTEDHARDWAREIM>
  universalprint           → --parent-id <ID_UNIVERSALPRINT>

STEP 4: Final report — table: service | rows | tasks created | failures

RULES: Dry-run before every live run. Stop on error.
```
