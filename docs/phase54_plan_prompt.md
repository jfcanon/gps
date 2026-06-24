# Phase 54 — NS Domain Research Enrichment Pass (20 Phase 52 CSVs → .final.csv)
## Plan Prompt (Persistent — reuse in new sessions)

**Last updated**: 2026-06-24
**Status**: READY — 20 Phase 52 CSVs exist in data/outputs/, need Q1+Q2+Q3 enrichment

---

## Why This Phase Exists

Phase 52 created 20 NS CSVs from xlsx baselines using training knowledge for `still_not_applicable` verdicts. It did NOT run live Exa web search. Phase 54 completes the quality pipeline:

1. **Q1** — Exa web search every `still_not_applicable` row → flip to `now_applicable_native` where Azure added support 2025/2026
2. **Q2** — Add 1-3 supplemental rows per service for v2-only gaps missing from v3 (NS-4 WAF, NS-7 legacy endpoint removal)
3. **Q3** — Verify `now_applicable_native` rows set in Phase 52 with live evidence URL

Output: `data/outputs/ns/{slug}.final.csv` for all 20 services.

This matches what was done for the 14 original NS CSVs (Phases 47-50 → `data/outputs/ns/*.final.csv`).

---

## Analogy

Phase 52 CSVs = rough draft with penciled-in guesses on unknown rows.
Phase 54 = researcher goes online, verifies every guess, adds missed items, pens in final answers.
`.final.csv` = pen-on-paper, ready for stakeholders.

---

## Input CSVs (already in data/outputs/)

| # | Slug | Service | Rows | File |
|---|---|---|---|---|
| 1 | virtualnetwork | Virtual Network | 35 | `virtualnetwork_rechecked_controls_v2.csv` |
| 2 | natgateway | NAT Gateway | 35 | `natgateway_rechecked_controls_v2.csv` |
| 3 | virtualwan | Virtual WAN | 35 | `virtualwan_rechecked_controls_v2.csv` |
| 4 | loadbalancer | Load Balancer | 35 | `loadbalancer_rechecked_controls_v2.csv` |
| 5 | trafficmanager | Traffic Manager | 35 | `trafficmanager_rechecked_controls_v2.csv` |
| 6 | peeringservice | Peering Service | 35 | `peeringservice_rechecked_controls_v2.csv` |
| 7 | appservice | App Service | 43 | `appservice_rechecked_controls_v2.csv` |
| 8 | cognitivesearch | Cognitive Search | 35 | `cognitivesearch_rechecked_controls_v2.csv` |
| 9 | datafactory | Data Factory | 35 | `datafactory_rechecked_controls_v2.csv` |
| 10 | databasemigration | Database Migration Service | 35 | `databasemigration_rechecked_controls_v2.csv` |
| 11 | databricks | Databricks | 36 | `databricks_rechecked_controls_v2.csv` |
| 12 | eventgrid | Event Grid | 35 | `eventgrid_rechecked_controls_v2.csv` |
| 13 | eventhubs | Event Hubs | 35 | `eventhubs_rechecked_controls_v2.csv` |
| 14 | filesync | File Sync | 35 | `filesync_rechecked_controls_v2.csv` |
| 15 | functions | Functions | 35 | `functions_rechecked_controls_v2.csv` |
| 16 | logicapps | Logic Apps | 35 | `logicapps_rechecked_controls_v2.csv` |
| 17 | notificationhubs | Notification Hubs | 35 | `notificationhubs_rechecked_controls_v2.csv` |
| 18 | cognitiveservices | Cognitive Services | 35 | `cognitiveservices_rechecked_controls_v2.csv` |
| 19 | virtualdesktop | Virtual Desktop | 36 | `virtualdesktop_rechecked_controls_v2.csv` |
| 20 | azurecdn | Azure CDN | 3 | `azurecdn_rechecked_controls_v2.csv` |

---

## Output

All output files go to: `data/outputs/ns/{slug}.final.csv`

Naming: `{slug}.final.csv` (e.g., `virtualnetwork.final.csv`)

Schema: same 14-col v2 schema as Phase 52.

---

## Pipeline Steps (per service, in order 1→20)

### Step A — READ Phase 52 CSV

```python
import csv
rows = list(csv.DictReader(open(f'data/outputs/{slug}_rechecked_controls_v2.csv')))
```

Confirm 14 cols. Identify all rows where `verdict_2025 == 'still_not_applicable'`.

### Step B — Q1: Exa Web Search (all still_not_applicable rows)

For EVERY `still_not_applicable` row:

```
Exa search query: "Azure {service_name} {feature_name} 2025 2026"
Question: "Does Azure {service_name} now support {feature_name} as of 2025 or 2026?"
```

If YES with evidence → change `verdict_2025` to `now_applicable_native`. Store evidence URL in `notes` field: `"now_applicable_native: {feature} GA {date}. Source: {url}"`.
If NO or unclear → keep `still_not_applicable`. Add search evidence to notes: `"Exa {date}: no evidence of support as of 2026"`.

DO NOT skip this step. DO NOT rely on training knowledge alone. Exa search is mandatory for each row.

Save cache: `data/outputs/{slug}_na_research.json` with schema:
```json
[{"asb_control_id":"NS-1","feature_name":"...","original_verdict":"still_not_applicable",
  "research_date":"2026-06-24","verdict_2026":"now_applicable_native|still_not_applicable",
  "evidence_url":"https://...","evidence_date":"2025-xx","notes":"..."}]
```

### Step C — Q2: Add Supplemental v2-Only Gap Rows

MCSB v2 had NS controls that v3 removed or collapsed. Check each service for applicability:

**NS-4 (WAF/DDoS Protection — v2 mandatory, v3 optional)**
- Applicable to: appservice, functions, logicapps, cognitiveservices (sit behind App Gateway or Front Door which can enforce WAF)
- Row to add:
  ```
  asb_control_id=NS-4-SUPPLEMENT
  feature_name=WAF Protection (v2 mandatory gap — v3 marks Optional)
  feature_supported_original=False
  feature_enabled_by_default_original=Not Applicable
  status_2025=v2_gap
  verdict_2025=conditional
  azure_api_property=properties.webApplicationFirewallConfiguration (App Gateway)
  script_module=
  script_function=
  notes=ASB v2 NS-4 required WAF for services exposed via App Gateway/Front Door. v3 marks as optional. Real gap: if service exposed without WAF, NS-4 not satisfied. conditional: applies only when App Gateway/Front Door in path.
  service={slug}
  severity=High
  blast_radius=Wide
  risk_rank=6
  ```

**NS-7 (Remove legacy public endpoints when Private Endpoint exists — v2 explicit, v3 merged into NS-2)**
- Applicable to: appservice, cognitivesearch, datafactory, databricks, eventgrid, eventhubs, functions, logicapps, cognitiveservices (all support Private Endpoints)
- Row to add:
  ```
  asb_control_id=NS-7-SUPPLEMENT
  feature_name=Remove Public Network Access When Private Endpoint Active (v2 gap)
  feature_supported_original=False
  feature_enabled_by_default_original=Not Applicable
  status_2025=v2_gap
  verdict_2025=conditional
  azure_api_property=properties.publicNetworkAccess
  script_module=
  script_function=
  notes=ASB v2 NS-7 required disabling public endpoints once Private Link/PE configured. v3 NS-2 only checks PE existence, not public access removal. conditional: gap exists only if service has PE but publicNetworkAccess=Enabled simultaneously.
  service={slug}
  severity=High
  blast_radius=Wide
  risk_rank=6
  ```

**NS-6 (IDPS — Network Intrusion Detection/Prevention)**
- NOT applicable to these 20 services (all PaaS — IDPS is for network appliances like Azure Firewall). SKIP for Phase 54.

### Step D — Q3: Verify now_applicable_native rows from Phase 52

For rows Phase 52 already set to `now_applicable_native` (from training knowledge, not live search):

```
Exa search: "Azure {service_name} {feature_name} GA release date"
Question: "When did Azure {service_name} add {feature_name} support? Is it GA?"
```

If confirmed → keep `now_applicable_native`, update `notes` with evidence URL.
If contradicted → change back to `still_not_applicable`, update `notes` with contradiction evidence.

### Step E — RECOMPUTE severity / blast_radius / risk_rank

After any verdict change, recompute:
- `severity`: NS controls → `High` (severity_score=3)
- `blast_radius`: `Wide` if verdict=`conditional` OR `azure_api_property` empty/N/A OR `feature_enabled_by_default_original=False`; else `Narrow`
- `risk_rank`: `severity_score × blast_radius_score` (Wide=2, Narrow=1) → max 6

### Step F — WRITE output

```python
import csv, pathlib
out = pathlib.Path(f'data/outputs/ns/{slug}.final.csv')
with open(out, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(HEADER)
    for row in final_rows:
        w.writerow(row)
```

Header (14 cols):
```
asb_control_id,feature_name,feature_supported_original,feature_enabled_by_default_original,
status_2025,verdict_2025,azure_api_property,script_module,script_function,notes,
service,severity,blast_radius,risk_rank
```

### Step G — VALIDATE

```bash
python3 -c "
import csv
slug = '{slug}'
rows = list(csv.DictReader(open(f'data/outputs/ns/{slug}.final.csv')))
cols = len(rows[0]) if rows else 0
verdicts = {r['verdict_2025'] for r in rows}
allowed = {'implemented','now_applicable_native','upgraded_implemented',
           'still_not_applicable','conditional','not_applicable_paas','not_applicable_arm'}
bad = verdicts - allowed
empty_notes = [r for r in rows if not r.get('notes','').strip()]
print(f'{slug}: {len(rows)} rows, {cols} cols, bad_verdicts={bad}, empty_notes={len(empty_notes)}')"
```

Must pass: cols=14, bad_verdicts=set(), empty_notes=0.

### Step H — COMMIT

```bash
git add data/outputs/ns/{slug}.final.csv data/outputs/{slug}_na_research.json
git commit -m "feat: Phase 54 NS — {ServiceName} .final.csv ({N} rows, Q1+Q2+Q3 enriched)"
```

### Step I — REPEAT steps A-H for next service

Process in order 1→20. Validate before committing. Commit per service (not batch).

---

## Q1 Search Priority Guide

These rows from Phase 52 training-knowledge verdicts should be prioritized for Q1 Exa search:

| Service | Control | Feature | Phase 52 verdict | Q1 hypothesis |
|---|---|---|---|---|
| appservice | NS-2 | Azure Private Link | now_applicable_native | VERIFY — Private Link for App Service GA 2022 |
| cognitivesearch | NS-2 | Azure Private Link | now_applicable_native | VERIFY — AI Search Private Endpoint GA |
| datafactory | NS-2 | Azure Private Link | now_applicable_native | VERIFY — Data Factory Managed VNet PE |
| databricks | NS-2 | Azure Private Link | now_applicable_native | VERIFY — Databricks VNet injection GA |
| eventgrid | NS-2 | Azure Private Link | now_applicable_native | VERIFY — Event Grid PE GA |
| eventhubs | NS-2 | Azure Private Link | now_applicable_native | VERIFY — Event Hubs Premium PE GA |
| functions | NS-2 | Azure Private Link | now_applicable_native | VERIFY — Functions VNet integration GA |
| cognitiveservices | NS-2 | Azure Private Link | now_applicable_native | VERIFY — Cognitive Services PE GA |
| virtualdesktop | NS-2 | Azure Private Link | now_applicable_native | VERIFY — AVD RDP Shortpath GA |
| virtualnetwork | IM-3 | Managed Identities | still_not_applicable | SEARCH — VNet itself doesn't have MI |
| loadbalancer | LT-4 | Resource Logs | still_not_applicable | SEARCH — ALB diagnostic logs GA |
| trafficmanager | LT-4 | Resource Logs | still_not_applicable | SEARCH — Traffic Manager diagnostics |

---

## v2-Only Gap Rows — Applicability Matrix

| Service | NS-4 WAF (supplement) | NS-7 public→PE removal (supplement) |
|---|---|---|
| virtualnetwork | NO (is the network itself) | NO |
| natgateway | NO | NO |
| virtualwan | NO | NO |
| loadbalancer | NO | NO |
| trafficmanager | NO | MAYBE (check if PE supported) |
| peeringservice | NO | NO |
| appservice | YES | YES |
| cognitivesearch | NO (not web-facing entrypoint) | YES |
| datafactory | NO | YES |
| databasemigration | NO | MAYBE |
| databricks | NO | YES |
| eventgrid | NO | YES |
| eventhubs | NO | YES |
| filesync | NO | NO (no PE for File Sync) |
| functions | YES | YES |
| logicapps | YES | YES |
| notificationhubs | NO | NO |
| cognitiveservices | NO | YES |
| virtualdesktop | NO | NO (control-plane service) |
| azurecdn | NO | NO |

**MAYBE**: verify via Exa if PE supported before adding row. If no PE support → skip supplement.

---

## Quality Gate (after all 20 services)

```bash
python3 -c "
import csv, pathlib, glob

slugs = ['virtualnetwork','natgateway','virtualwan','loadbalancer','trafficmanager',
         'peeringservice','appservice','cognitivesearch','datafactory','databasemigration',
         'databricks','eventgrid','eventhubs','filesync','functions','logicapps',
         'notificationhubs','cognitiveservices','virtualdesktop','azurecdn']

ALLOWED = {'implemented','now_applicable_native','upgraded_implemented',
           'still_not_applicable','conditional','not_applicable_paas','not_applicable_arm'}

print(f'{'Slug':<25} {'Rows':>5} {'Cols':>5} {'BadVerdict':>10} {'EmptyNotes':>11} {'Status':>8}')
print('-' * 80)
for s in slugs:
    p = pathlib.Path(f'data/outputs/ns/{s}.final.csv')
    if not p.exists():
        print(f'{s:<25} MISSING')
        continue
    rows = list(csv.DictReader(open(p)))
    cols = len(rows[0]) if rows else 0
    bad = {r['verdict_2025'] for r in rows} - ALLOWED
    empty = len([r for r in rows if not r.get('notes','').strip()])
    ok = cols == 14 and not bad and empty == 0
    print(f'{s:<25} {len(rows):>5} {cols:>5} {str(bad):>10} {empty:>11} {\"OK\" if ok else \"FAIL\":>8}')
"
```

All 20 must show: `cols=14, BadVerdict=set(), EmptyNotes=0, Status=OK`.

---

## Constraints

- DO NOT modify Phase 52 CSVs in `data/outputs/` — read only
- Exa search is MANDATORY for each `still_not_applicable` row — no skipping
- Output always to `data/outputs/ns/{slug}.final.csv`, never overwrite input
- Commit per service, not batch
- NS-6 IDPS supplement: skip for all 20 (PaaS services, not network appliances)
- Cache research to `{slug}_na_research.json` before writing CSV
- After Phase 54: 34 NS `.final.csv` files total in `data/outputs/ns/` (14 original + 20 Phase 54)
- DO NOT import to ADO in this phase

---

## Deliverable Count After Phase 54

`data/outputs/ns/` will contain:
- 14 from Phases 47-50 (appgateway, azuredns, azurefirewall, bastion, ddosprotection, firewallmanager, frontdoor, networkwatcher, privatelink, publicip, redis, servicebus, vpngateway, waf) — already `.final.csv`
- 20 from Phase 54 (all slugs above) — new `.final.csv`
- **Total: 34 NS `.final.csv` files** = complete NS domain assessment output

---

## JSON-LD Plan Prompt

```json
{
  "@context": {
    "@vocab": "https://schema.org/",
    "nsg": "https://newsecgap.internal/ontology#"
  },
  "@type": "SoftwareProject",
  "@id": "nsg:phase-54-ns-research-enrichment",
  "name": "NewSecGap Phase 54 — NS Domain Research Enrichment (20 Phase 52 CSVs → .final.csv)",
  "phase": "54",
  "projectRoot": "/Users/nahuelavalos/Repo/NewSecGap",
  "description": "Apply Q1 (Exa web search for all still_not_applicable rows), Q2 (add NS-4 WAF and NS-7 legacy endpoint v2-only gap supplement rows), and Q3 (verify Phase 52 now_applicable_native with live evidence) to all 20 Phase 52 NS CSVs. Output: data/outputs/ns/{slug}.final.csv. DO NOT import to ADO.",
  "targetDomain": {"name": "Network Security", "termCode": "NS"},
  "inputSource": "data/outputs/{slug}_rechecked_controls_v2.csv (Phase 52, 20 files)",
  "outputDestination": "data/outputs/ns/{slug}.final.csv",
  "readFirst": [
    {"order": 1, "path": "docs/phase52_plan_prompt.md", "why": "Full pipeline spec, verdict rules, schema"},
    {"order": 2, "path": "data/outputs/ns/appgateway.final.csv", "why": "Reference .final.csv with enriched notes and Q2 supplement rows"},
    {"order": 3, "path": "data/outputs/appservice_rechecked_controls_v2.csv", "why": "Largest Phase 52 CSV (43 rows) — start here to calibrate Q1 search volume"}
  ],
  "serviceScope": {
    "totalCount": 20,
    "services": [
      {"position": 1, "slug": "virtualnetwork", "rows": 35},
      {"position": 2, "slug": "natgateway", "rows": 35},
      {"position": 3, "slug": "virtualwan", "rows": 35},
      {"position": 4, "slug": "loadbalancer", "rows": 35},
      {"position": 5, "slug": "trafficmanager", "rows": 35},
      {"position": 6, "slug": "peeringservice", "rows": 35},
      {"position": 7, "slug": "appservice", "rows": 43},
      {"position": 8, "slug": "cognitivesearch", "rows": 35},
      {"position": 9, "slug": "datafactory", "rows": 35},
      {"position": 10, "slug": "databasemigration", "rows": 35},
      {"position": 11, "slug": "databricks", "rows": 36},
      {"position": 12, "slug": "eventgrid", "rows": 35},
      {"position": 13, "slug": "eventhubs", "rows": 35},
      {"position": 14, "slug": "filesync", "rows": 35},
      {"position": 15, "slug": "functions", "rows": 35},
      {"position": 16, "slug": "logicapps", "rows": 35},
      {"position": 17, "slug": "notificationhubs", "rows": 35},
      {"position": 18, "slug": "cognitiveservices", "rows": 35},
      {"position": 19, "slug": "virtualdesktop", "rows": 36},
      {"position": 20, "slug": "azurecdn", "rows": 3}
    ]
  },
  "pipeline": {
    "Q1": "Exa web search EVERY still_not_applicable row. Flip to now_applicable_native with evidence URL if Azure added support 2025/2026. Mandatory — no training-knowledge shortcuts.",
    "Q2": "Add NS-4 WAF supplement row for appservice/functions/logicapps. Add NS-7 public→PE gap row for appservice/cognitivesearch/datafactory/databricks/eventgrid/eventhubs/functions/logicapps/cognitiveservices.",
    "Q3": "Verify all now_applicable_native rows Phase 52 set from training — confirm with live Exa evidence URL or revert to still_not_applicable."
  },
  "researchCache": "data/outputs/{slug}_na_research.json",
  "verdictTaxonomy": ["implemented","now_applicable_native","upgraded_implemented","still_not_applicable","conditional","not_applicable_paas","not_applicable_arm"],
  "supplementRows": {
    "NS4-WAF": {"asb_control_id": "NS-4-SUPPLEMENT", "verdict_2025": "conditional", "severity": "High", "blast_radius": "Wide", "risk_rank": 6},
    "NS7-PublicEndpoint": {"asb_control_id": "NS-7-SUPPLEMENT", "verdict_2025": "conditional", "severity": "High", "blast_radius": "Wide", "risk_rank": 6}
  },
  "executionSteps": [
    {"position": 1, "action": "READ Phase 52 CSV for service"},
    {"position": 2, "action": "Q1: Exa search each still_not_applicable row → flip or confirm with evidence URL"},
    {"position": 3, "action": "Q3: Exa search each now_applicable_native row Phase 52 set → confirm or revert"},
    {"position": 4, "action": "Q2: Add v2-only gap supplement rows where applicable"},
    {"position": 5, "action": "RECOMPUTE blast_radius and risk_rank after any verdict change"},
    {"position": 6, "action": "WRITE to data/outputs/ns/{slug}.final.csv"},
    {"position": 7, "action": "VALIDATE: 14 cols, no bad verdicts, no empty notes"},
    {"position": 8, "action": "COMMIT per service"},
    {"position": 9, "action": "REPEAT for next service"},
    {"position": 10, "action": "UPDATE ado/activity.log after all 20 complete"}
  ],
  "constraints": [
    "DO NOT modify Phase 52 CSVs in data/outputs/ — read-only input",
    "Exa search mandatory for EVERY still_not_applicable row",
    "Output to data/outputs/ns/{slug}.final.csv only",
    "NS-6 IDPS supplement: skip — these 20 are PaaS services",
    "Commit per service, not batch",
    "DO NOT import to ADO"
  ],
  "qualityGate": {
    "expectedFinalFiles": 20,
    "totalExpectedInNsFolder": 34,
    "mustPass": ["cols=14", "no bad verdicts", "no empty notes", "evidence URL in notes for all now_applicable_native rows"]
  },
  "phaseAfter": {
    "options": [
      "Phase 55: NS ADO import (34 .final.csv → Tasks under NS User Stories)",
      "Phase 55: IM ADO import (9 IM CSVs → Tasks under IM User Stories)"
    ]
  }
}
```
