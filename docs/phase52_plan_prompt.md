# Phase 52 — NS Domain Full Assessment Pipeline
## Plan Prompt (Persistent — reuse in new sessions)

**Last updated**: 2026-06-24
**Status**: READY FOR EXECUTION — pending new Claude session

---

## Context You Must Read First (in this order)

Before doing anything, read these files:

1. `ado/wiki/delivery-approach.md` — full project architecture, ADO hierarchy, effort model
2. `ado/user_stories/ns.md` — all 52 NS User Stories (the scope of Phase 52)
3. `ado/resource_domain_mapping.md` — v2 control → v3 xlsx resource mapping
4. `data/outputs/context.md` — all files in data/outputs/, what they are, verdicts
5. `docs/avd_task_import_guide.md` — ADO import script usage

---

## What Phase 52 Is

Apply the full assessment pipeline to ALL remaining NS (Network Security) domain services
that do NOT yet have a `*_rechecked_controls_v2.csv` file in `data/outputs/`.

The 14 NS services already done (reuse, do not redo):
- appgateway, azuredns, azurefirewall, bastion, ddosprotection, firewallmanager,
  frontdoor, networkwatcher, privatelink, publicip, redis, servicebus, vpngateway, waf

The 52 NS User Stories in `ado/user_stories/ns.md` map to Azure services.
Cross-reference: which of those 52 User Story resources still need v2 CSVs?
Answer: all resources in ns.md that do NOT appear in the 14 list above.

---

## What Phase 52 Is NOT

- NOT an ADO import of existing CSVs (that was the wrong plan — ignore Phase 52 plan in activity.log dated 2026-06-24)
- NOT assessment of IM, PA, BR, DP, AM, LT, PV, ES, GS domains
- NOT a new schema or new approach — same pipeline as Phases 40–50

---

## The Pipeline (same as Phases 40–50)

For each remaining NS service:

### Step 1 — Find the xlsx baseline

Location: `data/inputs/v3_baselines/`
File naming: `{service-slug}-azure-security-benchmark-v3-latest-security-baseline.xlsx`
Sheet: **"Feature Summary"** (NOT the active sheet — always specify this explicitly)

If no xlsx exists for a service: it is a "pure v2" User Story (no v3 data).
Mark verdict as `not_applicable_arm` or reference the User Story directly.
Do NOT fabricate rows.

### Step 2 — Extract all rows from "Feature Summary"

Columns to extract:
- `asb_control_id` (e.g. NS-2, IM-3, PA-7)
- `feature_name`
- `feature_supported` → becomes `feature_supported_original`
- `feature_enabled_by_default` → becomes `feature_enabled_by_default_original`

Each row = one feature check for that service.
Typical count: ~35 rows per service (all MCSB domains mixed — NS, IM, PA, DP, etc.)

### Step 3 — Assign verdict_2025

Apply this logic to each row:

| feature_supported | feature_enabled_by_default | Verdict |
|---|---|---|
| True | True | `implemented` — notes: `microsoft_managed: <explanation>` |
| True | False | `implemented` — notes: `LIVE-DIRECT: <explanation>` + fill `azure_api_property` |
| False or N/A | N/A | Check web → if feature NOW exists: `now_applicable_native`; else: `still_not_applicable` |
| N/A | N/A | `still_not_applicable` — notes: feature_supported=Not Applicable; reason |

Also use these verdicts where appropriate:
- `upgraded_implemented` — feature existed but was upgraded/replaced
- `conditional` — feature exists but requires customer configuration
- `not_applicable_paas` — PaaS service, control not applicable by design
- `not_applicable_arm` — no ARM property path available

### Step 4 — Web research for False/NA controls (Phase 48 approach)

For every row where `feature_supported_original = False` or `= Not Applicable`:
- Search via Exa (or web) for: `"{service_name} {feature_name} azure 2025 2026"`
- Question: "Does this Azure service now support this feature as of 2025/2026?"
- If YES → change verdict to `now_applicable_native`
- If NO or unclear → keep `still_not_applicable`
- Store evidence in `azure_api_property` or `notes` field

This is the key quality step. Do NOT skip it.
Cached research from prior phases is in `data/outputs/*_na_research.json` — check if service already has research cached before running new web searches.

### Step 5 — Build the 14-col v2 CSV

Filename: `data/outputs/{service-slug}_rechecked_controls_v2.csv`

Schema (14 columns, exact order):
```
asb_control_id, feature_name, feature_supported_original, feature_enabled_by_default_original,
status_2025, verdict_2025, azure_api_property, script_module, script_function, notes,
service, severity, blast_radius, risk_rank
```

Column rules:
- `status_2025` = same value as `verdict_2025` (legacy duplicate field)
- `script_module` = empty string (Phase 52)
- `script_function` = empty string (Phase 52)
- `service` = slug (e.g. "appservice", "eventgrid")
- `severity` = domain score: NS/IM/PA/LT/IR = High; DP/AM/ES/BR = Medium; PV/GS = Low
- `blast_radius` = Wide if: verdict=conditional OR azure_api_property empty/N/A OR feature_enabled_by_default_original=False
- `risk_rank` = severity_score × blast_radius_score where High=3, Medium=2, Low=1 and Wide=2, Narrow=1

### Step 6 — Validate before next service

```bash
python3 -c "
import csv
rows = list(csv.DictReader(open('data/outputs/{service}_rechecked_controls_v2.csv')))
expected = ['asb_control_id','feature_name','feature_supported_original',
    'feature_enabled_by_default_original','status_2025','verdict_2025',
    'azure_api_property','script_module','script_function','notes',
    'service','severity','blast_radius','risk_rank']
actual = list(rows[0].keys()) if rows else []
missing = [c for c in expected if c not in actual]
empty_verdict = [r['asb_control_id'] for r in rows if not r.get('verdict_2025')]
print(f'rows={len(rows)}, cols={len(actual)}, missing_cols={missing}, empty_verdict={empty_verdict}')
"
```

Must show: correct row count, 14 cols, missing_cols=[], empty_verdict=[]

### Step 7 — Commit after each service (or batch of 3–5)

```bash
git add data/outputs/{service}_rechecked_controls_v2.csv
git add data/outputs/{service}_na_research.json  # if web research was cached
git commit -m "feat: Phase 52 NS — {ServiceName} rechecked_controls_v2"
git push origin master
```

### Step 8 — Update activity.log

Append entry to `ado/activity.log` after each commit.

---

## NS Services Remaining (to assess in Phase 52)

Cross-reference `ado/user_stories/ns.md` with `data/outputs/` to confirm exact list.
Approximate remaining services (excluding already-done 14 + excluded infra list):

**Excluded from infra scope** (from delivery-approach.md — skip these):
Batch, Communication Services, Communications Gateway, Container Apps, Digital Twins,
HPC Cache, Machine Learning Service, Managed Lustre, Nutanix on Azure, Remote Rendering,
SignalR Service, Spring Apps, Stack Edge, VMware Solution, Web PubSub

**Likely remaining to assess** (verify against actual ns.md + data/inputs/v3_baselines/):
- Virtual Network (vnet)
- Virtual Network NAT / NAT Gateway
- Virtual WAN
- Load Balancer
- Traffic Manager
- Peering Service
- App Service
- Cognitive Search
- Data Factory
- Database Migration Service
- Databricks
- Event Grid
- Event Hubs
- File Sync
- Functions
- Logic Apps
- Notification Hubs
- Service Bus ← already done (servicebus_rechecked_controls_v2.csv exists)
- Cognitive Services
- Content Delivery Network
- Azure Firewall ← already done
- Firewall Manager ← already done
- DDoS Protection ← already done
- Public IP ← already done
- Application Gateway ← already done
- Front Door ← already done
- WAF ← already done
- Network Watcher ← already done
- VPN Gateway ← already done
- Private Link ← already done
- Bastion ← already done
- Virtual Desktop (avd)
- Azure DNS ← already done

**First task in Phase 52**: run exact diff between ns.md User Story resource list and
`ls data/outputs/*_rechecked_controls_v2.csv` to get the definitive remaining list.

---

## Execution Order

1. Start with services that have xlsx baselines in `data/inputs/v3_baselines/`
2. Process one service at a time — validate before moving to next
3. Pure v2 stories (no xlsx) — note them separately, handle last
4. After all NS services complete: run phase49-style analytics on NS-only rows

---

## Stop Conditions

- STOP if xlsx "Feature Summary" sheet has unexpected schema
- STOP if web search returns no clear evidence for a False/NA control — use `still_not_applicable`, document uncertainty in notes
- STOP after all NS services are done — do NOT start IM/PA/BR in this phase
- STOP and ask if row count deviates >10% from expected ~35 rows per service

---

## End-of-Phase Deliverables

1. One `{service}_rechecked_controls_v2.csv` per remaining NS service (14-col schema)
2. Optional: `{service}_na_research.json` per service (web research cache)
3. Updated `data/outputs/context.md` Section 1 — all new NS services added
4. Updated `data/outputs/context.md` Section 11 — NS delivery progress table
5. Phase 52 entry in `ado/activity.log`
6. All committed and pushed to master

---

## Reference: Already-Done NS Services (reuse, do not redo)

| Service | File | Rows | Notes |
|---|---|---|---|
| Application Gateway | appgateway_rechecked_controls_v2.csv | 35 | 14-col OK |
| Azure DNS | azuredns_rechecked_controls_v2.csv | 35 | 14-col OK |
| Azure Firewall | azurefirewall_rechecked_controls_v2.csv | 36 | 14-col OK |
| Azure Bastion | bastion_rechecked_controls_v2.csv | 35 | 14-col OK |
| DDoS Protection | ddosprotection_rechecked_controls_v2.csv | 35 | 14-col OK |
| Firewall Manager | firewallmanager_rechecked_controls_v2.csv | 35 | 14-col OK |
| Front Door | frontdoor_rechecked_controls_v2.csv | 35 | 14-col OK |
| Network Watcher | networkwatcher_rechecked_controls_v2.csv | 35 | 14-col OK |
| Private Link | privatelink_rechecked_controls_v2.csv | 35 | 14-col OK |
| Public IP | publicip_rechecked_controls_v2.csv | 36 | 14-col OK |
| Azure Cache for Redis | redis_rechecked_controls_v2.csv | 35 | 14-col OK |
| Service Bus | servicebus_rechecked_controls_v2.csv | 34 | 14-col OK |
| VPN Gateway | vpngateway_rechecked_controls_v2.csv | 35 | 14-col OK |
| Web Application Firewall | waf_rechecked_controls_v2.csv | 35 | 14-col OK |

---

## Key File Paths (quick reference)

| Purpose | Path |
|---|---|
| NS User Stories | `ado/user_stories/ns.md` |
| v3 xlsx baselines | `data/inputs/v3_baselines/` |
| v2 CSV outputs | `data/outputs/{service}_rechecked_controls_v2.csv` |
| Web research cache | `data/outputs/{service}_na_research.json` |
| ADO import script | `scripts/import_assessment_tasks_to_ado.py` |
| ADO import guide | `docs/avd_task_import_guide.md` |
| Delivery approach | `ado/wiki/delivery-approach.md` |
| Activity log | `ado/activity.log` |
| Context inventory | `data/outputs/context.md` |

---

## JSON-LD Plan Prompt (for AI sessions)

```json
{
  "@context": {
    "@vocab": "https://schema.org/",
    "nsg": "https://newsecgap.internal/ontology#",
    "phase": "nsg:phase",
    "targetDomain": "nsg:targetDomain",
    "csvSchema": "nsg:csvSchema",
    "verdictTaxonomy": "nsg:verdictTaxonomy",
    "serviceScope": "nsg:serviceScope",
    "readFirst": "nsg:readFirst"
  },
  "@type": "SoftwareProject",
  "@id": "nsg:phase-52-ns-full-assessment",
  "name": "NewSecGap Phase 52 — NS Domain Full Assessment Pipeline",
  "version": "1.0.0",
  "dateCreated": "2026-06-24",
  "phase": "52",
  "projectRoot": "/Users/nahuelavalos/Repo/NewSecGap",
  "gitRemote": "https://github.com/jfcanon/gps",
  "description": "Apply full v3 xlsx → verdict → web research → 14-col v2 CSV pipeline to all 20 remaining NS domain services. Do NOT import to ADO. Do NOT assess other domains. 14 existing NS v2 CSVs are done — reuse, do not redo.",
  "targetDomain": {"name":"Network Security","termCode":"NS","adoFeature":"Security Domain #1: Network Security (NS) Baselines","totalUserStories":52},
  "readFirst": [
    {"order":1,"path":"ado/wiki/delivery-approach.md","why":"ADO hierarchy, exclusion list"},
    {"order":2,"path":"ado/user_stories/ns.md","why":"52 NS User Stories, defines scope"},
    {"order":3,"path":"data/outputs/context.md","why":"Which v2 CSVs already exist"},
    {"order":4,"path":"docs/phase52_plan_prompt.md","why":"This document — full plan"}
  ],
  "alreadyDone": {"count":14,"services":["appgateway","azuredns","azurefirewall","bastion","ddosprotection","firewallmanager","frontdoor","networkwatcher","privatelink","publicip","redis","servicebus","vpngateway","waf"]},
  "exclusionList": ["Batch","Communication Services","Communications Gateway","Container Apps","Digital Twins","HPC Cache","Machine Learning Service","Managed Lustre","Nutanix on Azure","Remote Rendering","SignalR Service","Spring Apps","Stack Edge","VMware Solution","Web PubSub"],
  "serviceScope": {"totalCount":20,"itemListElement":[
    {"position":1,"name":"Virtual Network","xlsxSlug":"virtual-network","outputCSV":"data/outputs/virtualnetwork_rechecked_controls_v2.csv","nsControl":"NS-1"},
    {"position":2,"name":"NAT Gateway","xlsxSlug":"azure-nat-gateway","outputCSV":"data/outputs/natgateway_rechecked_controls_v2.csv","nsControl":"NS-1"},
    {"position":3,"name":"Virtual WAN","xlsxSlug":"virtual-wan","outputCSV":"data/outputs/virtualwan_rechecked_controls_v2.csv","nsControl":"NS-1"},
    {"position":4,"name":"Load Balancer","xlsxSlug":"azure-load-balancer","outputCSV":"data/outputs/loadbalancer_rechecked_controls_v2.csv","nsControl":"NS-1"},
    {"position":5,"name":"Traffic Manager","xlsxSlug":"traffic-manager","outputCSV":"data/outputs/trafficmanager_rechecked_controls_v2.csv","nsControl":"NS-1"},
    {"position":6,"name":"Peering Service","xlsxSlug":"microsoft-azure-peering-service","outputCSV":"data/outputs/peeringservice_rechecked_controls_v2.csv","nsControl":"NS-1"},
    {"position":7,"name":"App Service","xlsxSlug":"app-service","outputCSV":"data/outputs/appservice_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":8,"name":"Cognitive Search","xlsxSlug":"azure-cognitive-search","outputCSV":"data/outputs/cognitivesearch_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":9,"name":"Data Factory","xlsxSlug":"data-factory","outputCSV":"data/outputs/datafactory_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":10,"name":"Database Migration Service","xlsxSlug":"azure-database-migration-service","outputCSV":"data/outputs/databasemigration_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":11,"name":"Databricks","xlsxSlug":"azure-databricks","outputCSV":"data/outputs/databricks_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":12,"name":"Event Grid","xlsxSlug":"event-grid","outputCSV":"data/outputs/eventgrid_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":13,"name":"Event Hubs","xlsxSlug":"event-hubs","outputCSV":"data/outputs/eventhubs_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":14,"name":"File Sync","xlsxSlug":"azure-file-sync","outputCSV":"data/outputs/filesync_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":15,"name":"Functions","xlsxSlug":"functions","outputCSV":"data/outputs/functions_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":16,"name":"Logic Apps","xlsxSlug":"logic-apps","outputCSV":"data/outputs/logicapps_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":17,"name":"Notification Hubs","xlsxSlug":"notification-hubs","outputCSV":"data/outputs/notificationhubs_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":18,"name":"Cognitive Services","xlsxSlug":"cognitive-services","outputCSV":"data/outputs/cognitiveservices_rechecked_controls_v2.csv","nsControl":"NS-2"},
    {"position":19,"name":"Virtual Desktop","xlsxSlug":"azure-virtual-desktop","outputCSV":"data/outputs/virtualdesktop_rechecked_controls_v2.csv","nsControl":"NS-9"},
    {"position":20,"name":"Content Delivery Network","xlsxSlug":null,"outputCSV":"data/outputs/azurecdn_rechecked_controls_v2.csv","nsControl":"NS-2","hasXlsx":false,"specialHandling":"No xlsx. Create minimal CSV from ns.md [SEC-2] CDN. verdict=conditional, blast_radius=Wide."}
  ]},
  "csvSchema": {
    "columns": ["asb_control_id","feature_name","feature_supported_original","feature_enabled_by_default_original","status_2025","verdict_2025","azure_api_property","script_module","script_function","notes","service","severity","blast_radius","risk_rank"],
    "scriptFields": "empty string",
    "severityMapping": {"NS":"High","IM":"High","PA":"High","LT":"High","IR":"High","DP":"Medium","AM":"Medium","ES":"Medium","BR":"Medium","PV":"Low","GS":"Low"},
    "blastRadiusRule": "Wide if verdict=conditional OR azure_api_property empty/NA OR feature_enabled_by_default_original=False",
    "riskRankFormula": "severity_score(H=3,M=2,L=1) × blast_radius_score(Wide=2,Narrow=1)"
  },
  "verdictTaxonomy": {
    "values": ["implemented","now_applicable_native","upgraded_implemented","still_not_applicable","conditional","not_applicable_paas","not_applicable_arm"],
    "rules": {"True/True":"implemented — microsoft_managed","True/False":"implemented — LIVE-DIRECT + fill azure_api_property","False/NA":"web research → now_applicable_native or still_not_applicable","NA/NA":"still_not_applicable"}
  },
  "webResearchRule": {"trigger":"feature_supported_original=False OR Not Applicable","query":"Azure {ServiceName} {feature_name} 2025 2026","cacheFile":"data/outputs/{service}_na_research.json","checkCacheFirst":true},
  "executionSteps": [
    {"position":1,"action":"READ xlsx sheet='Feature Summary' with openpyxl data_only=True"},
    {"position":2,"action":"EXTRACT all ~35 rows (all domains, not just NS)"},
    {"position":3,"action":"APPLY verdict logic per verdictTaxonomy.rules"},
    {"position":4,"action":"WEB RESEARCH all False/NA controls via Exa — check cache first"},
    {"position":5,"action":"COMPUTE severity, blast_radius, risk_rank per csvSchema"},
    {"position":6,"action":"WRITE 14-col CSV to data/outputs/{service}_rechecked_controls_v2.csv"},
    {"position":7,"action":"VALIDATE: 14 cols, rows>0, no empty verdict_2025"},
    {"position":8,"action":"COMMIT per service: feat: Phase 52 NS — {Name} rechecked_controls_v2"},
    {"position":9,"action":"REPEAT for next service"},
    {"position":10,"action":"UPDATE ado/activity.log every 5 services"},
    {"position":11,"action":"STOP after 20 done — do not start Phase 53"}
  ],
  "constraints": [
    "One service at a time — validate before next",
    "Do NOT modify 14 existing NS v2 CSVs",
    "Do NOT assess non-NS services",
    "Do NOT import to ADO",
    "xlsx sheet always = 'Feature Summary' NOT active sheet",
    "script_module and script_function = empty string",
    "Check na_research.json cache before Exa search",
    "CDN: no xlsx — minimal CSV from ns.md",
    "NS-4, NS-8: pure v2, no per-service CSV"
  ],
  "qualityGate": {
    "expectedNewFiles": 20,
    "totalNSFilesAfter": 34,
    "expectedCols": 14,
    "mustPass": ["34 NS v2 CSVs total","All 14 cols","No empty verdict_2025","All False/NA controls have web research evidence","git status clean"]
  }
}
```
