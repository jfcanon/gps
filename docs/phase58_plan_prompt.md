# Phase 58 — NS 20 CSVs Per-Row Deep Research
## Plan Prompt (Human-Readable)

**Created**: 2026-06-24
**Status**: READY FOR EXECUTION — pass to /eccplan then /eccimplement
**Continues from**: `docs/session6_handover.md`, Phase 57 (Session 6)
**Target confidence**: ~80%+ per-row evidence depth on all 20 new NS CSVs
**Current confidence**: ~45% (bulk MCSB URL applied in Phase 57; no per-row feature verification done)
**Phase number**: 58

---

## Context Read Order (MANDATORY before any action)

1. `CLAUDE.md` — full phase log through Phase 57, scope gates
2. `ado/activity.log` — tail Phase 57 entry (Session 6 complete)
3. `data/outputs/context.md` — Section 5 (ns/ inventory), Section 11 (delivery table)
4. `scripts/phase56_url_backfill.py` — URL backfill pattern (Phase 57 already did this)
5. `scripts/phase56_individual_patches.py` — individual patch pattern to mirror
6. `scripts/phase56_supplement_rows.py` — supplement row pattern to mirror
7. `data/outputs/ns/*.final.csv` — the 20 files to enrich (read header + sample rows)

---

## What Phase 58 Is

Bring 20 NS Phase 52 `final.csv` files from ~45% to ~80%+ per-row evidence confidence.

Phase 57 gave every row a generic MCSB baseline URL. Phase 58 goes deeper:
- Verify each `now_applicable_native` row: what feature, when GA, ARM property, how customer enables
- Verify `conditional` rows: specific conditional logic + source
- Verify key `still_not_applicable` rows: confirm N/A still holds June 2026
- Q2 per-service: find new 2025-2026 features not yet in rows (add SUPPLEMENT)
- Fix appservice duplicate NS-2 row (two identical rows for Azure Private Link)

---

## The 20 Target Files

```
data/outputs/ns/appservice.final.csv         (43 rows)
data/outputs/ns/azurecdn.final.csv           (3 rows — intentionally sparse, legacy CDN)
data/outputs/ns/cognitivesearch.final.csv    (35 rows)
data/outputs/ns/cognitiveservices.final.csv  (35 rows)
data/outputs/ns/databasemigration.final.csv  (35 rows)
data/outputs/ns/databricks.final.csv         (36 rows)
data/outputs/ns/datafactory.final.csv        (35 rows)
data/outputs/ns/eventgrid.final.csv          (35 rows)
data/outputs/ns/eventhubs.final.csv          (35 rows)
data/outputs/ns/filesync.final.csv           (35 rows)
data/outputs/ns/functions.final.csv          (35 rows)
data/outputs/ns/loadbalancer.final.csv       (35 rows)
data/outputs/ns/logicapps.final.csv          (35 rows)
data/outputs/ns/natgateway.final.csv         (35 rows)
data/outputs/ns/notificationhubs.final.csv   (35 rows)
data/outputs/ns/peeringservice.final.csv     (35 rows)
data/outputs/ns/trafficmanager.final.csv     (35 rows)
data/outputs/ns/virtualdesktop.final.csv     (36 rows)
data/outputs/ns/virtualnetwork.final.csv     (36 rows)
data/outputs/ns/virtualwan.final.csv         (36 rows)
```

---

## Workstream Q1-A: Per-Row now_applicable_native Verification (HIGH PRIORITY)

These rows currently have `now_applicable_native` verdict with ONLY the MCSB baseline URL.
Each needs specific evidence: feature name, GA date, ARM property, customer enable step.

### NS-2 Azure Private Link rows (10 services — cross-service batch)

All have identical pattern: `now_applicable_native` for NS-2 Azure Private Link.
One batch Exa/WebSearch per service confirming Private Link GA for that specific service.

| Service | MCSB baseline URL (confirmed) |
|---|---|
| appservice | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/app-service-security-baseline |
| databricks | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-databricks-security-baseline |
| datafactory | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/data-factory-security-baseline |
| eventgrid | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/event-grid-security-baseline |
| eventhubs | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/event-hubs-security-baseline |
| functions | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/functions-security-baseline |
| logicapps | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/logic-apps-security-baseline |
| virtualdesktop | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-virtual-desktop-security-baseline |
| cognitivesearch | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cognitive-search-security-baseline |
| cognitiveservices | https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/cognitive-services-security-baseline |

**Exa query pattern**: `"{ServiceName} Azure Private Link private endpoint GA supported ARM property"`
**ARM property pattern**: varies by service — find the `privateEndpointConnections` or equivalent.
**Note update pattern**: Replace generic MCSB baseline note with:
```
Azure Private Link GA: private endpoint supported (privateEndpointConnections[].properties.privateLinkServiceConnectionState). Customer creates private endpoint in target VNet; service assigns private IP. Public network access can then be disabled via {publicNetworkAccess property}. Source: {specific_doc_url} | MCSB v3 baseline: {baseline_url}
```

### IM-7 Conditional Access rows (4 services)

Services: appservice, cognitivesearch, cognitiveservices, virtualdesktop.
All `now_applicable_native` for IM-7 Conditional Access for Data Plane.

**Exa query**: `"{ServiceName} Entra ID Conditional Access data plane MFA enforced 2024 2025 GA"`
**Note update**: Specific Entra Conditional Access GA confirmation + ARM property (usually via App Registration → Conditional Access policy in Entra, not ARM property on the service itself).

### appservice duplicate row fix

`appservice.final.csv` has TWO rows with `asb_control_id=NS-2, feature_name=Azure Private Link`.
Action: keep ONE row (the first), remove the duplicate. Update notes on remaining row with specific evidence.
Write a targeted patch or fix in `scripts/phase58_individual_patches.py`.

---

## Workstream Q1-B: Conditional Rows (MEDIUM)

### azurecdn — 3 rows only (intentionally sparse)

Both `NS-2` rows are `conditional`. Add specific conditional logic:
- NS-2 Disable Public Network Access: Azure CDN classic does NOT support `publicNetworkAccess` toggle. Only via WAF policy attachment or Front Door migration. Note: legacy product.
- NS-2 Azure Private Link: Azure CDN classic Private Link in preview → GA status as of June 2026 needs verification.

**Exa query**: `"Azure CDN classic Private Link private endpoint GA 2024 2025"`

### virtualwan NS-7-SUPPLEMENT-VIRTUALWAN (already has URL — verify ARM property)

Confirm the ARM property path for forced tunneling routing config.

---

## Workstream Q1-C: Key still_not_applicable Verification (MEDIUM)

Focus on services with high N/A counts where the N/A verdict came from Phase 52 automated assessment without per-row web search.

### High-priority N/A verifications

| Service | Control | Feature | Why check |
|---|---|---|---|
| notificationhubs | NS-1 | VNet Integration | Phase 52 said N/A — verify notification hubs VNet support hasn't changed |
| filesync | NS-2 | Azure Private Link | Phase 52 said N/A — Azure File Sync private endpoint GA may have changed |
| databasemigration | NS-2 | Azure Private Link | Phase 52 said N/A — DMS private endpoint status |
| peeringservice | NS-2 | Azure Private Link | Phase 52 said N/A — peering service is infrastructure-managed |
| trafficmanager | NS-2 | Azure Private Link | Phase 52 said N/A — Traffic Manager has no private endpoint |
| natgateway | NS-2 | Azure Private Link | Phase 52 said N/A — NAT Gateway is VNet infrastructure |
| loadbalancer | NS-2 | Azure Private Link | Phase 52 said N/A — LB is VNet infrastructure, not a Private Link consumer |

**Query pattern**: `"{ServiceName} Azure Private Link private endpoint supported 2025"`
**Action**: Confirm verdict still valid → add standard rationale note. If flipped to now_applicable_native → update verdict + add source URL.

---

## Workstream Q2: Per-Service New-Row Audit 2025-2026 (MEDIUM)

Group searches by service cluster. One search per group. If new feature found → add SUPPLEMENT row.

### Group A — PaaS compute + integration (HIGH)

Services: appservice, functions, logicapps, virtualdesktop

```
Q2-A1: "Azure App Service Functions Logic Apps new network security feature NS-1 NS-2 NS-7 2025 2026"
Q2-A2: "Azure Virtual Desktop AVD new NS security feature private link session host 2025 2026"
```

Focus: Flex Consumption Plan private networking (Functions), Logic Apps Standard VNet injection improvements, AVD Private Link for session hosts (new GA).

### Group B — Data + analytics (HIGH)

Services: databricks, datafactory, eventhubs, eventgrid

```
Q2-B1: "Azure Databricks Data Factory new network security NS-2 NS-7 Unity Catalog managed VNet 2025 2026"
Q2-B2: "Azure Event Hubs Event Grid new private endpoint NS-2 schema registry Kafka 2025 2026"
```

Focus: Databricks Unity Catalog network isolation, ADF managed private endpoints GA, Event Hubs Kafka endpoint private access.

### Group C — AI services (MEDIUM)

Services: cognitivesearch, cognitiveservices

```
Q2-C1: "Azure Cognitive Search AI Foundry new network security NS-2 vector search private 2025 2026"
Q2-C2: "Azure Cognitive Services AI Services new network security private endpoint 2025 2026"
```

### Group D — File/migration/notification (LOW)

Services: filesync, databasemigration, notificationhubs

```
Q2-D1: "Azure File Sync Database Migration Service new network security feature 2025 2026"
```

### Group E — Network infrastructure (LOW)

Services: virtualnetwork (supplement already added), virtualwan (supplement already added), peeringservice, trafficmanager, natgateway, loadbalancer, azurecdn

```
Q2-E1: "Azure Load Balancer NAT Gateway Traffic Manager Peering Service new NS feature 2025 2026"
```

**Supplement row format** (mirror phase57_supplement_rows.py):
```
asb_control_id: NS-{N}-SUPPLEMENT or NS-{N}-SUPPLEMENT-{slug}
status_2025: gap
verdict_2025: now_applicable_native or conditional
service: {slug}
severity: High/Medium/Low
blast_radius: Wide or Narrow
risk_rank: int 1–6
notes: "v2 gap: {description}. Source: {url} | Q2-{group} WebSearch June 2026 confirmed GA."
```

---

## Scripts to Write

### `scripts/phase58_individual_patches.py`

Mirror `scripts/phase56_individual_patches.py`.

Patches to include:
1. appservice NS-2 Azure Private Link (×2 duplicate) — keep first, update notes with specific evidence, remove second
2. All `now_applicable_native` rows across 20 services — update notes with service-specific Private Link / Conditional Access evidence
3. azurecdn NS-2 conditional rows — add specific conditional logic note

### `scripts/phase58_supplement_rows.py`

Mirror `scripts/phase56_supplement_rows.py`.
Only write if Q2 finds at least one new feature not already in rows.
Idempotent (skip if asb_control_id already present).

---

## Execution Order

```
1. Read context files (CLAUDE.md, activity.log, context.md, 20 final.csv files)
2. Exa/WebSearch Q1-A: 10 NS-2 Private Link searches (parallel) + 4 IM-7 Conditional Access searches
3. Exa/WebSearch Q1-B: azurecdn conditional rows
4. Exa/WebSearch Q1-C: 7 key still_not_applicable rows to verify
5. Exa/WebSearch Q2: Groups A–E (5 queries, parallel)
6. Write scripts/phase58_individual_patches.py — all Q1 patches
7. Run python3 scripts/phase58_individual_patches.py
8. Write scripts/phase58_supplement_rows.py — if Q2 found new features
9. Run python3 scripts/phase58_supplement_rows.py
10. Run quality gate — all 20 must PASS (same gate from session6_handover.md)
11. Fix any FAIL rows
12. git add -f data/outputs/ns/ scripts/phase58_*.py && git commit
13. Update ado/activity.log — Phase 58 entry
14. Update CLAUDE.md — Phase 58 one-liner
15. STOP
```

---

## Quality Gate

```python
python3 -c "
import csv, pathlib
ALLOWED = {'implemented','now_applicable_native','upgraded_implemented',
           'still_not_applicable','conditional','not_applicable_paas','not_applicable_arm'}
slugs = ['appservice','azurecdn','cognitivesearch','cognitiveservices','databasemigration',
         'databricks','datafactory','eventgrid','eventhubs','filesync','functions',
         'loadbalancer','logicapps','natgateway','notificationhubs','peeringservice',
         'trafficmanager','virtualdesktop','virtualnetwork','virtualwan']
all_ok = True
for s in slugs:
    rows = list(csv.DictReader(open(f'data/outputs/ns/{s}.final.csv')))
    bad = {r['verdict_2025'] for r in rows} - ALLOWED
    no_url = [r for r in rows if r['verdict_2025']=='now_applicable_native'
              and 'http' not in r.get('notes','')]
    uncovered = [r for r in rows
                 if 'http' not in r.get('notes','')
                 and 'Source' not in r.get('notes','')
                 and not any(x in r.get('notes','').lower()
                             for x in ['infrastructure','azure platform','no customer',
                                       'not applicable','monitoring service'])]
    ok = not bad and not no_url and len(uncovered) < 5
    if not ok: all_ok = False
    print(f'[{\"OK\" if ok else \"FAIL\"}] {s:<22} rows={len(rows):>3} no_url={len(no_url):>2} uncov={len(uncovered):>3}')
print()
print('QUALITY GATE:', 'PASS' if all_ok else 'FAIL')
"
```

**Pass criteria**:
- Zero bad verdicts
- Zero `now_applicable_native` without URL
- Uncovered < 5 per CSV
- azurecdn exception: 3 rows only — max 3 uncovered acceptable
- appservice: duplicate NS-2 row resolved (one removed)

---

## Constraints

| Constraint | Rule |
|---|---|
| No verdict flip | Without MCSB baseline evidence |
| No CSV recreation | Enrich in-place only |
| git add ns/ | Needs `-f` flag |
| azurecdn | 3 rows — DO NOT regenerate |
| appservice 43 rows | All valid — only remove ONE duplicate NS-2 row |
| virtualnetwork/virtualwan | Supplement rows already added — do NOT add duplicate supplements |
| Cost hook | Ignore — user green-lit full execution |

---

## Success Criteria

- All 20 CSVs: zero bad verdicts (already passing — maintain)
- All `now_applicable_native` rows: specific feature evidence in notes (beyond generic baseline URL)
- azurecdn: conditional logic documented
- Q2 audit: documented (new rows added OR explicit "no new features" in activity.log)
- Commits pushed: CSVs + scripts + activity.log + CLAUDE.md
- Research depth: ~80%+ for all 20 (from ~45%)

---

## JSONLD Version

See `docs/phase58_plan_prompt_jsonld.json`
