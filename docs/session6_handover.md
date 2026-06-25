# Phase 57 — Session 6 Handover

Generated: 2026-06-24. Start fresh session after reading this.

---

## PROJECT CONTEXT (read this cold)

**Goal**: Azure Infrastructure Security Gap Assessment. MCSB v2/v3 controls mapped to
active infra, work items in ADO, effort estimated, and — NEW DIRECTION — Python assessment
scripts that check each control against real Azure resources.

**Repo**: `/Users/nahuelavalos/Repo/NewSecGap/`
**GitHub remote**: `https://github.com/jfcanon/gps.git` (PAT needed — user provides)

Read this first:
- /Users/nahuelavalos/Repo/NewSecGap/ado/wiki/delivery-approach.md

## WHAT IS DONE (Sessions 1–5)

### NS Domain — 14 services COMPLETE (final.csv in data/outputs/ns/)

| Service slug | Rows | Confidence | Key notes |
|---|---|---|---|
| appgateway | 36 | ~95% | +NS-7-SUPPLEMENT-APPGW |
| azuredns | 36 | ~95% | +NS-1-SUPPLEMENT; PA-7 now_applicable_native |
| azurefirewall | 37 | ~95% | +NS-6-SUPPLEMENT (IDPS) |
| bastion | 35 | ~95% | Standard rationale complete |
| ddosprotection | 35 | ~95% | DP-3 no data plane confirmed |
| firewallmanager | 35 | ~95% | DP-3 no data plane confirmed |
| frontdoor | 36 | ~95% | +NS-2-SUPPLEMENT (WAF DRS 2.2) |
| networkwatcher | 35 | ~95% | |
| privatelink | 35 | ~95% | |
| publicip | 36 | ~95% | |
| redis | 36 | ~95% | +NS-7-SUPPLEMENT (publicNetworkAccess) |
| servicebus | 35 | ~95% | +NS-7-SUPPLEMENT; Phase 48 errors fixed |
| vpngateway | 35 | ~95% | |
| waf | 35 | ~95% | |

Quality gate: all 14 PASS. Commit: `cd86700`.

### Phase 52 — 20 NS services ASSESSED, NOT YET FINALIZED

Phase 52 created `data/outputs/{slug}_rechecked_controls_v2.csv` (14-col v2 schema) for 20 more NS services. These are NOT yet in `data/outputs/ns/` and NOT yet Exa-enriched. These 20 files were moved to /data/outputs/archive, retrieve from there then perform rework on data/outputs/ns. 

---

## SESSION 6 TASK: Phase 57

**Goal**: Finalize the 20 Phase 52 NS CSVs — same approach as Phase 56.

### Steps

1. Write + run `scripts/phase57_copy_to_final.py` — copies 20 `_rechecked_controls_v2.csv` → `data/outputs/ns/{slug}.final.csv`
2. Exa batch: 20 MCSB baseline searches (one per service slug) — get canonical URLs
3. Write + run `scripts/phase57_url_backfill.py` — bulk URL append to uncovered rows (mirror `scripts/phase56_url_backfill.py`)
4. Individual patches for any rows that need custom notes (same pattern as `scripts/phase56_individual_patches.py`)
5. Q2 audit: 3–4 targeted Exa queries for new 2025-2026 NS features on these services (VNet, App Service, Functions, Databricks focus)
6. Write + run `scripts/phase57_supplement_rows.py` if Q2 finds new features
7. Run quality gate — all 20 must PASS (uncovered < 5 per CSV)
8. Commit all changed files + scripts
9. Update `ado/activity.log` Phase 57 entry
10. Update `CLAUDE.md` Phase 57 one-liner
11. **STOP** — do not start Session 7 (IM domain) without user confirmation

---

## THE 20 SERVICES — INVENTORY

| Slug | Rows | No-URL | Verdict breakdown | MCSB baseline slug (try first) | Priority |
|---|---|---|---|---|---|
| virtualdesktop | 36 | 35 | impl=20, now_app=2, still_na=14 | `azure-virtual-desktop` | HIGH |
| appservice | 43 | 32 | impl=17, now_app=3, still_na=23 | `app-service` | HIGH |
| cognitivesearch | 35 | 25 | impl=12, now_app=2, still_na=21 | `azure-cognitive-search` | HIGH |
| cognitiveservices | 35 | 25 | impl=15, now_app=2, still_na=18 | `cognitive-services` | HIGH |
| datafactory | 35 | 24 | impl=20, now_app=1, still_na=14 | `azure-data-factory` | HIGH |
| functions | 35 | 24 | impl=20, now_app=1, still_na=14 | `azure-functions` | HIGH |
| eventgrid | 35 | 25 | impl=11, now_app=1, still_na=23 | `event-grid` | HIGH |
| eventhubs | 35 | 25 | impl=16, now_app=1, still_na=18 | `event-hubs` | HIGH |
| logicapps | 35 | 21 | impl=17, now_app=1, still_na=17 | `azure-logic-apps` | HIGH |
| databricks | 36 | 21 | impl=16, now_app=1, still_na=19 | `azure-databricks` | HIGH |
| notificationhubs | 35 | 23 | impl=4, still_na=31 | `notification-hubs` | MED |
| filesync | 35 | 23 | impl=6, still_na=29 | `azure-file-sync` | MED |
| databasemigration | 35 | 16 | impl=6, still_na=29 | `azure-database-migration-service` | MED |
| peeringservice | 35 | 7 | impl=2, still_na=33 | `azure-peering-service` | LOW |
| virtualnetwork | 35 | 7 | impl=3, still_na=32 | `azure-virtual-network` | LOW |
| virtualwan | 35 | 6 | impl=5, still_na=30 | `azure-virtual-wan` | LOW |
| trafficmanager | 35 | 5 | impl=2, still_na=33 | `traffic-manager` | LOW |
| natgateway | 35 | 4 | impl=2, still_na=33 | `nat-gateway` | LOW |
| loadbalancer | 35 | 3 | impl=3, still_na=32 | `azure-load-balancer` | LOW |
| azurecdn | 3 | 2 | cond=2, still_na=1 | `azure-content-delivery-network` | NOTE |

**azurecdn NOTE**: Only 3 rows — legacy Azure CDN. Azure Front Door Standard/Premium (frontdoor.final.csv) already covers the modern CDN product. The 3 rows are NS-2 focused (HTTPS-only delivery, Private Link for origin, NSG not applicable). This is intentionally sparse. Do NOT regenerate from scratch. Add URL note and move on.

**Total rows to process**: ~681 rows (643 + 3 + 35 anomalies in appservice)

---

## PATTERNS TO MIRROR

| Script | Pattern for | Location |
|---|---|---|
| `phase57_copy_to_final.py` | copy _v2 → final, same content | New script (trivial) |
| `phase56_url_backfill.py` | bulk MCSB URL backfill | `scripts/phase56_url_backfill.py` |
| `phase56_individual_patches.py` | individual row patches | `scripts/phase56_individual_patches.py` |
| `phase56_supplement_rows.py` | Q2 supplement rows | `scripts/phase56_supplement_rows.py` |

MCSB baseline URL pattern (same as Phase 56):
```
https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/{mcsb-slug}-security-baseline
```

Exa query pattern per service:
```
"{ServiceName} MCSB security baseline feature summary site:learn.microsoft.com"
```

---

## QUALITY GATE (run after all 20 finalized)

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

Pass criteria (same as Phase 56):
- Zero bad verdicts
- Zero `now_applicable_native` without URL
- Uncovered < 5 per CSV

Exception: `azurecdn` — 3 rows only, max uncovered = 3 acceptable (intentionally limited).

---

## KEY CONSTRAINTS (carry forward from all prior sessions)

| Constraint | Rule |
|---|---|
| ADO_PAT | Env var only — never committed |
| No verdict flip | Without MCSB baseline evidence |
| No CSV recreation | Enrich in-place only (copy _v2 → final, then enrich) |
| No ADO ops | Phase 53 blocked on User Story IDs from user |
| git add ns/ | Needs `-f` flag (`git add -f data/outputs/ns/`) |
| Supplements | asb_control_id format: `NS-{N}-SUPPLEMENT` or `NS-{N}-SUPPLEMENT-{slug}` if service-specific |
| STOP signal | After Phase 57 quality gate PASS + commit — do not start IM domain |
| Cost hook | User instruction: ignore cost hook. Standing green light for this project. |

---

## Q2 AUDIT — TARGETED QUERIES FOR SESSION 6

Run these 4 queries for the new 20 services (skip queries already answered in Phase 56):

| ID | Query | Target services |
|---|---|---|
| Q2-A | `"Azure Virtual Desktop AVD NS-2 private endpoint VNet 2025 2026 new"` | virtualdesktop |
| Q2-B | `"Azure App Service Functions Logic Apps VNet integration NS-2 private endpoint 2025 2026"` | appservice, functions, logicapps |
| Q2-C | `"Azure Event Hubs Event Grid Databricks private endpoint NS-2 NS-7 disable public access 2025 2026"` | eventhubs, eventgrid, databricks |
| Q2-D | `"Azure Virtual Network VNet NS-3 NS-4 TLS 1.3 firewall rules 2025 2026 new"` | virtualnetwork, virtualwan |

For each new feature found: add SUPPLEMENT row (same format as Phase 56 supplements).

---

## FULL NS DOMAIN STATUS AFTER SESSION 6

Target: 34 total NS services with final.csv in data/outputs/ns/ (14 existing + 20 new).

Out-of-scope (excluded in Phase 39):
Batch, Communication Services, Communications Gateway, Container Apps, Digital Twins,
HPC Cache, Machine Learning Service, Managed Lustre, Nutanix on Azure, Remote Rendering,
SignalR Service, Spring Apps, Stack Edge, VMware Solution, Web PubSub

---

## KEY FILES

| File | Purpose |
|---|---|
| `ado/activity.log` | Phase log — tail for Phase 56 + pivot decision |
| `CLAUDE.md` | Full phase log Phases 1-56, scope gates |
| `data/outputs/context.md` | File inventory (Section 5 = ns/ folder) |
| `data/outputs/ns/` | 14 enriched final CSVs (reference for patterns) |
| `scripts/phase56_url_backfill.py` | Pattern: bulk MCSB URL backfill |
| `scripts/phase56_individual_patches.py` | Pattern: individual row patches |
| `scripts/phase56_supplement_rows.py` | Pattern: Q2 supplement rows |
| `data/outputs/appservice_rechecked_controls_v2.csv` | Largest Phase 52 CSV (43 rows) |


---

## AFTER SESSION 6 — SESSION 7 (IM DOMAIN)

Session 7 scope (NOT Session 6):
- IM domain initial prompt
- 9 IM CSVs exist as `_rechecked_controls_v2.csv`: addds, apimanagement, attestation, botservice, cloudshell, intelligentrecommendations, spatialanchors, trustedhardwareim, universalprint
- Reference: docs/plan_prompt.md, docs/session3_handover.md, docs/session4_handover.md
- Phase 53 (IM ADO import) still blocked on user providing User Story IDs

Phase 57 STOP condition: quality gate 20/20 PASS + commit + activity.log updated. Then ask user to confirm Session 7 start.
