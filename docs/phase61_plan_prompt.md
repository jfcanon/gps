# Phase 61 — Assessment Scripts: 20 Missing NS Services (Batch 1 of N)

## Context

**What exists**: 15 NS services have complete assessment scripts in `scripts/assessment/`. Pattern: 9 domain files + 1 runner, ~56 registered checks each. Read-only Azure ARM/API calls via `DefaultAzureCredential`.

**Gap**: 20 NS services have final.csv but NO assessment scripts. This phase creates Batch 1 (5 highest-traffic services). Remaining batches in future phases.

**Template**: `scripts/assessment/appgateway/` — closest to general-purpose NS service pattern. `scripts/assessment/redis/` — original gold standard.

**Output target**: running the `run_{service}_assessment.py` against a real Azure subscription produces a JSON/CSV report confirming whether each `implemented`/`now_applicable_native`/`conditional` row actually passes.

---

## Batch 1 — 5 Services (Priority: high infra footprint)

| Service | Slug | Final CSV | Non-NA rows | Priority reason |
|---|---|---|---|---|
| App Service | `appservice` | `ns/appservice.final.csv` | ~15 | Most common Azure web workload |
| Virtual Network | `virtualnetwork` | `ns/virtualnetwork.final.csv` | ~12 | Foundation — all services depend on it |
| Event Hubs | `eventhubs` | `ns/eventhubs.final.csv` | ~14 | High-traffic messaging infra |
| Azure Functions | `functions` | `ns/functions.final.csv` | ~14 | Serverless — large NS surface |
| Event Grid | `eventgrid` | `ns/eventgrid.final.csv` | ~12 | Event routing — NS-critical |

---

## Per-Service Script Structure (mirror appgateway pattern)

```
scripts/assessment/{slug}/
    ns_{slug}.py          # NS-1 WAF/NSG/DDoS, NS-2 Private Link/public access, NS-3, NS-6, NS-7
    dp_{slug}.py          # DP-2 DLP, DP-3 TLS, DP-4 platform keys, DP-5 CMK, DP-6 KV, DP-7 cert
    im_{slug}.py          # IM-1 AAD/local auth, IM-3 MI, IM-7 CA, IM-8 KV secrets
    lt_{slug}.py          # LT-1/2/3/4 logging (diag settings, activity log, NSG flow, KV audit)
    br_{slug}.py          # BR-1/2/3 backup config, soft delete, geo-redundancy
    am_{slug}.py          # AM-1/2/3/4 asset management
    pa_{slug}.py          # PA-1 limits, PA-7 RBAC
    es_{slug}.py          # ES-1 endpoint protection
    pv_{slug}.py          # PV-1/2/3 vulnerability assessment
    run_{slug}_assessment.py  # CHECK_REGISTRY + runner + argparse + JSON/CSV output
```

Each check function signature:
```python
def check_{domain}{n}_{feature}(credential, subscription_id: str, resource_group: str | None, resource_name: str | None) -> dict:
    # Returns: {resource, control_id, feature, status, actual_value, expected_value, evidence_url}
    # status values: PASS | FAIL | UNKNOWN | NOT_APPLICABLE | ERROR
```

---

## Execution Steps (per batch)

### Step 0 — Read first
- `scripts/assessment/appgateway/ns_appgateway.py` — NS check pattern
- `scripts/assessment/appgateway/run_appgateway_assessment.py` — registry + runner pattern
- `data/outputs/ns/{slug}.final.csv` — which non-NA rows need checks (per service)

### Step 1 — Per service, read final CSV to identify check targets
For each of 5 services: read final.csv, filter verdict_2025 NOT IN (still_not_applicable, not_applicable_paas, not_applicable_arm). These rows = check targets. Map each to control_id + feature_name → determines which check functions to implement.

### Step 2 — Write domain check files
9 files per service. Each function:
- Uses appropriate Azure SDK client (NetworkManagementClient, WebSiteManagementClient, EventHubManagementClient, etc.)
- Reads ARM property named in `azure_api_property` column of final.csv
- Returns PASS/FAIL/UNKNOWN based on expected value

### Step 3 — Write runner
`run_{slug}_assessment.py`: import all domain modules, build CHECK_REGISTRY dict, argparse (--subscription-id, --resource-group, --resource-name, --output-format json|csv), DefaultAzureCredential, output results.

### Step 4 — AST validate all functions registered
```bash
python3 -c "import ast; [ast.parse(open(f).read()) for f in glob.glob('scripts/assessment/{slug}/*.py')]"
```

### Step 5 — Dry import test (no Azure creds needed)
```bash
cd scripts/assessment/{slug} && python3 -c "import run_{slug}_assessment; print(len(run_{slug}_assessment.CHECK_REGISTRY), 'checks registered')"
```

### Step 6 — Commit
```bash
git add scripts/assessment/{slug}/ && git commit -m "feat: Phase 61 assessment scripts — {slug}"
```
One commit per service. 5 commits total for Batch 1.

### Step 7 — Update CLAUDE.md + activity.log, final commit

---

## Quality Gate

Per service, PASS requires:
- [ ] All 5 batched services have 9 domain files + 1 runner
- [ ] CHECK_REGISTRY entries ≥ non-NA row count in final.csv
- [ ] AST parse clean (zero syntax errors)
- [ ] Dry import prints correct check count
- [ ] No hardcoded subscription IDs, resource groups, or credentials

---

## ADO Import Readiness (assessment scripts ≠ ADO tasks)

Assessment scripts run AFTER ADO import is done. They produce live compliance evidence per resource. ADO tasks are already imported (Phase 60 + ADO fix). Assessment scripts close the loop: run against real Azure infra → attach results to ADO tasks as comments/attachments.

---

## Constraints

- Read-only: zero ARM writes, zero resource mutations
- Auth: `DefaultAzureCredential` only — no hardcoded PATs or keys
- Missing SDK resource type → return UNKNOWN, never fabricate PASS
- Services with no ARM property in final.csv row → UNKNOWN
- `keyvault` uses `scripts/assessment/keyvault/v2/` — do not touch v1

---

## Remaining Batches (future phases)

- Batch 2: azurecdn, cognitivesearch, cognitiveservices, databasemigration, databricks
- Batch 3: datafactory, filesync, loadbalancer, logicapps, natgateway
- Batch 4: notificationhubs, peeringservice, trafficmanager, virtualdesktop, virtualwan
- Phase 62+: IM domain (9 services, 74 non-NA rows)
- Phase 63+: BR domain (2 services, 26 non-NA rows)
