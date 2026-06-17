# NewSecGap — Handoff Plan Prompt
# Next session: read this first before doing anything

Generated: 2026-06-16. Session cost when generated: ~$101. Start fresh session.

---

## PROJECT CONTEXT (read this cold)

**Goal**: Azure Infrastructure Security Gap Assessment. MCSB v2/v3 controls mapped to
active infra, work items in ADO, effort estimated, and — NEW DIRECTION — Python assessment
scripts that check each control against real Azure resources.

**Repo**: `/Users/nahuelavalos/Repo/NewSecGap/`
**GitHub remote**: `https://github.com/jfcanon/gps.git` (PAT needed — user provides)
**Local Qwen3**: `qwen3:30b-a3b` via Ollama. EXACT invoke:
```bash
cd /Users/nahuelavalos/Repo/claude/workspaces/kimi/demo-local && AI_PROVIDER=local uv run python main.py "$(cat /tmp/qwen_prompt.txt)"
```
Qwen3 = stateless. No internet. Claude reads files, injects content, calls Qwen3, captures output.
Use Qwen3 for ALL boilerplate Python drafts. Claude validates, patches, finalizes.

**Active domains (10)**: NS, IM, PA, DP, AM, LT, PV, ES, BR, GS
**Closed (out of scope)**: IR, DS (infra-only engagement)
**Current effort estimate**: 485h / 60.6 days (1 FTE sequential)

**Sprint cadence**: 2-week sprints. Sprint 2 starts Jun 18, 2026.
**Sprint 2 focus**: NS domain user story execution (37 active stories, 124h).

---

## KEY FILES

| File | Purpose |
|---|---|
| `CLAUDE.md` | Project scope gates, phase log, deferred items — READ FIRST |
| `ado/activity.log` | Phase-by-phase log — check tail for latest completed |
| `ado/wiki/delivery-approach.md` | Stakeholder wiki with mermaid Gantt, estimates |
| `data/outputs/v3_service_controls_reclassified.csv` | 4,157 rows, Qwen3-classified (gitignored) |
| `data/outputs/effort_estimates_ns_filtered.csv` | NS filtered: 124h / 15.5 days (gitignored) |
| `data/inputs/v3_baselines/` | 118 cached v3 xlsx files (gitignored) |
| `scripts/estimate_effort_ns_filtered.py` | Phase 39 pattern — NS filtered estimate |
| `scripts/reclassify_v3_controls.py` | Phase 37 Qwen3 reclassification engine |

---

## REDIS ROW BREAKDOWN (35 rows — MVP/POC for Phase 43)

Source: `data/outputs/v3_service_controls_reclassified.csv` where `service_name == "azure-cache-for-redis"`
Source xlsx: `data/inputs/v3_baselines/azure-cache-for-redis-azure-security-benchmark-v3-latest-security-baseline.xlsx`

### PATH B — not_applicable (14 rows) — Claude web research needed

| Control | Feature Supported | Feature Name | Research Priority |
|---|---|---|---|
| IM-1 | False | Azure AD Authentication Required for Data Plane Access | HIGH — AAD auth added 2023 |
| PA-7 | False | Azure RBAC for Data Plane | HIGH — Access Policy (RBAC) GA Nov 2023 |
| IM-3 | False | Managed Identities | HIGH — Redis MI support added 2024 |
| IM-3 | False | Service Principals | HIGH — same capability as MI |
| LT-1 | False | Microsoft Defender for Service / Product Offering | HIGH — Defender for Redis released |
| DP-5 | False | Data at Rest Encryption Using CMK | MED — Premium tier supports CMK |
| IM-7 | False | Conditional Access for Data Plane | MED — requires AAD auth (IM-1) |
| DP-7 | False | Certificate Management in Azure Key Vault | MED — TLS cert via KV |
| DP-6 | False | Key Management in Azure Key Vault | MED — CMK-related |
| DP-1 | False | Sensitive Data Discovery and Classification | MED — Purview may cover Redis |
| PA-8 | False | Customer Lockbox | LOW — unlikely for cache service |
| ES-2 | Not Applicable | Anti-Malware Solution | LOW — cache, no OS surface |
| PV-6 | Not Applicable | Azure Automation Update Management | LOW — PaaS, no OS |
| PV-5 | Not Applicable | Vulnerability Assessment using Microsoft Defender | LOW — but Defender for Redis may cover |

### PATH A customer (17 rows) — Qwen3 drafts scripts

| Control | Class | Feature Supported | Feature Name |
|---|---|---|---|
| NS-1 | script_medium | True | Network Security Group Support |
| NS-1 | script_medium | True | Virtual Network Integration |
| NS-2 | script_simple | True | Azure Private Link |
| AM-2 | script_medium | True | Azure Policy Support |
| LT-4 | script_simple | True | Azure Resource Logs |
| IM-8 | script_medium | False | Service Credential and Secrets Support (Key Vault) |
| BR-1 | script_simple | False | Azure Backup |
| BR-1 | script_simple | False | Service Native Backup Capability |
| DP-2 | script_simple | False | Data Leakage/Loss Prevention |
| PA-1 | script_medium | False | Local Admin Accounts |
| ES-1 | script_simple | Not Applicable | EDR Solution (Phase 37 flip) |
| ES-3 | script_medium | Not Applicable | Anti-Malware Solution Health Monitoring (Phase 37 flip) |
| AM-5 | script_simple | Not Applicable | Defender Adaptive Application Controls |
| PV-3 | script_medium | Not Applicable | Azure Automation State Configuration |
| PV-3 | script_medium | Not Applicable | Azure Policy Guest Configuration Agent |
| PV-3 | script_medium | Not Applicable | Custom Container Images |
| PV-3 | script_medium | Not Applicable | Custom VM Images |

### PATH A microsoft_managed (4 rows) — verify default not overridden

| Control | Class | Feature Supported | Feature Name |
|---|---|---|---|
| DP-4 | script_simple | True | Data at Rest Encryption Using Platform Keys |
| DP-3 | script_simple | True | Data in Transit Encryption |
| NS-2 | script_simple | True | Disable Public Network Access |
| IM-1 | script_simple | True | Local Authentication Methods for Data Plane Access |

---

## PHASE 43 PART 0 — PLAN PROMPT (pass to plan agent)

```
Phase 43 Part 0: Assessment Script Infrastructure — Scaffolding

GOAL
----
Before writing any assessment scripts (Part 1) or doing N/A research (Path B),
set up the folder structure, data extraction, script skeleton, and runner harness
so Part 1 can focus purely on content (script logic + N/A research verdicts).

This phase writes NO assessment logic. Only scaffolding.

TASKS
-----

Task 1 — Extract Redis control data to structured JSON
  Script: scripts/extract_service_controls.py
  Input:  data/outputs/v3_service_controls_reclassified.csv
  Args:   --service azure-cache-for-redis
  Output: data/inputs/assessment_data/{service_name}_controls.json

  JSON format per row:
  {
    "asb_control_id": "NS-1",
    "control_domain": "Network Security",
    "asb_control_title": "...",
    "feature_name": "Network Security Group Support",
    "feature_description": "...",
    "feature_reference": "https://...",
    "feature_notes": "...",
    "responsibility": "Customer",
    "feature_supported": "True",
    "feature_enabled_by_default": "True",
    "applicability": "customer",
    "automation_class": "script_medium",
    "newly_applicable": "False",
    "reclassification_rationale": "..."
  }

  This file = Qwen3 input for Part 1 script drafting.
  NOTE: feature_supported, feature_enabled_by_default come from raw CSV, not reclassified.
  Join on (service_name, asb_control_id, feature_name).

Task 2 — Create assessment script folder structure
  mkdir -p scripts/assessment/redis/
  mkdir -p data/outputs/assessment_results/

  Create scripts/assessment/redis/README.md:
    - Purpose: read-only Azure compliance checks for Azure Cache for Redis
    - Auth: requires azure-identity (DefaultAzureCredential)
    - Output: JSON per control check → PASS | FAIL | UNKNOWN
    - Run: python3 run_redis_assessment.py --subscription-id X [--resource-group Y] [--redis-name Z]
    - No side effects — zero writes to Azure

Task 3 — Create runner skeleton (empty, to be filled in Part 1)
  File: scripts/assessment/redis/run_redis_assessment.py
  Skeleton only — argparse, logging, empty check registry dict, main() stub.
  Comments mark WHERE Part 1 will insert check functions.

Task 4 — Create N/A research output template
  File: data/outputs/redis_na_research.json
  Empty array [] with schema comment:
  Schema:
  {
    "asb_control_id": "PA-7",
    "feature_name": "Azure RBAC for Data Plane",
    "original_status": "not_applicable",
    "feature_supported_original": "False",
    "verdict_2025": "now_applicable_native | now_applicable_3rdparty | conditional | still_not_applicable",
    "evidence_url": "https://...",
    "evidence_date": "YYYY-MM",
    "script_feasible": true,
    "notes": "Redis AAD auth + Access Policy (RBAC) GA as of Nov 2023",
    "azure_api_property": "properties.redisConfiguration.aadEnabled",
    "suggested_check": "GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Cache/redis/{name}"
  }

Task 5 — Validate structure
  ls scripts/assessment/redis/
  python3 scripts/extract_service_controls.py --service azure-cache-for-redis
  cat data/inputs/assessment_data/azure-cache-for-redis_controls.json | python3 -m json.tool > /dev/null

Task 6 — Update bookkeeping
  ado/activity.log — Phase 43 Part 0 complete
  CLAUDE.md — Phase 43 Part 0 scope gate
  git commit scripts/assessment/ scripts/extract_service_controls.py docs/ CLAUDE.md ado/activity.log

QWEN3 USAGE
-----------
  Use Qwen3 to draft extract_service_controls.py (CSV→JSON extraction script).
  Claude validates: correct column names from both raw + reclassified CSV, correct join key.
  Qwen3 invoke (EXACT):
    cd /Users/nahuelavalos/Repo/claude/workspaces/kimi/demo-local && AI_PROVIDER=local uv run python main.py "$(cat /tmp/qwen_prompt.txt)"

VALIDATION
----------
  python3 scripts/extract_service_controls.py --service azure-cache-for-redis
  # Expected: 35 rows in output JSON
  # Expected: feature_supported field present (joined from raw CSV)
  python3 -c "import json; d=json.load(open('data/inputs/assessment_data/azure-cache-for-redis_controls.json')); print(len(d), 'rows'); assert len(d)==35"
```

---

## PHASE 43 PART 1 — PLAN PROMPT (after Part 0 complete)

```
Phase 43 Part 1: Azure Cache for Redis — Script Generation + N/A Research

PREREQUISITE: Phase 43 Part 0 complete.
  data/inputs/assessment_data/azure-cache-for-redis_controls.json exists (35 rows)
  scripts/assessment/redis/ structure exists
  data/outputs/redis_na_research.json template exists

PATH B — N/A Research (Claude does this, NOT Qwen3 — requires internet)
  For each of 14 not_applicable rows (see docs/plan_prompt.md PATH B table):
  1. Use web search / Exa MCP to research: "[feature_name] Azure Cache for Redis 2023 2024 2025 support"
  2. Check: Microsoft docs, Azure updates blog, marketplace, 3rd-party security tools
  3. Verdict: now_applicable_native | now_applicable_3rdparty | conditional | still_not_applicable
  4. Write verdict + evidence_url + evidence_date + azure_api_property to redis_na_research.json
  5. HIGH priority rows first: PA-7, IM-1, IM-3 (both), LT-1 (strong evidence these changed)

PATH A — Script Generation (Qwen3 drafts, Claude validates)
  For each scriptable row (17 customer + 4 microsoft_managed + newly upgraded from Path B):
  1. Claude reads row from azure-cache-for-redis_controls.json
  2. Build Qwen3 prompt (inject: asb_control_id, feature_name, feature_description, feature_reference, feature_supported, expected_state)
  3. Qwen3 outputs Python function: check_{control}_{feature}(credential, subscription_id, resource_group, redis_name) → dict
  4. Claude validates: correct azure-mgmt-redis SDK call, read-only, correct property path
  5. Group into domain files: ns_redis.py, dp_redis.py, im_redis.py, lt_redis.py, pv_redis.py, pa_redis.py, am_redis.py, br_redis.py, es_redis.py
  6. Register each function in run_redis_assessment.py registry

Script output format (every check):
  {
    "resource": "my-redis-cache",
    "control_id": "NS-2",
    "feature": "Disable Public Network Access",
    "status": "PASS | FAIL | UNKNOWN",
    "actual_value": "Disabled",
    "expected_value": "Disabled",
    "evidence_url": "https://docs.microsoft.com/..."
  }

Read-only guarantee: zero ARM writes. Use azure-mgmt-redis GET only.
Auth: DefaultAzureCredential() — works with managed identity, az login, env vars.
```

---

## REMAINING PHASES OVERVIEW

### Phase 41 — Infra filter: remaining 9 domains
```
Same pattern as Phase 39 (scripts/estimate_effort_ns_filtered.py).
User provides excluded service list per domain.
Run scripts/estimate_effort_ns_filtered.py --domain DP (or similar parameterization).
Expected: each domain reduces 10-25%. Total estimate drops from 485h further.
Domains: DP, GS, ES, PV, LT, PA, IM, BR, AM.
```

### Phase 42 — Resource inventory scan
```
Goal: identify which services have ZERO deployed resources in the tenant.
Script: scripts/scan_resource_inventory.py
Uses: az resource list --output json (runs on Azure-connected VM)
Output: data/outputs/resource_inventory.json {service_type: count}
Effect: stories for zero-resource service types → excluded automatically.
This is the NEXT biggest scope reduction after service exclusion.
Requires: Azure-connected VM with az login active (not this machine).
Handoff: generate the script here, other AI runs it.
```

### Phase 43 Part 2 — Scale Path A to all 10 domains
```
After Redis MVP validates the pattern:
Run same script generation for all 10 active domains.
scripts/assessment/{domain}/ — one folder per domain.
Qwen3 batches: 34 unique asb_control_id values → 34 Qwen3 calls → scripts for all services.
(Same efficiency as Phase 37 — 34 calls covers 4,157 rows via parameterized service arg)
```

### Phase 44 — Path B at scale: all N/A rows
```
2,861 not_applicable rows in reclassified CSV.
Cluster by (asb_control_id, feature_name) → ~200-400 unique clusters.
Claude researches each cluster (web search per cluster, not per row).
Verdict propagates to all rows in cluster.
Output: data/outputs/na_research_all.json
Feeds: updated reclassified CSV + new script targets for Phase 43 Part 2.
```

### Phase 45 — Gap report template
```
Markdown template: docs/gap_report_template.md
Engineers fill in as they run assessment scripts.
Structure: Executive Summary → per-domain gap table → remediation priority matrix → appendix.
```

---

## RULES FOR NEXT SESSION

1. **Qwen3 for ALL Python script drafts** — no exceptions. Claude reviews/patches only.
2. **Read CLAUDE.md + tail ado/activity.log first** — verify last completed phase before starting.
3. **Path B research = Claude + web search** (Exa MCP: `mcp__plugin_ecc_exa__web_search_exa`). Qwen3 cannot do internet research.
4. **Infra scope = 10 domains** (NS, IM, PA, DP, AM, LT, PV, ES, BR, GS). IR and DS are CLOSED.
5. **Assessment scripts = read-only** — zero Azure writes. Every PR reviewed for this constraint.
6. **Git**: commit to master. User provides GitHub PAT when ready to push.
7. **Cost**: watch session cost. Over $50 = flag. Over $80 = wrap up + handoff.

---

## CURRENT BACKLOG PRIORITY

| Priority | Phase | What | Blocker |
|---|---|---|---|
| 1 | 43 Part 0 | Scaffolding + extract_service_controls.py | None — start here |
| 2 | 43 Part 1 | Redis N/A research + script generation | Part 0 done |
| 3 | 41 | Infra filter remaining 9 domains | User provides excluded service lists |
| 4 | 42 | Resource inventory script | Other AI runs on Azure VM |
| 5 | 43 Part 2 | All-domain script generation | Redis MVP done |
| 6 | 44 | Path B at scale (2,861 N/A rows) | Redis Path B done |
| 7 | 45 | Gap report template | Assessment scripts in place |

---

## PHASE 43 STATUS: COMPLETE (2026-06-16)

- Part 0: infra scaffolding — DONE (commit `86550af`)
- Part 1: Redis 34 checks, 9 domain files, PATH B research — DONE (commit `704ad68`)
- Output: `data/outputs/redis_rechecked_controls.csv` (35 rows)
- Remote push FAILED — `jfcanon/gps.git` not found. User must fix remote before next push.

---

## PHASE 43 PART 2 — Azure Key Vault Assessment Scripts

**Same two-part pattern as Phase 43. Read this section cold.**

### Quick facts

| | |
|---|---|
| Service name in CSV | `key-vault` |
| SDK | `azure-mgmt-keyvault` |
| Client class | `KeyVaultManagementClient` |
| Scope params | `resource_group`, `vault_name` |
| Total rows | 36 |
| feature_supported=True (PATH A) | 20 |
| feature_supported=False (PATH B) | 3 |
| feature_supported=Not Applicable (PATH B) | 13 |

### ARM client pattern

```python
from azure.mgmt.keyvault import KeyVaultManagementClient
client = KeyVaultManagementClient(credential, subscription_id)

# Single vault
vault = client.vaults.get(resource_group, vault_name)

# By resource group
vaults = list(client.vaults.list_by_resource_group(resource_group))

# By subscription
vaults = list(client.vaults.list())  # returns paged VaultListResult
```

### Key properties (all on `vault.properties`)

| Property | Type | What to check |
|---|---|---|
| `network_acls.default_action` | str | `'Deny'` = network restricted |
| `network_acls.virtual_network_rules` | list | VNet integration |
| `public_network_access` | str | `'Disabled'` = PASS for NS-2 |
| `private_endpoint_connections` | list | embedded on vault object |
| `enable_rbac_authorization` | bool | `True` = RBAC, `False` = legacy access policies |
| `minimum_tls_version` | str | `'1.2'` or `'1.3'` for DP-3 |
| `enable_soft_delete` | bool | BR-1 native backup proxy |
| `enable_purge_protection` | bool | BR-1 native backup proxy |
| `sku.name` | str | `'standard'` or `'premium'` |
| `sku.family` | str | `'A'` |
| `tags` | dict | AM-2 proxy |

### KV-specific logic notes

- **DP-6 Key Management in KV**: KV IS the key management service → automatic PASS
- **DP-7 Certificate Management in KV**: KV IS the cert management service → automatic PASS
- **IM-1 AAD Auth**: KV legacy "access policies" = local auth. `enable_rbac_authorization == True` → PASS (Entra RBAC enforced, access policies disabled)
- **PA-1 Local Admin**: Same check — `enable_rbac_authorization`. `False` = local access policies active = FAIL
- **PA-7 RBAC**: `enable_rbac_authorization == True` AND at least one RBAC role assignment exists (check via azure-mgmt-authorization, or proxy: just check the flag)
- **LT-1 Defender**: Defender for Key Vault EXISTS (unlike Redis). Check via `azure-mgmt-security`, `SecurityCenter.pricings.get('KeyVaults')`, pricing_tier == 'Standard' → PASS
- **DP-5 CMK**: KV Premium SKU uses HSM-backed keys for keys it stores. But KV itself doesn't support CMK for its own data — Microsoft-managed HSMs only. Return UNKNOWN with explanation.
- **BR-1 Native Backup**: `enable_soft_delete == True` AND `enable_purge_protection == True` → PASS
- **NS-1 NSG/VNet**: `network_acls.virtual_network_rules` not empty → PASS
- **NS-2 Private Link**: `private_endpoint_connections` not empty and any Approved → PASS
- **NS-2 Disable Public**: `public_network_access == 'Disabled'` OR `network_acls.default_action == 'Deny'` → PASS
- **IM-7 Conditional Access**: Same as Redis — not checkable via ARM → UNKNOWN

### PATH B research rows (16 total — Claude researches, NOT Qwen3)

| asb_control_id | feature_name | original | expected verdict |
|---|---|---|---|
| AM-5 | Defender AAC | Not Applicable | still_not_applicable (PaaS) |
| ES-1 | EDR Solution | Not Applicable | still_not_applicable (PaaS) |
| ES-2 | Anti-Malware | Not Applicable | still_not_applicable (PaaS) |
| ES-3 | Anti-Malware Health | Not Applicable | still_not_applicable (PaaS) |
| PV-3 | Automation State Config | Not Applicable | still_not_applicable (PaaS) |
| PV-3 | Guest Config Agent | Not Applicable | still_not_applicable (PaaS) |
| PV-3 | Custom Containers | Not Applicable | still_not_applicable (PaaS) |
| PV-3 | Custom VM Images | Not Applicable | still_not_applicable (PaaS) |
| PV-6 | Update Management | Not Applicable | still_not_applicable (PaaS) |
| PV-5 | Defender VA | Not Applicable | still_not_applicable (PaaS) |
| DP-2 | DLP | Not Applicable | research needed — KV has network ACLs, may flip |
| DP-1 | Sensitive Data Discovery | Not Applicable | still_not_applicable (KV secrets not Purview-scannable) |
| PA-8 | Customer Lockbox | Not Applicable | research needed — KV was added to Lockbox list? |
| BR-1 | Azure Backup | False | conditional — native backup CLI exists but limited |
| PA-1 | Local Admin Accounts | False | now_applicable — check enable_rbac_authorization |
| IM-1 | Local Authentication Methods | False | now_applicable — check enable_rbac_authorization |

### Phase 43 Part 2, Part 0 — Infrastructure scaffolding

```
PREREQUISITE: Phase 43 complete.

TASKS:
1. Run extract_service_controls.py for key-vault:
   python3 scripts/extract_service_controls.py --service key-vault \
     --reclassified-csv data/outputs/v3_service_controls_reclassified.csv \
     --raw-csv data/outputs/v3_service_controls_raw.csv \
     --output-dir data/inputs/assessment_data/
   → data/inputs/assessment_data/key-vault_controls.json (36 rows)

2. Create scripts/assessment/keyvault/ folder:
   - README.md (same pattern as redis/README.md — replace redis/Redis with keyvault/Key Vault)
   - run_keyvault_assessment.py (copy run_redis_assessment.py pattern, update service name, empty CHECK_REGISTRY)
   - data/outputs/keyvault_na_research.json (empty array)

3. Validate: 36 rows in key-vault_controls.json

Dependencies: azure-mgmt-keyvault, azure-mgmt-monitor, azure-mgmt-security, azure-identity
```

### Phase 44 Part 1 — Scripts + N/A research

```
PATH B — N/A Research (Claude does this, NOT Qwen3):
  For each of 16 PATH B rows:
  1. Most PV-3/ES/AM-5 rows → copy Redis verdicts (same PaaS rationale)
  2. Research: PA-8 Customer Lockbox for Key Vault (likely now supported — check 2024 docs)
  3. Research: DP-2 DLP for Key Vault (network ACLs exist → likely now_applicable_native)
  4. Research: PA-1 / IM-1 (enable_rbac_authorization → now_applicable_native confirmed)
  5. Write data/outputs/keyvault_na_research.json

PATH A — Script Generation (Qwen3 drafts, Claude validates):
  Same domain file grouping as Redis:
  - ns_keyvault.py: check_ns1_nsg, check_ns1_vnet, check_ns2_private_link, check_ns2_disable_public_access
  - dp_keyvault.py: check_dp3_tls_transit, check_dp4_platform_keys, check_dp5_cmk, check_dp6_key_mgmt, check_dp7_cert_kv
  - im_keyvault.py: check_im1_local_auth, check_im1_aad_auth, check_im3_mi, check_im3_sp, check_im7_ca, check_im8_kv
  - lt_keyvault.py: check_lt1_defender, check_lt4_resource_logs
  - br_keyvault.py: check_br1_azure_backup, check_br1_native_backup
  - am_keyvault.py: check_am2_policy, check_am5_defender_aac
  - pa_keyvault.py: check_pa1_local_admin, check_pa7_rbac, check_pa8_lockbox
  - es_keyvault.py: check_es1_edr, check_es2_antimalware, check_es3_antimalware_health
  - pv_keyvault.py: check_pv3_*, check_pv5_defender_va, check_pv6_update_management

  Qwen3 prompt inject pattern (same as Redis — see /tmp/qwen_*.txt examples):
    File: /tmp/qwen_kv_ns_dp.txt, /tmp/qwen_kv_im_lt.txt, /tmp/qwen_kv_br_am_pa.txt

  Validation: AST-check all functions, register in CHECK_REGISTRY
  Output: data/outputs/keyvault_rechecked_controls.csv
```

### Updated backlog priority (post Phase 43)

| Priority | Phase | What | Blocker |
|---|---|---|---|
| 0 | — | Fix git remote (jfcanon/gps.git not found) | User provides new remote |
| 1 | 44 Part 0 | KV scaffolding + extract controls JSON | None |
| 2 | 44 Part 1 | KV scripts + N/A research | Part 0 done |
| 3 | 41 | Infra filter remaining 9 domains | User provides excluded service lists |
| 4 | 42 | Resource inventory script | Other AI runs on Azure VM |
| 5 | 43 Part 2 | All-domain script generation (scale Redis pattern) | Redis + KV MVPs done |
| 6 | 45 | Path B at scale (2,861 N/A rows) | KV Path B done |
| 7 | 46 | Gap report template | Assessment scripts in place |
