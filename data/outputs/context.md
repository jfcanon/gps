# data/outputs — File Inventory

Generated: 2026-06-24 | Phase 50 housekeeping

---

## 1. Per-Service v2 CSVs — PRIMARY (ADO import input)

**Pattern**: `{service}_rechecked_controls_v2.csv`
**Count**: 29 files | **Total rows**: 1020
**Schema (14 cols)**: `asb_control_id, feature_name, feature_supported_original, feature_enabled_by_default_original, status_2025, verdict_2025, azure_api_property, script_module, script_function, notes, service, severity, blast_radius, risk_rank`
**Consumer**: `scripts/import_assessment_tasks_to_ado.py` (ADO task import), manual Excel review
**Status**: ACTIVE — current authoritative per-service assessment

| Service | File | Rows |
|---|---|---|
| Active Directory DS | addds_rechecked_controls_v2.csv | 35 |
| API Management | apimanagement_rechecked_controls_v2.csv | 35 |
| Application Gateway | appgateway_rechecked_controls_v2.csv | 35 |
| Attestation | attestation_rechecked_controls_v2.csv | 35 |
| Azure Automation | automation_rechecked_controls_v2.csv | 35 |
| Azure DNS | azuredns_rechecked_controls_v2.csv | 35 |
| Azure Firewall | azurefirewall_rechecked_controls_v2.csv | 36 |
| Azure Backup | backup_rechecked_controls_v2.csv | 36 |
| Azure Bastion | bastion_rechecked_controls_v2.csv | 35 |
| Bot Service | botservice_rechecked_controls_v2.csv | 35 |
| Cloud Shell | cloudshell_rechecked_controls_v2.csv | 35 |
| Customer Lockbox | customerlockbox_rechecked_controls_v2.csv | 35 |
| DDoS Protection | ddosprotection_rechecked_controls_v2.csv | 35 |
| Firewall Manager | firewallmanager_rechecked_controls_v2.csv | 35 |
| Front Door | frontdoor_rechecked_controls_v2.csv | 35 |
| Intelligent Recommendations | intelligentrecommendations_rechecked_controls_v2.csv | 38 |
| Key Vault | keyvault_rechecked_controls_v2.csv | 34 |
| Azure Lighthouse | lighthouse_rechecked_controls_v2.csv | 35 |
| Network Watcher | networkwatcher_rechecked_controls_v2.csv | 35 |
| Private Link | privatelink_rechecked_controls_v2.csv | 35 |
| Public IP | publicip_rechecked_controls_v2.csv | 36 |
| Redis Cache | redis_rechecked_controls_v2.csv | 35 |
| Service Bus | servicebus_rechecked_controls_v2.csv | 34 |
| Site Recovery | siterecovery_rechecked_controls_v2.csv | 35 |
| Spatial Anchors | spatialanchors_rechecked_controls_v2.csv | 36 |
| Trusted Hardware IM | trustedhardwareim_rechecked_controls_v2.csv | 35 |
| Universal Print | universalprint_rechecked_controls_v2.csv | 35 |
| VPN Gateway | vpngateway_rechecked_controls_v2.csv | 35 |
| WAF | waf_rechecked_controls_v2.csv | 35 |

> **keyvault**: pre-existing v2 file from prior session; no v1 source on disk — review and confirm before ADO import.

---

## 2. Archived v1 CSVs — SUPERSEDED

**Pattern**: `archive/{service}_rechecked_controls.csv`
**Count**: 28 files | **Schema (10 cols)**: original assessment cols, no scoring
**Consumer**: none active — superseded by v2
**Status**: ARCHIVED — kept in git history for reference; do not use as ADO import input

These are the original per-service assessment files produced in Phases 40–48. The v2 files contain all the same rows with 4 scoring columns appended. The v1 files are preserved in `archive/` via `git mv` so blame/history is intact.

**Proposal**: DELETE from git in Phase 55+ once v2 is confirmed stable in ADO. Alternatively keep in archive indefinitely — they are small files.

---

## 3. Phase 49 Analytics — KEEP (derived outputs)

**Count**: 4 files
**Status**: ACTIVE — secondary assessment layer, not used by ADO import script

| File | Purpose | Rows/Size |
|---|---|---|
| `phase49_applicable_controls.csv` | Cross-service view, applicable rows only (verdict ∈ keep set) | 250 rows, 14 cols |
| `phase49_risk_ranked_backlog.csv` | Same 250 rows sorted by risk_rank DESC — remediation backlog | 250 rows, 14 cols |
| `phase49_policy_initiative.json` | Azure Policy audit initiative — 13 policyDefinitions for top ARM-auditable controls | ~14 KB |
| `phase49_cspm_mapping.csv` | MDFC recommendation linkage for all 250 applicable rows (27/250 filled) | 250 rows, 7 cols |

---

## 4. Obsolescence Proposals

| File Set | Count | Verdict | Rationale |
|---|---|---|---|
| `*_rechecked_controls_v2.csv` | 29 | **KEEP — PRIMARY** | Current authoritative source; ADO import uses these |
| `archive/*_rechecked_controls.csv` | 28 | **KEEP in archive** (review Phase 55+) | Superseded but small; git history value; safe to delete after v2 confirmed |
| `phase49_*.csv / .json` | 4 | **KEEP** | Analytics/policy blueprint — separate use case from ADO import |
| `keyvault_rechecked_controls_v2.csv` | 1 | **REVIEW** | No v1 source; verify rows are correct before ADO import |
| `context.md` (this file) | 1 | **KEEP** | Inventory reference |

---

## Scoring Formula (v2 cols)

```
severity  = domain(asb_control_id): NS/IM/PA/LT/IR → High(3), DP/AM/ES/BR → Medium(2), PV/GS → Low(1)
blast_radius = Wide(2) if verdict=conditional OR azure_api_property empty OR feature_enabled_by_default=False
            = Narrow(1) otherwise
risk_rank  = severity_score × blast_radius_score  (max=6)
```
