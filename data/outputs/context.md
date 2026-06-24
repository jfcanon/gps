# data/outputs — Complete File Inventory

**Updated**: Phase 51, 2026-06-24 | **Total files**: 65+ (root + archive)


> This document is the authoritative inventory of every file in `data/outputs/` and `data/outputs/archive/`.
> Verdicts are **recommendations for user review** — no files are deleted by this document.

---

## 1. Active Per-Service v2 CSVs — PRIMARY

**Pattern**: `{service}_rechecked_controls_v2.csv` | **Count**: 29 | **Consumer**: `scripts/import_assessment_tasks_to_ado.py` (ADO task import)

**Shared schema (14 cols)**: `asb_control_id, feature_name, feature_supported_original, feature_enabled_by_default_original, status_2025, verdict_2025, azure_api_property, script_module, script_function, notes, service, severity, blast_radius, risk_rank`

**Created in**: Phase 50 (scored from Phase 40–48 v1 CSVs). Scoring: `risk_rank = severity_score × blast_radius_score` (max 6).

| # | Filename | Service | ADO Domain | Rows | Cols | Size | Verdict | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | `addds_rechecked_controls_v2.csv` | Active Directory Domain Services | IM | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 2 | `apimanagement_rechecked_controls_v2.csv` | API Management | IM | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 3 | `appgateway_rechecked_controls_v2.csv` | Application Gateway | NS | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 4 | `attestation_rechecked_controls_v2.csv` | Attestation | IM | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 5 | `automation_rechecked_controls_v2.csv` | Azure Automation | PA | 35 | 14 | 10KB | KEEP — PRIMARY |  |
| 6 | `azuredns_rechecked_controls_v2.csv` | Azure DNS | NS | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 7 | `azurefirewall_rechecked_controls_v2.csv` | Azure Firewall | NS | 36 | 14 | 10KB | KEEP — PRIMARY |  |
| 8 | `backup_rechecked_controls_v2.csv` | Azure Backup | BR | 36 | 14 | 10KB | KEEP — PRIMARY |  |
| 9 | `bastion_rechecked_controls_v2.csv` | Azure Bastion | NS | 35 | 14 | 10KB | KEEP — PRIMARY |  |
| 10 | `botservice_rechecked_controls_v2.csv` | Bot Service | IM | 35 | 14 | 8KB | KEEP — PRIMARY |  |
| 11 | `cloudshell_rechecked_controls_v2.csv` | Cloud Shell | IM | 35 | 14 | 10KB | KEEP — PRIMARY |  |
| 12 | `customerlockbox_rechecked_controls_v2.csv` | Customer Lockbox | PA | 35 | 14 | 10KB | KEEP — PRIMARY |  |
| 13 | `ddosprotection_rechecked_controls_v2.csv` | DDoS Protection | NS | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 14 | `firewallmanager_rechecked_controls_v2.csv` | Firewall Manager | NS | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 15 | `frontdoor_rechecked_controls_v2.csv` | Front Door | NS | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 16 | `intelligentrecommendations_rechecked_controls_v2.csv` | Intelligent Recommendations | IM | 38 | 14 | 10KB | KEEP — PRIMARY |  |
| 17 | `keyvault_rechecked_controls_v2.csv` | Key Vault | NS | 34 | 10 | 8KB | KEEP — PRIMARY | ⚠️ ANOMALY: 10 cols not 14 — pre-Phase50 file, not regenerated (no v1 source). Verify before ADO import. |
| 18 | `lighthouse_rechecked_controls_v2.csv` | Azure Lighthouse | PA | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 19 | `networkwatcher_rechecked_controls_v2.csv` | Network Watcher | NS | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 20 | `privatelink_rechecked_controls_v2.csv` | Private Link | NS | 35 | 14 | 10KB | KEEP — PRIMARY |  |
| 21 | `publicip_rechecked_controls_v2.csv` | Public IP | NS | 36 | 14 | 9KB | KEEP — PRIMARY |  |
| 22 | `redis_rechecked_controls_v2.csv` | Azure Cache for Redis | NS | 35 | 14 | 12KB | KEEP — PRIMARY |  |
| 23 | `servicebus_rechecked_controls_v2.csv` | Service Bus | NS | 34 | 14 | 9KB | KEEP — PRIMARY |  |
| 24 | `siterecovery_rechecked_controls_v2.csv` | Site Recovery | BR | 35 | 14 | 10KB | KEEP — PRIMARY |  |
| 25 | `spatialanchors_rechecked_controls_v2.csv` | Spatial Anchors | IM | 36 | 14 | 9KB | KEEP — PRIMARY |  |
| 26 | `trustedhardwareim_rechecked_controls_v2.csv` | Trusted Hardware IM | IM | 35 | 14 | 11KB | KEEP — PRIMARY |  |
| 27 | `universalprint_rechecked_controls_v2.csv` | Universal Print | IM | 35 | 14 | 9KB | KEEP — PRIMARY |  |
| 28 | `vpngateway_rechecked_controls_v2.csv` | VPN Gateway | NS | 35 | 14 | 10KB | KEEP — PRIMARY |  |
| 29 | `waf_rechecked_controls_v2.csv` | Web Application Firewall | NS | 35 | 14 | 9KB | KEEP — PRIMARY |  |

---

## 2. Phase 49 Analytics Files

**Created in**: Phase 49. These are derived analytics outputs — NOT used by ADO import script. Purpose: executive view, Azure Policy deployment, MDFC mapping.

| Filename | Rows/Size | Cols | What it is | How created | Known limitations | Consumer | Verdict |
|---|---|---|---|---|---|---|---|
| `phase49_applicable_controls.csv` | 250 rows | 14 | Cross-service filter: all 986 rows from 28 v1 CSVs, kept only verdict ∈ {implemented, now_applicable_native, upgraded_implemented, conditional}. Result is the 'what IS secured' view. | Phase 49 Task A — Python script reading all 28 v1 CSVs | Does NOT include still_not_applicable rows — not a full dataset | Analytics, exec review, input for future analytics phases | KEEP |
| `phase49_risk_ranked_backlog.csv` | 250 rows | 14 | Same 250 rows as applicable_controls.csv, sorted risk_rank DESC then service ASC. Purpose: prioritized remediation order — top rows = highest severity × widest blast radius. | Phase 49 Task B — sort of applicable_controls.csv | Same data as applicable_controls, different sort order — redundant if you can sort in Excel | Analytics, exec review, remediation planning | KEEP (or regenerate on demand) |
| `phase49_policy_initiative.json` | 13 policyDefinitions | JSON | Azure Policy Set Definition (initiative) with 13 audit-effect policy rules. Deploy to Azure Policy portal to get automated compliance scoring for those 13 controls. | Phase 49 Task C — Python script selecting top rows with clean ARM property paths | Plan targeted 20 rules; only 13 had clean enough ARM property paths (no RBAC/sub-resource paths). 13 of 250 controls covered = 5% automation coverage. | Azure Policy admin | KEEP if planning Azure Policy deployment; ARCHIVE otherwise |
| `phase49_cspm_mapping.csv` | 250 rows | 7 | Maps each of 250 applicable rows to MDFC (Microsoft Defender for Cloud) recommendation IDs and display names. Only 27/250 rows filled (10.8% fill rate). | Phase 49 Task D — Exa web search on MDFC public docs (learn.microsoft.com) | Very sparse: niche services (Attestation, Spatial Anchors, Site Recovery, Lighthouse, etc.) have no public MDFC recommendations. 89% empty. | Defender for Cloud admin | ARCHIVE — too sparse to be actionable |

---

## 3. Service Research JSON Cache (`*_na_research.json`)

**Count**: 16 files | **Created in**: Phase 48 (web search research phase)

**What these are**: Each file is a list of 27 items — one per False/NA control row for that service. Each item stores: `asb_control_id, feature_name, original_verdict, research_date, verdict_2026, evidence_url, evidence_date, ...`. These are cached Exa web search research results used to determine which False/NA controls had changed status (now_applicable_native vs still_not_applicable).

**Consumer**: None active — the verdicts are already incorporated into the `*_rechecked_controls_v2.csv` files.

| Filename | Size | Service | Verdict |
|---|---|---|---|
| `apimanagement_na_research.json` | 5KB | API Management | ARCHIVE — research cache; verdicts in v2 CSVs |
| `appgateway_na_research.json` | 4KB | Application Gateway | ARCHIVE — research cache; verdicts in v2 CSVs |
| `azuredns_na_research.json` | 17KB | Azure DNS | ARCHIVE — research cache; verdicts in v2 CSVs |
| `azurefirewall_na_research.json` | 19KB | Azure Firewall | ARCHIVE — research cache; verdicts in v2 CSVs |
| `bastion_na_research.json` | 19KB | Azure Bastion | ARCHIVE — research cache; verdicts in v2 CSVs |
| `frontdoor_na_research.json` | 15KB | Front Door | ARCHIVE — research cache; verdicts in v2 CSVs |
| `keyvault_na_research.json` | 10KB | Key Vault | ARCHIVE — research cache; verdicts in v2 CSVs |
| `keyvault_na_research_2.json` | 11KB | Key Vault | ARCHIVE — research cache; verdicts in v2 CSVs |
| `keyvault_na_research_v2.json` | 10KB | Key Vault | ARCHIVE — research cache; verdicts in v2 CSVs |
| `privatelink_na_research.json` | 21KB | Private Link | ARCHIVE — research cache; verdicts in v2 CSVs |
| `redis_na_research.json` | 11KB | Azure Cache for Redis | ARCHIVE — research cache; verdicts in v2 CSVs |
| `servicebus_na_research.json` | 5KB | Service Bus | ARCHIVE — research cache; verdicts in v2 CSVs |
| `vpngateway_na_research.json` | 20KB | VPN Gateway | ARCHIVE — research cache; verdicts in v2 CSVs |
| `waf_na_research.json` | 18KB | Web Application Firewall | ARCHIVE — research cache; verdicts in v2 CSVs |

---

## 4. Early Project Files — `v3_service_controls_*`

These are large outputs from the initial data extraction phase (Phases 1–15). The `v3_service_controls_raw.csv` is the source extraction of ALL 118 xlsx baselines into a flat CSV. Subsequent files are reclassified and reviewed versions of that extraction.

| Filename | Rows | Cols | Size | What it is | Created in | Verdict |
|---|---|---|---|---|---|---|
| `v3_service_controls_raw.csv` | 4157 | 13 | 1.8MB | Raw extraction from 118 xlsx baselines: every service × every control × feature. Source of truth for initial data. | Phase 1–10 extraction scripts | ARCHIVE — all useful data is in v2 CSVs; huge file |
| `v3_service_controls_reclassified.csv` | 4157 | 19 | 2.5MB | Same 4157 rows with 6 extra classification cols added (automation class, applicability, etc.). | Phase 10–15 reclassification | ARCHIVE — superseded by per-service CSVs |
| `v3_service_controls_reviewed.csv` | 4157 | 16 | 2MB | Same 4157 rows with review cols. Human-reviewed version. | Phase 15–20 review | ARCHIVE — superseded by per-service CSVs |
| `v3_controls.csv` | 85 | 8 | 38KB | MCSB v3 control definitions: asb_id, domain_code, control_domain, recommendation, relevance, automation_class, policy_mapping, policy_guid. One row per v3 control. | Phase 1–5 control extraction | KEEP — useful reference for control metadata |
| `v3_unique_controls.csv` | 34 | 6 | 24KB | Unique controls with service_count and automation class distribution. Summary view. | Phase 5–10 | ARCHIVE — v3_controls.csv is more useful |
| `mcsb_v3_raw.csv` | 18 | 7 | 0KB | Small early extraction: v3_control_id, azure_resource, v3_control_title, description, responsibility, feature, source. | Phase 1 | ARCHIVE — superseded |
| `v3_control_judgments.json` | 34 items | JSON | 9KB | List of 34 control-level judgments: control_id, applicability_2025, newly_applicable, automation_class, confidence, rationale. | Phase 10–15 AI judgment pass | KEEP — captures control-level assessment rationale |

---

## 5. Effort Estimation Files

Created during early planning phases to estimate implementation effort per User Story. Not consumed by any current pipeline — historical planning artifacts.

| Filename | Rows | Cols | Size | What it is | Verdict |
|---|---|---|---|---|---|
| `effort_estimates.csv` | 160 | 6 | 14KB | Per-story estimates: domain, story_id, story_title, policy_status, automation_class, estimated_hours. 160 stories. | ARCHIVE — superseded by v3 estimates |
| `effort_estimates_ns_filtered.csv` | 52 | 9 | 4KB | NS-domain filtered subset with extra columns. | ARCHIVE |
| `effort_estimates_v3.csv` | 152 | 10 | 20KB | Updated effort estimates with resource and matched_service cols. | ARCHIVE — planning artifact |
| `effort_estimates_v3_revised.csv` | 152 | 10 | 20KB | Revised version of v3 estimates. | ARCHIVE — planning artifact |
| `effort_summary.csv` | 13 | 4 | 0KB | Domain-level effort summary. | ARCHIVE |

---

## 6. Anomalous / Unclassified Files

| Filename | Rows | Cols | Size | What it is | Issue | Verdict |
|---|---|---|---|---|---|---|
| `keyvault_rechecked_controls_2.csv` | 36 | 15 | 15KB | Key Vault assessment with extended schema: adds `status_2026, verdict_2026, customer_responsibility, script_feasible, evidence_url, evidence_date`. Likely an experimental extended schema from a later session. | Non-standard schema — 15 cols, not 10 or 14. Does NOT match v2 or v1 schema. | REVIEW — if this is the most complete keyvault data, extract and regenerate proper v2. Otherwise ARCHIVE. |
| `keyvault_rechecked_controls_v2.csv` | 34 | 10 | 8KB | Pre-existing keyvault v2 file from a prior session. Has original 10-col schema — NOT the 14-col v2 schema. Phase 50's scoring script skipped it (no v1 source). | ⚠️ 10 cols not 14 — INCONSISTENT with all other _v2 files. Missing service, severity, blast_radius, risk_rank cols. | ACTION REQUIRED — regenerate from keyvault_rechecked_controls_2.csv or correct v1 source before ADO import |
| `automation_classes.csv` | 21 | 3 | 0KB | Domain-level automation classification counts: domain_code, automation_class (script_complex/script_simple/etc.), count. | Unknown provenance — likely Phase 10–15 analysis output | ARCHIVE — small, no active consumer |
| `context.md` | — | — | — | This inventory document. | — | KEEP — maintained as living doc |

---

## 7. Empty Directories

| Path | Status |
|---|---|
| `assessment_results/` | Empty — created but never populated. DELETE or repurpose in future phase. |

---

## 8. Archive — v1 Per-Service CSVs

**Location**: `data/outputs/archive/` | **Count**: 28 | **Moved in**: Phase 50 via `git mv` (git history preserved)

**What they are**: Original 10-col per-service assessment CSVs generated in Phases 40–48. Superseded by v2 files. Schema: `asb_control_id, feature_name, feature_supported_original, feature_enabled_by_default_original, status_2025, verdict_2025, azure_api_property, script_module, script_function, notes`

| # | Filename | Rows | Superseded by | Verdict |
|---|---|---|---|---|
| 1 | `archive/addds_rechecked_controls.csv` | 35 | `addds_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 2 | `archive/apimanagement_rechecked_controls.csv` | 35 | `apimanagement_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 3 | `archive/appgateway_rechecked_controls.csv` | 35 | `appgateway_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 4 | `archive/attestation_rechecked_controls.csv` | 35 | `attestation_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 5 | `archive/automation_rechecked_controls.csv` | 35 | `automation_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | PA |
| 6 | `archive/azuredns_rechecked_controls.csv` | 35 | `azuredns_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 7 | `archive/azurefirewall_rechecked_controls.csv` | 36 | `azurefirewall_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 8 | `archive/backup_rechecked_controls.csv` | 36 | `backup_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | BR |
| 9 | `archive/bastion_rechecked_controls.csv` | 35 | `bastion_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 10 | `archive/botservice_rechecked_controls.csv` | 35 | `botservice_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 11 | `archive/cloudshell_rechecked_controls.csv` | 35 | `cloudshell_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 12 | `archive/customerlockbox_rechecked_controls.csv` | 35 | `customerlockbox_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | PA |
| 13 | `archive/ddosprotection_rechecked_controls.csv` | 35 | `ddosprotection_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 14 | `archive/firewallmanager_rechecked_controls.csv` | 35 | `firewallmanager_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 15 | `archive/frontdoor_rechecked_controls.csv` | 35 | `frontdoor_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 16 | `archive/intelligentrecommendations_rechecked_controls.csv` | 38 | `intelligentrecommendations_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 17 | `archive/lighthouse_rechecked_controls.csv` | 35 | `lighthouse_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | PA |
| 18 | `archive/networkwatcher_rechecked_controls.csv` | 35 | `networkwatcher_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 19 | `archive/privatelink_rechecked_controls.csv` | 35 | `privatelink_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 20 | `archive/publicip_rechecked_controls.csv` | 36 | `publicip_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 21 | `archive/redis_rechecked_controls.csv` | 35 | `redis_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 22 | `archive/servicebus_rechecked_controls.csv` | 34 | `servicebus_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 23 | `archive/siterecovery_rechecked_controls.csv` | 35 | `siterecovery_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | BR |
| 24 | `archive/spatialanchors_rechecked_controls.csv` | 36 | `spatialanchors_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 25 | `archive/trustedhardwareim_rechecked_controls.csv` | 35 | `trustedhardwareim_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 26 | `archive/universalprint_rechecked_controls.csv` | 35 | `universalprint_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | IM |
| 27 | `archive/vpngateway_rechecked_controls.csv` | 35 | `vpngateway_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |
| 28 | `archive/waf_rechecked_controls.csv` | 35 | `waf_rechecked_controls_v2.csv` | ARCHIVED — keep for git history; delete in Phase 55+ once v2 confirmed stable | NS |

---

## 9. Obsolescence Decision Table

Summary for human review. Verdicts are recommendations — nothing is deleted by this document.

| File / Pattern | Count | Status | Verdict | Rationale | Suggested Action |
|---|---|---|---|---|---|
| `*_rechecked_controls_v2.csv` | 29 | ACTIVE | **KEEP** | Primary ADO import input, authoritative per-service assessment | No action |
| `keyvault_rechecked_controls_v2.csv` | 1 | ANOMALY | **ACTION REQUIRED** | 10-col v2 is inconsistent — missing 4 scoring cols | Regenerate from correct v1 source |
| `keyvault_rechecked_controls_2.csv` | 1 | ANOMALY | **REVIEW** | 15-col experimental schema — may be most complete keyvault data | Review rows, extract to standard v2, then archive |
| `phase49_applicable_controls.csv` | 1 | ACTIVE | **KEEP** | Cross-service applicable-row view; analytics input | No action |
| `phase49_risk_ranked_backlog.csv` | 1 | ACTIVE | **KEEP** | Priority remediation view | No action |
| `phase49_policy_initiative.json` | 1 | ACTIVE | **CONDITIONAL KEEP** | Useful only if Azure Policy will be deployed | Keep if Azure Policy planned; archive otherwise |
| `phase49_cspm_mapping.csv` | 1 | SPARSE | **ARCHIVE** | 10.8% fill rate — not actionable | Move to archive/ |
| `*_na_research.json` | 16 | STALE | **ARCHIVE** | Web search caches; verdicts already in v2 CSVs | Move to archive/ |
| `v3_service_controls_raw.csv` | 1 | STALE | **ARCHIVE** | 1.8MB source extraction; superseded by per-service CSVs | Move to archive/ |
| `v3_service_controls_reclassified.csv` | 1 | STALE | **ARCHIVE** | 2.5MB; superseded | Move to archive/ |
| `v3_service_controls_reviewed.csv` | 1 | STALE | **ARCHIVE** | 2MB; superseded | Move to archive/ |
| `v3_controls.csv` | 1 | REFERENCE | **KEEP** | MCSB v3 control definitions — useful reference | No action |
| `v3_unique_controls.csv` | 1 | STALE | **ARCHIVE** | v3_controls.csv is more useful | Move to archive/ |
| `mcsb_v3_raw.csv` | 1 | STALE | **ARCHIVE** | Superseded early extraction | Move to archive/ |
| `v3_control_judgments.json` | 1 | REFERENCE | **KEEP** | Control-level assessment rationale — historical value | No action |
| `effort_estimates*.csv` / `effort_summary.csv` | 5 | STALE | **ARCHIVE** | Planning artifacts; no active pipeline use | Move to archive/ |
| `automation_classes.csv` | 1 | STALE | **ARCHIVE** | Unknown provenance; no active consumer | Move to archive/ |
| `context.md` | 1 | ACTIVE | **KEEP** | This inventory | No action |
| `archive/*_rechecked_controls.csv` | 28 | ARCHIVED | **KEEP in archive** | Git history preserved | Delete in Phase 55+ once v2 stable |
| `assessment_results/` (dir) | 1 | EMPTY | **DELETE dir** | Never populated | `rmdir data/outputs/assessment_results` |

---

## 10. Quick Reference — Schema Definitions

### v2 CSV schema (14 cols)
| Col | Type | Notes |
|---|---|---|
| `asb_control_id` | string | MCSB v3 control ID e.g. NS-2, IM-3 |
| `feature_name` | string | Feature being assessed |
| `feature_supported_original` | bool/NA | Value from original xlsx baseline |
| `feature_enabled_by_default_original` | bool/NA | Value from original xlsx baseline |
| `status_2025` | string | deprecated — same as verdict_2025 in old files |
| `verdict_2025` | enum | implemented / now_applicable_native / upgraded_implemented / conditional / still_not_applicable / not_applicable_paas / not_applicable_arm |
| `azure_api_property` | string | ARM property path e.g. Microsoft.Cache/Redis/properties/subnetId |
| `script_module` | string | (empty in Phase 40–50) |
| `script_function` | string | (empty in Phase 40–50) |
| `notes` | string | Evidence, source URLs, conditional logic |
| `service` | string | Derived from filename slug |
| `severity` | High/Medium/Low | Domain of asb_control_id |
| `blast_radius` | Wide/Narrow | Wide if conditional/empty ARM prop/disabled by default |
| `risk_rank` | int 1–6 | severity_score × blast_radius_score |
