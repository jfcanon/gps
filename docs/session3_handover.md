# Phase 43 — Session 3 Handover

# Generated: 2026-06-18. Start fresh session after reading this.

***

## WHAT IS DONE (Sessions 1 + 2)

| Part | Service                    | Scripts                                             | Checks | CSV rows | Status   |
| ---- | -------------------------- | --------------------------------------------------- | ------ | -------- | -------- |
| 0    | Infrastructure scaffolding | extract\_service\_controls.py, runner skeleton      | —      | —        | complete |
| 1    | azure-cache-for-redis      | scripts/assessment/redis/ (9 files)                 | 34     | 35       | complete |
| 2    | azure-key-vault            | scripts/assessment/keyvault/v2/ (9 files)           | 34     | 36       | complete |
| 3    | azure-service-bus          | scripts/assessment/servicebus/ (9 files)            | 34     | 35       | complete |
| 4A   | azure-application-gateway  | scripts/assessment/appgateway/ (9 files)            | 35     | 36       | complete |
| 4B   | ADO tooling                | scripts/import\_assessment\_tasks\_to\_ado.py (new) | —      | —        | complete |

**Domain correction (Part 4 onward)**: Phase 43 must focus on **Network Security domain services** only.\
NS-domain queue — remaining: azure-firewall, azure-front-door, azure-ddos-protection, vpn-gateway, azure-web-application-firewall, network-watcher, azure-private-link, azure-public-ip, azure-firewall-manager, azure-dns, azure-bastion.

***

## CANONICAL v2 PATTERN

**Mirror this for every new service**:

```
scripts/assessment/keyvault/v2/pa_keyvault.py   ← primary pattern file
scripts/assessment/keyvault/v2/am_keyvault.py   ← static UNKNOWN pattern
scripts/assessment/keyvault/v2/run_keyvault_assessment_v2.py  ← runner pattern
```

v2 rules (non-negotiable):

- `try/except Exception as e` wrapping every gateway fetch
- No `"resource"` key in the base result dict (only per-gateway dicts have it)
- `first_pass = first_pass or r` pattern for list iteration
- `_get_gateways(client, resource_group, gateway_name)` scope helper in every domain file
- All stubs return `{"status": "UNKNOWN", "actual_value": "...", "expected_value": "N/A", "evidence_url": "..."}`
- Validate with: `python3 -c "import ast; ast.parse(open('$f').read()); print('OK', '$f')"` (Azure SDK not installed locally)

***

## KEY FILES

| File                                                | Purpose                                                       |
| --------------------------------------------------- | ------------------------------------------------------------- |
| `ado/activity.log`                                  | Phase log — tail for latest state                             |
| `docs/plan_prompt.md`                               | Prior session handover doc (superseded by this file)          |
| `data/outputs/v3_service_controls_reclassified.csv` | 4,157 rows, source of truth for PATH A/B                      |
| `data/outputs/appgateway_rechecked_controls.csv`    | 10-col Redis schema, 36 rows                                  |
| `data/outputs/servicebus_rechecked_controls.csv`    | 10-col Redis schema, 35 rows                                  |
| `scripts/import_assessment_tasks_to_ado.py`         | NEW — reads \*\_rechecked\_controls.csv, creates ADO Tasks    |
| `scripts/import_to_ado.py`                          | Existing ADO importer — H1/H2 bugs identified, not yet fixed  |
| `scripts/ado_config.py`                             | ADO\_PAT from env, ADO\_ORG, ADO\_PROJECT, API\_VERSION="7.1" |

***

## 10-COL CSV SCHEMA (Redis schema — use for all services)

```
asb_control_id, feature_name, feature_supported_original, feature_enabled_by_default_original,
status_2025, verdict_2025, azure_api_property, script_module, script_function, notes
```

Verdict taxonomy: `implemented`, `now_applicable_native`, `upgraded_implemented`, `still_not_applicable`, `conditional`, `not_applicable_paas`, `not_applicable_arm`

***

## ADO TOOLING STATUS

`scripts/import_assessment_tasks_to_ado.py` — reads any `*_rechecked_controls.csv`, creates Tasks under parent User Stories.

```bash
# dry-run (safe — zero API calls)
python3 scripts/import_assessment_tasks_to_ado.py \
  --csv data/outputs/servicebus_rechecked_controls.csv \
  --service-name azure-service-bus \
  --dry-run

# live run
ADO_PAT=<token> python3 scripts/import_assessment_tasks_to_ado.py \
  --csv data/outputs/appgateway_rechecked_controls.csv \
  --service-name azure-application-gateway
```

`scripts/import_to_ado.py` known bugs (not yet fixed):

- H1: no duplicate check on Story create — re-run creates duplicates
- H2: Feature 429 has no retry (only Story 429 retries)
- M1: cfg.validate() skipped on dry-run → malformed config not caught early

***

## OPEN ITEMS FOR SESSION 3

1. **Phase 43 Part 5** — Azure Firewall scripts (recommended next — see initial prompt below)
2. Fix H1/H2 in `scripts/import_to_ado.py` (can be a quick standalone task)
3. Continue NS-domain queue after Firewall

***

## SESSION 3 INITIAL PROMPT

Copy-paste this to start Session 3:

```
You are continuing Phase 43 of the NewSecGap project.
Repo: /Users/nahuelavalos/Repo/NewSecGap/

READ FIRST: docs/session3_handover.md — it has full context. Ignore "SESSION 3 INITIAL PROMPT" section. 
Then read: ado/activity.log (tail) to confirm current state.

TASK: Phase 43 Part 5 — Azure Firewall assessment scripts.

SERVICE FACTS
┌─────────────────────┬────────────────────────────────────────────────────────────────────────┐
│ Property            │ Value                                                                  │
├─────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Service name in CSV │ azure-firewall                                                         │
│ SDK                 │ azure-mgmt-network                                                     │
│ Client              │ NetworkManagementClient                                                │
│ Resource term       │ firewall                                                               │
│ Scope params        │ resource_group, firewall_name                                          │
│ Get                 │ client.azure_firewalls.get(rg, name)                                   │
│ List by RG          │ client.azure_firewalls.list(rg)                                        │
│ List all            │ client.azure_firewalls.list_all()                                      │
└─────────────────────┴────────────────────────────────────────────────────────────────────────┘

KEY PROPERTIES (firewall.*)
- threat_intel_mode: 'Alert'/'Deny'/'Off' → NS-1 threat detection
- network_rule_collections / application_rule_collections / nat_rule_collections: rule count proxy
- ip_configurations[*].subnet.id: contains 'AzureFirewallSubnet' → proper subnet placement
- sku.tier: 'Standard'/'Premium' → Premium unlocks TLS inspection, IDPS
- additional_properties.get('Network.IDPS.SignatureOverrides') / idps_settings: NS-1 IDPS (Premium)
- transport_security.certificate_authority.key_vault_secret_id: DP-6/DP-7 KV cert (Premium TLS inspect)
- identity: IM-3 MI (used for KV cert access in Premium)
- tags: AM-2 proxy
- firewall_policy.id: linked FirewallPolicy resource (preferred config model for v2)

FIREWALL-SPECIFIC LOGIC
- NS-1 Threat Intel: threat_intel_mode == 'Deny' → PASS; 'Alert' → WARN; 'Off' → FAIL
- NS-1 IDPS: Premium SKU + idps_settings.mode == 'Deny' → PASS (Standard has no IDPS)
- DP-3 TLS: Premium only — transport_security.certificate_authority set → TLS inspection active → PASS proxy
- DP-6/DP-7: Premium — transport_security.certificate_authority.key_vault_secret_id set + identity → PASS
- IM-3 MI: firewall.identity present → PASS (used for KV cert in Premium TLS)
- LT-4 Logs: MonitorManagementClient.diagnostic_settings.list(fw.id) — AzureFirewallApplicationRule + AzureFirewallNetworkRule logs → PASS
- AM-2: tags proxy
- ES/PV: PaaS → all UNKNOWN static
- IM-1 local auth: No local auth concept on Firewall (ARM RBAC only) → UNKNOWN static
- BR-1: No Azure Backup for Firewall config → UNKNOWN static

OUTPUT PATHS
scripts/assessment/azurefirewall/
  ns_azurefirewall.py
  dp_azurefirewall.py
  im_azurefirewall.py
  lt_azurefirewall.py
  br_azurefirewall.py
  am_azurefirewall.py
  pa_azurefirewall.py
  es_azurefirewall.py
  pv_azurefirewall.py
  run_azurefirewall_assessment.py

data/outputs/azurefirewall_rechecked_controls.csv   (10-col Redis schema)
data/outputs/azurefirewall_na_research.json

CANONICAL PATTERN: scripts/assessment/keyvault/v2/pa_keyvault.py (v2 style)
VALIDATION: cd scripts/assessment/azurefirewall && for f in *.py; do python3 -c "import ast; ast.parse(open('$f').read()); print('OK', '$f')"; done

DEPENDENCIES: pip install azure-identity azure-mgmt-network azure-mgmt-monitor

SCOPE HELPER:
def _get_firewalls(client, resource_group, firewall_name):
    if resource_group and firewall_name:
        return [client.azure_firewalls.get(resource_group, firewall_name)]
    elif resource_group:
        return list(client.azure_firewalls.list(resource_group))
    else:
        return list(client.azure_firewalls.list_all())

Follow same workflow as Parts 3+4: PATH B research first, then PATH A scripts, then CSV + JSON outputs, then validate.
```

