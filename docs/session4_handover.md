# Phase 43 — Session 4 Handover

Generated: 2026-06-18. Start fresh session after reading this.

***

## WHAT IS DONE (Sessions 1 + 2 + 3)

| Part | Service                      | Scripts                                                  | Checks | CSV rows | Commit   | Status   |
|------|------------------------------|----------------------------------------------------------|--------|----------|----------|----------|
| 0    | Infrastructure scaffolding   | extract_service_controls.py, runner skeleton             | —      | —        | —        | complete |
| 1    | azure-cache-for-redis        | scripts/assessment/redis/ (9 files)                      | 34     | 35       | —        | complete |
| 2    | azure-key-vault              | scripts/assessment/keyvault/v2/ (9 files)                | 34     | 36       | —        | complete |
| 3    | azure-service-bus            | scripts/assessment/servicebus/ (9 files)                 | 34     | 35       | —        | complete |
| 4A   | azure-application-gateway    | scripts/assessment/appgateway/ (9 files)                 | 35     | 36       | —        | complete |
| 4B   | ADO tooling                  | scripts/import_assessment_tasks_to_ado.py                | —      | —        | —        | complete |
| 5    | azure-firewall               | scripts/assessment/azurefirewall/ (10 files)             | 35     | 35       | 659d333  | complete |
| 6    | azure-public-ip              | scripts/assessment/publicip/ (10 files)                  | 36     | 36       | 8ca2586  | complete |
| 7    | azure-ddos-protection        | scripts/assessment/ddosprotection/ (10 files)            | 35     | 35       | 7feebd7  | complete |
| 8    | network-watcher              | scripts/assessment/networkwatcher/ (10 files)            | 35     | 35       | f853123  | complete |
| 9    | azure-firewall-manager       | scripts/assessment/firewallmanager/ (10 files)           | 35     | 35       | e5e2d4d  | complete |

**NS-domain remaining queue:**

| Part | Service                     | Priority |
|------|-----------------------------|----------|
| 10   | azure-dns                   | next     |
| 11   | azure-front-door            | —        |
| 12   | vpn-gateway                 | —        |
| 13   | azure-web-application-firewall | —     |
| 14   | azure-private-link          | —        |
| 15   | azure-bastion               | —        |

***

## CANONICAL v2 PATTERN

Mirror this for every new service:

```
scripts/assessment/keyvault/v2/pa_keyvault.py        ← primary pattern
scripts/assessment/keyvault/v2/am_keyvault.py        ← static UNKNOWN + tags live
scripts/assessment/keyvault/v2/run_keyvault_assessment_v2.py  ← runner
scripts/assessment/networkwatcher/dp_networkwatcher.py        ← PASS static pattern
scripts/assessment/firewallmanager/dp_firewallmanager.py      ← DP-7 Premium KV branch
```

v2 rules (non-negotiable):
- `try/except Exception as e` wrapping every live check
- `first_pass = first_pass or r` pattern for list iteration; return FAIL on first failure
- `_get_X(client, resource_group, resource_name)` scope helper in files that do live checks
- All stubs: `{"status": "UNKNOWN", "actual_value": "...", "expected_value": "N/A", "evidence_url": "..."}`
- PASS static: return dict directly, no SDK call, no try/except
- Validate: `python3 -c "import ast; ast.parse(open('$f').read()); print('OK', '$f')"` (Azure SDK not installed locally)
- Runner: `CHECK_REGISTRY: dict[str, Callable]`, output `{service}_{sub}_{ts}.json`

***

## KEY FILES

| File                                                    | Purpose                                                        |
|---------------------------------------------------------|----------------------------------------------------------------|
| `ado/activity.log`                                      | Phase log — tail for latest state                              |
| `data/outputs/v3_service_controls_reclassified.csv`     | 4,157 rows, source of truth for PATH A/B per service           |
| `data/outputs/networkwatcher_rechecked_controls.csv`    | Most recent example — 35 rows, 10-col schema                   |
| `data/outputs/firewallmanager_rechecked_controls.csv`   | Most recent with live DP-7 KV cert check                       |
| `scripts/assessment/firewallmanager/dp_firewallmanager.py` | DP-7 Premium SKU branching pattern (reuse for similar)      |
| `scripts/assessment/networkwatcher/lt_networkwatcher.py`| LT-1/LT-4 UNKNOWN static pattern with notes                   |
| `scripts/assessment/appgateway/lt_appgateway.py`        | LT-4 DiagnosticSettings live check pattern                    |

***

## 10-COL CSV SCHEMA (Redis schema — use for all services)

```
asb_control_id, feature_name, feature_supported_original, feature_enabled_by_default_original,
status_2025, verdict_2025, azure_api_property, script_module, script_function, notes
```

Verdict taxonomy: `implemented`, `now_applicable_native`, `upgraded_implemented`, `still_not_applicable`, `conditional`, `not_applicable_paas`, `not_applicable_arm`

***

## IMPORTANT PATTERNS FROM SESSION 3

### PASS static (microsoft_managed)
Used when CSV shows `feature_supported=True, enabled_by_default=True` (platform default):
```python
def check_dp3_tls_transit(...) -> dict:
    return {"resource": name or "all", "control_id": "DP-3", "feature": "...",
            "status": "PASS", "actual_value": "HTTPS/TLS enforced by platform...",
            "expected_value": "...", "evidence_url": "..."}
```

### DP-7 Premium SKU branch (firewallmanager pattern)
```python
sku_tier = getattr(getattr(policy, 'sku', None), 'tier', 'Standard') or 'Standard'
if sku_tier == 'Premium':
    ts = getattr(policy, 'transport_security', None)
    ca = getattr(ts, 'certificate_authority', None) if ts else None
    kv_ref = getattr(ca, 'key_vault_secret_id', None) if ca else None
    # PASS if kv_ref else FAIL
else:
    # UNKNOWN — Premium-only feature
```

### Defender plan check (LT-1 live — NEW in azure-dns)
```python
from azure.mgmt.security import SecurityCenter
sec_client = SecurityCenter(credential, subscription_id)
pricing = sec_client.pricings.get(
    scope=f'/subscriptions/{subscription_id}',
    pricing_name='Dns'
)
pricing.pricing_tier == 'Standard' → PASS; 'Free' → FAIL
```
Note: Defender for DNS is a real plan (may show as deprecated/merged in newer tenants). Handle exceptions.

### DiagnosticSettings live check (LT-4)
```python
from azure.mgmt.monitor import MonitorManagementClient
monitor = MonitorManagementClient(credential, subscription_id)
settings = list(monitor.diagnostic_settings.list(resource_id))
# any enabled log or metric → PASS
```

***

## ADO TOOLING STATUS

`scripts/import_assessment_tasks_to_ado.py` — reads any `*_rechecked_controls.csv`, creates Tasks under parent User Stories.

Known bugs in `scripts/import_to_ado.py` (NOT YET FIXED):
- H1: no duplicate check on Story create — re-run creates duplicates
- H2: Feature 429 has no retry (only Story 429 retries)
- M1: cfg.validate() skipped on dry-run

***

## SESSION 4 INITIAL PROMPT

Copy-paste this to start Session 4:

```
You are continuing Phase 43 of the NewSecGap project.
Repo: /Users/nahuelavalos/Repo/NewSecGap/

READ FIRST: docs/session4_handover.md — full context for session 4.
Then read: ado/activity.log (tail) to confirm current state.

TASK: Phase 43 Part 10 — Azure DNS assessment scripts (start here).

SERVICE FACTS
┌─────────────────────┬──────────────────────────────────────────────────────────────────────┐
│ Service name in CSV │ azure-dns                                                            │
│ SDK (primary)       │ azure-mgmt-dns → DnsManagementClient                                │
│ SDK (LT-1)          │ azure-mgmt-security → SecurityCenter                                 │
│ SDK (LT-4)          │ azure-mgmt-monitor → MonitorManagementClient                         │
│ Resource term       │ dns_zone                                                             │
│ Scope params        │ resource_group, zone_name                                            │
│ Get                 │ client.zones.get(rg, zone_name)                                      │
│ List by RG          │ client.zones.list_by_resource_group(rg)                              │
│ List all            │ client.zones.list()                                                  │
└─────────────────────┴──────────────────────────────────────────────────────────────────────┘

KEY PROPERTIES (zone.*)
- zone_type: 'Public'/'Private' → note in checks (Private DNS is different product)
- tags: AM-2 proxy
- name_servers: list of authoritative NS for public zone
- number_of_record_sets: record count

AZURE-DNS-SPECIFIC LOGIC

PATH A — Live checks (3):
- LT-1: True, False → Defender for DNS → LIVE via azure-mgmt-security:
    from azure.mgmt.security import SecurityCenter
    pricing = sec_client.pricings.get(scope=f'/subscriptions/{sub}', pricing_name='Dns')
    pricing_tier == 'Standard' → PASS; 'Free' → FAIL
    (subscription-level check, not per-zone; handle ResourceNotFoundError → UNKNOWN with note about plan deprecation)
- LT-4: True, False → DiagnosticSettings on zone resource → LIVE via MonitorManagementClient
    monitor.diagnostic_settings.list(zone.id) — any enabled log/metric → PASS
    Key categories: QueryVolume, VirtualNetworkLinkWithRegistration, VirtualNetworkLink
- AM-2: True, False → tags proxy → live (same pattern as all services)
- PA-7: True, Customer → ARM RBAC for DNS zone management → UNKNOWN static
    (RBAC enforced by ARM but customer must configure correct assignments;
     DNS query plane for Public zones is unauthenticated — no RBAC on queries)

PATH B — UNKNOWN static (31+):
- NS-1 NSG: Not Applicable → DNS Zone is PaaS; NSG doesn't apply to DNS resource
- NS-1 VNet: False, Not Applicable → Private DNS VNet link exists but not checkable as NS control
- NS-2 Private Link: Not Applicable → DNS zone itself has no Private Link concept
- NS-2 Disable Public: Not Applicable → Public DNS by design; no toggle
- DP-1/2/3/4/5/6/7: All Not Applicable — DNS zone stores DNS records only; no customer PII/data
  (DP-3 is Not Applicable — DNS protocol is cleartext by design; DoH not natively supported by Azure DNS)
- IM-1/3/7/8: All Not Applicable — no data-plane auth; DNS queries are unauthenticated
- BR-1/2: Not Applicable — DNS zones recreatable from IaC; no backup product
- PA-1/8: Not Applicable
- ES-1/2/3: Not Applicable — PaaS; no compute
- PV-3x4/5/6: Not Applicable — PaaS; no OS substrate

OUTPUT PATHS
scripts/assessment/azuredns/
  ns_azuredns.py
  dp_azuredns.py
  im_azuredns.py
  lt_azuredns.py
  br_azuredns.py
  am_azuredns.py
  pa_azuredns.py
  es_azuredns.py
  pv_azuredns.py
  run_azuredns_assessment.py

data/outputs/azuredns_rechecked_controls.csv (35 rows)
data/outputs/azuredns_na_research.json

SCOPE HELPER:
def _get_dns_zones(client, resource_group, zone_name):
    if resource_group and zone_name:
        return [client.zones.get(resource_group, zone_name)]
    elif resource_group:
        return list(client.zones.list_by_resource_group(resource_group))
    else:
        return list(client.zones.list())

DEPENDENCIES: pip install azure-identity azure-mgmt-dns azure-mgmt-monitor azure-mgmt-security

CANONICAL PATTERN: scripts/assessment/networkwatcher/ (most recent, v2 style)
VALIDATION: cd scripts/assessment/azuredns && for f in *.py; do python3 -c "import ast; ast.parse(open('$f').read()); print('OK', '$f')"; done

Follow same workflow as Parts 5-9: PATH B CSV first, then 9 domain files, runner, validate, commit.

After Part 10, continue with Parts 11-15 in order:
11: azure-front-door
12: vpn-gateway
13: azure-web-application-firewall
14: azure-private-link
15: azure-bastion
```
