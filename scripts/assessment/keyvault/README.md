# Azure Key Vault — MCSB v3 Assessment Scripts

Read-only compliance checks for Azure Key Vault. Zero ARM writes. Auth via DefaultAzureCredential.

## Run

```bash
python3 scripts/assessment/keyvault/run_keyvault_assessment.py \
  --subscription-id <SUBSCRIPTION_ID> \
  [--resource-group <RG>] \
  [--vault-name <VAULT_NAME>] \
  [--output-dir data/outputs/assessment_results]
```

Scope: both `--resource-group` + `--vault-name` → single vault. Only `--resource-group` → all vaults in RG. Neither → all vaults in subscription.

## Output

`data/outputs/assessment_results/keyvault_{subscription_id}_{timestamp}.json`

```json
{
  "service": "azure-key-vault",
  "subscription_id": "...",
  "run_timestamp": "20260616T182000Z",
  "total_checks": 34,
  "pass": 0, "fail": 0, "unknown": 0,
  "results": [...]
}
```

Each result:
```json
{
  "resource": "my-key-vault",
  "control_id": "NS-2",
  "feature": "Disable Public Network Access",
  "status": "PASS|FAIL|UNKNOWN",
  "actual_value": "...",
  "expected_value": "...",
  "evidence_url": "https://..."
}
```

## Domain files

| File | Controls |
|---|---|
| `ns_keyvault.py` | NS-1 (NSG, VNet), NS-2 (Private Link, Disable Public) |
| `dp_keyvault.py` | DP-3 (TLS), DP-4 (Platform Keys), DP-5 (CMK), DP-6 (Key Mgmt), DP-7 (Cert KV) |
| `im_keyvault.py` | IM-1 (Local Auth, AAD Required), IM-3 (MI, SP), IM-7 (CA), IM-8 (KV Secrets) |
| `lt_keyvault.py` | LT-1 (Defender for KV), LT-4 (Resource Logs) |
| `br_keyvault.py` | BR-1 (Azure Backup UNKNOWN, Native via soft-delete + purge-protection) |
| `am_keyvault.py` | AM-2 (Policy/tags), AM-5 (Defender AAC — PaaS UNKNOWN) |
| `pa_keyvault.py` | PA-1 (Local Admin), PA-7 (RBAC), PA-8 (Lockbox) |
| `es_keyvault.py` | ES-1, ES-2, ES-3 (all PaaS UNKNOWN) |
| `pv_keyvault.py` | PV-3 (×4), PV-5, PV-6 (all PaaS UNKNOWN) |

## Dependencies

```bash
pip install azure-identity azure-mgmt-keyvault azure-mgmt-monitor azure-mgmt-security
```
