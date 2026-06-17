# Azure Cache for Redis — Compliance Assessment Scripts

Read-only Azure compliance checks mapped to MCSB v3 controls.

## Auth

Requires `azure-identity`. Uses `DefaultAzureCredential` — works with `az login`, managed identity, or env vars (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`).

## Output

Each check returns a JSON dict:
```json
{
  "resource": "my-redis-cache",
  "control_id": "NS-2",
  "feature": "Disable Public Network Access",
  "status": "PASS | FAIL | UNKNOWN",
  "actual_value": "Disabled",
  "expected_value": "Disabled",
  "evidence_url": "https://docs.microsoft.com/..."
}
```

Results written to `data/outputs/assessment_results/redis_{subscription_id}_{timestamp}.json`.

## Run

```bash
python3 run_redis_assessment.py --subscription-id <SUB_ID> [--resource-group <RG>] [--redis-name <NAME>]
```

- `--subscription-id` — required
- `--resource-group` — optional, scopes to one RG
- `--redis-name` — optional, scopes to one cache instance

## Zero Side Effects

No ARM writes. All checks use ARM GET operations only via `azure-mgmt-redis`. Safe to run in production.

## Script Files

| File | Domain | Controls |
|---|---|---|
| `ns_redis.py` | Network Security | NS-1, NS-2 |
| `dp_redis.py` | Data Protection | DP-1, DP-2, DP-4, DP-5, DP-6, DP-7 |
| `im_redis.py` | Identity Management | IM-1, IM-3, IM-7, IM-8 |
| `lt_redis.py` | Logging & Threat Detection | LT-1, LT-4 |
| `pv_redis.py` | Posture & Vulnerability Mgmt | PV-3, PV-5, PV-6 |
| `pa_redis.py` | Privileged Access | PA-1, PA-7, PA-8 |
| `am_redis.py` | Asset Management | AM-2, AM-5 |
| `br_redis.py` | Backup & Recovery | BR-1 |
| `es_redis.py` | Endpoint Security | ES-1, ES-2, ES-3 |
