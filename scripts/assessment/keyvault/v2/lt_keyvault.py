"""
Logging and Threat Detection checks for Azure Key Vault (MCSB v3).

LT-1: Defender for Key Vault — real check via SecurityCenter pricings API (not UNKNOWN like Redis).
LT-4: Resource diagnostic logs enabled via MonitorManagementClient.

Read-only. Zero ARM writes.
"""
from azure.mgmt.keyvault import KeyVaultManagementClient


def _get_vaults(client: KeyVaultManagementClient, resource_group: str | None, vault_name: str | None) -> list:
    if resource_group and vault_name:
        return [client.vaults.get(resource_group, vault_name)]
    elif resource_group:
        return list(client.vaults.list_by_resource_group(resource_group))
    else:
        return list(client.vaults.list())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for Key Vault",
        "expected_value": "Defender for Key Vault pricing_tier=Standard",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction",
    }
    try:
        from azure.mgmt.security import SecurityCenter
        sc = SecurityCenter(credential, subscription_id)
        pricing = sc.pricings.get("KeyVaults")
        tier = getattr(pricing, "pricing_tier", None)
        if tier == "Standard":
            return {**base, "resource": vault_name or subscription_id, "status": "PASS",
                    "actual_value": f"Defender for Key Vault pricing_tier={tier}"}
        else:
            return {**base, "resource": vault_name or subscription_id, "status": "FAIL",
                    "actual_value": f"Defender for Key Vault pricing_tier={tier} (expected Standard)"}
    except ImportError:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN",
                "actual_value": "azure-mgmt-security not installed; install with: pip install azure-mgmt-security"}
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic setting with at least one log category enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/logging",
    }
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        mon_client = MonitorManagementClient(credential, subscription_id)
        vaults = _get_vaults(kv_client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            try:
                settings = list(mon_client.diagnostic_settings.list(vault.id))
            except Exception as e:
                return {**base, "resource": vault.name, "status": "UNKNOWN",
                        "actual_value": f"diagnostic_settings.list failed: {e}"}
            has_logs = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if has_logs:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s), at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s) but no enabled log categories found"}
        return first_pass
    except ImportError:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN",
                "actual_value": "azure-mgmt-monitor not installed; install with: pip install azure-mgmt-monitor"}
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
