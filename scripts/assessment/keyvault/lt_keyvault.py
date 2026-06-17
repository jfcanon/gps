"""
Logging and Threat Detection checks for Azure Key Vault (MCSB v3).

LT-1: Defender for Key Vault — real check via SecurityCenter pricings API.
LT-4: Resource diagnostic logs enabled.

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
        "resource": vault_name or resource_group or subscription_id,
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
            return {**base, "status": "PASS", "actual_value": f"Defender for Key Vault pricing_tier={tier}"}
        else:
            return {**base, "status": "FAIL", "actual_value": f"Defender for Key Vault pricing_tier={tier} (expected Standard)"}
    except ImportError:
        return {**base, "status": "UNKNOWN", "actual_value": "azure-mgmt-security not installed; cannot check Defender pricing"}
    except Exception as e:
        return {**base, "status": "UNKNOWN", "actual_value": f"Defender pricing check failed: {e}"}


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic setting with AuditEvent logs enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/logging",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    try:
        from azure.mgmt.monitor import MonitorManagementClient
        monitor = MonitorManagementClient(credential, subscription_id)
    except ImportError:
        return {**base, "status": "UNKNOWN", "actual_value": "azure-mgmt-monitor not installed; cannot check diagnostic settings"}

    first_pass = None
    for vault in vaults:
        resource_uri = vault.id
        try:
            settings = list(monitor.diagnostic_settings.list(resource_uri))
        except Exception as e:
            return {**base, "resource": vault.name, "status": "UNKNOWN", "actual_value": f"diagnostic_settings.list failed: {e}"}

        has_logs = False
        for s in settings:
            logs = getattr(s, "logs", None) or []
            for log in logs:
                if getattr(log, "enabled", False):
                    has_logs = True
                    break
            if has_logs:
                break

        if has_logs:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"diagnostic_settings={len(settings)}, no enabled log category found",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "Diagnostic settings with enabled logs present",
    }
