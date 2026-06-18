"""
Endpoint Security checks for Azure Key Vault (MCSB v3).

ES-1, ES-2, ES-3: All return UNKNOWN — Key Vault is fully managed PaaS with no
customer-accessible OS or compute layer. EDR agents and anti-malware cannot be
deployed by customers. Microsoft manages the underlying infrastructure.
"""


def _paas_na(vault_name, control_id, feature, url, note=""):
    return {
        "resource": vault_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": f"PaaS — {note or 'no customer OS/compute layer; control not applicable'}",
        "expected_value": "N/A",
        "evidence_url": url,
    }


_KV_URL = "https://learn.microsoft.com/en-us/azure/key-vault/general/overview"


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "ES-1", "EDR Solution", _KV_URL,
        "no customer-accessible compute; EDR agent deployment not supported on PaaS"
    )


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "ES-2", "Anti-Malware Solution", _KV_URL,
        "no customer OS layer; anti-malware agent deployment not supported on PaaS"
    )


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "ES-3", "Anti-Malware Solution Health Monitoring", _KV_URL,
        "ES-2 not applicable → health monitoring also not applicable on PaaS"
    )
