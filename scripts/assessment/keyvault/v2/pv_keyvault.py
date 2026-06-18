"""
Posture and Vulnerability Management checks for Azure Key Vault (MCSB v3).

PV-3 (all variants), PV-5, PV-6: Key Vault is fully managed PaaS.
No customer OS, VM images, Automation DSC, or Guest Config agent. All UNKNOWN.
"""


def _paas_na(vault_name, control_id, feature, url, note=""):
    return {
        "resource": vault_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": f"PaaS — {note or 'control not applicable to fully managed service'}",
        "expected_value": "N/A",
        "evidence_url": url,
    }


_KV_URL = "https://learn.microsoft.com/en-us/azure/key-vault/general/overview"
_DFCS_URL = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-cloud"


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "PV-3", "Azure Automation State Configuration", _KV_URL,
        "no customer OS; Azure Automation DSC targets VMs and Arc servers, not PaaS"
    )


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "PV-3", "Azure Policy Guest Configuration Agent", _KV_URL,
        "no customer guest OS; Guest Config agent runs on VMs and Arc machines only"
    )


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "PV-3", "Custom Container Images", _KV_URL,
        "Microsoft manages KV runtime; no customer-supplied container images"
    )


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "PV-3", "Custom VM Images", _KV_URL,
        "fully managed PaaS; no customer-supplied VM images accepted"
    )


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "PV-5", "Vulnerability Assessment using Microsoft Defender", _DFCS_URL,
        "Defender for Key Vault provides threat detection, not VA scanning; no software stack to scan on PaaS"
    )


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return _paas_na(
        vault_name, "PV-6", "Azure Automation Update Management", _KV_URL,
        "Microsoft patches KV infrastructure; Azure Automation Update Management targets VMs only"
    )
