"""
Posture and Vulnerability Management checks for Azure Cache for Redis.

PV-3 (all variants), PV-5, PV-6: Azure Cache for Redis is fully managed PaaS —
no customer OS, no VM images, no Azure Automation DSC, no Guest Config agent.
Microsoft manages the underlying OS and patching. All return UNKNOWN with explanation.
"""


def _paas_not_applicable(redis_name: str | None, control_id: str, feature: str, evidence_url: str, note: str = "") -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": f"PaaS service — {note or 'control not applicable to fully managed service'}",
        "expected_value": "N/A",
        "evidence_url": evidence_url,
    }


_BASE_URL = "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-overview"


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "PV-3", "Azure Automation State Configuration",
        _BASE_URL, "no customer OS layer; Azure Automation DSC targets VMs, not PaaS"
    )


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "PV-3", "Azure Policy Guest Configuration Agent",
        _BASE_URL, "no customer compute; Guest Config agent runs on VMs and Arc machines"
    )


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "PV-3", "Custom Container Images",
        _BASE_URL, "no customer container images; Redis runtime managed by Microsoft"
    )


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "PV-3", "Custom VM Images",
        _BASE_URL, "no customer VM images; Redis is PaaS with no customer-supplied VM"
    )


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "PV-5", "Vulnerability Assessment using Microsoft Defender",
        "https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-cloud",
        "Defender for Cloud provides CSPM recommendations for Redis but no VA scan; Defender for Open-Source Relational Databases covers PostgreSQL/MySQL/MariaDB only"
    )


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "PV-6", "Azure Automation Update Management",
        _BASE_URL, "fully managed PaaS; Microsoft patches OS; Azure Automation Update Management targets VMs"
    )
