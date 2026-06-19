"""
Posture and Vulnerability Management checks for Azure DNS (MCSB v3).

All PV controls: Azure DNS Zone is PaaS with no OS substrate, no compute, no containers.
DSC, Guest Config, custom images, vulnerability scanning, and update management are not applicable.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/dns/dns-overview"


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PV-3",
        "feature": "Automation State Configuration",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS Zone; no OS substrate. DSC/Azure Automation State Configuration not applicable.",
        "expected_value": "N/A — PaaS; no OS; DSC not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PV-3",
        "feature": "Guest Config Agent",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS Zone; no VM or OS substrate. Azure Policy Guest Config agent not applicable.",
        "expected_value": "N/A — PaaS; no VM; Guest Config not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PV-3",
        "feature": "Custom Container Images",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS Zone; no container workloads. Custom container image control not applicable.",
        "expected_value": "N/A — PaaS; no containers; custom image control not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PV-3",
        "feature": "Custom VM Images",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS Zone; no VM substrate. Custom VM image control not applicable.",
        "expected_value": "N/A — PaaS; no VM; VM image control not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PV-5",
        "feature": "Vulnerability Assessment",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS Zone; no compute substrate. Defender vulnerability assessment (Qualys/MDVM integration) not applicable.",
        "expected_value": "N/A — PaaS; no compute; vulnerability scanning not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PV-6",
        "feature": "Software Update Management",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS Zone; no OS substrate. Azure Update Manager and patch orchestration not applicable.",
        "expected_value": "N/A — PaaS; no OS; update management not applicable",
        "evidence_url": _EVIDENCE,
    }
