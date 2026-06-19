"""
Posture and Vulnerability Management checks for Azure Front Door (MCSB v3).

All PV controls: AFD is PaaS CDN with no OS, no VM, no containers.
DSC, Guest Config, custom images, VA, update management — all Not Applicable.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview"


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PV-3",
        "feature": "Automation State Configuration",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no OS substrate. DSC/Automation State Config not applicable.",
        "expected_value": "N/A — PaaS; no OS; DSC not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PV-3",
        "feature": "Guest Config Agent",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no VM or OS. Azure Policy Guest Config not applicable.",
        "expected_value": "N/A — PaaS; no VM; Guest Config not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PV-3",
        "feature": "Custom Container Images",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no container workloads. Custom container image control not applicable.",
        "expected_value": "N/A — PaaS; no containers; custom image control not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PV-3",
        "feature": "Custom VM Images",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no VM substrate. Custom VM image control not applicable.",
        "expected_value": "N/A — PaaS; no VM; VM image control not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PV-5",
        "feature": "Vulnerability Assessment",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no compute. Defender vulnerability assessment (Qualys/MDVM) not applicable.",
        "expected_value": "N/A — PaaS; no compute; VA not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PV-6",
        "feature": "Software Update Management",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no OS substrate. Azure Update Manager not applicable.",
        "expected_value": "N/A — PaaS; no OS; update management not applicable",
        "evidence_url": _EVIDENCE,
    }
