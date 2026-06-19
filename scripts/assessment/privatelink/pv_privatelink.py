"""
Posture and Vulnerability Management checks for Azure Private Link / Private Endpoint (MCSB v3).

PV-3×4/PV-5/PV-6: UNKNOWN static — PE is a PaaS NIC resource.
    Azure Automation DSC, Guest Config Agent, custom images, Defender VA,
    and Update Manager all target compute workloads.
    Private Endpoint is a network configuration resource with no OS or compute.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
_PAAS_NOTE = "PaaS NIC resource — no OS/VM/container substrate; "


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Azure Automation State Configuration",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Automation State Configuration (DSC) manages OS-level desired state on VMs and Arc servers. PE has no OS or compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS NIC; no OS/compute; DSC not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Azure Policy Guest Configuration Agent",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Policy Guest Configuration audits and enforces OS-level settings on VMs and Arc servers. PE has no OS substrate. not_applicable.",
        "expected_value": "N/A — PaaS NIC; no OS; Guest Config not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Custom Container Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "No container runtime in PE managed infrastructure. Custom container image hardening not applicable.",
        "expected_value": "N/A — PaaS NIC; no container runtime; not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Custom VM Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "No VM substrate in PE managed infrastructure. Custom VM image hardening not applicable.",
        "expected_value": "N/A — PaaS NIC; no VM substrate; not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PV-5",
        "feature": "Vulnerability Assessment",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Microsoft Defender vulnerability assessment targets VMs, container registries, SQL servers. PE is a PaaS NIC resource with no compute. not_applicable.",
        "expected_value": "N/A — PaaS NIC; no compute; VA not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PV-6",
        "feature": "Azure Automation Update Management",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Update Manager targets VMs and Arc-enabled servers. PE has no OS. Microsoft manages underlying infrastructure patching. not_applicable.",
        "expected_value": "N/A — PaaS NIC; no OS; Update Manager not applicable",
        "evidence_url": _EVIDENCE,
    }
