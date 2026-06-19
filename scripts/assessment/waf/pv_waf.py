"""
Posture and Vulnerability Management checks for Azure WAF Policy (MCSB v3).

PV-3×4/PV-5/PV-6: UNKNOWN static — PaaS configuration resource; no OS/VM/container.
    Azure Automation DSC, Guest Config Agent, custom images, Defender VA,
    and Update Manager all target compute workloads.
    WAF Policy is a configuration ARM resource only.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"
_PAAS_NOTE = "PaaS configuration resource — no OS/VM/container substrate; "


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PV-3",
        "feature": "Azure Automation State Configuration",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Automation State Configuration (DSC) manages OS-level desired state on VMs and Arc servers. WAF Policy has no OS or compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS; no OS/compute; DSC not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PV-3",
        "feature": "Azure Policy Guest Configuration Agent",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Policy Guest Configuration audits and enforces OS-level settings on VMs and Arc servers. WAF Policy has no OS substrate. not_applicable.",
        "expected_value": "N/A — PaaS; no OS; Guest Config not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PV-3",
        "feature": "Custom Container Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "No container runtime in WAF Policy managed infrastructure. Custom container image hardening not applicable.",
        "expected_value": "N/A — PaaS; no container runtime; not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PV-3",
        "feature": "Custom VM Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "No VM substrate in WAF Policy managed infrastructure. Custom VM image hardening not applicable.",
        "expected_value": "N/A — PaaS; no VM substrate; not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PV-5",
        "feature": "Vulnerability Assessment",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Microsoft Defender vulnerability assessment targets VMs, container registries, SQL servers. WAF Policy is a PaaS configuration resource with no compute. not_applicable.",
        "expected_value": "N/A — PaaS; no compute; VA not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PV-6",
        "feature": "Azure Automation Update Management",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Update Manager targets VMs and Arc-enabled servers. WAF Policy has no OS. Microsoft manages underlying infrastructure patching. not_applicable.",
        "expected_value": "N/A — PaaS; no OS; Update Manager not applicable",
        "evidence_url": _EVIDENCE,
    }
