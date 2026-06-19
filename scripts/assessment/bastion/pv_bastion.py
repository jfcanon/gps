"""
Posture and Vulnerability Management checks for Azure Bastion (MCSB v3).

PV-3×4/PV-5/PV-6: UNKNOWN static — all feature_supported=Not Applicable, final_verdict=not_applicable.
    Azure Automation DSC, Guest Config Agent, custom images, Defender VA,
    and Update Manager all target compute workloads with customer OS access.
    Azure Bastion is a managed PaaS jump host with no customer OS or compute.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
_PAAS_NOTE = "Azure Bastion is a managed PaaS jump host — no customer OS, VM, or container substrate; "


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Azure Automation State Configuration",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Automation State Configuration (DSC) manages OS-level desired state on VMs and Arc servers. Bastion has no customer-accessible OS. not_applicable.",
        "expected_value": "N/A — PaaS managed service; DSC not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Azure Policy Guest Configuration Agent",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Policy Guest Configuration audits and enforces OS-level settings on VMs and Arc servers. No customer OS in Bastion. not_applicable.",
        "expected_value": "N/A — PaaS managed service; Guest Config not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Custom Container Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "no container runtime in Bastion managed infrastructure. Custom container image hardening not applicable. not_applicable.",
        "expected_value": "N/A — PaaS managed service; container images not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PV-3",
        "feature": "Custom VM Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "no customer VM substrate in Bastion managed infrastructure. Custom VM image hardening not applicable. not_applicable.",
        "expected_value": "N/A — PaaS managed service; VM images not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PV-5",
        "feature": "Vulnerability Assessment",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Microsoft Defender vulnerability assessment targets VMs, container registries, SQL servers. Bastion has no customer compute. not_applicable.",
        "expected_value": "N/A — PaaS managed service; VA not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PV-6",
        "feature": "Azure Automation Update Management",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Update Manager targets VMs and Arc-enabled servers. Bastion has no customer OS. Microsoft manages underlying Bastion infrastructure patching. not_applicable.",
        "expected_value": "N/A — PaaS managed service; Update Manager not applicable; Microsoft patches Bastion",
        "evidence_url": _EVIDENCE,
    }
