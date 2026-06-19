"""
Posture and Vulnerability Management checks for Azure VPN Gateway (MCSB v3).

PV-3×4/PV-5/PV-6: All Not Applicable → UNKNOWN static (still_not_applicable).
    PaaS network service; no OS/VM/container substrate.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways"
_PAAS_NOTE = "PaaS network service — no OS/VM/container substrate; "


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PV-3",
        "feature": "Azure Automation State Configuration",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Automation State Configuration (DSC) targets VMs and Azure Arc servers. Not applicable to VPN GW managed infrastructure.",
        "expected_value": "N/A — PaaS; no OS/compute; DSC not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PV-3",
        "feature": "Azure Policy Guest Configuration Agent",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Policy Guest Configuration targets VMs and Arc-enabled servers. Not applicable to VPN GW managed infrastructure.",
        "expected_value": "N/A — PaaS; no compute; Guest Config not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PV-3",
        "feature": "Custom Container Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "No container runtime in VPN GW managed infrastructure. Custom container image hardening not applicable.",
        "expected_value": "N/A — PaaS; no container runtime; not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PV-3",
        "feature": "Custom VM Images",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "No VM substrate in VPN GW managed infrastructure. Custom VM image hardening not applicable.",
        "expected_value": "N/A — PaaS; no VM substrate; not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PV-5",
        "feature": "Vulnerability Assessment",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Microsoft Defender vulnerability assessment targets VMs, container registries, SQL servers. Not applicable to VPN GW PaaS service.",
        "expected_value": "N/A — PaaS; no compute; VA not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PV-6",
        "feature": "Azure Automation Update Management",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Azure Update Manager targets VMs and Arc-enabled servers. VPN GW managed infrastructure has no customer-accessible OS. Not applicable.",
        "expected_value": "N/A — PaaS; no OS; Update Manager not applicable",
        "evidence_url": _EVIDENCE,
    }
