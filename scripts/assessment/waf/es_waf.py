"""
Endpoint Security checks for Azure WAF Policy (MCSB v3).

ES-1/2/3: UNKNOWN static — PaaS configuration resource; no compute substrate.
    EDR and anti-malware target compute workloads (VMs, Arc servers).
    WAF Policy is a policy/configuration ARM resource only.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"
_PAAS_NOTE = "PaaS configuration resource — no compute substrate; "


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "ES-1",
        "feature": "Endpoint Detection and Response (EDR)",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "EDR (Microsoft Defender for Endpoint) targets compute workloads (VMs, servers). WAF Policy is a configuration resource with no compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS; no compute; EDR not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "ES-2",
        "feature": "Anti-Malware Solution",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Anti-malware targets compute workloads with accessible file systems. WAF Policy configuration resource has no compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS; no compute; anti-malware not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "ES-3",
        "feature": "Anti-Malware Solution Health Monitoring",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Anti-malware health monitoring requires anti-malware deployment on compute. WAF Policy has no compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS; no compute; health monitoring not applicable",
        "evidence_url": _EVIDENCE,
    }
