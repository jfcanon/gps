"""
Endpoint Security checks for Azure Private Link / Private Endpoint (MCSB v3).

ES-1/2/3: UNKNOWN static — PE is a PaaS NIC resource.
    EDR and anti-malware target compute workloads (VMs, Arc servers).
    Private Endpoint managed infrastructure has no customer-accessible compute.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
_PAAS_NOTE = "PaaS NIC resource — no customer-accessible compute substrate; "


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "ES-1",
        "feature": "Endpoint Detection and Response (EDR)",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "EDR (Microsoft Defender for Endpoint) targets compute workloads (VMs, servers). PE is a NIC resource with no compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS NIC; no compute; EDR not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "ES-2",
        "feature": "Anti-Malware Solution",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Anti-malware targets compute workloads with accessible file systems. PE has no compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS NIC; no compute; anti-malware not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "ES-3",
        "feature": "Anti-Malware Solution Health Monitoring",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Anti-malware health monitoring presupposes anti-malware deployment on compute. PE has no compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS NIC; no compute; health monitoring not applicable",
        "evidence_url": _EVIDENCE,
    }
