"""
Endpoint Security checks for Azure DNS (MCSB v3).

All ES controls: Azure DNS Zone is PaaS with no compute substrate.
EDR, antimalware, and antimalware health monitoring are not applicable.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/dns/dns-overview"


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "ES-1",
        "feature": "Endpoint Protection using EDR",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS hosting service; no compute substrate. EDR (Defender for Servers/MDE) not applicable to Azure DNS Zone resource.",
        "expected_value": "N/A — PaaS; no compute; EDR not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "ES-2",
        "feature": "Use of Anti-Malware Software",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS service; no OS or compute substrate. Antimalware not applicable to Azure DNS Zone resource.",
        "expected_value": "N/A — PaaS; no OS; antimalware not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "ES-3",
        "feature": "Ensure Anti-Malware Software and Signatures are Updated",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS service; no compute substrate. Antimalware signature update management not applicable.",
        "expected_value": "N/A — PaaS; no compute; antimalware health monitoring not applicable",
        "evidence_url": _EVIDENCE,
    }
