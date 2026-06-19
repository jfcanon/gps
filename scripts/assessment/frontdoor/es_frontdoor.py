"""
Endpoint Security checks for Azure Front Door (MCSB v3).

All ES controls: AFD is PaaS global CDN with no compute substrate.
EDR, antimalware, and signature management are not applicable.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview"


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "ES-1",
        "feature": "Endpoint Protection using EDR",
        "status": "UNKNOWN",
        "actual_value": "PaaS global CDN/WAF service; no compute substrate. EDR (Defender for Servers/MDE) not applicable to AFD resource.",
        "expected_value": "N/A — PaaS; no compute; EDR not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "ES-2",
        "feature": "Use of Anti-Malware Software",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no OS or compute. Antimalware not applicable to AFD resource.",
        "expected_value": "N/A — PaaS; no OS; antimalware not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "ES-3",
        "feature": "Ensure Anti-Malware Software and Signatures are Updated",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no compute. Antimalware health monitoring not applicable.",
        "expected_value": "N/A — PaaS; no compute; antimalware health not applicable",
        "evidence_url": _EVIDENCE,
    }
