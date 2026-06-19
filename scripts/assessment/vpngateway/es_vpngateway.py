"""
Endpoint Security checks for Azure VPN Gateway (MCSB v3).

ES-1/2/3: All Not Applicable → UNKNOWN static (still_not_applicable).
    PaaS network service; no compute substrate; EDR/anti-malware not applicable.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways"
_PAAS_NOTE = "PaaS network service — no compute substrate; "


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "ES-1",
        "feature": "Endpoint Detection and Response (EDR)",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Endpoint Detection and Response (Microsoft Defender for Endpoint) targets compute workloads (VMs, servers). Not applicable to VPN GW managed infrastructure.",
        "expected_value": "N/A — PaaS; no compute; EDR not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "ES-2",
        "feature": "Anti-Malware Solution",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Anti-malware (Microsoft Defender Antivirus / Defender for Endpoint) targets compute workloads. Not applicable to VPN GW managed infrastructure.",
        "expected_value": "N/A — PaaS; no compute; anti-malware not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "ES-3",
        "feature": "Anti-Malware Solution Health Monitoring",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "Anti-malware health monitoring not applicable to PaaS VPN GW managed infrastructure.",
        "expected_value": "N/A — PaaS; no compute; health monitoring not applicable",
        "evidence_url": _EVIDENCE,
    }
