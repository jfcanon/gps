"""
Logging and Threat Detection checks for Azure Private Link / Private Endpoint (MCSB v3).

LT-1: UNKNOWN static — No Microsoft Defender plan exists for Private Link as a service.
    feature_supported=Not Applicable, final_verdict=not_applicable in MCSB v3 baseline.
    Defender for DNS, App Services, etc. cover the connected services; not PE itself.

LT-4: UNKNOWN static — Private Endpoint resource emits NO resource logs.
    feature_supported=False, final_verdict=not_applicable in MCSB v3 baseline.
    Do NOT attempt DiagnosticSettings on PE.id — it will return empty (no log categories).
    Network traffic logging for PEs is done via NSG Flow Logs on the PE subnet (NSG control).

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service",
        "status": "UNKNOWN",
        "actual_value": "No Microsoft Defender plan for Private Link as a service. Defender for Cloud covers the connected PaaS services (e.g., Defender for Storage, SQL, App Services). feature_supported=Not Applicable in MCSB v3 baseline. not_applicable at PE resource level.",
        "expected_value": "N/A — no Defender plan for Private Link; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "status": "UNKNOWN",
        "actual_value": "Private Endpoint resource emits no resource logs (feature_supported=False in MCSB v3 baseline). DiagnosticSettings on PE.id returns no log categories. Network traffic for PEs is observable via NSG Flow Logs on the PE subnet. not_applicable at PE resource level.",
        "expected_value": "N/A — PE emits no resource logs; feature_supported=False in baseline",
        "evidence_url": _EVIDENCE,
    }
