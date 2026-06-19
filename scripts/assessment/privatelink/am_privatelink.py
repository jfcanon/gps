"""
Asset Management checks for Azure Private Link / Private Endpoint (MCSB v3).

AM-2 Azure Policy Support: LIVE-DIRECT — tags proxy.
    customer/True/False in baseline. feature_supported=True, enabled_by_default=False.
    Tags non-empty → PASS (Azure Policy governance visible).
    Tags empty → FAIL.

AM-5 Defender AAC: UNKNOWN static.
    PaaS network resource; no VM compute substrate.
    Adaptive Application Controls target VMs and Arc servers. not_applicable.

Read-only. Zero ARM writes.
SDK: azure-mgmt-network (AM-2 only).
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"


def _get_endpoints(client, resource_group, endpoint_name):
    if endpoint_name and resource_group:
        return [client.private_endpoints.get(resource_group, endpoint_name)]
    elif resource_group:
        return list(client.private_endpoints.list(resource_group))
    else:
        return list(client.private_endpoints.list_by_subscription())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    client = NetworkManagementClient(credential, subscription_id)

    try:
        endpoints = _get_endpoints(client, resource_group, endpoint_name)
    except Exception as e:
        return {
            "resource": endpoint_name or resource_group or "all",
            "control_id": "AM-2",
            "feature": "Azure Policy Support",
            "status": "UNKNOWN",
            "actual_value": f"Error listing endpoints: {e}",
            "expected_value": "endpoint.tags non-empty",
            "evidence_url": _EVIDENCE,
        }

    if not endpoints:
        return {
            "resource": endpoint_name or resource_group or "all",
            "control_id": "AM-2",
            "feature": "Azure Policy Support",
            "status": "UNKNOWN",
            "actual_value": "No private endpoints found in scope",
            "expected_value": "endpoint.tags non-empty",
            "evidence_url": _EVIDENCE,
        }

    tagged = [ep for ep in endpoints if ep.tags]
    status = "PASS" if tagged else "FAIL"
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "AM-2",
        "feature": "Azure Policy Support",
        "status": status,
        "actual_value": f"{len(tagged)}/{len(endpoints)} private endpoints have tags",
        "expected_value": "endpoint.tags non-empty",
        "evidence_url": _EVIDENCE,
    }


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "AM-5",
        "feature": "Microsoft Defender for Cloud — Adaptive Application Controls",
        "status": "UNKNOWN",
        "actual_value": "PaaS network resource (NIC); no VM compute substrate. Adaptive Application Controls target VMs and Azure Arc-enabled servers. not_applicable at PE resource level.",
        "expected_value": "N/A — PaaS NIC resource; AAC not applicable",
        "evidence_url": _EVIDENCE,
    }
