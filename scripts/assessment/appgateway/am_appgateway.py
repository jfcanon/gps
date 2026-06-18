"""
Asset Management checks for Azure Application Gateway (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.
AM-5: Defender for Cloud AAC — PaaS, targets VMs → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        return [client.application_gateways.get(resource_group, gateway_name)]
    elif resource_group:
        return list(client.application_gateways.list(resource_group))
    else:
        return list(client.application_gateways.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/policy-reference",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            tags = getattr(gw, "tags", None) or {}
            if tags:
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "AM-5",
        "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Adaptive Application Controls target VMs and Arc-enabled servers only; not applicable to Application Gateway",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }
