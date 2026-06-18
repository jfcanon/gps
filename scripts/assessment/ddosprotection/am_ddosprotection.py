"""
Asset Management checks for Azure DDoS Protection (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.
AM-5: Defender AAC — targets VMs only → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_ddos_plans(client: NetworkManagementClient, resource_group: str | None, plan_name: str | None) -> list:
    if resource_group and plan_name:
        return [client.ddos_protection_plans.get(resource_group, plan_name)]
    elif resource_group:
        return list(client.ddos_protection_plans.list_by_resource_group(resource_group))
    else:
        return list(client.ddos_protection_plans.list())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/policy-reference",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        plans = _get_ddos_plans(client, resource_group, plan_name)
        if not plans:
            return {**base, "resource": plan_name or "none", "status": "PASS",
                    "actual_value": "No DDoS Protection Plan instances found in scope"}
        first_pass = None
        for plan in plans:
            tags = getattr(plan, "tags", None) or {}
            if tags:
                r = {**base, "resource": plan.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": plan.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": plan_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "AM-5", "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC", "status": "UNKNOWN", "actual_value": "PaaS control-plane resource — Adaptive Application Controls target VMs and Arc-enabled servers only; not applicable to DDoS Protection Plan", "expected_value": "N/A", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls"}
