"""
Asset Management checks for Azure Firewall Manager (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage — live check.
AM-5: Defender AAC — targets VMs only → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_firewall_policies(client: NetworkManagementClient, resource_group: str | None, policy_name: str | None) -> list:
    if resource_group and policy_name:
        return [client.firewall_policies.get(resource_group, policy_name)]
    elif resource_group:
        return list(client.firewall_policies.list(resource_group))
    else:
        return list(client.firewall_policies.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_firewall_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "none", "status": "PASS",
                    "actual_value": "No Firewall Policy instances found in scope"}
        first_pass = None
        for policy in policies:
            tags = getattr(policy, "tags", None) or {}
            if tags:
                r = {**base, "resource": policy.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": policy.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": policy_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "AM-5", "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC", "status": "UNKNOWN", "actual_value": "PaaS management-plane service — Adaptive Application Controls target VMs and Arc-enabled servers; not applicable to Firewall Policy.", "expected_value": "N/A — PaaS; AAC not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls"}
