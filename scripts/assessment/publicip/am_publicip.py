"""
Asset Management checks for Azure Public IP (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.
AM-5: Defender for Cloud AAC — targets VMs only → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_public_ips(client: NetworkManagementClient, resource_group: str | None, public_ip_name: str | None) -> list:
    if resource_group and public_ip_name:
        return [client.public_ip_addresses.get(resource_group, public_ip_name)]
    elif resource_group:
        return list(client.public_ip_addresses.list(resource_group))
    else:
        return list(client.public_ip_addresses.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#network",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        pips = _get_public_ips(client, resource_group, public_ip_name)
        if not pips:
            return {**base, "resource": public_ip_name or "none", "status": "PASS",
                    "actual_value": "No Public IP instances found in scope"}
        first_pass = None
        for pip in pips:
            tags = getattr(pip, "tags", None) or {}
            if tags:
                r = {**base, "resource": pip.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": pip.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": public_ip_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "AM-5", "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC", "status": "UNKNOWN", "actual_value": "PaaS network resource — Adaptive Application Controls target VMs and Arc-enabled servers only; not applicable to Azure Public IP", "expected_value": "N/A", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls"}
