"""
Asset Management checks for Azure Firewall (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.
AM-5: Defender for Cloud AAC — PaaS, targets VMs → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_firewalls(client: NetworkManagementClient, resource_group: str | None, firewall_name: str | None) -> list:
    if resource_group and firewall_name:
        return [client.azure_firewalls.get(resource_group, firewall_name)]
    elif resource_group:
        return list(client.azure_firewalls.list(resource_group))
    else:
        return list(client.azure_firewalls.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#network",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            tags = getattr(fw, "tags", None) or {}
            if tags:
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "AM-5",
        "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Adaptive Application Controls target VMs and Arc-enabled servers only; not applicable to Azure Firewall",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }
