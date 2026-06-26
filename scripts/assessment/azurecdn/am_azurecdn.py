"""
Asset Management checks for Azure CDN / AFD (MCSB v3).
AM-2: Tags proxy for policy governance.
"""
from azure.mgmt.cdn import CdnManagementClient


def check_am2_policy(credential, subscription_id, resource_group, profile_name):
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cdn/security-baseline#am-2-use-only-approved-azure-services",
    }
    try:
        client = CdnManagementClient(credential, subscription_id)
        if resource_group and profile_name:
            profiles = [client.profiles.get(resource_group, profile_name)]
        elif resource_group:
            profiles = list(client.profiles.list_by_resource_group(resource_group))
        else:
            profiles = list(client.profiles.list())
        if not profiles:
            return {**base, "resource": profile_name or "none", "status": "PASS",
                    "actual_value": "No profiles found"}
        first_pass = None
        for p in profiles:
            tags = getattr(p, "tags", None) or {}
            if tags:
                r = {**base, "resource": p.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": p.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": profile_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
