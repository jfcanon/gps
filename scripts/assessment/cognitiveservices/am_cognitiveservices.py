"""AM-2 tags check for Azure Cognitive Services (MCSB v3)."""
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient


def check_am2_policy(credential, subscription_id, resource_group, account_name):
    base = {"control_id": "AM-2", "feature": "Use Only Approved Azure Services — Azure Policy Support",
            "expected_value": "Resource tags present",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/security-baseline#am-2-use-only-approved-azure-services"}
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        if resource_group and account_name:
            accounts = [client.accounts.get(resource_group, account_name)]
        elif resource_group:
            accounts = list(client.accounts.list_by_resource_group(resource_group))
        else:
            accounts = list(client.accounts.list())
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            tags = getattr(acct, "tags", None) or {}
            if tags:
                r = {**base, "resource": acct.name, "status": "PASS", "actual_value": f"tags: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": acct.name, "status": "FAIL", "actual_value": "tags={} — no tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
