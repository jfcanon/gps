"""AM-2 tags check for Azure Logic Apps (MCSB v3)."""
from azure.mgmt.logic import LogicManagementClient


def check_am2_policy(credential, subscription_id, resource_group, workflow_name):
    base = {"control_id": "AM-2", "feature": "Use Only Approved Azure Services — Azure Policy Support",
            "expected_value": "Resource tags present",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/security-baseline#am-2-use-only-approved-azure-services"}
    try:
        client = LogicManagementClient(credential, subscription_id)
        if resource_group and workflow_name:
            workflows = [client.workflows.get(resource_group, workflow_name)]
        elif resource_group:
            workflows = list(client.workflows.list_by_resource_group(resource_group))
        else:
            workflows = list(client.workflows.list_by_subscription())
        if not workflows:
            return {**base, "resource": workflow_name or "none", "status": "PASS", "actual_value": "No workflows found"}
        first_pass = None
        for wf in workflows:
            tags = getattr(wf, "tags", None) or {}
            if tags:
                r = {**base, "resource": wf.name, "status": "PASS", "actual_value": f"tags: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wf.name, "status": "FAIL", "actual_value": "tags={} — no tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workflow_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
