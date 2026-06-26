"""AM-2 tags check for Azure Databricks (MCSB v3)."""
from azure.mgmt.databricks import AzureDatabricksManagementClient


def check_am2_policy(credential, subscription_id, resource_group, workspace_name):
    base = {"control_id": "AM-2", "feature": "Use Only Approved Azure Services — Azure Policy Support",
            "expected_value": "Resource tags present",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/baseline#am-2-use-only-approved-azure-services"}
    try:
        client = AzureDatabricksManagementClient(credential, subscription_id)
        if resource_group and workspace_name:
            workspaces = [client.workspaces.get(resource_group, workspace_name)]
        elif resource_group:
            workspaces = list(client.workspaces.list_by_resource_group(resource_group))
        else:
            workspaces = list(client.workspaces.list_by_subscription())
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "PASS", "actual_value": "No workspaces found"}
        first_pass = None
        for ws in workspaces:
            tags = getattr(ws, "tags", None) or {}
            if tags:
                r = {**base, "resource": ws.name, "status": "PASS", "actual_value": f"tags: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "FAIL", "actual_value": "tags={} — no tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
