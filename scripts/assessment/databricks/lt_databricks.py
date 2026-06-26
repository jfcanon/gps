"""LT checks for Azure Databricks (MCSB v3). LT-4: DiagnosticSettings on workspace."""
from azure.mgmt.databricks import AzureDatabricksManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_workspaces(client, rg, name):
    if rg and name:
        return [client.workspaces.get(rg, name)]
    elif rg:
        return list(client.workspaces.list_by_resource_group(rg))
    else:
        return list(client.workspaces.list_by_subscription())


def check_lt1_defender(c, s, r, n):
    return {"resource": n or "all", "control_id": "LT-1", "feature": "Enable Threat Detection Capabilities",
            "status": "UNKNOWN",
            "actual_value": "Defender for Cloud may surface Databricks workspace recommendations. No standalone Defender for Databricks product.",
            "expected_value": "N/A — monitor via Defender for Cloud",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"}


def check_lt4_resource_logs(credential, subscription_id, resource_group, workspace_name):
    base = {"control_id": "LT-4", "feature": "Enable Logging for Azure Resources",
            "expected_value": "At least one diagnostic log category enabled",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/account-settings/audit-log-delivery"}
    try:
        db_client = AzureDatabricksManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        workspaces = _get_workspaces(db_client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "PASS", "actual_value": "No workspaces found"}
        first_pass = None
        for ws in workspaces:
            settings = list(monitor.diagnostic_settings.list(ws.id))
            logs_enabled = any(getattr(lg, "enabled", False) for s in settings for lg in (getattr(s, "logs", None) or []))
            if logs_enabled:
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); logs enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
