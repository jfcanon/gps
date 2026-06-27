"""LT checks for Azure Logic Apps (MCSB v3). LT-4: DiagnosticSettings on workflow."""
from azure.mgmt.logic import LogicManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_workflows(client, rg, name):
    if rg and name:
        return [client.workflows.get(rg, name)]
    elif rg:
        return list(client.workflows.list_by_resource_group(rg))
    else:
        return list(client.workflows.list_by_subscription())


def check_lt1_defender(c, s, r, n):
    return {"resource": n or "all", "control_id": "LT-1", "feature": "Enable Threat Detection Capabilities",
            "status": "UNKNOWN",
            "actual_value": "No standalone Defender for Logic Apps. Use Defender for Cloud recommendations.",
            "expected_value": "N/A",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"}


def check_lt4_resource_logs(credential, subscription_id, resource_group, workflow_name):
    base = {"control_id": "LT-4", "feature": "Enable Logging for Azure Resources",
            "expected_value": "At least one diagnostic log category enabled (WorkflowRuntime)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/monitor-logic-apps"}
    try:
        logic_client = LogicManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        workflows = _get_workflows(logic_client, resource_group, workflow_name)
        if not workflows:
            return {**base, "resource": workflow_name or "none", "status": "PASS", "actual_value": "No workflows found"}
        first_pass = None
        for wf in workflows:
            settings = list(monitor.diagnostic_settings.list(wf.id))
            logs_enabled = any(getattr(lg, "enabled", False) for s in settings for lg in (getattr(s, "logs", None) or []))
            if logs_enabled:
                r = {**base, "resource": wf.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); logs enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wf.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workflow_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
