"""LT checks for Azure Cognitive Services (MCSB v3). LT-4: DiagnosticSettings."""
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_accounts(client, rg, name):
    if rg and name:
        return [client.accounts.get(rg, name)]
    elif rg:
        return list(client.accounts.list_by_resource_group(rg))
    else:
        return list(client.accounts.list())


def check_lt1_defender(credential, subscription_id, resource_group, account_name):
    return {"resource": account_name or "all", "control_id": "LT-1", "feature": "Enable Threat Detection Capabilities",
            "status": "UNKNOWN", "actual_value": "No standalone Defender for Cognitive Services. Use Defender for Cloud recommendations.",
            "expected_value": "N/A", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"}


def check_lt4_resource_logs(credential, subscription_id, resource_group, account_name):
    base = {"control_id": "LT-4", "feature": "Enable Logging for Azure Resources",
            "expected_value": "At least one diagnostic log category enabled",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/diagnostic-logging"}
    try:
        cs_client = CognitiveServicesManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        accounts = _get_accounts(cs_client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            settings = list(monitor.diagnostic_settings.list(acct.id))
            logs_enabled = any(getattr(lg, "enabled", False) for s in settings for lg in (getattr(s, "logs", None) or []))
            if logs_enabled:
                r = {**base, "resource": acct.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); logs enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
