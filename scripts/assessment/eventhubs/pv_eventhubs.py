"""
Posture and Vulnerability Management checks for Azure Event Hubs (MCSB v3).
PaaS — Microsoft manages infrastructure. All UNKNOWN.
"""


def _paas_na(namespace_name, control_id, feature, url):
    return {
        "resource": namespace_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Microsoft manages Event Hubs infrastructure, OS, and runtime",
        "expected_value": "N/A",
        "evidence_url": url,
    }


def check_pv3_automation_state_config(credential, subscription_id, resource_group, namespace_name):
    return _paas_na(namespace_name, "PV-3", "Azure Automation State Configuration",
                    "https://learn.microsoft.com/en-us/azure/automation/automation-dsc-overview")


def check_pv3_guest_config_agent(credential, subscription_id, resource_group, namespace_name):
    return _paas_na(namespace_name, "PV-3", "Azure Policy Guest Configuration Agent",
                    "https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview")


def check_pv5_defender_va(credential, subscription_id, resource_group, namespace_name):
    return _paas_na(namespace_name, "PV-5", "Vulnerability Assessment using Microsoft Defender",
                    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management")


def check_pv6_update_management(credential, subscription_id, resource_group, namespace_name):
    return _paas_na(namespace_name, "PV-6", "Azure Automation Update Management",
                    "https://learn.microsoft.com/en-us/azure/automation/update-management/overview")
