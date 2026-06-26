"""
Posture and Vulnerability Management checks for Azure Virtual Network (MCSB v3).
Network infrastructure — Microsoft manages underlay. All UNKNOWN.
"""


def _paas_na(vnet_name, control_id, feature, url):
    return {
        "resource": vnet_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": "Azure Virtual Network is managed network infrastructure; posture/vulnerability management applies to workloads within the VNet, not the VNet resource itself",
        "expected_value": "N/A",
        "evidence_url": url,
    }


def check_pv3_automation_state_config(credential, subscription_id, resource_group, vnet_name):
    return _paas_na(vnet_name, "PV-3", "Azure Automation State Configuration",
                    "https://learn.microsoft.com/en-us/azure/automation/automation-dsc-overview")


def check_pv3_guest_config_agent(credential, subscription_id, resource_group, vnet_name):
    return _paas_na(vnet_name, "PV-3", "Azure Policy Guest Configuration Agent",
                    "https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview")


def check_pv5_defender_va(credential, subscription_id, resource_group, vnet_name):
    return _paas_na(vnet_name, "PV-5", "Vulnerability Assessment using Microsoft Defender",
                    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management")


def check_pv6_update_management(credential, subscription_id, resource_group, vnet_name):
    return _paas_na(vnet_name, "PV-6", "Azure Automation Update Management",
                    "https://learn.microsoft.com/en-us/azure/automation/update-management/overview")
