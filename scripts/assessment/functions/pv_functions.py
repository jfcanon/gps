"""
Posture and Vulnerability Management checks for Azure Functions (MCSB v3).
PaaS — Microsoft manages infrastructure, OS, runtime. All UNKNOWN.
"""


def _paas_na(site_name, control_id, feature, url):
    return {
        "resource": site_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Microsoft manages Azure Functions infrastructure, OS, and runtime",
        "expected_value": "N/A",
        "evidence_url": url,
    }


def check_pv3_automation_state_config(credential, subscription_id, resource_group, site_name):
    return _paas_na(site_name, "PV-3", "Azure Automation State Configuration",
                    "https://learn.microsoft.com/en-us/azure/automation/automation-dsc-overview")


def check_pv3_guest_config_agent(credential, subscription_id, resource_group, site_name):
    return _paas_na(site_name, "PV-3", "Azure Policy Guest Configuration Agent",
                    "https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview")


def check_pv3_custom_container_images(credential, subscription_id, resource_group, site_name):
    return _paas_na(site_name, "PV-3", "Custom Container Images",
                    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction")


def check_pv5_defender_va(credential, subscription_id, resource_group, site_name):
    return _paas_na(site_name, "PV-5", "Vulnerability Assessment using Microsoft Defender",
                    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management")


def check_pv6_update_management(credential, subscription_id, resource_group, site_name):
    return _paas_na(site_name, "PV-6", "Azure Automation Update Management",
                    "https://learn.microsoft.com/en-us/azure/automation/update-management/overview")
