"""
Posture and Vulnerability Management checks for Azure Application Gateway (MCSB v3).
PaaS — Microsoft manages infrastructure. All UNKNOWN.
"""


def _paas_na(gateway_name, control_id, feature, url):
    return {
        "resource": gateway_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Microsoft manages Application Gateway infrastructure, OS, and runtime; control not applicable to customer workloads",
        "expected_value": "N/A",
        "evidence_url": url,
    }


def check_pv3_automation_state_config(credential, subscription_id, resource_group, gateway_name):
    return _paas_na(gateway_name, "PV-3", "Azure Automation State Configuration",
                    "https://learn.microsoft.com/en-us/azure/automation/automation-dsc-overview")


def check_pv3_guest_config_agent(credential, subscription_id, resource_group, gateway_name):
    return _paas_na(gateway_name, "PV-3", "Azure Policy Guest Configuration Agent",
                    "https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview")


def check_pv3_custom_container_images(credential, subscription_id, resource_group, gateway_name):
    return _paas_na(gateway_name, "PV-3", "Custom Container Images",
                    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction")


def check_pv3_custom_vm_images(credential, subscription_id, resource_group, gateway_name):
    return _paas_na(gateway_name, "PV-3", "Custom VM Images",
                    "https://learn.microsoft.com/en-us/azure/virtual-machines/shared-image-galleries")


def check_pv5_defender_va(credential, subscription_id, resource_group, gateway_name):
    return _paas_na(gateway_name, "PV-5", "Vulnerability Assessment using Microsoft Defender",
                    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management")


def check_pv6_update_management(credential, subscription_id, resource_group, gateway_name):
    return _paas_na(gateway_name, "PV-6", "Azure Automation Update Management",
                    "https://learn.microsoft.com/en-us/azure/automation/update-management/overview")
