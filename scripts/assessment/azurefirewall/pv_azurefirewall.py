"""
Posture and Vulnerability Management checks for Azure Firewall (MCSB v3).

PV-3/5/6: PaaS — no VM, container, or OS substrate accessible to customer → all UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PV-3",
        "feature": "Azure Automation State Configuration",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Azure Firewall has no customer-accessible OS or VM substrate. Azure Automation State Configuration applies to VMs and Arc-enabled servers; not applicable to this managed network service.",
        "expected_value": "N/A — PaaS; no OS configuration substrate",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#pv-3-define-and-establish-secure-configurations-for-compute-resources",
    }


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PV-3",
        "feature": "Azure Policy Guest Configuration Agent",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Azure Policy Guest Configuration agent requires VM or Arc-enabled server substrate. Azure Firewall compute nodes are Microsoft-managed and do not support guest configuration agent deployment.",
        "expected_value": "N/A — PaaS; guest config agent not deployable",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#pv-3-define-and-establish-secure-configurations-for-compute-resources",
    }


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PV-3",
        "feature": "Custom Container Images",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Azure Firewall does not use or accept custom container images. The service runs on Microsoft-managed, hardened infrastructure.",
        "expected_value": "N/A — PaaS; no custom container image support",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#pv-3-define-and-establish-secure-configurations-for-compute-resources",
    }


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PV-3",
        "feature": "Custom VM Images",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Azure Firewall does not support custom VM images. Microsoft manages the underlying compute infrastructure with hardened platform images.",
        "expected_value": "N/A — PaaS; no custom VM image support",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#pv-3-define-and-establish-secure-configurations-for-compute-resources",
    }


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PV-5",
        "feature": "Vulnerability Assessment using Microsoft Defender",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Microsoft Defender vulnerability assessment targets VMs, container registries, App Service, and SQL. Azure Firewall is not in the supported services list for Defender VA scanning.",
        "expected_value": "N/A — PaaS; Defender VA not applicable to Azure Firewall",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PV-6",
        "feature": "Azure Automation Update Management",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Azure Automation Update Management applies to VMs and Arc-enabled servers. Azure Firewall platform updates are managed exclusively by Microsoft with zero-downtime deployment via availability zones.",
        "expected_value": "N/A — PaaS; platform updates managed by Microsoft",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#pv-6-rapidly-and-automatically-remediate-vulnerabilities",
    }
