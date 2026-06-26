"""
Data Protection checks for Azure Virtual Network (MCSB v3).
VNet is network infrastructure — DP controls are generally N/A. All UNKNOWN.
"""


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit",
        "status": "UNKNOWN",
        "actual_value": "Azure Virtual Network is L3 network infrastructure. TLS encryption is enforced at the workload level (VMs, PaaS services) running within the VNet, not on the VNet resource itself.",
        "expected_value": "N/A — enforce TLS at workload level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/security-baseline",
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "UNKNOWN",
        "actual_value": "VNet configuration is encrypted at rest by Azure infrastructure using Microsoft-managed keys. No configurable encryption property exists on the VNet resource itself.",
        "expected_value": "N/A — platform-managed by default",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }
