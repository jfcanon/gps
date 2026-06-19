"""
Backup and Recovery checks for Azure VPN Gateway (MCSB v3).

BR-1 Azure Backup: False, Not Applicable → UNKNOWN static (still_not_applicable).
    Azure Backup does not support VPN GW as a backup target.

BR-1 native: Not Applicable → UNKNOWN static (still_not_applicable).
    VPN GW has no native backup; config is IaC-recoverable via ARM/Bicep/Terraform.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways"


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Backup does not support VPN Gateway as a backup target. "
            "feature_supported=False in MCSB v3 baseline. "
            "VPN GW configuration (connections, PSKs, routing tables) is recoverable via "
            "ARM template export, Bicep, or Terraform — IaC is the recommended recovery approach."
        ),
        "expected_value": "N/A — Azure Backup does not support VPN GW; use IaC (ARM/Bicep/Terraform) for config recovery",
        "evidence_url": _EVIDENCE,
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "status": "UNKNOWN",
        "actual_value": (
            "VPN GW has no native backup capability. Not Applicable in MCSB v3 baseline. "
            "Recovery: VPN GW configuration (gateway SKU, routing, local network gateways, connections) "
            "can be re-created from exported ARM templates or IaC. "
            "PSK and connection credentials should be stored outside VPN GW "
            "(e.g., Key Vault or IaC secrets management) for recovery."
        ),
        "expected_value": "N/A — no native backup; recover via ARM template export or IaC re-deployment",
        "evidence_url": _EVIDENCE,
    }
