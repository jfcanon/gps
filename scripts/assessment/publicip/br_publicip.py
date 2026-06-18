"""
Backup and Recovery checks for Azure Public IP (MCSB v3).

BR-1: No backup concept for PIP — IP address is recreatable from IaC → UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "BR-1", "feature": "Azure Backup", "status": "UNKNOWN", "actual_value": "Azure Backup does not support Public IP addresses as a backup target. A PIP is a lightweight network resource fully recoverable from infrastructure-as-code (ARM template, Bicep, Terraform). Static PIPs retain their IP on redeploy.", "expected_value": "N/A — no backup needed; PIP recreatable from IaC", "evidence_url": "https://learn.microsoft.com/en-us/azure/backup/backup-support-matrix"}


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "BR-1", "feature": "Service Native Backup Capability", "status": "UNKNOWN", "actual_value": "No native backup capability for Azure Public IP. Standard SKU Static PIPs retain their assigned IP address when deallocated. Recommended practice: define PIPs in IaC and store in source control. Basic Dynamic PIPs may receive a different IP on redeploy.", "expected_value": "N/A — no native backup; use Static SKU + IaC for recovery", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}
