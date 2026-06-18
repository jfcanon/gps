"""
Backup and Recovery checks for Azure Network Watcher (MCSB v3).
BR-1: NW auto-created per region when VNets exist; no backup concept — UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "BR-1", "feature": "Azure Backup", "status": "UNKNOWN", "actual_value": "Azure Backup not supported for Network Watcher. NW is auto-provisioned per region by Azure when VNets exist; it is stateless configuration — recreated automatically. Flow log configurations are IaC-recoverable.", "expected_value": "N/A — NW auto-provisioned; no backup required", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "BR-1", "feature": "Service Native Backup Capability", "status": "UNKNOWN", "actual_value": "No native backup for NW. NW resource is auto-created by Azure and auto-regenerated if deleted. Flow log and connection monitor configurations should be stored in IaC (ARM/Bicep/Terraform) as compensating control.", "expected_value": "N/A — auto-provisioned; IaC as compensating control", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}
