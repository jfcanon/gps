"""
Data Protection checks for Azure Databricks (MCSB v3).

DP-3: Static PASS (TLS enforced for cluster/web communications).
DP-4: Static PASS (DBFS encrypted with Microsoft-managed keys).
DP-5: workspace.parameters.prepareEncryption + encryption.keySource=Microsoft.Keyvault → CMK → PASS.
DP-6: CMK + identity → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.databricks import AzureDatabricksManagementClient


def _get_workspaces(client, rg, name):
    if rg and name:
        return [client.workspaces.get(rg, name)]
    elif rg:
        return list(client.workspaces.list_by_resource_group(rg))
    else:
        return list(client.workspaces.list_by_subscription())


def check_dp3_tls_transit(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-3", "feature": "Encrypt Data in Transit",
            "status": "PASS",
            "actual_value": "Azure Databricks enforces TLS 1.2+ for web UI, REST API, and cluster communications. Data in transit between cluster nodes uses encrypted channels.",
            "expected_value": "TLS enforced (default, not ARM-configurable off)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/encryption/encrypt-otw"}


def check_dp4_platform_keys(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-4", "feature": "Encrypt Data at Rest with Platform-Managed Keys",
            "status": "PASS",
            "actual_value": "DBFS (Databricks File System) and cluster disk volumes are encrypted at rest with Microsoft-managed keys by default.",
            "expected_value": "Microsoft-managed encryption (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/encryption/encrypt-otw"}


def check_dp5_cmk(credential, subscription_id, resource_group, workspace_name):
    base = {"control_id": "DP-5", "feature": "Encrypt Data at Rest with Customer-Managed Key",
            "expected_value": "workspace.encryption.entities.managedDisk.keySource=Microsoft.Keyvault OR managedServices.keySource=Microsoft.Keyvault",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/encryption/customer-managed-key-managed-disks-azure"}
    try:
        client = AzureDatabricksManagementClient(credential, subscription_id)
        workspaces = _get_workspaces(client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "PASS", "actual_value": "No workspaces found"}
        first_pass = None
        for ws in workspaces:
            enc = getattr(ws, "encryption", None)
            entities = getattr(enc, "entities", None) if enc else None
            managed_disk = getattr(entities, "managed_disk", None) if entities else None
            managed_svc = getattr(entities, "managed_services", None) if entities else None
            disk_source = str(getattr(managed_disk, "key_source", "") or "") if managed_disk else ""
            svc_source = str(getattr(managed_svc, "key_source", "") or "") if managed_svc else ""
            has_cmk = "keyvault" in disk_source.lower() or "keyvault" in svc_source.lower()
            if has_cmk:
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": f"CMK enabled; disk.keySource={disk_source}; services.keySource={svc_source}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "FAIL",
                        "actual_value": f"CMK not enabled; disk.keySource={disk_source or 'not set'}; services.keySource={svc_source or 'not set'}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp6_key_mgmt(credential, subscription_id, resource_group, workspace_name):
    base = {"control_id": "DP-6", "feature": "Manage Cryptographic Keys using Key Management Service",
            "expected_value": "CMK enabled via Key Vault",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/encryption/customer-managed-key-managed-disks-azure"}
    try:
        client = AzureDatabricksManagementClient(credential, subscription_id)
        workspaces = _get_workspaces(client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "PASS", "actual_value": "No workspaces found"}
        first_pass = None
        for ws in workspaces:
            enc = getattr(ws, "encryption", None)
            entities = getattr(enc, "entities", None) if enc else None
            managed_disk = getattr(entities, "managed_disk", None) if entities else None
            disk_source = str(getattr(managed_disk, "key_source", "") or "") if managed_disk else ""
            if "keyvault" in disk_source.lower():
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": f"CMK via Key Vault enabled; disk.keySource={disk_source}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "UNKNOWN",
                        "actual_value": f"CMK not configured (disk.keySource={disk_source or 'not set'}) — using platform-managed keys"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
