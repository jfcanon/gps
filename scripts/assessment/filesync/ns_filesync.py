"""
Network Security checks for Azure File Sync (MCSB v3).

NS-2 PE: storageSyncService.properties.privateEndpointConnections non-empty → PASS.
NS-2 disable public: storageSyncService.properties.incomingTrafficPolicy == 'AllowVirtualNetworksOnly' → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.storagesync import MicrosoftStorageSync


def _get_sync_services(client: MicrosoftStorageSync, resource_group: str | None, service_name: str | None) -> list:
    if resource_group and service_name:
        return [client.storage_sync_services.get(resource_group, service_name)]
    elif resource_group:
        return list(client.storage_sync_services.list_by_resource_group(resource_group))
    else:
        return list(client.storage_sync_services.list_by_subscription())


def check_ns2_private_link(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "storageSyncService.properties.privateEndpointConnections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-networking-endpoints",
    }
    try:
        client = MicrosoftStorageSync(credential, subscription_id)
        services = _get_sync_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS", "actual_value": "No sync services found"}
        first_pass = None
        for svc in services:
            pe_conns = getattr(svc, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "storageSyncService.properties.incomingTrafficPolicy == 'AllowVirtualNetworksOnly'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-networking-endpoints",
    }
    try:
        client = MicrosoftStorageSync(credential, subscription_id)
        services = _get_sync_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS", "actual_value": "No sync services found"}
        first_pass = None
        for svc in services:
            policy = str(getattr(svc, "incoming_traffic_policy", "") or "AllowAllTraffic")
            if policy.lower() == "allowvirtualnetworksonly":
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"incomingTrafficPolicy={policy}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": f"incomingTrafficPolicy={policy} — public network access not restricted"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
