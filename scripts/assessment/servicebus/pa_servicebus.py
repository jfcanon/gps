"""
Privileged Access checks for Azure Service Bus (MCSB v3).

PA-1: disable_local_auth=False → SAS keys active = broad permissions without RBAC granularity (FAIL).
PA-7: disable_local_auth=True → Entra/RBAC data-plane active (PASS proxy).
PA-8: Customer Lockbox — Service Bus in supported services list; subscription-level only → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.servicebus import ServiceBusManagementClient


def _get_namespaces(client: ServiceBusManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "PA-1",
        "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin",
        "expected_value": "disable_local_auth=True (SAS shared access keys disabled)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/disable-local-authentication",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            local_auth = getattr(ns, "disable_local_auth", False)
            if local_auth:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — SAS keys disabled; no broad local-admin equivalent active"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — SAS shared access keys active; Manage-level SAS grants full send/receive/manage equivalent to local admin"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "expected_value": "disable_local_auth=True (Entra ID / RBAC data-plane active)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/authenticate-application",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            local_auth = getattr(ns, "disable_local_auth", False)
            if local_auth:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — Entra ID / RBAC enforced for data plane; full JEA verification requires azure-mgmt-authorization"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — SAS keys active; Entra RBAC not enforced for data plane (no JEA enforcement)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Azure Service Bus is in the Customer Lockbox supported services list. Lockbox enablement is at subscription level — not readable per-namespace via ARM. Check via Azure Portal > Customer Lockbox or azure-mgmt-support.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability",
    }
