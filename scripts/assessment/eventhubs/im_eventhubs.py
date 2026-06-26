"""
Identity Management checks for Azure Event Hubs (MCSB v3).

IM-1 AAD: namespace.disable_local_auth=True → SAS disabled, Entra-only → PASS.
IM-1 local auth: same property — disable_local_auth=True → PASS.
IM-3 MI: namespace.identity assigned → PASS.
IM-3 SP: ARM RBAC role assignments — not ARM-readable per namespace → UNKNOWN.
IM-7 CA: Entra tenant-level — not ARM-readable → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventhub import EventHubManagementClient


def _get_namespaces(client: EventHubManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def check_im1_aad_auth(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required (Disable SAS)",
        "expected_value": "namespace.disable_local_auth=True (SAS key authentication disabled)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/authenticate-shared-access-signature",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            disable_local = getattr(ns, "disable_local_auth", None)
            if disable_local is True:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — SAS key auth disabled; Entra ID only"}
                first_pass = first_pass or r
            elif disable_local is False:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — SAS key authentication enabled; local credentials accepted"}
            else:
                return {**base, "resource": ns.name, "status": "UNKNOWN",
                        "actual_value": "disable_local_auth property not returned — assume SAS enabled (default)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth Methods",
        "expected_value": "namespace.disable_local_auth=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/authenticate-shared-access-signature",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            disable_local = getattr(ns, "disable_local_auth", None)
            if disable_local is True:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — SAS/local auth methods disabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"disable_local_auth={disable_local} — SAS key auth still available"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "expected_value": "namespace.identity.type assigned (SystemAssigned or UserAssigned)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/authenticate-managed-identity",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            identity = getattr(ns, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity assigned"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication — Service Principal",
        "status": "UNKNOWN",
        "actual_value": "Service principal role assignments not readable per-namespace via Event Hubs ARM API. Use azure-mgmt-authorization for role assignment enumeration.",
        "expected_value": "Prefer managed identity over service principal credentials",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/authenticate-managed-identity",
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Conditional Access policies are Entra ID tenant-level. Not readable per Event Hubs namespace via ARM API.",
        "expected_value": "Conditional Access policies applied to Event Hubs application registration",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/security-baseline",
    }
