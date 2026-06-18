"""
Identity Management checks for Azure Service Bus (MCSB v3).

IM-1: disable_local_auth=True → SAS keys disabled, Entra ID enforced → PASS.
IM-3 MI: namespace.identity present → MI assigned → PASS proxy.
IM-3 SP: disable_local_auth=True → Entra/RBAC enforced → SP assignments supported → PASS proxy.
IM-7: Conditional Access — Entra tenant-level; not ARM-readable → UNKNOWN.
IM-8: disable_local_auth=True → no SAS secrets exposed → PASS proxy.

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


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth",
        "expected_value": "disable_local_auth=True (SAS key authentication disabled)",
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
                     "actual_value": "disable_local_auth=True — SAS key authentication disabled; Entra ID is sole auth method"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — SAS shared access keys active; local authentication not disabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
        "expected_value": "disable_local_auth=True (Entra ID enforced as sole auth method)",
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
                     "actual_value": "disable_local_auth=True — Entra ID enforced as sole authentication method for data plane"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — SAS keys still valid; Entra ID not enforced as exclusive auth"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "expected_value": "namespace.identity assigned (SystemAssigned or UserAssigned)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/authenticate-managed-identity",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            identity = getattr(ns, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type} — Managed Identity assigned; MI-based auth supported"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no Managed Identity assigned to namespace"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Service Principals for Azure Resource Authentication",
        "expected_value": "disable_local_auth=True (Entra ID / RBAC enforced; SP auth supported)",
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
                     "actual_value": "disable_local_auth=True — Entra/RBAC enforced; Service Principal auth assignments supported"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — SAS keys active; SP-only auth not enforced"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Conditional Access policies are Entra tenant-level configuration; not readable via ARM on per-namespace basis. Check via Entra ID portal or MS Graph API.",
        "expected_value": "N/A (Entra tenant-level)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "IM-8",
        "feature": "Restrict the Exposure of Credential and Secrets — Use Azure Key Vault",
        "expected_value": "disable_local_auth=True (no SAS connection strings exposed; KV not needed for credential storage)",
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
                     "actual_value": "disable_local_auth=True — SAS connection strings disabled; no shared secrets to store in KV"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "UNKNOWN",
                        "actual_value": "disable_local_auth=False — SAS connection strings active; should be stored in Azure Key Vault but not ARM-verifiable"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
