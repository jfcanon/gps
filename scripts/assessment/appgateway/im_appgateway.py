"""
Identity Management checks for Azure Application Gateway (MCSB v3).

IM-1: AppGW has no SAS/shared-key local auth concept — ARM RBAC only → UNKNOWN (not applicable).
IM-3 MI: gateway.identity present (SystemAssigned/UserAssigned) → PASS proxy.
IM-3 SP: ARM RBAC controls management plane — SP assignments supported; data plane not applicable → UNKNOWN.
IM-7: Conditional Access — Entra tenant-level; not ARM-readable → UNKNOWN.
IM-8: ssl_certificates with key_vault_secret_id + MI → KV-managed certs/secrets → PASS proxy.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        return [client.application_gateways.get(resource_group, gateway_name)]
    elif resource_group:
        return list(client.application_gateways.list(resource_group))
    else:
        return list(client.application_gateways.list_all())


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth",
        "status": "UNKNOWN",
        "actual_value": "Application Gateway has no local authentication concept (no SAS keys, connection strings, or shared secrets). Management plane access is exclusively via Azure ARM RBAC (Entra ID). Control is inherently satisfied for the management plane; no per-gateway ARM property to check.",
        "expected_value": "N/A — no local auth mechanism exists on Application Gateway",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/overview",
    }


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
        "status": "UNKNOWN",
        "actual_value": "Application Gateway management plane uses Azure ARM (Entra ID) exclusively — no alternative auth method exists. This is inherently satisfied but not surfaced as a configurable ARM property. Data plane (client traffic) has no authentication layer on the gateway itself.",
        "expected_value": "N/A — ARM RBAC (Entra ID) is the only auth method",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/overview",
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "expected_value": "gateway.identity assigned (SystemAssigned or UserAssigned) — used for KV certificate access",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            identity = getattr(gw, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type} — Managed Identity assigned (typically for KV certificate retrieval)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no Managed Identity assigned to gateway"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-3",
        "feature": "Use Azure AD Service Principals for Azure Resource Authentication",
        "status": "UNKNOWN",
        "actual_value": "Application Gateway management plane uses ARM RBAC — Service Principal role assignments are supported but not readable per-gateway without azure-mgmt-authorization. Data plane (client HTTP traffic) has no SP authentication layer.",
        "expected_value": "ARM RBAC role assignments enumerable via azure-mgmt-authorization",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Conditional Access policies are Entra tenant-level configuration; not readable via ARM on per-gateway basis. Check via Entra ID portal or MS Graph API.",
        "expected_value": "N/A (Entra tenant-level)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "IM-8",
        "feature": "Restrict the Exposure of Credential and Secrets — Use Azure Key Vault",
        "expected_value": "ssl_certificates with key_vault_secret_id AND identity (MI) — credentials stored in KV",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            certs = getattr(gw, "ssl_certificates", None) or []
            if not certs:
                r = {**base, "resource": gw.name, "status": "UNKNOWN",
                     "actual_value": "No SSL certificates configured — no KV-backed secrets to verify"}
                first_pass = first_pass or r
                continue
            kv_certs = [c for c in certs if getattr(c, "key_vault_secret_id", None)]
            identity = getattr(gw, "identity", None)
            if kv_certs and identity:
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"{len(kv_certs)}/{len(certs)} cert(s) reference KV secrets; MI assigned — secrets managed in KV"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"{len(certs)} cert(s) present; {len(kv_certs)} KV-backed; MI={'present' if identity else 'absent'} — inline cert storage"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
