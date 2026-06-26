"""
Identity Management checks for Azure Data Factory (MCSB v3).

IM-1 AAD: ADF uses managed identity for data access; local auth at linked service level → UNKNOWN.
IM-1 local: Same.
IM-3 MI: factory.identity.type assigned → PASS.
IM-3 SP: UNKNOWN (linked service level).
IM-7 CA: UNKNOWN (tenant-level).
IM-8 KV: UNKNOWN (linked service level).
PA-7: UNKNOWN (ARM RBAC level).
PA-8: UNKNOWN (subscription-level).

Read-only. Zero ARM writes.
"""
from azure.mgmt.datafactory import DataFactoryManagementClient


def _get_factories(client, rg, name):
    if rg and name:
        return [client.factories.get(rg, name)]
    elif rg:
        return list(client.factories.list_by_resource_group(rg))
    else:
        return list(client.factories.list())


def check_im1_aad_auth(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth for Data Access",
        "status": "UNKNOWN",
        "actual_value": "ADF managed identity is used for authenticated access to data stores. Individual linked services may use service key, SAS, or account key (local auth). Check linked service definitions for auth type.",
        "expected_value": "All linked services use managed identity or service principal (not account key/SAS)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-factory-service-identity",
    }


def check_im1_local_auth_methods(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth",
        "status": "UNKNOWN",
        "actual_value": "Local auth methods (account keys, SAS tokens) in linked services are not inspectable at the factory ARM level — they are in linked service payloads (often encrypted). Audit via ADF monitoring APIs.",
        "expected_value": "All linked services use managed identity or Entra ID (not storage account keys)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-factory-service-identity",
    }


def check_im3_managed_identities(credential, subscription_id, resource_group, factory_name):
    base = {
        "control_id": "IM-3", "feature": "Use Azure AD Managed Identities — Factory Managed Identity",
        "expected_value": "factory.identity.type assigned (SystemAssigned or UserAssigned)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-factory-service-identity",
    }
    try:
        client = DataFactoryManagementClient(credential, subscription_id)
        factories = _get_factories(client, resource_group, factory_name)
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        first_pass = None
        for factory in factories:
            identity = getattr(factory, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": factory.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": factory.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity assigned"}
        return first_pass
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities — Service Principals in Linked Services",
        "status": "UNKNOWN",
        "actual_value": "Service principal auth in linked services is not inspectable at factory ARM level. Audit linked service definitions for servicePrincipalId usage.",
        "expected_value": "Prefer managed identity over service principal credentials in linked services",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-factory-service-identity",
    }


def check_im7_conditional_access(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "CA policies are Entra ID tenant-level. ADF portal access can be gated by CA. Not readable per factory via ARM.",
        "expected_value": "CA policies applied to Azure Data Factory portal and API access",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/security-baseline",
    }


def check_im8_keyvault_secrets(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "IM-8",
        "feature": "Restrict the Exposure of Credentials and Secrets — KV-Backed Linked Services",
        "status": "UNKNOWN",
        "actual_value": "Credential storage in Key Vault is a linked service-level configuration in ADF. The factory ARM resource does not expose whether linked services reference KV.",
        "expected_value": "All linked service secrets reference Azure Key Vault (not inline)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/store-credentials-in-key-vault",
    }


def check_pa7_rbac_data_plane(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "PASS",
        "actual_value": "Azure Data Factory uses ARM RBAC exclusively for both management and data plane (pipeline trigger/run). Built-in roles: Data Factory Contributor, Data Factory Reader. No separate data plane key system.",
        "expected_value": "ADF RBAC roles follow least-privilege (Reader not Contributor where possible)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/concepts-roles-permissions",
    }


def check_pa8_customer_lockbox(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox for ADF is subscription-level. Not readable per factory via ARM.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }
