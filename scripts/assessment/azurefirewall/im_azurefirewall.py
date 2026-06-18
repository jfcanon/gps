"""
Identity Management checks for Azure Firewall (MCSB v3).

IM-1 local auth: No local auth concept on Firewall; ARM RBAC controls management plane → UNKNOWN.
IM-1 AAD: ARM RBAC is the only auth model; no data-plane AAD auth concept → UNKNOWN.
IM-3 MI: firewall.identity present (SystemAssigned or UserAssigned) → PASS (now_applicable_native).
IM-3 SP: Service principal data-plane auth not supported → UNKNOWN.
IM-7: No Conditional Access for Firewall data plane → UNKNOWN.
IM-8: Premium — transport_security.certificate_authority.key_vault_secret_id set → PASS (KV used for cert storage).

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_firewalls(client: NetworkManagementClient, resource_group: str | None, firewall_name: str | None) -> list:
    if resource_group and firewall_name:
        return [client.azure_firewalls.get(resource_group, firewall_name)]
    elif resource_group:
        return list(client.azure_firewalls.list(resource_group))
    else:
        return list(client.azure_firewalls.list_all())


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "IM-1",
        "feature": "Local Authentication Methods for Data Plane Access",
        "status": "UNKNOWN",
        "actual_value": "Azure Firewall has no data plane; all management is via ARM (Azure Resource Manager). No local username/password or API key authentication exists. ARM RBAC is the sole management access model.",
        "expected_value": "N/A — no local auth concept; ARM RBAC only",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#im-1-use-centralized-identity-and-authentication-system",
    }


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required for Data Plane Access",
        "status": "UNKNOWN",
        "actual_value": "Azure Firewall is a fully managed network service with no customer-accessible data plane. Management plane authentication is enforced by ARM/Entra ID RBAC. No separate data-plane AAD authentication toggle exists.",
        "expected_value": "N/A — ARM RBAC enforces Entra ID auth for all management operations",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#im-1-use-centralized-identity-and-authentication-system",
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Managed Identities",
        "expected_value": "firewall.identity present (SystemAssigned or UserAssigned) — used for Key Vault cert access in Premium TLS inspection",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/premium-certificates#azure-key-vault",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            identity = getattr(fw, "identity", None)
            if identity:
                identity_type = getattr(identity, "type", "Unknown")
                principal_id = getattr(identity, "principal_id", None)
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"Managed identity configured: type={identity_type}, principal_id={principal_id or 'UserAssigned'}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "firewall.identity is None — no managed identity assigned; Premium TLS inspection requires MI for Key Vault cert access"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "IM-3",
        "feature": "Service Principals",
        "status": "UNKNOWN",
        "actual_value": "Azure Firewall does not support service principal authentication for data plane access. Service principals may be used in ARM RBAC for management operations only.",
        "expected_value": "N/A — no data-plane service principal auth for Azure Firewall",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#im-3-manage-application-identities-securely-and-automatically",
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Azure Firewall has no customer-accessible data plane. Conditional Access applies to ARM management operations via Entra ID at the subscription level, not per-firewall resource.",
        "expected_value": "N/A — no data-plane access; Conditional Access is ARM-level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#im-7-restrict-resource-access-based-on-conditions",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "IM-8",
        "feature": "Service Credential and Secrets Support Integration and Storage in Azure Key Vault",
        "expected_value": "Premium SKU; transport_security.certificate_authority.key_vault_secret_id set (intermediate CA cert stored in KV)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/premium-certificates",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            sku = getattr(fw, "sku", None)
            tier = getattr(sku, "tier", "Standard") if sku else "Standard"
            if str(tier) != "Premium":
                return {**base, "resource": fw.name, "status": "UNKNOWN",
                        "actual_value": f"sku.tier={tier} — Key Vault secret integration for TLS inspection is Premium-only; Standard has no credential stored in KV"}
            transport_sec = getattr(fw, "transport_security", None)
            ca = getattr(transport_sec, "certificate_authority", None) if transport_sec else None
            kv_secret_id = getattr(ca, "key_vault_secret_id", None) if ca else None
            if kv_secret_id:
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"Premium SKU; intermediate CA certificate stored in Key Vault — secret ID configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "Premium SKU but key_vault_secret_id not configured — TLS inspection cert not stored in Key Vault"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
