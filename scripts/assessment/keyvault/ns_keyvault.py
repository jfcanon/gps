"""
Network Security checks for Azure Key Vault (MCSB v3).

NS-1: NSG support (N/A — KV not subnet-injected; VNet service endpoint check).
NS-2: Private Link and disable public network access.

Read-only. Zero ARM writes.
"""
from azure.mgmt.keyvault import KeyVaultManagementClient


def _rg_from_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return "unknown"


def _get_vaults(client: KeyVaultManagementClient, resource_group: str | None, vault_name: str | None) -> list:
    if resource_group and vault_name:
        return [client.vaults.get(resource_group, vault_name)]
    elif resource_group:
        return list(client.vaults.list_by_resource_group(resource_group))
    else:
        return list(client.vaults.list())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "expected_value": "Network ACLs restrict access (VNet rules or default_action=Deny)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        props = vault.properties
        acls = getattr(props, "network_acls", None)
        default_action = getattr(acls, "default_action", "Allow") if acls else "Allow"
        vnet_rules = getattr(acls, "virtual_network_rules", None) or []
        public_access = getattr(props, "public_network_access", "Enabled")

        if default_action == "Deny" or public_access == "Disabled" or vnet_rules:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"default_action={default_action}, public_network_access={public_access}, vnet_rules={len(vnet_rules)}",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "Network ACLs restrict access or public access disabled",
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "expected_value": "VNet service endpoint rules configured or private endpoint used",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        props = vault.properties
        acls = getattr(props, "network_acls", None)
        vnet_rules = getattr(acls, "virtual_network_rules", None) or []
        pec = getattr(props, "private_endpoint_connections", None) or []

        if vnet_rules or pec:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"vnet_rules=0, private_endpoint_connections=0",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "VNet integration or private endpoint configured",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "expected_value": "At least one approved private endpoint connection exists",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        props = vault.properties
        pec = getattr(props, "private_endpoint_connections", None) or []
        approved = [c for c in pec if getattr(getattr(c, "private_link_service_connection_state", None), "status", "") == "Approved"]

        if approved:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"private_endpoint_connections={len(pec)}, approved=0",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "Approved private endpoint connection present",
    }


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "expected_value": "public_network_access=Disabled or network_acls.default_action=Deny",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        props = vault.properties
        public_access = getattr(props, "public_network_access", "Enabled")
        acls = getattr(props, "network_acls", None)
        default_action = getattr(acls, "default_action", "Allow") if acls else "Allow"

        if public_access == "Disabled" or default_action == "Deny":
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"public_network_access={public_access}, default_action={default_action}",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "Public network access disabled or network ACLs deny by default",
    }
