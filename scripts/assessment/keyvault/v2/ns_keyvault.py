"""
Network Security checks for Azure Key Vault (MCSB v3).

NS-1: NSG proxy (VNet rules / network ACL default-deny) and VNet integration.
NS-2: Private Link (approved private endpoints) and disable public network access.

Read-only. Zero ARM writes.
"""
from azure.mgmt.keyvault import KeyVaultManagementClient


def _get_vaults(client: KeyVaultManagementClient, resource_group: str | None, vault_name: str | None) -> list:
    if resource_group and vault_name:
        return [client.vaults.get(resource_group, vault_name)]
    elif resource_group:
        return list(client.vaults.list_by_resource_group(resource_group))
    else:
        return list(client.vaults.list())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "expected_value": "network_acls.default_action=Deny OR public_network_access=Disabled OR VNet rules configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            props = vault.properties
            acls = getattr(props, "network_acls", None)
            default_action = getattr(acls, "default_action", "Allow") if acls else "Allow"
            vnet_rules = getattr(acls, "virtual_network_rules", None) or []
            pub_access = getattr(props, "public_network_access", "Enabled")
            if default_action == "Deny" or pub_access == "Disabled" or vnet_rules:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"default_action={default_action}, public_network_access={pub_access}, vnet_rules={len(vnet_rules)}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": f"default_action=Allow, public_network_access=Enabled, vnet_rules=0 — no network restriction"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "expected_value": "VNet service endpoint rules or private endpoints configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            props = vault.properties
            acls = getattr(props, "network_acls", None)
            vnet_rules = getattr(acls, "virtual_network_rules", None) or []
            pec = getattr(props, "private_endpoint_connections", None) or []
            if vnet_rules or pec:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"vnet_rules={len(vnet_rules)}, private_endpoint_connections={len(pec)}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": "No VNet service endpoint rules and no private endpoint connections configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "expected_value": "At least one approved private endpoint connection",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            pec = getattr(vault.properties, "private_endpoint_connections", None) or []
            if not pec:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": "No private endpoint connections configured"}
            approved = [
                c for c in pec
                if getattr(
                    getattr(getattr(c, "properties", None), "private_link_service_connection_state", None),
                    "status", ""
                ) == "Approved"
            ]
            if approved:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"{len(pec)} private endpoint(s), {len(approved)} Approved"}
                first_pass = first_pass or r
            else:
                states = [
                    getattr(
                        getattr(getattr(c, "properties", None), "private_link_service_connection_state", None),
                        "status", "unknown"
                    ) for c in pec
                ]
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": f"Private endpoint(s) exist but none Approved — states: {', '.join(states)}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "expected_value": "public_network_access=Disabled OR network_acls.default_action=Deny",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            props = vault.properties
            pub_access = getattr(props, "public_network_access", "Enabled")
            acls = getattr(props, "network_acls", None)
            default_action = getattr(acls, "default_action", "Allow") if acls else "Allow"
            if pub_access == "Disabled" or default_action == "Deny":
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"public_network_access={pub_access}, network_acls.default_action={default_action}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pub_access}, network_acls.default_action={default_action}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
