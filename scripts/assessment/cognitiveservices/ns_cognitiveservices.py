"""
Network Security checks for Azure Cognitive Services (MCSB v3).

NS-2 PE: account.properties.private_endpoint_connections non-empty → PASS.
NS-2 disable public: account.properties.public_network_access == 'Disabled' → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient


def _get_accounts(client: CognitiveServicesManagementClient, resource_group: str | None, account_name: str | None) -> list:
    if resource_group and account_name:
        return [client.accounts.get(resource_group, account_name)]
    elif resource_group:
        return list(client.accounts.list_by_resource_group(resource_group))
    else:
        return list(client.accounts.list())


def check_ns1_nsg(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG",
        "status": "UNKNOWN",
        "actual_value": "Azure Cognitive Services accounts are PaaS — not deployed in customer VNet. Network restriction via private endpoints and network ACLs. No NSG ARM property.",
        "expected_value": "N/A — use private endpoints (NS-2) and network ACLs",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns2_private_link(credential, subscription_id, resource_group, account_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "account.properties.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/cognitive-services-virtual-networks",
    }
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = _get_accounts(client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            pe_conns = getattr(acct, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": acct.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id, resource_group, account_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "account.properties.public_network_access == 'Disabled'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/cognitive-services-virtual-networks",
    }
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = _get_accounts(client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            pna = str(getattr(acct, "public_network_access", "") or "Enabled")
            if pna.lower() == "disabled":
                r = {**base, "resource": acct.name, "status": "PASS", "actual_value": f"public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pna} — public access enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
