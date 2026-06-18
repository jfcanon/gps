"""
Network Security checks for Azure Public IP (MCSB v3).

NS-1 NSG: NSG attaches to NIC/subnet of associated resource, not to PIP ARM object → UNKNOWN static.
NS-1 SKU: sku.tier == 'Standard' → PASS (closed-by-default, zone-redundant); 'Basic' → FAIL (deprecated, open-by-default).
NS-1 VNet: ip_configuration present (not None) → IP attached to a resource → PASS; None → orphaned → FAIL.
NS-2 Private Link: PIP IS a public address; no private endpoint concept on PIP → UNKNOWN static.
NS-2 Disable Public: Service IS public exposure by definition; toggle does not apply → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_public_ips(client: NetworkManagementClient, resource_group: str | None, public_ip_name: str | None) -> list:
    if resource_group and public_ip_name:
        return [client.public_ip_addresses.get(resource_group, public_ip_name)]
    elif resource_group:
        return list(client.public_ip_addresses.list(resource_group))
    else:
        return list(client.public_ip_addresses.list_all())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {
        "resource": public_ip_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": (
            "NSG rules apply to the NIC or subnet of the resource associated with this Public IP "
            "(e.g. the VM NIC or Load Balancer subnet), not to the Public IP ARM resource itself. "
            "Per-PIP NSG status is not readable via the Public IP resource. "
            "Check the associated resource's NIC or subnet for NSG assignment."
        ),
        "expected_value": "N/A — NSG attaches to the associated resource, not the PIP resource directly",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
    }


def check_ns1_sku(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Standard SKU (Secure-by-Default Network Boundary)",
        "expected_value": "sku.tier='Standard' (closed-by-default, zone-redundant, DDoS Standard compatible)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses#sku",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        pips = _get_public_ips(client, resource_group, public_ip_name)
        if not pips:
            return {**base, "resource": public_ip_name or "none", "status": "PASS",
                    "actual_value": "No Public IP instances found in scope"}
        first_pass = None
        for pip in pips:
            sku = getattr(pip, "sku", None)
            tier = getattr(sku, "tier", "Basic") if sku else "Basic"
            name_val = getattr(sku, "name", "Basic") if sku else "Basic"
            if str(name_val) == "Standard" or str(tier) == "Standard":
                r = {**base, "resource": pip.name, "status": "PASS",
                     "actual_value": f"sku.name=Standard — closed-by-default model; inbound traffic blocked unless explicitly opened via NSG/load balancer rules; zone-redundant"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": pip.name, "status": "FAIL",
                        "actual_value": f"sku.name={name_val} — Basic SKU is deprecated (retirement Sep 2025); open-by-default model; no zone redundancy; no DDoS Standard support"}
        return first_pass
    except Exception as e:
        return {**base, "resource": public_ip_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Virtual Network Integration — IP Attachment Status",
        "expected_value": "ip_configuration present (IP attached to a VNet resource — not orphaned)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        pips = _get_public_ips(client, resource_group, public_ip_name)
        if not pips:
            return {**base, "resource": public_ip_name or "none", "status": "PASS",
                    "actual_value": "No Public IP instances found in scope"}
        first_pass = None
        for pip in pips:
            ip_config = getattr(pip, "ip_configuration", None)
            if ip_config:
                config_id = getattr(ip_config, "id", "unknown")
                resource_hint = config_id.split("/")[8] if "/" in config_id and len(config_id.split("/")) > 8 else config_id
                r = {**base, "resource": pip.name, "status": "PASS",
                     "actual_value": f"ip_configuration present — IP attached to: {resource_hint}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": pip.name, "status": "FAIL",
                        "actual_value": "ip_configuration=None — IP is orphaned (not attached to any resource); unattached public IPs represent unnecessary attack surface and should be deleted"}
        return first_pass
    except Exception as e:
        return {**base, "resource": public_ip_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {
        "resource": public_ip_name or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Public IP is a globally routable IP address resource — it IS public by definition. "
            "Private Link enables private connectivity to Azure services and does not apply to the Public IP "
            "resource itself. Public IP addresses are used on the public-facing side of Private Link configurations."
        ),
        "expected_value": "N/A — PIP is a public address; Private Link concept does not apply to this resource",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/private-link/private-link-overview",
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {
        "resource": public_ip_name or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Public IP IS the public network access resource — disabling public access would mean deleting the PIP. "
            "This control does not have a 'toggle off' concept for Public IP addresses. "
            "Governance of public exposure is managed by controlling which resources are assigned Public IPs, "
            "not by a property on the PIP resource itself."
        ),
        "expected_value": "N/A — service is public exposure by definition; remove orphaned PIPs instead",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses",
    }
