"""
Network Security checks for Azure Bastion (MCSB v3).

NS-1 NSG Support: LIVE-DIRECT (with AzureBastionSubnet cross-ref).
    Bastion requires specific NSG rules to function. Check: does NSG EXIST on
    AzureBastionSubnet? NSG existence = PASS. Missing NSG = FAIL.
    Do NOT validate individual rules — prescriptive and fragile across SKUs.
    Cross-ref: bastion.ip_configurations[0].subnet.id → subnets.get().

NS-1 VNet Integration: LIVE-DIRECT.
    Bastion must be in subnet named 'AzureBastionSubnet' AND prefix ≤ /26.
    Azure enforces the name constraint but not always the size.
    PASS: correct name + /26 or larger (/24, /25, /26 all pass).
    FAIL: wrong name or too small (/27, /28 etc).

NS-2 Azure Private Link: UNKNOWN static.
    feature_supported=False, final_verdict=not_applicable.
    Bastion has no Private Link for its management plane.

NS-2 Disable Public Network Access: UNKNOWN static.
    feature_supported=False, final_verdict=not_applicable.
    Bastion by design requires a public IP for browser-initiated HTTPS sessions.
    No "disable public" concept exists at Bastion service level.

Read-only. Zero ARM writes.
SDK: azure-mgmt-network (NetworkManagementClient).
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
_EVIDENCE_NSG = "https://learn.microsoft.com/en-us/azure/bastion/bastion-nsg"
_EVIDENCE_VNET = "https://learn.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal"


def _get_bastions(client, resource_group, bastion_name):
    if bastion_name and resource_group:
        return [client.bastion_hosts.get(resource_group, bastion_name)]
    elif resource_group:
        return list(client.bastion_hosts.list(resource_group))
    else:
        return list(client.bastion_hosts.list_all())


def _parse_subnet_id(subnet_id: str):
    """Return (subnet_rg, vnet_name, subnet_name) from ARM subnet resource ID."""
    parts = subnet_id.split('/')
    return parts[4], parts[8], parts[10]


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    client = NetworkManagementClient(credential, subscription_id)

    try:
        bastions = _get_bastions(client, resource_group, bastion_name)
    except Exception as e:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "NS-1",
            "feature": "Network Security Group Support",
            "status": "UNKNOWN",
            "actual_value": f"Error listing bastion hosts: {e}",
            "expected_value": "NSG associated with AzureBastionSubnet",
            "evidence_url": _EVIDENCE_NSG,
        }

    if not bastions:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "NS-1",
            "feature": "Network Security Group Support",
            "status": "UNKNOWN",
            "actual_value": "No Azure Bastion hosts found in scope",
            "expected_value": "NSG associated with AzureBastionSubnet",
            "evidence_url": _EVIDENCE_NSG,
        }

    results = []
    for bastion in bastions:
        ip_configs = getattr(bastion, 'ip_configurations', None) or []
        if not ip_configs:
            results.append(("UNKNOWN", bastion.name, "No ip_configurations on bastion host"))
            continue
        ip_config = ip_configs[0]
        if not ip_config.subnet or not ip_config.subnet.id:
            results.append(("UNKNOWN", bastion.name, "No subnet attached to bastion ip_configuration"))
            continue
        try:
            subnet_rg, vnet_name, subnet_name = _parse_subnet_id(ip_config.subnet.id)
            subnet = client.subnets.get(subnet_rg, vnet_name, subnet_name)
            nsg = getattr(subnet, 'network_security_group', None)
            if nsg:
                results.append(("PASS", bastion.name, f"NSG={nsg.id.split('/')[-1]}"))
            else:
                results.append(("FAIL", bastion.name, "No NSG on AzureBastionSubnet"))
        except IndexError:
            results.append(("UNKNOWN", bastion.name, f"Cannot parse subnet ID: {ip_config.subnet.id}"))
        except Exception as e:
            results.append(("UNKNOWN", bastion.name, str(e)))

    statuses = [r[0] for r in results]
    if "FAIL" in statuses:
        agg_status = "FAIL"
    elif all(s == "PASS" for s in statuses):
        agg_status = "PASS"
    else:
        agg_status = "UNKNOWN"

    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": agg_status,
        "actual_value": str(results),
        "expected_value": "NSG associated with AzureBastionSubnet",
        "evidence_url": _EVIDENCE_NSG,
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    client = NetworkManagementClient(credential, subscription_id)

    try:
        bastions = _get_bastions(client, resource_group, bastion_name)
    except Exception as e:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "NS-1",
            "feature": "Virtual Network Integration",
            "status": "UNKNOWN",
            "actual_value": f"Error listing bastion hosts: {e}",
            "expected_value": "subnet='AzureBastionSubnet' AND prefix_len <= 26",
            "evidence_url": _EVIDENCE_VNET,
        }

    if not bastions:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "NS-1",
            "feature": "Virtual Network Integration",
            "status": "UNKNOWN",
            "actual_value": "No Azure Bastion hosts found in scope",
            "expected_value": "subnet='AzureBastionSubnet' AND prefix_len <= 26",
            "evidence_url": _EVIDENCE_VNET,
        }

    results = []
    for bastion in bastions:
        ip_configs = getattr(bastion, 'ip_configurations', None) or []
        if not ip_configs:
            results.append(("UNKNOWN", bastion.name, "No ip_configurations on bastion host"))
            continue
        ip_config = ip_configs[0]
        if not ip_config.subnet or not ip_config.subnet.id:
            results.append(("UNKNOWN", bastion.name, "No subnet attached"))
            continue
        try:
            subnet_rg, vnet_name, subnet_name = _parse_subnet_id(ip_config.subnet.id)
            subnet = client.subnets.get(subnet_rg, vnet_name, subnet_name)
            address_prefix = getattr(subnet, 'address_prefix', None)
            if not address_prefix:
                results.append(("UNKNOWN", bastion.name, "subnet.address_prefix is None"))
                continue
            prefix_len = int(address_prefix.split('/')[1])
            name_ok = (subnet_name == 'AzureBastionSubnet')
            size_ok = (prefix_len <= 26)
            if name_ok and size_ok:
                results.append(("PASS", bastion.name, f"subnet={subnet_name} prefix={address_prefix}"))
            else:
                reason = []
                if not name_ok:
                    reason.append(f"wrong subnet name: '{subnet_name}' (expected 'AzureBastionSubnet')")
                if not size_ok:
                    reason.append(f"subnet too small: {address_prefix} (need /26 or larger)")
                results.append(("FAIL", bastion.name, "; ".join(reason)))
        except IndexError:
            results.append(("UNKNOWN", bastion.name, f"Cannot parse subnet ID: {ip_config.subnet.id}"))
        except Exception as e:
            results.append(("UNKNOWN", bastion.name, str(e)))

    statuses = [r[0] for r in results]
    if "FAIL" in statuses:
        agg_status = "FAIL"
    elif all(s == "PASS" for s in statuses):
        agg_status = "PASS"
    else:
        agg_status = "UNKNOWN"

    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": agg_status,
        "actual_value": str(results),
        "expected_value": "subnet='AzureBastionSubnet' AND prefix_len <= 26",
        "evidence_url": _EVIDENCE_VNET,
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": "feature_supported=False in MCSB v3 baseline. Azure Bastion has no Private Link integration for its management plane. Bastion management traffic (user browser → bastion.azure.com) is not Private Link-capable. not_applicable.",
        "expected_value": "N/A — feature_supported=False; Private Link not available for Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "UNKNOWN",
        "actual_value": "feature_supported=False in MCSB v3 baseline. Azure Bastion by design requires a public IP address to receive browser-initiated HTTPS sessions from users (port 443). There is no 'disable public network access' concept for Bastion. not_applicable.",
        "expected_value": "N/A — feature_supported=False; public IP required by Bastion architecture",
        "evidence_url": _EVIDENCE,
    }
