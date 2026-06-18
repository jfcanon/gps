"""
Network Security checks for Azure Firewall (MCSB v3).

NS-1 NSG: AzureFirewallSubnet prohibits NSGs — platform-managed NIC NSG not visible → UNKNOWN.
NS-1 VNet: ip_configurations[*].subnet.id contains 'AzureFirewallSubnet' → PASS (microsoft_managed default True).
NS-1 Threat Intel: threat_intel_mode 'Deny' → PASS; 'Alert'/'Off' → FAIL.
NS-1 IDPS: Premium SKU + idps_settings.mode 'Deny' → PASS; Standard → FAIL (feature not available).

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


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall is a managed service deployed in AzureFirewallSubnet. "
            "Subnet-level NSGs are disabled on AzureFirewallSubnet to prevent service interruption — "
            "the platform applies NIC-level NSGs that are not visible via ARM. "
            "NSG-based segmentation is enforced on spoke subnets routing through the firewall, not on the firewall subnet itself."
        ),
        "expected_value": "N/A — NSG not applicable to AzureFirewallSubnet; platform-managed protection in place",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/firewall-faq#are-there-any-firewall-resource-group-restrictions",
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "expected_value": "ip_configurations[*].subnet.id contains 'AzureFirewallSubnet' (VNet-deployed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/tutorial-firewall-deploy-portal",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            ip_configs = getattr(fw, "ip_configurations", None) or []
            subnet_ids = [
                getattr(cfg, "subnet", None) and getattr(getattr(cfg, "subnet", None), "id", "") or ""
                for cfg in ip_configs
            ]
            fw_subnet = next((s for s in subnet_ids if "AzureFirewallSubnet" in s), None)
            if fw_subnet:
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"Deployed in AzureFirewallSubnet: {fw_subnet.split('/')[-3]}/{fw_subnet.split('/')[-1]}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": f"ip_configurations subnet IDs do not contain 'AzureFirewallSubnet' — firewall not in expected subnet: {subnet_ids}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_threat_intel(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Threat Intelligence Mode",
        "expected_value": "threat_intel_mode='Deny' (blocks traffic to/from known malicious IPs/FQDNs)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/threat-intel",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            mode = getattr(fw, "threat_intel_mode", None) or "Off"
            if str(mode) == "Deny":
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"threat_intel_mode=Deny — known malicious traffic blocked"}
                first_pass = first_pass or r
            elif str(mode) == "Alert":
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "threat_intel_mode=Alert — threat intelligence only logs; malicious traffic not blocked"}
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": f"threat_intel_mode={mode} — threat intelligence disabled; no detection or blocking"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_idps(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Intrusion Detection and Prevention System (IDPS)",
        "expected_value": "sku.tier='Premium' and idps_settings.mode='Deny'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/premium-features#idps",
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
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": f"sku.tier={tier} — IDPS requires Premium SKU; not available on Standard/Basic"}
            idps = getattr(fw, "idps_settings", None)
            if idps is None:
                # Fallback: check additional_properties
                additional = getattr(fw, "additional_properties", None) or {}
                idps_mode = additional.get("Network.IDPS.Mode") or additional.get("Network.IDPS.SignatureOverrides")
            else:
                idps_mode = getattr(idps, "mode", None)
            if str(idps_mode) == "Deny":
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"Premium SKU; IDPS mode=Deny — intrusion traffic blocked"}
                first_pass = first_pass or r
            elif str(idps_mode) == "Alert":
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "Premium SKU but IDPS mode=Alert — IDPS only logs; intrusion traffic not blocked"}
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": f"Premium SKU but IDPS mode={idps_mode} — IDPS not in Deny mode"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
