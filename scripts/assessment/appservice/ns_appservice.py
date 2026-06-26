"""
Network Security checks for Azure App Service (MCSB v3).

NS-1 NSG: NSG lives on the VNet integration subnet, not the site resource → UNKNOWN.
NS-1 VNet integration: virtual_network_subnet_id present → PASS.
NS-2 PE: private_endpoint_connections non-empty → PASS.
NS-2 disable public: public_network_access == 'Disabled' → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.web import WebSiteManagementClient


def _get_sites(client: WebSiteManagementClient, resource_group: str | None, site_name: str | None) -> list:
    if resource_group and site_name:
        return [client.web_apps.get(resource_group, site_name)]
    elif resource_group:
        return list(client.web_apps.list_by_resource_group(resource_group))
    else:
        return list(client.web_apps.list())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on VNet Integration Subnet",
        "status": "UNKNOWN",
        "actual_value": "NSG is associated with the VNet integration subnet, not the App Service resource directly. Verify via NetworkManagementClient: check the subnet's network_security_group property for the subnet referenced in virtual_network_subnet_id.",
        "expected_value": "NSG attached to the VNet integration subnet",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns1_vnet_integration(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — VNet Integration",
        "expected_value": "site.virtual_network_subnet_id set (VNet-integrated App Service)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/overview-vnet-integration",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            vnet_subnet = getattr(site, "virtual_network_subnet_id", None)
            if vnet_subnet:
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"virtual_network_subnet_id={vnet_subnet}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": "virtual_network_subnet_id=None — site not VNet-integrated; outbound traffic routes via public internet"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "site.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/networking/private-endpoint",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            pe_conns = getattr(site, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s) configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint; inbound accessible via public endpoint"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "site.public_network_access == 'Disabled'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/networking-features#inbound-scenarios",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            pna = str(getattr(site, "public_network_access", "") or "Enabled")
            if pna.lower() == "disabled":
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pna} — public inbound access enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
