"""
Network Security checks for Azure Functions (MCSB v3).

Functions are Microsoft.Web/sites with kind=functionapp.
NS-1 NSG: NSG on VNet integration subnet — not per-site ARM → UNKNOWN.
NS-1 VNet: virtual_network_subnet_id set → VNet-integrated → PASS.
NS-2 PE: private_endpoint_connections non-empty → PASS.
NS-2 disable public: public_network_access == 'Disabled' → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.web import WebSiteManagementClient


def _get_function_apps(client: WebSiteManagementClient, resource_group: str | None, site_name: str | None) -> list:
    if resource_group and site_name:
        site = client.web_apps.get(resource_group, site_name)
        return [site] if "functionapp" in (getattr(site, "kind", "") or "").lower() else []
    elif resource_group:
        return [s for s in client.web_apps.list_by_resource_group(resource_group)
                if "functionapp" in (getattr(s, "kind", "") or "").lower()]
    else:
        return [s for s in client.web_apps.list()
                if "functionapp" in (getattr(s, "kind", "") or "").lower()]


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on VNet Integration Subnet",
        "status": "UNKNOWN",
        "actual_value": "NSG is on the VNet integration subnet (virtual_network_subnet_id), not the Function App resource. Verify via NetworkManagementClient.",
        "expected_value": "NSG attached to the VNet integration subnet",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns1_vnet_integration(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — VNet Integration",
        "expected_value": "site.virtual_network_subnet_id set (VNet-integrated Function App)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/functions-networking-options#virtual-network-integration",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        apps = _get_function_apps(client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        first_pass = None
        for app in apps:
            vnet_subnet = getattr(app, "virtual_network_subnet_id", None)
            if vnet_subnet:
                r = {**base, "resource": app.name, "status": "PASS",
                     "actual_value": f"virtual_network_subnet_id={vnet_subnet}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": app.name, "status": "FAIL",
                        "actual_value": "virtual_network_subnet_id=None — Function App not VNet-integrated"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "site.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/functions-create-vnet",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        apps = _get_function_apps(client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        first_pass = None
        for app in apps:
            pe_conns = getattr(app, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": app.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s) configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": app.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "site.public_network_access == 'Disabled'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/functions-networking-options",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        apps = _get_function_apps(client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        first_pass = None
        for app in apps:
            pna = str(getattr(app, "public_network_access", "") or "Enabled")
            if pna.lower() == "disabled":
                r = {**base, "resource": app.name, "status": "PASS",
                     "actual_value": f"public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": app.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pna} — public inbound access enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
