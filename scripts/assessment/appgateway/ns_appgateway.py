"""
Network Security checks for Azure Application Gateway (MCSB v3).

NS-1 WAF: web_application_firewall_configuration.enabled+Prevention OR firewall_policy linked → PASS.
NS-1 NSG: NSG lives on subnet, not on gateway resource → UNKNOWN (not ARM-checkable per-gateway).
NS-2 Private Link: private_link_configurations non-empty → PASS.
NS-2 Disable Public Access: no public_ip_address in frontend_ip_configurations → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        return [client.application_gateways.get(resource_group, gateway_name)]
    elif resource_group:
        return list(client.application_gateways.list(resource_group))
    else:
        return list(client.application_gateways.list_all())


def check_ns1_waf(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Network Security Group Support — Web Application Firewall",
        "expected_value": "WAF enabled in Prevention mode OR firewall_policy linked (WAF v2)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            # WAF v2: check linked firewall_policy (preferred)
            fw_policy = getattr(gw, "firewall_policy", None)
            if fw_policy and getattr(fw_policy, "id", None):
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"firewall_policy linked: {fw_policy.id.split('/')[-1]} — WAF v2 policy active"}
                first_pass = first_pass or r
                continue
            # WAF v1 inline config
            waf_cfg = getattr(gw, "web_application_firewall_configuration", None)
            if waf_cfg:
                enabled = getattr(waf_cfg, "enabled", False)
                mode = getattr(waf_cfg, "firewall_mode", "Detection")
                if enabled and str(mode) == "Prevention":
                    r = {**base, "resource": gw.name, "status": "PASS",
                         "actual_value": f"waf_configuration.enabled=True, firewall_mode=Prevention"}
                    first_pass = first_pass or r
                elif enabled and str(mode) == "Detection":
                    return {**base, "resource": gw.name, "status": "FAIL",
                            "actual_value": "waf_configuration.enabled=True but firewall_mode=Detection — Detection mode does not block attacks"}
                else:
                    return {**base, "resource": gw.name, "status": "FAIL",
                            "actual_value": "waf_configuration.enabled=False — WAF disabled"}
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": "No WAF configuration or firewall_policy — gateway has no WAF protection"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": "NSG is attached to the subnet containing the Application Gateway, not to the gateway resource itself. Per-gateway NSG status is not readable via the Application Gateway ARM resource. Check the subnet NSG via NetworkManagementClient.network_interfaces or the subnet resource.",
        "expected_value": "NSG applied to Application Gateway subnet with appropriate inbound rules",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/configuration-infrastructure#network-security-groups",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "expected_value": "private_link_configurations non-empty (Private Link configured on frontend)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/private-link",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            pl_configs = getattr(gw, "private_link_configurations", None) or []
            if pl_configs:
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"{len(pl_configs)} private link configuration(s) — Private Link active on frontend"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": "private_link_configurations=[] — no Private Link configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "expected_value": "No public_ip_address in frontend_ip_configurations (private-only deployment)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/private-link",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            frontend_ips = getattr(gw, "frontend_ip_configurations", None) or []
            public_frontends = [
                f for f in frontend_ips
                if getattr(f, "public_ip_address", None) is not None
            ]
            if not public_frontends:
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"{len(frontend_ips)} frontend(s), none with public IP — private-only deployment"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"{len(public_frontends)} public frontend IP(s) configured — gateway publicly accessible"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
