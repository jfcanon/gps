"""
Network Security checks for Azure WAF Policy (MCSB v3).

NS-1 NSG: LIVE-INDIRECT — cross-reference App Gateway subnet for NSG.
NS-1 VNet: PASS static (microsoft_managed — App GW always in customer VNet).
NS-2 Private Link: LIVE-INDIRECT — App Gateway private_link_configurations.
NS-2 Disable Public: LIVE-INDIRECT — App Gateway frontend_ip_configurations.

LIVE-INDIRECT checks require App Gateway cross-reference.
Scope: App Gateway WAF Policy only (ApplicationGatewayWebApplicationFirewallPolicy).
Classic inline WAF (web_application_firewall_configuration) has no policy.id link —
those App Gateways are not reachable from a WAF policy resource.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"


def _get_waf_policies(client, resource_group, policy_name):
    if resource_group and policy_name:
        return [client.web_application_firewall_policies.get(resource_group, policy_name)]
    elif resource_group:
        return list(client.web_application_firewall_policies.list(resource_group))
    else:
        return list(client.web_application_firewall_policies.list_all())


def _get_app_gateways_for_policy(client, policy_id):
    """Return App Gateways that reference this WAF policy ID (policy-based WAF only)."""
    result = []
    for ag in client.application_gateways.list_all():
        fp = getattr(ag, 'firewall_policy', None)
        if fp and getattr(fp, 'id', '').lower() == policy_id.lower():
            result.append(ag)
    return result


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "expected_value": "NSG attached to App Gateway subnet",
        "evidence_url": _EVIDENCE,
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found in scope"}

        first_pass = None
        for policy in policies:
            ags = _get_app_gateways_for_policy(client, policy.id)
            if not ags:
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": "Policy not attached to any Application Gateway (policy-based WAF only)"}
                first_pass = first_pass or r
                continue
            for ag in ags:
                gw_ip_cfgs = getattr(ag, 'gateway_ip_configurations', None) or []
                if not gw_ip_cfgs:
                    r = {**base, "resource": policy.name, "status": "UNKNOWN",
                         "actual_value": f"AG {ag.name}: no gateway_ip_configurations found"}
                    first_pass = first_pass or r
                    continue
                subnet_id = getattr(gw_ip_cfgs[0].subnet, 'id', None) if getattr(gw_ip_cfgs[0], 'subnet', None) else None
                if not subnet_id:
                    r = {**base, "resource": policy.name, "status": "UNKNOWN",
                         "actual_value": f"AG {ag.name}: subnet ID not found"}
                    first_pass = first_pass or r
                    continue
                parts = subnet_id.split('/')
                # /subscriptions/[1]/[2]/resourceGroups/[3]/[4]/providers/[5]/[6]/Microsoft.Network/[7]/virtualNetworks/[8]/[9]/subnets/[10]/[11]
                # Index:  0  1         2               3   4            5   6                    7   8                 9   10      11
                rg_sub = parts[4]
                vnet_name = parts[8]
                subnet_name = parts[10]
                try:
                    subnet = client.subnets.get(rg_sub, vnet_name, subnet_name)
                except Exception as se:
                    r = {**base, "resource": policy.name, "status": "UNKNOWN",
                         "actual_value": f"AG {ag.name}: subnet lookup failed: {se}"}
                    first_pass = first_pass or r
                    continue
                nsg = getattr(subnet, 'network_security_group', None)
                if nsg:
                    r = {**base, "resource": policy.name, "status": "PASS",
                         "actual_value": f"NSG attached to subnet {subnet_name} (AG: {ag.name})"}
                else:
                    return {**base, "resource": policy.name, "status": "FAIL",
                            "actual_value": f"No NSG on subnet {subnet_name} (AG: {ag.name}) — spoke subnet NSGs recommended"}
                first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No App Gateway associations found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": "PASS",
        "actual_value": "App Gateway (WAF host) always deployed in customer VNet GatewaySubnet (microsoft_managed)",
        "expected_value": "VNet integration inherent to App GW deployment",
        "evidence_url": _EVIDENCE,
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "expected_value": "App Gateway private_link_configurations non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/private-link",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found"}

        first_pass = None
        for policy in policies:
            ags = _get_app_gateways_for_policy(client, policy.id)
            if not ags:
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": "Policy not attached to any Application Gateway"}
                first_pass = first_pass or r
                continue
            for ag in ags:
                pl_cfgs = getattr(ag, 'private_link_configurations', None) or []
                if pl_cfgs:
                    r = {**base, "resource": policy.name, "status": "PASS",
                         "actual_value": f"Private Link configured on AG {ag.name} ({len(pl_cfgs)} config(s))"}
                else:
                    return {**base, "resource": policy.name, "status": "FAIL",
                            "actual_value": f"No private_link_configurations on AG {ag.name}"}
                first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No App Gateway associations found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "expected_value": "App Gateway frontend uses only private IP (no public IP assigned)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-private-deployment",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found"}

        first_pass = None
        for policy in policies:
            ags = _get_app_gateways_for_policy(client, policy.id)
            if not ags:
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": "Policy not attached to any Application Gateway"}
                first_pass = first_pass or r
                continue
            for ag in ags:
                fe_ips = getattr(ag, 'frontend_ip_configurations', None) or []
                has_public = any(getattr(f, 'public_ip_address', None) for f in fe_ips)
                has_private = any(getattr(f, 'private_ip_address', None) for f in fe_ips)
                if has_public:
                    return {**base, "resource": policy.name, "status": "FAIL",
                            "actual_value": f"AG {ag.name} has public IP in frontend_ip_configurations; consider private-only deployment"}
                if has_private:
                    r = {**base, "resource": policy.name, "status": "PASS",
                         "actual_value": f"AG {ag.name} uses private IP only; no public frontend IP"}
                else:
                    r = {**base, "resource": policy.name, "status": "UNKNOWN",
                         "actual_value": f"AG {ag.name}: no frontend IP configurations found"}
                first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No App Gateway associations found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}
