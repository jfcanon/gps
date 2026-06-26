"""
Network Security checks for Azure CDN / Azure Front Door Standard|Premium (MCSB v3).

NS-2 PE: AFD origin private link OR CDN endpoint private link → PASS.
NS-2 disable public: AFD endpoint enabled_state + WAF association or CDN restriction.

CdnManagementClient handles both classic CDN (profiles + endpoints)
and AFD Standard/Premium (profiles + afdEndpoints).

Read-only. Zero ARM writes.
"""
from azure.mgmt.cdn import CdnManagementClient


def _get_profiles(client: CdnManagementClient, resource_group: str | None, profile_name: str | None) -> list:
    if resource_group and profile_name:
        return [client.profiles.get(resource_group, profile_name)]
    elif resource_group:
        return list(client.profiles.list_by_resource_group(resource_group))
    else:
        return list(client.profiles.list())


def _rg_of(profile, fallback: str | None) -> str | None:
    if fallback:
        return fallback
    pid = getattr(profile, "id", "") or ""
    parts = pid.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, profile_name: str | None) -> dict:
    return {
        "resource": profile_name or "all",
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG",
        "status": "UNKNOWN",
        "actual_value": "Azure CDN / Azure Front Door is a global PaaS edge service — no customer VNet, no NSG concept. Network restriction via WAF policy or IP allow/deny rules at endpoint/routing rule level.",
        "expected_value": "N/A — use WAF policy (NS-6) and NS-2 controls for network restriction",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cdn/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, profile_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Private Link (AFD Premium origins)",
        "expected_value": "At least one AFD origin uses sharedPrivateLinkResource (Private Link to origin)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/private-link",
    }
    try:
        client = CdnManagementClient(credential, subscription_id)
        profiles = _get_profiles(client, resource_group, profile_name)
        if not profiles:
            return {**base, "resource": profile_name or "none", "status": "PASS",
                    "actual_value": "No CDN/AFD profiles found in scope"}
        first_pass = None
        for profile in profiles:
            sku = str(getattr(getattr(profile, "sku", None), "name", "") or "")
            rg = _rg_of(profile, resource_group)
            if "premium" not in sku.lower() and "standard_afd" not in sku.lower():
                r = {**base, "resource": profile.name, "status": "UNKNOWN",
                     "actual_value": f"sku={sku} — Private Link for origins requires AFD Premium tier. Classic CDN does not support origin private link."}
                first_pass = first_pass or r
                continue
            if not rg:
                return {**base, "resource": profile.name, "status": "UNKNOWN",
                        "actual_value": "Could not determine resource group — pass --resource-group"}
            pl_origins = []
            try:
                for og in client.afd_origin_groups.list_by_profile(rg, profile.name):
                    for origin in client.afd_origins.list_by_origin_group(rg, profile.name, og.name):
                        spl = getattr(origin, "shared_private_link_resource", None)
                        if spl:
                            pl_origins.append(origin.name)
            except Exception:
                pass
            if pl_origins:
                r = {**base, "resource": profile.name, "status": "PASS",
                     "actual_value": f"sku={sku}; {len(pl_origins)} origin(s) using Private Link: {pl_origins[:3]}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": profile.name, "status": "FAIL",
                        "actual_value": f"sku={sku}; no origins with sharedPrivateLinkResource configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": profile_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, profile_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access to Origin",
        "expected_value": "AFD endpoints enabled; origins use Private Link OR classic CDN has IP filtering",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/how-to-configure-private-link-blob-storage-portal",
    }
    try:
        client = CdnManagementClient(credential, subscription_id)
        profiles = _get_profiles(client, resource_group, profile_name)
        if not profiles:
            return {**base, "resource": profile_name or "none", "status": "PASS",
                    "actual_value": "No CDN/AFD profiles found in scope"}
        first_pass = None
        for profile in profiles:
            sku = str(getattr(getattr(profile, "sku", None), "name", "") or "")
            rg = _rg_of(profile, resource_group)
            if not rg:
                return {**base, "resource": profile.name, "status": "UNKNOWN",
                        "actual_value": "Could not determine resource group"}
            try:
                if "afd" in sku.lower() or "premium" in sku.lower():
                    endpoints = list(client.afd_endpoints.list_by_profile(rg, profile.name))
                    disabled_count = sum(1 for e in endpoints
                                        if str(getattr(e, "enabled_state", "") or "").lower() == "disabled")
                    if endpoints and disabled_count == 0:
                        r = {**base, "resource": profile.name, "status": "UNKNOWN",
                             "actual_value": f"sku={sku}; {len(endpoints)} AFD endpoint(s) all enabled. Use WAF policy or Private Link to restrict origin access — endpoint-level public disable not available."}
                        first_pass = first_pass or r
                    else:
                        r = {**base, "resource": profile.name, "status": "UNKNOWN",
                             "actual_value": f"sku={sku}; {disabled_count}/{len(endpoints)} endpoint(s) disabled. Public access restriction for CDN/AFD is managed at WAF and origin level."}
                        first_pass = first_pass or r
                else:
                    r = {**base, "resource": profile.name, "status": "UNKNOWN",
                         "actual_value": f"sku={sku} — Classic CDN. Public network access cannot be fully disabled on classic CDN; use IP filtering or migrate to AFD Standard/Premium."}
                    first_pass = first_pass or r
            except Exception as ex:
                return {**base, "resource": profile.name, "status": "UNKNOWN", "actual_value": str(ex)}
        return first_pass
    except Exception as e:
        return {**base, "resource": profile_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
