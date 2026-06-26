"""
Asset Management checks for Azure App Service (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.

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


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/security-baseline#am-2-use-only-approved-azure-services",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            tags = getattr(site, "tags", None) or {}
            if tags:
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
