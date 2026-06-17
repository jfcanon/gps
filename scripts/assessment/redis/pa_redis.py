"""
Privileged Access checks for Azure Cache for Redis.

PA-1: Local Admin Accounts (disable_access_key_authentication — access keys = local admin equivalent)
PA-7: Azure RBAC for Data Plane (Entra auth + access policy assignments — GA Nov 2024)
PA-8: Customer Lockbox (UNKNOWN — not in supported services list as of 2025)
"""
from azure.mgmt.redis import RedisManagementClient


def _rg_from_id(resource_id: str) -> str:
    return resource_id.split("/resourceGroups/")[1].split("/")[0]


def _get_caches(client: RedisManagementClient, resource_group: str | None, redis_name: str | None):
    if resource_group and redis_name:
        return [client.redis.get(resource_group, redis_name)]
    elif resource_group:
        return list(client.redis.list_by_resource_group(resource_group))
    else:
        return list(client.redis.list_by_subscription())


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "PA-1",
        "feature": "Local Admin Accounts",
        "expected_value": "disableAccessKeyAuthentication: True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            daka = getattr(cache.properties, "disable_access_key_authentication", None)
            actual = f"disableAccessKeyAuthentication: {daka}"
            if daka is True:
                r = {**base, "resource": cache.name, "status": "PASS", "actual_value": actual}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL", "actual_value": actual}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "PA-7",
        "feature": "Azure RBAC for Data Plane",
        "expected_value": "Entra auth enabled with at least one RBAC access policy assignment",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-configure-role-based-access-control",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "UNKNOWN", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            rg = resource_group or _rg_from_id(cache.id)

            try:
                daka = getattr(cache.properties, "disable_access_key_authentication", None)
            except AttributeError:
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": "disableAccessKeyAuthentication property not available in this SDK version"}

            if not daka:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": f"Entra auth not enabled (disableAccessKeyAuthentication: {daka})"}

            try:
                assignments = list(client.access_policy_assignment.list(rg, cache.name))
            except AttributeError:
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": "access_policy_assignment not available in this SDK version"}
            except Exception as e:
                return {**base, "resource": cache.name, "status": "UNKNOWN", "actual_value": str(e)}

            if assignments:
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"Entra auth enabled; {len(assignments)} access policy assignment(s)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "Entra auth enabled but no access policy assignments found"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": "PA-8",
        "feature": "Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox not supported for Azure Cache for Redis (not in supported services list)",
        "expected_value": "Customer Lockbox available and enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }
