"""
Identity Management checks for Azure Cache for Redis.

IM-1: Local Authentication Methods for Data Plane Access (disable_access_key_authentication)
IM-1: Azure AD Authentication Required for Data Plane Access (disable_access_key_authentication)
IM-3: Managed Identities (access_policy_assignment list — GA Nov 2024)
IM-3: Service Principals (access_policy_assignment list — GA Nov 2024)
IM-7: Conditional Access for Data Plane (UNKNOWN — not checkable via Redis ARM)
IM-8: Service Credential and Secrets Support in Key Vault (disable_access_key_authentication proxy)
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


def _daka_check(cache) -> tuple[str, str]:
    """Returns (status, actual_value) based on disableAccessKeyAuthentication property."""
    try:
        daka = getattr(cache.properties, "disable_access_key_authentication", None)
        actual = f"disableAccessKeyAuthentication: {daka}"
        if daka is True:
            return "PASS", actual
        elif daka is False:
            return "FAIL", actual
        else:
            return "UNKNOWN", f"disableAccessKeyAuthentication: {daka} (property unavailable — SDK version may not support Entra auth)"
    except AttributeError:
        return "UNKNOWN", "disableAccessKeyAuthentication property not available in this SDK version"


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Local Authentication Methods for Data Plane Access",
        "expected_value": "disableAccessKeyAuthentication: True (access keys disabled, Entra required)",
        "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-configure#access-keys",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            status, actual = _daka_check(cache)
            if status == "PASS":
                first_pass = first_pass or {**base, "resource": cache.name, "status": "PASS", "actual_value": actual}
            else:
                return {**base, "resource": cache.name, "status": status, "actual_value": actual}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required for Data Plane Access",
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
            status, actual = _daka_check(cache)
            if status == "PASS":
                first_pass = first_pass or {**base, "resource": cache.name, "status": "PASS", "actual_value": actual}
            else:
                return {**base, "resource": cache.name, "status": status, "actual_value": actual}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Managed Identities",
        "expected_value": "At least one managed identity assigned to a Redis access policy",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "UNKNOWN", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            rg = resource_group or _rg_from_id(cache.id)
            daka = getattr(cache.properties, "disable_access_key_authentication", None)

            try:
                assignments = list(client.access_policy_assignment.list(rg, cache.name))
            except AttributeError:
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": "access_policy_assignment not available in this SDK version"}
            except Exception as e:
                return {**base, "resource": cache.name, "status": "UNKNOWN", "actual_value": str(e)}

            if not daka:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": f"Entra auth not enabled (disableAccessKeyAuthentication: {daka}); Managed Identity token auth requires Entra"}

            mi_assignments = [
                a for a in assignments
                if "managedidentity" in getattr(a, "object_id_type", "").lower()
            ]
            if mi_assignments:
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"{len(mi_assignments)} managed identity access policy assignment(s) found"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": f"Entra auth enabled but no managed identity assignments found ({len(assignments)} total assignment(s))"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Service Principals",
        "expected_value": "At least one service principal assigned to a Redis access policy",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "UNKNOWN", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            rg = resource_group or _rg_from_id(cache.id)
            daka = getattr(cache.properties, "disable_access_key_authentication", None)

            try:
                assignments = list(client.access_policy_assignment.list(rg, cache.name))
            except AttributeError:
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": "access_policy_assignment not available in this SDK version"}
            except Exception as e:
                return {**base, "resource": cache.name, "status": "UNKNOWN", "actual_value": str(e)}

            if not daka:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "Entra auth not enabled; Service Principal token auth requires Entra"}

            if assignments:
                sp_assignments = [
                    a for a in assignments
                    if "managedidentity" not in getattr(a, "object_id_type", "").lower()
                ]
                n = len(sp_assignments) if sp_assignments else len(assignments)
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"{n} service principal/user access policy assignment(s) found"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "Entra auth enabled but no access policy assignments found"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access for Data Plane",
        "status": "UNKNOWN",
        "actual_value": (
            "Conditional Access policy configuration not checkable via Redis ARM API; "
            "check Entra ID CA policies for Redis app audience (acca5fbb-b7e4-4009-81f1-37e38fd66d78)"
        ),
        "expected_value": "Entra Conditional Access policy scoped to Redis app audience",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "IM-8",
        "feature": "Service Credential and Secrets Support Integration and Storage in Azure Key Vault",
        "expected_value": "Access keys stored in Key Vault or Entra auth enabled (keys disabled)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-portal",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            daka = getattr(cache.properties, "disable_access_key_authentication", None)
            if daka is True:
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": "Access keys disabled; Entra auth enforced (KV not needed for secrets)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "Access keys active — recommend storing in Azure Key Vault and rotating; consider enabling Entra auth"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
