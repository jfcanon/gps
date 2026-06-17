"""
Logging and Threat Detection checks for Azure Cache for Redis.

LT-1: Microsoft Defender for Service / Product Offering (UNKNOWN — no Defender product for Redis)
LT-4: Azure Resource Logs (diagnostic settings check via MonitorManagementClient)
"""
from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _rg_from_id(resource_id: str) -> str:
    return resource_id.split("/resourceGroups/")[1].split("/")[0]


def _get_caches(client: RedisManagementClient, resource_group: str | None, redis_name: str | None):
    if resource_group and redis_name:
        return [client.redis.get(resource_group, redis_name)]
    elif resource_group:
        return list(client.redis.list_by_resource_group(resource_group))
    else:
        return list(client.redis.list_by_subscription())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service / Product Offering",
        "status": "UNKNOWN",
        "actual_value": (
            "No Microsoft Defender product for Azure Cache for Redis; "
            "Defender for Open-Source Relational Databases covers PostgreSQL/MySQL/MariaDB only"
        ),
        "expected_value": "Defender product available and enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-cloud",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "expected_value": "At least one diagnostic setting configured",
        "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-monitor-diagnostic-settings",
    }
    try:
        redis_client = RedisManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)
        caches = _get_caches(redis_client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            rg = resource_group or _rg_from_id(cache.id)
            resource_uri = (
                f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
                f"/providers/Microsoft.Cache/redis/{cache.name}"
            )
            try:
                settings = list(monitor_client.diagnostic_settings.list(resource_uri))
            except Exception as e:
                return {**base, "resource": cache.name, "status": "UNKNOWN", "actual_value": str(e)}

            if settings:
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s) configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "No diagnostic settings configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
