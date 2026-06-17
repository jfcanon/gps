"""
Backup and Recovery checks for Azure Cache for Redis.

BR-1: Azure Backup (UNKNOWN — not supported for Redis; use native persistence instead)
BR-1: Service Native Backup Capability (RDB/AOF persistence — Premium tier only)
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


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Backup does not support Azure Cache for Redis; "
            "use native Redis persistence (RDB/AOF) via Premium tier instead"
        ),
        "expected_value": "Azure Backup configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-premium-persistence",
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "expected_value": "RDB or AOF persistence enabled (Premium tier)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-premium-persistence",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            sku = cache.properties.sku.name if cache.properties and cache.properties.sku else None
            if sku != "Premium":
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": f"Persistence requires Premium SKU; current SKU: {sku}"}

            cfg = cache.properties.redis_configuration if cache.properties else None
            rdb = getattr(cfg, "rdb_backup_enabled", None) if cfg else None
            aof = getattr(cfg, "aof_backup_enabled", None) if cfg else None

            if str(rdb).lower() == "true" or str(aof).lower() == "true":
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"rdbBackupEnabled: {rdb}, aofBackupEnabled: {aof}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": f"rdbBackupEnabled: {rdb or 'false'}, aofBackupEnabled: {aof or 'false'} — no persistence configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
