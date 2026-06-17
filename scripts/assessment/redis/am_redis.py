"""
Asset Management checks for Azure Cache for Redis.

AM-2: Azure Policy Support (proxy: resource tags presence)
AM-5: Microsoft Defender for Cloud - Adaptive Application Controls (UNKNOWN — PaaS, no VM compute)
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


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Azure Policy Support",
        "expected_value": "Resource tagged and Azure Policy compliance active",
        "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/policy-reference",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            tags = cache.tags or {}
            if tags:
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"Resource has {len(tags)} tag(s)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "No tags configured — governance/policy enforcement may be absent"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": "AM-5",
        "feature": "Microsoft Defender for Cloud - Adaptive Application Controls",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Adaptive Application Controls targets VM compute; not applicable to Azure Cache for Redis",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }
