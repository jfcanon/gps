"""
Network Security checks for Azure Cache for Redis.

NS-1: VNet integration / NSG (Premium tier only — subnet_id check)
NS-2: Private Link (private endpoint connections check)
NS-2: Disable Public Network Access (microsoft_managed verification)
"""
from azure.mgmt.redis import RedisManagementClient
from azure.core.exceptions import HttpResponseError


def _rg_from_id(resource_id: str) -> str:
    return resource_id.split("/resourceGroups/")[1].split("/")[0]


def _get_caches(client: RedisManagementClient, resource_group: str | None, redis_name: str | None):
    if resource_group and redis_name:
        return [client.redis.get(resource_group, redis_name)]
    elif resource_group:
        return list(client.redis.list_by_resource_group(resource_group))
    else:
        return list(client.redis.list_by_subscription())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {"control_id": "NS-1", "feature": "Network Security Group Support",
            "expected_value": "VNet-injected cache (subnet_id set)",
            "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-how-to-premium-vnet"}
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            sku = cache.properties.sku.name if cache.properties and cache.properties.sku else None
            subnet_id = getattr(cache.properties, "subnet_id", None) if cache.properties else None
            if sku != "Premium":
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": f"Non-Premium SKU ({sku}) — VNet injection not available"}
            if subnet_id:
                r = {**base, "resource": cache.name, "status": "PASS", "actual_value": f"VNet-injected, subnet_id set: {subnet_id}"}
            else:
                return {**base, "resource": cache.name, "status": "FAIL", "actual_value": "Premium tier but no subnet_id — not VNet-injected, NSG cannot apply"}
            first_pass = first_pass or r
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {"control_id": "NS-1", "feature": "Virtual Network Integration",
            "expected_value": "Premium tier with subnet_id configured",
            "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-how-to-premium-vnet"}
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            sku = cache.properties.sku.name if cache.properties and cache.properties.sku else None
            subnet_id = getattr(cache.properties, "subnet_id", None) if cache.properties else None
            if sku != "Premium":
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": f"Non-Premium SKU ({sku}) — VNet integration requires Premium tier"}
            if subnet_id:
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"Premium tier with VNet integration, subnet_id: {subnet_id}"}
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "Premium tier but subnet_id not set — VNet integration not configured"}
            first_pass = first_pass or r
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {"control_id": "NS-2", "feature": "Azure Private Link",
            "expected_value": "At least one approved private endpoint connection",
            "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-private-link"}
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            rg = resource_group or _rg_from_id(cache.id)
            try:
                connections = list(client.private_endpoint_connections.list(rg, cache.name))
            except Exception as e:
                return {**base, "resource": cache.name, "status": "UNKNOWN", "actual_value": str(e)}

            if not connections:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": "No private endpoint connections configured"}

            states = [c.properties.private_link_service_connection_state.status for c in connections if c.properties]
            if "Approved" in states:
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": f"{len(connections)} private endpoint(s), at least one Approved"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": f"Private endpoint(s) exist but none Approved — states: {', '.join(states)}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {"control_id": "NS-2", "feature": "Disable Public Network Access",
            "expected_value": "publicNetworkAccess: Disabled",
            "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-private-link"}
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            pna = getattr(cache.properties, "public_network_access", None) if cache.properties else None
            if pna == "Disabled":
                r = {**base, "resource": cache.name, "status": "PASS", "actual_value": "publicNetworkAccess: Disabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": f"publicNetworkAccess: {pna or 'Enabled'}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
