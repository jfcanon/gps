"""
Network Security checks for Azure Data Factory (MCSB v3).

NS-1 NSG: SSIS IR can join VNet — NSG on IR subnet, not factory ARM → UNKNOWN.
NS-1 VNet integration: SSIS IR VNet injection → check integration_runtime VNetProperties.
NS-2 PE: factory.properties.public_network_access == 'Disabled' + privateEndpointConnections.
NS-2 disable public: factory.properties.public_network_access == 'Disabled' → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.datafactory import DataFactoryManagementClient


def _get_factories(client: DataFactoryManagementClient, resource_group: str | None, factory_name: str | None) -> list:
    if resource_group and factory_name:
        return [client.factories.get(resource_group, factory_name)]
    elif resource_group:
        return list(client.factories.list_by_resource_group(resource_group))
    else:
        return list(client.factories.list())


def _rg_of(factory, fallback):
    if fallback:
        return fallback
    fid = getattr(factory, "id", "") or ""
    parts = fid.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def check_ns1_nsg(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on SSIS IR VNet Subnet",
        "status": "UNKNOWN",
        "actual_value": "NSG is on the SSIS Integration Runtime VNet integration subnet — not on the factory ARM resource. Verify via NetworkManagementClient on the IR subnet.",
        "expected_value": "NSG attached to SSIS IR VNet integration subnet",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/join-azure-ssis-integration-runtime-virtual-network",
    }


def check_ns1_vnet_integration(credential, subscription_id, resource_group, factory_name):
    base = {
        "control_id": "NS-1", "feature": "Establish Network Segmentation Boundaries — VNet Integration (SSIS IR)",
        "expected_value": "At least one SSIS IR with VNet integration configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/join-azure-ssis-integration-runtime-virtual-network",
    }
    try:
        client = DataFactoryManagementClient(credential, subscription_id)
        factories = _get_factories(client, resource_group, factory_name)
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        for factory in factories:
            rg = _rg_of(factory, resource_group)
            if not rg:
                return {**base, "resource": factory.name, "status": "UNKNOWN",
                        "actual_value": "Could not determine resource group"}
            try:
                irs = list(client.integration_runtimes.list_by_factory(rg, factory.name))
                vnet_irs = []
                for ir in irs:
                    props = getattr(ir, "properties", None)
                    compute = getattr(props, "compute_properties", None) if props else None
                    vnet = getattr(compute, "v_net_properties", None) if compute else None
                    if vnet and getattr(vnet, "v_net_id", None):
                        vnet_irs.append(ir.name)
                if vnet_irs:
                    return {**base, "resource": factory.name, "status": "PASS",
                            "actual_value": f"{len(vnet_irs)} SSIS IR(s) with VNet integration: {vnet_irs}"}
                elif irs:
                    return {**base, "resource": factory.name, "status": "UNKNOWN",
                            "actual_value": f"{len(irs)} integration runtime(s); none with VNet integration (may use Azure IR, not SSIS)"}
                else:
                    return {**base, "resource": factory.name, "status": "UNKNOWN",
                            "actual_value": "No integration runtimes found — default Azure IR is used (no VNet injection)"}
            except Exception as ex:
                return {**base, "resource": factory.name, "status": "UNKNOWN", "actual_value": str(ex)}
        return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id, resource_group, factory_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "factory.properties.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-factory-private-link",
    }
    try:
        client = DataFactoryManagementClient(credential, subscription_id)
        factories = _get_factories(client, resource_group, factory_name)
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        first_pass = None
        for factory in factories:
            rg = _rg_of(factory, resource_group)
            pe_conns = []
            if rg:
                try:
                    pe_conns = list(client.private_endpoint_connection.list_by_factory(rg, factory.name))
                except Exception:
                    pass
            if pe_conns:
                r = {**base, "resource": factory.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": factory.name, "status": "FAIL",
                        "actual_value": "No private endpoints configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id, resource_group, factory_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "factory.properties.public_network_access == 'Disabled'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-factory-private-link",
    }
    try:
        client = DataFactoryManagementClient(credential, subscription_id)
        factories = _get_factories(client, resource_group, factory_name)
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        first_pass = None
        for factory in factories:
            pna = str(getattr(factory, "public_network_access", "") or "Enabled")
            if pna.lower() == "disabled":
                r = {**base, "resource": factory.name, "status": "PASS",
                     "actual_value": f"public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": factory.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pna} — public access enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
