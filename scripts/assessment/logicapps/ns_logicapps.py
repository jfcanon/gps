"""
Network Security checks for Azure Logic Apps (MCSB v3).

NS-1 NSG: Consumption Logic Apps are multi-tenant PaaS — no NSG on customer subnet.
           ISE (Integration Service Environment) injects into customer VNet with NSG → UNKNOWN.
NS-1 VNet: workflow.properties.integration_service_environment.id set → ISE/VNet-injected → PASS.
NS-2 PE: Standard Logic Apps support PE (App Service based) — Consumption does not.
          Check ISE VNet injection for Consumption, or access_control restrictions.
NS-2 disable public: workflow.properties.access_control.triggers.allowed_caller_ip_addresses → restricted.

Read-only. Zero ARM writes.
"""
from azure.mgmt.logic import LogicManagementClient


def _get_workflows(client: LogicManagementClient, resource_group: str | None, workflow_name: str | None) -> list:
    if resource_group and workflow_name:
        return [client.workflows.get(resource_group, workflow_name)]
    elif resource_group:
        return list(client.workflows.list_by_resource_group(resource_group))
    else:
        return list(client.workflows.list_by_subscription())


def check_ns1_nsg(credential, subscription_id, resource_group, workflow_name):
    return {
        "resource": workflow_name or "all", "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG",
        "status": "UNKNOWN",
        "actual_value": "Consumption Logic Apps are multi-tenant PaaS — no customer subnet/NSG. ISE deploys into customer VNet with NSG on the ISE subnet (subnet-level, not workflow ARM).",
        "expected_value": "For ISE: NSG on ISE subnet. For Standard: NSG on App Service Environment subnet",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns1_vnet_integration(credential, subscription_id, resource_group, workflow_name):
    base = {
        "control_id": "NS-1", "feature": "Establish Network Segmentation Boundaries — VNet Integration (ISE)",
        "expected_value": "workflow.properties.integration_service_environment.id set (ISE / VNet-injected)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/connect-virtual-network-vnet-isolated-environment",
    }
    try:
        client = LogicManagementClient(credential, subscription_id)
        workflows = _get_workflows(client, resource_group, workflow_name)
        if not workflows:
            return {**base, "resource": workflow_name or "none", "status": "PASS", "actual_value": "No workflows found"}
        first_pass = None
        for wf in workflows:
            ise = getattr(wf, "integration_service_environment", None)
            ise_id = getattr(ise, "id", None) if ise else None
            if ise_id:
                r = {**base, "resource": wf.name, "status": "PASS",
                     "actual_value": f"ISE/VNet-injected; integration_service_environment.id={str(ise_id)[:60]}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wf.name, "status": "UNKNOWN",
                        "actual_value": "integration_service_environment.id not set — Consumption multi-tenant (no VNet injection) or Standard plan (App Service based)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workflow_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id, resource_group, workflow_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "ISE or Standard Logic Apps with private endpoint / VNet-injected",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/secure-single-tenant-workflow-virtual-network-private-endpoint",
    }
    try:
        client = LogicManagementClient(credential, subscription_id)
        workflows = _get_workflows(client, resource_group, workflow_name)
        if not workflows:
            return {**base, "resource": workflow_name or "none", "status": "PASS", "actual_value": "No workflows found"}
        first_pass = None
        for wf in workflows:
            ise = getattr(wf, "integration_service_environment", None)
            ise_id = getattr(ise, "id", None) if ise else None
            if ise_id:
                r = {**base, "resource": wf.name, "status": "PASS",
                     "actual_value": f"VNet-injected via ISE — private endpoint equivalent"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wf.name, "status": "UNKNOWN",
                        "actual_value": "Consumption Logic App — no private endpoint support. Standard Logic Apps (App Service) support PE but are managed via WebSiteManagementClient"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workflow_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id, resource_group, workflow_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "workflow.properties.access_control.triggers.allowed_caller_ip_addresses restricted",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app",
    }
    try:
        client = LogicManagementClient(credential, subscription_id)
        workflows = _get_workflows(client, resource_group, workflow_name)
        if not workflows:
            return {**base, "resource": workflow_name or "none", "status": "PASS", "actual_value": "No workflows found"}
        first_pass = None
        for wf in workflows:
            ac = getattr(wf, "access_control", None)
            triggers = getattr(ac, "triggers", None) if ac else None
            allowed_ips = getattr(triggers, "allowed_caller_ip_addresses", None) if triggers else None
            if allowed_ips:
                ip_list = [str(getattr(r, "address_range", r)) for r in allowed_ips]
                r = {**base, "resource": wf.name, "status": "PASS",
                     "actual_value": f"Trigger IP restriction: {ip_list[:3]}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wf.name, "status": "FAIL",
                        "actual_value": "access_control.triggers.allowed_caller_ip_addresses not set — trigger accessible from any IP"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workflow_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
