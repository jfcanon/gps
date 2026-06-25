"""Phase 55 Step 3 — Apply Exa research findings to .final.csv files.

For each row, applies:
- Verdict flips (still_na → now_applicable_native OR now_applicable_native → still_na)
- Evidence URLs
- Rationale notes
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

SEV_SCORE = {"High": 3, "Medium": 2, "Low": 1}
BR_SCORE  = {"Wide": 2, "Narrow": 1}


def compute_blast_radius(row: dict) -> str:
    api = row.get("azure_api_property", "").strip()
    no_api = not api or api.upper() in ("", "N/A", "NA")
    if (row["verdict_2025"] == "conditional"
            or no_api
            or row.get("feature_enabled_by_default_original", "") == "False"):
        return "Wide"
    return "Narrow"


def compute_risk_rank(row: dict) -> str:
    sev = SEV_SCORE.get(row.get("severity", "Medium"), 2)
    br  = BR_SCORE.get(row.get("blast_radius", "Narrow"), 1)
    return str(sev * br)


# Enrichment patches keyed by (slug, asb_control_id, feature_name_fragment)
# Feature name fragment: matched as substring (case-insensitive) in feature_name
# Actions:
#   flip_to: new verdict (or None to keep current)
#   notes: replacement note (if None, appends source)
#   append: if True, append to existing notes; if False, replace
PATCHES = [
    # === APPGATEWAY ===
    {
        "slug": "appgateway",
        "ctrl": "NS-1",
        "feat": "Network Security Group",
        "flip_to": "conditional",
        "append": False,
        "notes": (
            "NSG supported on App Gateway v2 subnet with required rules "
            "(allow AzureLoadBalancer inbound, allow outbound internet). "
            "Private App Gateway deployment (GA May 2025) has enhanced NSG controls "
            "with subnet delegation to Microsoft.Network/applicationGateways. "
            "Conditional: specific inbound/outbound rules required; NSG flow logs "
            "not supported on v2 subnet. "
            "Source: https://learn.microsoft.com/en-us/azure/application-gateway/configuration-infrastructure"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "DP-2",
        "feat": "anomal",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline (Feb 2025): False/Not Applicable. "
            "No native DLP solution for App Gateway traffic. "
            "Use Azure Monitor + Defender for Cloud policies for anomaly detection on subnet. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "DP-5",
        "feat": "Customer-Managed Key",
        "flip_to": None,
        "append": True,
        "notes": (
            "App Gateway not in Azure CMK support list as of May 2026. "
            "Managed keys encrypt configuration data at platform level. "
            "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-customer-managed-keys-support"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "DP-6",
        "feat": "Key Management",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: DP-6 Key Management in Key Vault = False/Not Applicable. "
            "App Gateway does not support CMK-based key management. "
            "DP-7 (certificate management) IS supported — separate feature. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "DP-7",
        "feat": "Certificate Management",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "App Gateway v2 supports TLS certificate management via Azure Key Vault. "
            "Certificates stored in Key Vault are auto-rotated every 4 hours. "
            "Requires user-assigned managed identity with Key Vault Secrets User role. "
            "MCSB v3 baseline: True/False/Customer. "
            "Source: https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "IM-1",
        "feat": "Local Authentication",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "App Gateway operates at network layer; no local auth methods concept at data plane. "
            "Management plane auth via Azure AD RBAC. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "IM-1",
        "feat": "Azure AD Authentication Required",
        "flip_to": "conditional",
        "append": False,
        "notes": (
            "JWT validation via Microsoft Entra ID now available in PUBLIC PREVIEW (Jan 2026). "
            "App Gateway validates JWTs on HTTPS listeners, blocks invalid tokens (401), "
            "injects x-msft-entra-identity header to backend. "
            "Conditional: requires Standard_v2/WAF_v2 SKU, HTTPS listener, "
            "ARM API 2025-03-01+, preview status (not for production). "
            "Source: https://learn.microsoft.com/en-us/azure/application-gateway/json-web-token-overview"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "IM-3",
        "feat": "Managed Identit",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "App Gateway uses user-assigned managed identity to authenticate to Azure Key Vault "
            "for TLS certificate retrieval. Managed identity is optional at deploy time but "
            "required for Key Vault cert integration. MCSB note: 'managed identity can be used "
            "by Application Gateway to authenticate to Azure Key Vault'. "
            "Source: https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "IM-7",
        "feat": "Conditional Access",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "App Gateway itself does not enforce Conditional Access policies at the data plane. "
            "CA applies to management plane (Azure Portal/ARM) access only. "
            "JWT preview (IM-1) provides token validation but is not Conditional Access. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "IM-8",
        "feat": "Credential and Secret",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "App Gateway v2 stores TLS certificates in managed Azure Key Vault automatically "
            "when uploaded. Key Vault integration supported via both access policy and RBAC models. "
            "MCSB v3 baseline: True/False/Customer. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "LT-1",
        "feat": "Defender",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: LT-1 Defender for Service = False/Not Applicable. "
            "No dedicated Defender plan for App Gateway. "
            "WAF v1 integration with Defender for Cloud security alerts was retired Sep 2024. "
            "App Gateway logs can feed into Sentinel/Azure Monitor for threat detection. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "PA-1",
        "feat": "Local Admin",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "App Gateway has no local administrative account concept. "
            "All management access via Azure AD RBAC at resource/resource-group level. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "PA-7",
        "feat": "Just Enough Administration",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable for data plane RBAC. "
            "App Gateway has no customer-accessible data plane requiring fine-grained RBAC. "
            "Management plane access controlled via Azure RBAC (Contributor, Reader roles). "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
        ),
    },
    {
        "slug": "appgateway",
        "ctrl": "PA-8",
        "feat": "Microsoft Support",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: Customer Lockbox = False/Not Applicable. "
            "App Gateway not in Customer Lockbox supported services list. "
            "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"
        ),
    },

    # === DDOSPROTECTION ===
    {
        "slug": "ddosprotection",
        "ctrl": "NS-1",
        "feat": "Network Security Group",
        "flip_to": None,
        "append": True,
        "notes": (
            "DDoS Protection plan is a subscription-level resource with no VNet/subnet presence. "
            "NSG concepts do not apply to this resource type. "
            "Source: https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"
        ),
    },
    {
        "slug": "ddosprotection",
        "ctrl": "NS-2",
        "feat": "Private Link",
        "flip_to": None,
        "append": True,
        "notes": (
            "DDoS Protection plan is a subscription-level policy resource with no network endpoint. "
            "Private Link is not applicable. "
            "Source: https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"
        ),
    },
    {
        "slug": "ddosprotection",
        "ctrl": "NS-2",
        "feat": "Public Network Access",
        "flip_to": None,
        "append": True,
        "notes": (
            "DDoS Protection plan has no public data plane endpoint to disable. "
            "Feature concept not applicable to this resource type. "
            "Source: https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"
        ),
    },
    {
        "slug": "ddosprotection",
        "ctrl": "LT-1",
        "feat": "Defender",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "DDoS Protection alerts stream to Microsoft Defender for Cloud automatically "
            "when Azure DDoS Protection is enabled — no additional configuration required. "
            "Two alert types: 'DDoS Attack detected for Public IP' and "
            "'DDoS Attack mitigated for Public IP'. "
            "Source: https://learn.microsoft.com/en-us/azure/defender-for-cloud/other-threat-protections"
        ),
    },

    # === FIREWALLMANAGER ===
    {
        "slug": "firewallmanager",
        "ctrl": "NS-1",
        "feat": "Network Security Group",
        "flip_to": None,
        "append": True,
        "notes": (
            "Firewall Manager is a management plane policy service with no VNet or subnet presence. "
            "NSG protection not applicable to this resource type. "
            "Source: https://learn.microsoft.com/en-us/azure/firewall-manager/overview"
        ),
    },
    {
        "slug": "firewallmanager",
        "ctrl": "NS-1",
        "feat": "Virtual Network Integration",
        "flip_to": None,
        "append": True,
        "notes": (
            "Firewall Manager is a control-plane service managing Azure Firewall policies. "
            "No VNet integration exists for the Firewall Manager resource itself. "
            "Source: https://learn.microsoft.com/en-us/azure/firewall-manager/overview"
        ),
    },
    {
        "slug": "firewallmanager",
        "ctrl": "NS-2",
        "feat": "Private Link",
        "flip_to": None,
        "append": True,
        "notes": (
            "Firewall Manager is an Azure management plane service accessed via ARM. "
            "No Private Link endpoint available for the Firewall Manager resource itself. "
            "Source: https://learn.microsoft.com/en-us/azure/firewall-manager/overview"
        ),
    },
    {
        "slug": "firewallmanager",
        "ctrl": "NS-2",
        "feat": "Public Network Access",
        "flip_to": None,
        "append": True,
        "notes": (
            "Firewall Manager operates via Azure Resource Manager APIs (management plane). "
            "No public data plane endpoint to disable. "
            "Source: https://learn.microsoft.com/en-us/azure/firewall-manager/overview"
        ),
    },
    {
        "slug": "firewallmanager",
        "ctrl": "LT-1",
        "feat": "Defender",
        "flip_to": None,
        "append": True,
        "notes": (
            "No dedicated Microsoft Defender plan for Azure Firewall Manager. "
            "Azure Firewall (managed by Firewall Manager) has its own threat intel/IDPS capabilities. "
            "Firewall Manager policy resource itself has no Defender offering. "
            "Source: https://learn.microsoft.com/en-us/azure/firewall-manager/overview"
        ),
    },
    {
        "slug": "firewallmanager",
        "ctrl": "LT-4",
        "feat": "Resource Logs",
        "flip_to": None,
        "append": True,
        "notes": (
            "Azure Firewall Manager (firewall policy resource) does not emit its own resource logs. "
            "Azure Firewall instances managed by Firewall Manager emit extensive resource logs "
            "(AZFWApplicationRule, AZFWNetworkRule, AZFWThreatIntel, etc.) via diagnostic settings. "
            "LT-4 logging for traffic/security analysis happens at Azure Firewall level, not manager level. "
            "Source: https://learn.microsoft.com/en-us/azure/firewall/monitor-firewall"
        ),
    },

    # === NETWORKWATCHER ===
    {
        "slug": "networkwatcher",
        "ctrl": "NS-1",
        "feat": "Network Security Group",
        "flip_to": None,
        "append": True,
        "notes": (
            "Network Watcher is an Azure monitoring service with no subnet/VNet presence. "
            "NSG protection not applicable to this resource type. "
            "Source: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
        ),
    },
    {
        "slug": "networkwatcher",
        "ctrl": "NS-1",
        "feat": "Virtual Network Integration",
        "flip_to": None,
        "append": True,
        "notes": (
            "Network Watcher is a monitoring/diagnostic service. "
            "It enables VNet diagnostics but does not itself reside in a VNet. "
            "Source: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
        ),
    },
    {
        "slug": "networkwatcher",
        "ctrl": "NS-2",
        "feat": "Private Link",
        "flip_to": None,
        "append": True,
        "notes": (
            "Network Watcher is a regional monitoring service accessed via ARM APIs. "
            "No Private Link endpoint available for the service itself. "
            "Source: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
        ),
    },
    {
        "slug": "networkwatcher",
        "ctrl": "NS-2",
        "feat": "Public Network Access",
        "flip_to": None,
        "append": True,
        "notes": (
            "Network Watcher operates via ARM management plane. "
            "No public data plane endpoint to disable. "
            "Source: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
        ),
    },
    {
        "slug": "networkwatcher",
        "ctrl": "LT-1",
        "feat": "Defender",
        "flip_to": None,
        "append": True,
        "notes": (
            "No dedicated Microsoft Defender plan for Azure Network Watcher. "
            "Network Watcher is a diagnostic tool; threat detection not applicable at service level. "
            "Source: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
        ),
    },
    {
        "slug": "networkwatcher",
        "ctrl": "LT-4",
        "feat": "Resource Logs",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "Network Watcher Connection Monitor produces logs to Azure Log Analytics workspace "
            "(NWConnectionMonitorTestResult, NWConnectionMonitorPathResult tables). "
            "NSG flow logs (managed via Network Watcher) also produce diagnostic log data. "
            "Logs available via diagnostic settings on connection monitor resources. "
            "Source: https://learn.microsoft.com/en-us/azure/network-watcher/connection-monitor-overview"
        ),
    },

    # === PUBLICIP ===
    {
        "slug": "publicip",
        "ctrl": "NS-1",
        "feat": "Network Security Group",
        "flip_to": None,
        "append": True,
        "notes": (
            "Public IP is a network addressing resource, not a networked compute resource. "
            "NSG protection applies to the subnet/NIC associated with the resource using the IP. "
            "No direct NSG attachment to Public IP resource itself. "
            "Source: https://learn.microsoft.com/en-us/azure/virtual-network/public-ip-addresses"
        ),
    },
    {
        "slug": "publicip",
        "ctrl": "NS-2",
        "feat": "Private Link",
        "flip_to": None,
        "append": True,
        "notes": (
            "Public IP is by definition a public-facing addressing resource. "
            "Private Link concept is architecturally incompatible with Public IP resource type. "
            "Source: https://learn.microsoft.com/en-us/azure/virtual-network/public-ip-addresses"
        ),
    },
    {
        "slug": "publicip",
        "ctrl": "NS-2",
        "feat": "Public Network Access",
        "flip_to": None,
        "append": True,
        "notes": (
            "Public IP resource exists specifically to provide public network access. "
            "Disabling public network access is not applicable — it would eliminate the purpose. "
            "Security is achieved via NSGs on the associated resource, not on the IP itself. "
            "Source: https://learn.microsoft.com/en-us/azure/virtual-network/public-ip-addresses"
        ),
    },
    {
        "slug": "publicip",
        "ctrl": "LT-1",
        "feat": "Defender",
        "flip_to": "conditional",
        "append": False,
        "notes": (
            "Azure DDoS Protection alerts for Public IPs stream to Microsoft Defender for Cloud "
            "automatically when DDoS Protection is enabled. Alert types: "
            "'DDoS Attack detected for Public IP' and 'DDoS Attack mitigated for Public IP'. "
            "Conditional: requires Azure DDoS Protection (Network or IP Protection) to be enabled. "
            "Source: https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-view-alerts-defender-for-cloud"
        ),
    },

    # === REDIS ===
    {
        "slug": "redis",
        "ctrl": "IM-8",
        "feat": "Credential and Secret",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "Azure Cache for Redis does not natively integrate credentials/secrets with Key Vault. "
            "Access keys are stored at cache level. Use Entra ID auth to avoid key-based auth. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cache-for-redis-security-baseline"
        ),
    },
    {
        "slug": "redis",
        "ctrl": "DP-2",
        "feat": "anomal",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "No native DLP solution for Redis cache traffic. "
            "Redis caches data in-memory; DLP monitoring at this layer not supported. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cache-for-redis-security-baseline"
        ),
    },
    {
        "slug": "redis",
        "ctrl": "PA-1",
        "feat": "Local Admin",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "Redis has no local administrative account concept. "
            "Access via access keys (deprecated) or Entra ID. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cache-for-redis-security-baseline"
        ),
    },

    # === SERVICEBUS ===
    # Items to flip BACK to still_not_applicable (cache was incorrect)
    {
        "slug": "servicebus",
        "ctrl": "DP-2",
        "feat": "anomal",
        "flip_to": "still_not_applicable",
        "append": False,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "No native DLP solution for Service Bus message traffic. "
            "Phase 48 cache incorrectly marked as now_applicable_native — reverted. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline"
        ),
    },
    {
        "slug": "servicebus",
        "ctrl": "IM-8",
        "feat": "Credential and Secret",
        "flip_to": "still_not_applicable",
        "append": False,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "Service Bus does not natively integrate credentials/secrets with Key Vault for IM-8. "
            "Note: DP-6 (CMK) IS supported for Premium tier via Key Vault — different feature. "
            "Phase 48 cache incorrectly marked as now_applicable_native — reverted. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline"
        ),
    },
    {
        "slug": "servicebus",
        "ctrl": "PA-1",
        "feat": "Local Admin",
        "flip_to": "still_not_applicable",
        "append": False,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "Service Bus has no local administrative account. "
            "All access via Entra ID RBAC or SAS tokens (latter should be disabled). "
            "Phase 48 cache incorrectly marked as now_applicable_native — reverted. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline"
        ),
    },
    {
        "slug": "servicebus",
        "ctrl": "PA-8",
        "feat": "Microsoft Support",
        "flip_to": "still_not_applicable",
        "append": False,
        "notes": (
            "MCSB v3 baseline: Customer Lockbox = False/Not Applicable. "
            "Service Bus not in Customer Lockbox supported services list. "
            "Phase 48 cache incorrectly marked as now_applicable_native — reverted. "
            "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"
        ),
    },
    # Items to confirm now_applicable_native with URLs
    {
        "slug": "servicebus",
        "ctrl": "IM-1",
        "feat": "Azure AD Authentication Required",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "Azure AD authentication required for Service Bus data plane — True/True/Microsoft. "
            "Entra ID auth supported via RBAC with built-in roles: "
            "Azure Service Bus Data Owner, Data Sender, Data Receiver. "
            "Local SAS key auth can be disabled. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline"
        ),
    },
    {
        "slug": "servicebus",
        "ctrl": "IM-1",
        "feat": "Local Authentication",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "Service Bus supports disabling local SAS key authentication, "
            "enforcing Entra ID-only access. "
            "'Azure Cache for Redis should not use access keys for authentication' policy available. "
            "Local auth disable = now applicable as of 2024+. "
            "Source: https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization"
        ),
    },
    {
        "slug": "servicebus",
        "ctrl": "IM-7",
        "feat": "Conditional Access",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "Conditional Access for Service Bus data plane = True/False/Customer per MCSB v3 baseline. "
            "Azure AD Conditional Access policies apply to Entra ID authentication for Service Bus. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline"
        ),
    },
    {
        "slug": "servicebus",
        "ctrl": "LT-1",
        "feat": "Defender",
        "flip_to": None,
        "append": True,
        "notes": (
            "MCSB v3 baseline: False/Not Applicable. "
            "No dedicated Microsoft Defender plan for Service Bus. "
            "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline"
        ),
    },
    {
        "slug": "servicebus",
        "ctrl": "PA-7",
        "feat": "Just Enough Administration",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "Azure RBAC for Service Bus data plane = True/False/Customer per MCSB v3 baseline. "
            "Built-in roles: Azure Service Bus Data Owner (full access), "
            "Data Sender (send only), Data Receiver (receive only). "
            "Scoped at namespace, queue, or topic subscription level. "
            "Source: https://learn.microsoft.com/en-us/azure/service-bus-messaging/authenticate-application"
        ),
    },

    # === VPNGATEWAY ===
    {
        "slug": "vpngateway",
        "ctrl": "LT-4",
        "feat": "Resource Logs",
        "flip_to": "now_applicable_native",
        "append": False,
        "notes": (
            "VPN Gateway supports extensive resource logs via diagnostic settings: "
            "GatewayDiagnosticLog (config/maintenance events), "
            "TunnelDiagnosticLog (tunnel connect/disconnect), "
            "RouteDiagnosticLog (static routes, BGP events), "
            "IKEDiagnosticLog (IKE/IPsec), P2SDiagnosticLog (point-to-site). "
            "Source: https://learn.microsoft.com/en-us/azure/vpn-gateway/monitor-vpn-gateway-reference"
        ),
    },
]


def match_row(row: dict, patch: dict) -> bool:
    """Match a CSV row to a patch entry."""
    ctrl_match = row["asb_control_id"].strip() == patch["ctrl"]
    feat_frag = patch["feat"].lower()
    feat_match = feat_frag in row["feature_name"].lower()
    return ctrl_match and feat_match


def apply_patch(row: dict, patch: dict) -> bool:
    """Apply patch to row. Returns True if changed."""
    if not match_row(row, patch):
        return False

    changed = False

    if patch["flip_to"] is not None:
        old_verdict = row["verdict_2025"]
        if old_verdict != patch["flip_to"]:
            row["verdict_2025"] = patch["flip_to"]
            row["blast_radius"] = compute_blast_radius(row)
            row["risk_rank"] = compute_risk_rank(row)
            changed = True

    current_notes = row.get("notes", "").rstrip()
    new_note = patch["notes"]
    if patch["append"]:
        if patch["notes"] not in current_notes:
            row["notes"] = f"{current_notes} | {new_note}".lstrip(" |")
            changed = True
    else:
        if current_notes != new_note:
            row["notes"] = new_note
            changed = True

    return changed


def process_slug(slug: str) -> int:
    csv_path = pathlib.Path(f"data/outputs/ns/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug}: SKIP (not found)")
        return 0

    rows = list(csv.DictReader(open(csv_path)))
    slug_patches = [p for p in PATCHES if p["slug"] == slug]
    total_changed = 0

    for patch in slug_patches:
        matched = 0
        for row in rows:
            if apply_patch(row, patch):
                matched += 1
        if matched == 0:
            print(f"  WARNING {slug} [{patch['ctrl']} ~{patch['feat'][:20]}]: NO ROW MATCHED")
        else:
            total_changed += matched

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return total_changed


if __name__ == "__main__":
    slugs_with_patches = sorted({p["slug"] for p in PATCHES})

    print("=" * 70)
    print("Phase 55 Step 3 — Exa enrichment patches")
    print("=" * 70)

    total = 0
    for slug in slugs_with_patches:
        changed = process_slug(slug)
        total += changed
        print(f"  {slug:<20} rows_updated={changed:>3}")

    print()
    print(f"Total rows updated: {total}")
    print()
    print("Done. Run quality gate to verify.")
