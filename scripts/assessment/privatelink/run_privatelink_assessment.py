#!/usr/bin/env python3
"""
Azure Private Link / Private Endpoint — Compliance Assessment Runner (v2)

Runs read-only MCSB v3 control checks against Azure Private Endpoint instances
(Microsoft.Network/privateEndpoints).

Zero writes to Azure. Auth via DefaultAzureCredential.

Scope: Private Endpoints (consumer side) only.
       Private Link Services (provider side, Microsoft.Network/privateLinkServices)
       are out of scope for this assessment.

Live checks:
  NS-1 NSG: LIVE-DIRECT — subnet.private_endpoint_network_policies.
            Default is 'Disabled' (NSG bypassed). Must be 'Enabled' or
            'NetworkSecurityGroupEnabled' for NSG rules to apply to PE subnet.
            Cross-refs subnet via subnets.get(rg, vnet, subnet) from PE.subnet.id.
  AM-2 tags: LIVE-DIRECT — endpoint.tags non-empty proxy for Azure Policy governance.

PASS static: NS-1 VNet (microsoft_managed), NS-2 Private Link (meta-tautology),
             NS-2 Disable Public (no public endpoint concept).

All other checks: UNKNOWN static (PaaS NIC resource — no data plane, no data store,
                  no compute, no CMK, no logs, no Defender plan).

LT-4 NOTE: Private Endpoint resource emits NO resource logs (feature_supported=False
           in MCSB v3 baseline). Do NOT attempt DiagSettings on PE.id.

Scope flags:
  --resource-group   : scope to specific RG (optional — list_by_subscription() available)
  --endpoint-name    : scope to specific PE name (optional, requires --resource-group)
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_privatelink
import dp_privatelink
import im_privatelink
import lt_privatelink
import br_privatelink
import am_privatelink
import pa_privatelink
import es_privatelink
import pv_privatelink

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    # NS — Network Security (NS-1 NSG LIVE, NS-1 VNet PASS, NS-2×2 PASS)
    "NS-1:nsg_support":               ns_privatelink.check_ns1_nsg,
    "NS-1:vnet_integration":          ns_privatelink.check_ns1_vnet,
    "NS-2:private_link":              ns_privatelink.check_ns2_private_link,
    "NS-2:disable_public":            ns_privatelink.check_ns2_disable_public,

    # DP — Data Protection (all UNKNOWN static — PE is network relay; no data store)
    "DP-1:sensitive_data":            dp_privatelink.check_dp1_sensitive_data,
    "DP-2:dlp":                       dp_privatelink.check_dp2_dlp,
    "DP-3:tls_transit":               dp_privatelink.check_dp3_tls_transit,
    "DP-4:platform_keys":             dp_privatelink.check_dp4_platform_keys,
    "DP-5:cmk":                       dp_privatelink.check_dp5_cmk,
    "DP-6:key_mgmt":                  dp_privatelink.check_dp6_key_mgmt,
    "DP-7:cert_kv":                   dp_privatelink.check_dp7_cert_kv,

    # IM — Identity Management (all UNKNOWN static — PE has no data plane auth)
    "IM-1:aad_auth":                  im_privatelink.check_im1_aad_auth,
    "IM-1:local_auth":                im_privatelink.check_im1_local_auth,
    "IM-3:managed_identities":        im_privatelink.check_im3_managed_identities,
    "IM-3:service_principals":        im_privatelink.check_im3_service_principals,
    "IM-7:conditional_access":        im_privatelink.check_im7_conditional_access,
    "IM-8:keyvault_secrets":          im_privatelink.check_im8_keyvault_secrets,

    # LT — Logging and Threat Detection (both UNKNOWN static — no Defender plan, no logs)
    "LT-1:defender":                  lt_privatelink.check_lt1_defender,
    "LT-4:resource_logs":             lt_privatelink.check_lt4_resource_logs,

    # BR — Backup and Recovery (all UNKNOWN static — IaC-recoverable config resource)
    "BR-1:azure_backup":              br_privatelink.check_br1_azure_backup,
    "BR-1:native_backup":             br_privatelink.check_br1_native_backup,

    # AM — Asset Management (AM-2 LIVE tags proxy; AM-5 UNKNOWN static)
    "AM-2:policy_support":            am_privatelink.check_am2_policy,
    "AM-5:defender_aac":              am_privatelink.check_am5_defender_aac,

    # PA — Privileged Access (all UNKNOWN static — no compute, no data plane, no Lockbox)
    "PA-1:local_admin":               pa_privatelink.check_pa1_local_admin,
    "PA-7:rbac_data_plane":           pa_privatelink.check_pa7_rbac_data_plane,
    "PA-8:customer_lockbox":          pa_privatelink.check_pa8_customer_lockbox,

    # ES — Endpoint Security (all UNKNOWN static — PaaS NIC; no compute)
    "ES-1:edr":                       es_privatelink.check_es1_edr,
    "ES-2:antimalware":               es_privatelink.check_es2_antimalware,
    "ES-3:antimalware_health":        es_privatelink.check_es3_antimalware_health,

    # PV — Posture and Vulnerability (all UNKNOWN static — PaaS NIC; no OS)
    "PV-3:automation_state":          pv_privatelink.check_pv3_automation_state_config,
    "PV-3:guest_config":              pv_privatelink.check_pv3_guest_config_agent,
    "PV-3:container_images":          pv_privatelink.check_pv3_custom_container_images,
    "PV-3:vm_images":                 pv_privatelink.check_pv3_custom_vm_images,
    "PV-5:defender_va":               pv_privatelink.check_pv5_defender_va,
    "PV-6:update_management":         pv_privatelink.check_pv6_update_management,
}


def run_checks(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, endpoint_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": endpoint_name or resource_group or "UNKNOWN",
                "control_id": control_id,
                "feature": feature,
                "status": "UNKNOWN",
                "actual_value": None,
                "expected_value": None,
                "evidence_url": None,
                "error": str(e),
            })
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Run MCSB v3 compliance checks for Azure Private Endpoint (v2)"
    )
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--resource-group", default=None,
                        help="Scope to specific resource group (optional — list_by_subscription() available)")
    parser.add_argument("--endpoint-name", default=None,
                        help="Scope to specific Private Endpoint name (optional, requires --resource-group)")
    parser.add_argument("--output-dir", default="data/outputs/assessment_results",
                        help="Output directory for results (default: %(default)s)")
    args = parser.parse_args()

    if args.endpoint_name and not args.resource_group:
        parser.error("--endpoint-name requires --resource-group")

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except ImportError:
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-network")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    log.info(f"Scope: resource_group={args.resource_group}, endpoint_name={args.endpoint_name}")
    log.info("Note: Scope is Private Endpoints (consumer side). Private Link Services (provider side) not assessed here.")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.endpoint_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = os.path.join(args.output_dir, f"privatelink_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-private-link",
        "version": "v2",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "endpoint_name": args.endpoint_name,
        "run_timestamp": timestamp,
        "total_checks": len(results),
        "pass": sum(1 for r in results if r.get("status") == "PASS"),
        "fail": sum(1 for r in results if r.get("status") == "FAIL"),
        "unknown": sum(1 for r in results if r.get("status") == "UNKNOWN"),
        "results": results,
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    log.info(f"Results written to {out_file}")
    log.info(f"PASS={summary['pass']} FAIL={summary['fail']} UNKNOWN={summary['unknown']}")


if __name__ == "__main__":
    main()
