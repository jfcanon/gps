#!/usr/bin/env python3
"""
Azure Bastion — Compliance Assessment Runner (v2)

Runs read-only MCSB v3 control checks against Azure Bastion instances
(Microsoft.Network/bastionHosts).

Zero writes to Azure. Auth via DefaultAzureCredential.

Live checks:
  NS-1 NSG: LIVE-DIRECT — NSG existence on AzureBastionSubnet.
            Bastion requires specific NSG rules to function. Check is whether NSG
            EXISTS on subnet, not individual rule validation (prescriptive/fragile).
            Cross-ref: bastion.ip_configurations[0].subnet.id → subnets.get().
  NS-1 VNet: LIVE-DIRECT — subnet name == 'AzureBastionSubnet' AND prefix <= /26.
  LT-4: LIVE-DIRECT — DiagnosticSettings(bastion.id) → BastionAuditLogs enabled.
         SDK: azure-mgmt-monitor.
  AM-2 tags: LIVE-DIRECT — bastion.tags non-empty proxy for Azure Policy governance.
  DP-6 KV SSH keys: LIVE→UNKNOWN — no ARM property on BastionHost to inspect;
                    connection-time behavioral pattern.
  IM-8 KV SSH secrets: LIVE→UNKNOWN — same as DP-6.

PASS static (2): IM-1 AAD (microsoft_managed), DP-3 TLS (microsoft_managed).

All other checks: UNKNOWN static (not_applicable — Bastion is a managed jump host;
                  no data plane, no data store, no compute, no Defender plan).

PA-7 NOTE: Bastion explicitly does not support Azure RBAC for user access
           (confirmed in MCSB v3 baseline notes). not_applicable.

Scope flags:
  --resource-group   : scope to specific RG (optional — list_all() available)
  --bastion-name     : scope to specific Bastion name (optional, requires --resource-group)
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_bastion
import dp_bastion
import im_bastion
import lt_bastion
import br_bastion
import am_bastion
import pa_bastion
import es_bastion
import pv_bastion

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    # NS — Network Security (NS-1 NSG LIVE, NS-1 VNet LIVE, NS-2×2 UNKNOWN static)
    "NS-1:nsg_support":               ns_bastion.check_ns1_nsg,
    "NS-1:vnet_integration":          ns_bastion.check_ns1_vnet,
    "NS-2:private_link":              ns_bastion.check_ns2_private_link,
    "NS-2:disable_public":            ns_bastion.check_ns2_disable_public,

    # DP — Data Protection (DP-3 PASS static; DP-6 LIVE→UNKNOWN; rest UNKNOWN static)
    "DP-1:sensitive_data":            dp_bastion.check_dp1_sensitive_data,
    "DP-2:dlp":                       dp_bastion.check_dp2_dlp,
    "DP-3:tls_transit":               dp_bastion.check_dp3_tls_transit,
    "DP-4:platform_keys":             dp_bastion.check_dp4_platform_keys,
    "DP-5:cmk":                       dp_bastion.check_dp5_cmk,
    "DP-6:key_mgmt":                  dp_bastion.check_dp6_key_mgmt,
    "DP-7:cert_kv":                   dp_bastion.check_dp7_cert_kv,

    # IM — Identity Management (IM-1 AAD PASS static; IM-8 LIVE→UNKNOWN; rest UNKNOWN static)
    "IM-1:aad_auth":                  im_bastion.check_im1_aad_auth,
    "IM-1:local_auth":                im_bastion.check_im1_local_auth,
    "IM-3:managed_identities":        im_bastion.check_im3_managed_identities,
    "IM-3:service_principals":        im_bastion.check_im3_service_principals,
    "IM-7:conditional_access":        im_bastion.check_im7_conditional_access,
    "IM-8:keyvault_secrets":          im_bastion.check_im8_keyvault_secrets,

    # LT — Logging and Threat Detection (LT-4 LIVE; LT-1 UNKNOWN static)
    "LT-1:defender":                  lt_bastion.check_lt1_defender,
    "LT-4:resource_logs":             lt_bastion.check_lt4_resource_logs,

    # BR — Backup and Recovery (BR-1×2 UNKNOWN static)
    "BR-1:azure_backup":              br_bastion.check_br1_azure_backup,
    "BR-1:native_backup":             br_bastion.check_br1_native_backup,

    # AM — Asset Management (AM-2 LIVE tags; AM-5 UNKNOWN static)
    "AM-2:policy_support":            am_bastion.check_am2_policy,
    "AM-5:defender_aac":              am_bastion.check_am5_defender_aac,

    # PA — Privileged Access (PA-1/7/8 UNKNOWN static — PA-7 explicitly not supported)
    "PA-1:local_admin":               pa_bastion.check_pa1_local_admin,
    "PA-7:rbac_data_plane":           pa_bastion.check_pa7_rbac_data_plane,
    "PA-8:customer_lockbox":          pa_bastion.check_pa8_customer_lockbox,

    # ES — Endpoint Security (ES-1/2/3 UNKNOWN static — PaaS managed jump host)
    "ES-1:edr":                       es_bastion.check_es1_edr,
    "ES-2:antimalware":               es_bastion.check_es2_antimalware,
    "ES-3:antimalware_health":        es_bastion.check_es3_antimalware_health,

    # PV — Posture and Vulnerability (PV-3×4/PV-5/PV-6 UNKNOWN static — no customer OS)
    "PV-3:automation_state":          pv_bastion.check_pv3_automation_state_config,
    "PV-3:guest_config":              pv_bastion.check_pv3_guest_config_agent,
    "PV-3:container_images":          pv_bastion.check_pv3_custom_container_images,
    "PV-3:vm_images":                 pv_bastion.check_pv3_custom_vm_images,
    "PV-5:defender_va":               pv_bastion.check_pv5_defender_va,
    "PV-6:update_management":         pv_bastion.check_pv6_update_management,
}


def run_checks(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, bastion_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": bastion_name or resource_group or "UNKNOWN",
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
        description="Run MCSB v3 compliance checks for Azure Bastion (v2)"
    )
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--resource-group", default=None,
                        help="Scope to specific resource group (optional — list_all() available)")
    parser.add_argument("--bastion-name", default=None,
                        help="Scope to specific Bastion host name (optional, requires --resource-group)")
    parser.add_argument("--output-dir", default="data/outputs/assessment_results",
                        help="Output directory for results (default: %(default)s)")
    args = parser.parse_args()

    if args.bastion_name and not args.resource_group:
        parser.error("--bastion-name requires --resource-group")

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except ImportError:
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-network azure-mgmt-monitor")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    log.info(f"Scope: resource_group={args.resource_group}, bastion_name={args.bastion_name}")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.bastion_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = os.path.join(args.output_dir, f"bastion_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-bastion",
        "version": "v2",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "bastion_name": args.bastion_name,
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
