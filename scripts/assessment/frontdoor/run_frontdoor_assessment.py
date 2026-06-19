#!/usr/bin/env python3
"""
Azure Front Door — Compliance Assessment Runner (v2)

Runs read-only MCSB v3 control checks against Azure Front Door (Classic) instances.
Zero writes to Azure. Auth via DefaultAzureCredential.

Live checks: NS-2 WAF policy link, DP-3/4 PASS static, DP-7 KV cert, IM-8 KV certs, LT-4 DiagSettings, AM-2 tags.
All other checks: UNKNOWN static (PaaS CDN — no NSG, no DP CMK, no IM data-plane controls).

Note: This script covers AFD Classic (azure-mgmt-frontdoor). AFD Standard/Premium resources
appear as CDN profiles (azure-mgmt-cdn) with SKU Standard_AzureFrontDoor / Premium_AzureFrontDoor
and require CdnManagementClient. Scope this runner to Classic instances only.

Scope flags:
  --resource-group    : limit to Front Doors in one resource group
  --front-door-name   : limit to one specific Front Door (requires --resource-group)
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_frontdoor
import dp_frontdoor
import im_frontdoor
import lt_frontdoor
import br_frontdoor
import am_frontdoor
import pa_frontdoor
import es_frontdoor
import pv_frontdoor

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    # NS — Network Security
    "NS-1:nsg_support":               ns_frontdoor.check_ns1_nsg,
    "NS-1:vnet_integration":          ns_frontdoor.check_ns1_vnet,
    "NS-2:private_link":              ns_frontdoor.check_ns2_private_link,
    "NS-2:waf_ip_filtering":          ns_frontdoor.check_ns2_waf_policy,

    # DP — Data Protection (DP-3/4 PASS static; DP-7 LIVE; rest UNKNOWN static)
    "DP-1:data_classification":       dp_frontdoor.check_dp1_data_classification,
    "DP-2:dlp":                       dp_frontdoor.check_dp2_dlp,
    "DP-3:tls_transit":               dp_frontdoor.check_dp3_tls_transit,
    "DP-4:platform_keys":             dp_frontdoor.check_dp4_platform_keys,
    "DP-5:cmk":                       dp_frontdoor.check_dp5_cmk,
    "DP-6:key_mgmt_kv":               dp_frontdoor.check_dp6_key_mgmt,
    "DP-7:cert_kv":                   dp_frontdoor.check_dp7_cert_kv,

    # IM — Identity Management (IM-8 LIVE; rest UNKNOWN static)
    "IM-1:local_auth_methods":        im_frontdoor.check_im1_local_auth_methods,
    "IM-1:aad_auth_required":         im_frontdoor.check_im1_aad_auth_required,
    "IM-3:managed_identities":        im_frontdoor.check_im3_managed_identities,
    "IM-3:service_principals":        im_frontdoor.check_im3_service_principals,
    "IM-7:conditional_access":        im_frontdoor.check_im7_conditional_access,
    "IM-8:keyvault_secrets":          im_frontdoor.check_im8_keyvault_secrets,

    # LT — Logging and Threat Detection (LT-4 LIVE; LT-1 UNKNOWN static)
    "LT-1:defender":                  lt_frontdoor.check_lt1_defender,
    "LT-4:resource_logs":             lt_frontdoor.check_lt4_resource_logs,

    # BR — Backup and Recovery (all UNKNOWN static)
    "BR-1:azure_backup":              br_frontdoor.check_br1_azure_backup,
    "BR-1:native_backup":             br_frontdoor.check_br1_native_backup,

    # AM — Asset Management (AM-2 LIVE; AM-5 UNKNOWN static)
    "AM-2:policy_support":            am_frontdoor.check_am2_policy,
    "AM-5:defender_aac":              am_frontdoor.check_am5_defender_aac,

    # PA — Privileged Access (all UNKNOWN static)
    "PA-1:local_admin":               pa_frontdoor.check_pa1_local_admin,
    "PA-7:rbac_data_plane":           pa_frontdoor.check_pa7_rbac_data_plane,
    "PA-8:customer_lockbox":          pa_frontdoor.check_pa8_customer_lockbox,

    # ES — Endpoint Security (all UNKNOWN static — PaaS; no compute)
    "ES-1:edr":                       es_frontdoor.check_es1_edr,
    "ES-2:antimalware":               es_frontdoor.check_es2_antimalware,
    "ES-3:antimalware_health":        es_frontdoor.check_es3_antimalware_health,

    # PV — Posture and Vulnerability (all UNKNOWN static — PaaS; no OS)
    "PV-3:automation_state":          pv_frontdoor.check_pv3_automation_state_config,
    "PV-3:guest_config":              pv_frontdoor.check_pv3_guest_config_agent,
    "PV-3:container_images":          pv_frontdoor.check_pv3_custom_container_images,
    "PV-3:vm_images":                 pv_frontdoor.check_pv3_custom_vm_images,
    "PV-5:defender_va":               pv_frontdoor.check_pv5_defender_va,
    "PV-6:update_management":         pv_frontdoor.check_pv6_update_management,
}


def run_checks(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, front_door_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": front_door_name or "UNKNOWN",
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
        description="Run MCSB v3 compliance checks for Azure Front Door Classic (v2)"
    )
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--resource-group", default=None,
                        help="Scope to resource group containing Front Door instance(s)")
    parser.add_argument("--front-door-name", default=None,
                        help="Scope to specific Front Door name")
    parser.add_argument("--output-dir", default="data/outputs/assessment_results",
                        help="Output directory for results (default: %(default)s)")
    args = parser.parse_args()

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except ImportError:
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-frontdoor azure-mgmt-monitor")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    log.info("Note: Covers AFD Classic only. AFD Standard/Premium uses azure-mgmt-cdn (CdnManagementClient).")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.front_door_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = os.path.join(args.output_dir, f"frontdoor_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-front-door",
        "version": "v2",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "front_door_name": args.front_door_name,
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
