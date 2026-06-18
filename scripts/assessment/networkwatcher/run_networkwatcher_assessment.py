#!/usr/bin/env python3
"""
Azure Network Watcher — Compliance Assessment Runner (v2)

Runs read-only MCSB v3 control checks against Azure Network Watcher instances.
Zero writes to Azure. Auth via DefaultAzureCredential.

Note: NW auto-provisions as "NetworkWatcher_<region>" in "NetworkWatcherRG" unless
custom RG configured. Use --resource-group NetworkWatcherRG to scope by default RG.
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_networkwatcher
import dp_networkwatcher
import im_networkwatcher
import lt_networkwatcher
import br_networkwatcher
import am_networkwatcher
import pa_networkwatcher
import es_networkwatcher
import pv_networkwatcher

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    # NS — Network Security (all UNKNOWN static)
    "NS-1:nsg_support":           ns_networkwatcher.check_ns1_nsg,
    "NS-1:vnet_integration":      ns_networkwatcher.check_ns1_vnet,
    "NS-2:private_link":          ns_networkwatcher.check_ns2_private_link,
    "NS-2:disable_public":        ns_networkwatcher.check_ns2_disable_public,

    # DP — Data Protection (DP-3/4 PASS static; rest UNKNOWN)
    "DP-1:data_classification":   dp_networkwatcher.check_dp1_data_classification,
    "DP-2:dlp":                   dp_networkwatcher.check_dp2_dlp,
    "DP-3:tls_transit":           dp_networkwatcher.check_dp3_tls_transit,
    "DP-4:platform_keys":         dp_networkwatcher.check_dp4_platform_keys,
    "DP-5:cmk":                   dp_networkwatcher.check_dp5_cmk,
    "DP-6:key_mgmt_kv":           dp_networkwatcher.check_dp6_key_mgmt,
    "DP-7:cert_kv":               dp_networkwatcher.check_dp7_cert_kv,

    # IM — Identity Management (IM-1 AAD PASS static; rest UNKNOWN)
    "IM-1:local_auth_methods":    im_networkwatcher.check_im1_local_auth_methods,
    "IM-1:aad_auth_required":     im_networkwatcher.check_im1_aad_auth_required,
    "IM-3:managed_identities":    im_networkwatcher.check_im3_managed_identities,
    "IM-3:service_principals":    im_networkwatcher.check_im3_service_principals,
    "IM-7:conditional_access":    im_networkwatcher.check_im7_conditional_access,
    "IM-8:keyvault_secrets":      im_networkwatcher.check_im8_keyvault_secrets,

    # LT — Logging and Threat Detection (all UNKNOWN static)
    "LT-1:defender":              lt_networkwatcher.check_lt1_defender,
    "LT-4:resource_logs":         lt_networkwatcher.check_lt4_resource_logs,

    # BR — Backup and Recovery (all UNKNOWN static)
    "BR-1:azure_backup":          br_networkwatcher.check_br1_azure_backup,
    "BR-1:native_backup":         br_networkwatcher.check_br1_native_backup,

    # AM — Asset Management (AM-2 live; AM-5 UNKNOWN)
    "AM-2:policy_support":        am_networkwatcher.check_am2_policy,
    "AM-5:defender_aac":          am_networkwatcher.check_am5_defender_aac,

    # PA — Privileged Access (PA-7 PASS static; PA-1/8 UNKNOWN)
    "PA-1:local_admin":           pa_networkwatcher.check_pa1_local_admin,
    "PA-7:rbac_data_plane":       pa_networkwatcher.check_pa7_rbac_data_plane,
    "PA-8:customer_lockbox":      pa_networkwatcher.check_pa8_customer_lockbox,

    # ES — Endpoint Security (all UNKNOWN static)
    "ES-1:edr":                   es_networkwatcher.check_es1_edr,
    "ES-2:antimalware":           es_networkwatcher.check_es2_antimalware,
    "ES-3:antimalware_health":    es_networkwatcher.check_es3_antimalware_health,

    # PV — Posture and Vulnerability (all UNKNOWN static)
    "PV-3:automation_state":      pv_networkwatcher.check_pv3_automation_state_config,
    "PV-3:guest_config":          pv_networkwatcher.check_pv3_guest_config_agent,
    "PV-3:container_images":      pv_networkwatcher.check_pv3_custom_container_images,
    "PV-3:vm_images":             pv_networkwatcher.check_pv3_custom_vm_images,
    "PV-5:defender_va":           pv_networkwatcher.check_pv5_defender_va,
    "PV-6:update_management":     pv_networkwatcher.check_pv6_update_management,
}


def run_checks(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, watcher_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": watcher_name or "UNKNOWN",
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
        description="Run MCSB v3 compliance checks for Azure Network Watcher (v2)"
    )
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--resource-group", default=None,
                        help="Scope to specific resource group (default RG is 'NetworkWatcherRG')")
    parser.add_argument("--watcher-name", default=None,
                        help="Scope to specific Network Watcher name (e.g. 'NetworkWatcher_eastus')")
    parser.add_argument("--output-dir", default="data/outputs/assessment_results",
                        help="Output directory for results (default: %(default)s)")
    args = parser.parse_args()

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except ImportError:
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-network")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    log.info("Tip: NW auto-provisions as 'NetworkWatcher_<region>' in 'NetworkWatcherRG'")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.watcher_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = os.path.join(args.output_dir, f"networkwatcher_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-network-watcher",
        "version": "v2",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "watcher_name": args.watcher_name,
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
