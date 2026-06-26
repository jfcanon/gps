#!/usr/bin/env python3
"""
Azure Virtual Network — Compliance Assessment Runner

Runs read-only MCSB v3 control checks against Virtual Network instances.
Zero writes to Azure. Auth via DefaultAzureCredential.
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_virtualnetwork
import dp_virtualnetwork
import im_virtualnetwork
import lt_virtualnetwork
import br_virtualnetwork
import am_virtualnetwork
import pa_virtualnetwork
import es_virtualnetwork
import pv_virtualnetwork

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    # NS — Network Security
    "NS-1:nsg_on_subnets":                          ns_virtualnetwork.check_ns1_nsg,
    "NS-2-SUPPLEMENT:default_outbound_access":       ns_virtualnetwork.check_ns2_supplement_default_outbound_access,

    # DP — Data Protection
    "DP-3:tls_transit":                              dp_virtualnetwork.check_dp3_tls_transit,
    "DP-4:platform_keys":                            dp_virtualnetwork.check_dp4_platform_keys,

    # IM — Identity Management
    "IM-1:local_auth_methods":                       im_virtualnetwork.check_im1_local_auth_methods,
    "IM-3:managed_identities":                       im_virtualnetwork.check_im3_managed_identities,

    # LT — Logging and Threat Detection
    "LT-1:defender":                                 lt_virtualnetwork.check_lt1_defender,
    "LT-4:resource_logs":                            lt_virtualnetwork.check_lt4_resource_logs,

    # BR — Backup and Recovery
    "BR-1:azure_backup":                             br_virtualnetwork.check_br1_azure_backup,

    # AM — Asset Management
    "AM-2:policy_support":                           am_virtualnetwork.check_am2_policy,

    # PA — Privileged Access
    "PA-1:local_admin":                              pa_virtualnetwork.check_pa1_local_admin,
    "PA-7:rbac_data_plane":                          pa_virtualnetwork.check_pa7_rbac_data_plane,

    # ES — Endpoint Security
    "ES-1:edr":                                      es_virtualnetwork.check_es1_edr,
    "ES-2:antimalware":                              es_virtualnetwork.check_es2_antimalware,
    "ES-3:antimalware_health":                       es_virtualnetwork.check_es3_antimalware_health,

    # PV — Posture and Vulnerability
    "PV-3:automation_state":                         pv_virtualnetwork.check_pv3_automation_state_config,
    "PV-3:guest_config":                             pv_virtualnetwork.check_pv3_guest_config_agent,
    "PV-5:defender_va":                              pv_virtualnetwork.check_pv5_defender_va,
    "PV-6:update_management":                        pv_virtualnetwork.check_pv6_update_management,
}


def run_checks(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, vnet_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": vnet_name or "UNKNOWN",
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
        description="Run MCSB v3 compliance checks for Azure Virtual Network"
    )
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--resource-group", default=None, help="Scope to specific resource group")
    parser.add_argument("--vnet-name", default=None, help="Scope to specific Virtual Network name")
    parser.add_argument("--output-dir", default="data/outputs/assessment_results",
                        help="Output directory for results (default: %(default)s)")
    args = parser.parse_args()

    if not CHECK_REGISTRY:
        log.warning("CHECK_REGISTRY is empty — no checks registered.")
        sys.exit(0)

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except ImportError:
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-network azure-mgmt-monitor")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.vnet_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = os.path.join(args.output_dir, f"virtualnetwork_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-virtual-network",
        "version": "v1",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "vnet_name": args.vnet_name,
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
