#!/usr/bin/env python3
"""
Azure Event Grid — Compliance Assessment Runner

Runs read-only MCSB v3 control checks against Event Grid topics.
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
import ns_eventgrid
import dp_eventgrid
import im_eventgrid
import lt_eventgrid
import br_eventgrid
import am_eventgrid
import pa_eventgrid
import es_eventgrid
import pv_eventgrid

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    # NS — Network Security
    "NS-1:nsg":                                     ns_eventgrid.check_ns1_nsg,
    "NS-2:private_link":                            ns_eventgrid.check_ns2_private_link,
    "NS-2:disable_public_access":                   ns_eventgrid.check_ns2_disable_public_access,
    "NS-2-SUPPLEMENT-EVENTGRID:mqtt_namespaces":    ns_eventgrid.check_ns2_supplement_eventgrid_namespaces,

    # DP — Data Protection
    "DP-3:tls_min_version":                         dp_eventgrid.check_dp3_tls_transit,
    "DP-4:platform_keys":                           dp_eventgrid.check_dp4_platform_keys,

    # IM — Identity Management
    "IM-1:aad_auth_required":                       im_eventgrid.check_im1_aad_auth,
    "IM-1:local_auth_disabled":                     im_eventgrid.check_im1_local_auth_methods,
    "IM-3:managed_identities":                      im_eventgrid.check_im3_managed_identities,
    "IM-3:service_principals":                      im_eventgrid.check_im3_service_principals,

    # LT — Logging and Threat Detection
    "LT-1:defender":                                lt_eventgrid.check_lt1_defender,
    "LT-4:resource_logs":                           lt_eventgrid.check_lt4_resource_logs,

    # BR — Backup and Recovery
    "BR-1:azure_backup":                            br_eventgrid.check_br1_azure_backup,

    # AM — Asset Management
    "AM-2:policy_support":                          am_eventgrid.check_am2_policy,

    # PA — Privileged Access
    "PA-7:rbac_data_plane":                         pa_eventgrid.check_pa7_rbac_data_plane,

    # ES — Endpoint Security (PaaS — all UNKNOWN)
    "ES-1:edr":                                     es_eventgrid.check_es1_edr,
    "ES-2:antimalware":                             es_eventgrid.check_es2_antimalware,
    "ES-3:antimalware_health":                      es_eventgrid.check_es3_antimalware_health,

    # PV — Posture and Vulnerability (PaaS — all UNKNOWN)
    "PV-3:automation_state":                        pv_eventgrid.check_pv3_automation_state_config,
    "PV-3:guest_config":                            pv_eventgrid.check_pv3_guest_config_agent,
    "PV-5:defender_va":                             pv_eventgrid.check_pv5_defender_va,
    "PV-6:update_management":                       pv_eventgrid.check_pv6_update_management,
}


def run_checks(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, topic_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": topic_name or "UNKNOWN",
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
        description="Run MCSB v3 compliance checks for Azure Event Grid"
    )
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--resource-group", default=None, help="Scope to specific resource group")
    parser.add_argument("--topic-name", default=None, help="Scope to specific Event Grid topic name")
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
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-eventgrid azure-mgmt-monitor")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.topic_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = os.path.join(args.output_dir, f"eventgrid_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-event-grid",
        "version": "v1",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "topic_name": args.topic_name,
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
