#!/usr/bin/env python3
"""
Azure Event Hubs — Compliance Assessment Runner

Runs read-only MCSB v3 control checks against Event Hubs namespaces.
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
import ns_eventhubs
import dp_eventhubs
import im_eventhubs
import lt_eventhubs
import br_eventhubs
import am_eventhubs
import pa_eventhubs
import es_eventhubs
import pv_eventhubs

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    # NS — Network Security
    "NS-1:nsg_subnet":              ns_eventhubs.check_ns1_nsg,
    "NS-1:vnet_rules":              ns_eventhubs.check_ns1_vnet_rules,
    "NS-2:private_link":            ns_eventhubs.check_ns2_private_link,
    "NS-2:disable_public_access":   ns_eventhubs.check_ns2_disable_public_access,

    # DP — Data Protection
    "DP-3:tls_min_version":         dp_eventhubs.check_dp3_tls_transit,
    "DP-4:platform_keys":           dp_eventhubs.check_dp4_platform_keys,
    "DP-5:cmk":                     dp_eventhubs.check_dp5_cmk,
    "DP-6:key_mgmt_kv":             dp_eventhubs.check_dp6_key_mgmt,

    # IM — Identity Management
    "IM-1:aad_auth_required":       im_eventhubs.check_im1_aad_auth,
    "IM-1:local_auth_disabled":     im_eventhubs.check_im1_local_auth_methods,
    "IM-3:managed_identities":      im_eventhubs.check_im3_managed_identities,
    "IM-3:service_principals":      im_eventhubs.check_im3_service_principals,
    "IM-7:conditional_access":      im_eventhubs.check_im7_conditional_access,

    # LT — Logging and Threat Detection
    "LT-1:defender":                lt_eventhubs.check_lt1_defender,
    "LT-4:resource_logs":           lt_eventhubs.check_lt4_resource_logs,

    # BR — Backup and Recovery
    "BR-1:azure_backup":            br_eventhubs.check_br1_azure_backup,

    # AM — Asset Management
    "AM-2:policy_support":          am_eventhubs.check_am2_policy,

    # PA — Privileged Access
    "PA-1:local_admin":             pa_eventhubs.check_pa1_local_admin,
    "PA-7:rbac_data_plane":         pa_eventhubs.check_pa7_rbac_data_plane,

    # ES — Endpoint Security (PaaS — all UNKNOWN)
    "ES-1:edr":                     es_eventhubs.check_es1_edr,
    "ES-2:antimalware":             es_eventhubs.check_es2_antimalware,
    "ES-3:antimalware_health":      es_eventhubs.check_es3_antimalware_health,

    # PV — Posture and Vulnerability (PaaS — all UNKNOWN)
    "PV-3:automation_state":        pv_eventhubs.check_pv3_automation_state_config,
    "PV-3:guest_config":            pv_eventhubs.check_pv3_guest_config_agent,
    "PV-5:defender_va":             pv_eventhubs.check_pv5_defender_va,
    "PV-6:update_management":       pv_eventhubs.check_pv6_update_management,
}


def run_checks(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, namespace_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": namespace_name or "UNKNOWN",
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
        description="Run MCSB v3 compliance checks for Azure Event Hubs"
    )
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--resource-group", default=None, help="Scope to specific resource group")
    parser.add_argument("--namespace-name", default=None, help="Scope to specific Event Hubs namespace name")
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
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-eventhub azure-mgmt-monitor")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.namespace_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = os.path.join(args.output_dir, f"eventhubs_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-event-hubs",
        "version": "v1",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "namespace_name": args.namespace_name,
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
