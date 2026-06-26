#!/usr/bin/env python3
"""Azure Virtual Desktop — MCSB v3 compliance assessment runner. Read-only."""
import argparse, json, logging, os, sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_virtualdesktop, dp_virtualdesktop, im_virtualdesktop, lt_virtualdesktop
import br_virtualdesktop, am_virtualdesktop, pa_virtualdesktop, es_virtualdesktop, pv_virtualdesktop

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    "NS-1:nsg":                     ns_virtualdesktop.check_ns1_nsg,
    "NS-1:vnet_integration":        ns_virtualdesktop.check_ns1_vnet_integration,
    "NS-2:private_link":            ns_virtualdesktop.check_ns2_private_link,
    "DP-1:sensitive_data":          dp_virtualdesktop.check_dp1_sensitive_data,
    "DP-2:data_leakage":            dp_virtualdesktop.check_dp2_data_leakage,
    "DP-3:tls_transit":             dp_virtualdesktop.check_dp3_tls_transit,
    "DP-4:platform_keys":           dp_virtualdesktop.check_dp4_platform_keys,
    "IM-1:aad_auth_required":       im_virtualdesktop.check_im1_aad_auth,
    "IM-3:managed_identities":      im_virtualdesktop.check_im3_managed_identities,
    "IM-3:service_principals":      im_virtualdesktop.check_im3_service_principals,
    "IM-7:conditional_access":      im_virtualdesktop.check_im7_conditional_access,
    "LT-1:defender":                lt_virtualdesktop.check_lt1_defender,
    "LT-4:resource_logs":           lt_virtualdesktop.check_lt4_resource_logs,
    "ES-1:edr":                     es_virtualdesktop.check_es1_edr,
    "ES-2:antimalware":             es_virtualdesktop.check_es2_antimalware,
    "ES-3:antimalware_health":      es_virtualdesktop.check_es3_antimalware_health,
    "BR-1:azure_backup":            br_virtualdesktop.check_br1_azure_backup,
    "AM-2:policy_support":          am_virtualdesktop.check_am2_policy,
    "PA-1:local_admin":             pa_virtualdesktop.check_pa1_local_admin,
    "PA-7:rbac_data_plane":         pa_virtualdesktop.check_pa7_rbac_data_plane,
    "PV-3:automation":              pv_virtualdesktop.check_pv3_automation,
    "PV-5:defender_va":             pv_virtualdesktop.check_pv5_defender_va,
}


def run_checks(credential, subscription_id, resource_group, workspace_name):
    results = []
    for key, fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            results.append(fn(credential, subscription_id, resource_group, workspace_name))
        except Exception as e:
            log.error(f"{key}: {e}")
            results.append({"resource": workspace_name or "UNKNOWN", "control_id": key.split(":")[0],
                            "feature": key, "status": "UNKNOWN", "actual_value": None,
                            "expected_value": None, "evidence_url": None, "error": str(e)})
    return results


def main():
    parser = argparse.ArgumentParser(description="MCSB v3 checks for Azure Virtual Desktop")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", default=None)
    parser.add_argument("--workspace-name", default=None)
    parser.add_argument("--output-dir", default="data/outputs/assessment_results")
    args = parser.parse_args()
    from azure.identity import DefaultAzureCredential
    credential = DefaultAzureCredential()
    log.info(f"Running {len(CHECK_REGISTRY)} checks")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.workspace_name)
    os.makedirs(args.output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(args.output_dir, f"virtualdesktop_{args.subscription_id}_{ts}.json")
    summary = {"service": "azure-virtual-desktop", "version": "v1",
               "subscription_id": args.subscription_id, "resource_group": args.resource_group,
               "workspace_name": args.workspace_name, "run_timestamp": ts,
               "total_checks": len(results),
               "pass": sum(1 for r in results if r.get("status") == "PASS"),
               "fail": sum(1 for r in results if r.get("status") == "FAIL"),
               "unknown": sum(1 for r in results if r.get("status") == "UNKNOWN"),
               "results": results}
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    log.info(f"Results → {out}  PASS={summary['pass']} FAIL={summary['fail']} UNKNOWN={summary['unknown']}")


if __name__ == "__main__":
    main()
