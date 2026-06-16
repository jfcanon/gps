#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description='Extract service controls from reclassified CSV')
    parser.add_argument('--service', required=True, help='Azure service name (e.g., azure-cache-for-redis)')
    parser.add_argument('--reclassified-csv', default='data/outputs/v3_service_controls_reclassified.csv',
                        help='Path to reclassified controls CSV (default: %(default)s)')
    parser.add_argument('--raw-csv', default='data/outputs/v3_service_controls_raw.csv',
                        help='Path to raw controls CSV (default: %(default)s)')
    parser.add_argument('--output-dir', default='data/inputs/assessment_data',
                        help='Output directory (default: %(default)s)')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, f"{args.service}_controls.json")

    raw_dict = {}
    with open(args.raw_csv, 'r', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            key = (row['service_name'], row['asb_control_id'], row['feature_name'])
            raw_dict[key] = {
                'feature_supported': row['feature_supported'],
                'feature_enabled_by_default': row['feature_enabled_by_default']
            }

    filtered_rows = []
    with open(args.reclassified_csv, 'r', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row['service_name'] == args.service:
                filtered_rows.append(row)

    if not filtered_rows:
        print(f"Error: No rows found for service '{args.service}' in {args.reclassified_csv}", file=sys.stderr)
        sys.exit(1)

    output_data = []
    for row in filtered_rows:
        key = (row['service_name'], row['asb_control_id'], row['feature_name'])
        if key in raw_dict:
            feature_supported = raw_dict[key]['feature_supported']
            feature_enabled_by_default = raw_dict[key]['feature_enabled_by_default']
        else:
            print(f"Warning: Raw data not found for key {key}, using reclassified values", file=sys.stderr)
            feature_supported = row['feature_supported']
            feature_enabled_by_default = row['feature_enabled_by_default']

        output_data.append({
            "asb_control_id": row['asb_control_id'],
            "control_domain": row['control_domain'],
            "asb_control_title": row['asb_control_title'],
            "feature_name": row['feature_name'],
            "feature_description": row['feature_description'],
            "feature_reference": row['feature_reference'],
            "feature_notes": row['feature_notes'],
            "responsibility": row['responsibility'],
            "feature_supported": feature_supported,
            "feature_enabled_by_default": feature_enabled_by_default,
            "applicability": row['applicability'],
            "automation_class": row['automation_class'],
            "newly_applicable": row['newly_applicable'],
            "reclassification_rationale": row['reclassification_rationale']
        })

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(output_data)} rows to {output_path}")


if __name__ == "__main__":
    main()
