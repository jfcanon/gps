#!/usr/bin/env bash
# Run full gap assessment pipeline in order.
# Place all input files in data/inputs/ before running.
# Outputs written to data/outputs/.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

cd "$ROOT"

echo "=== Azure Infra Security Gap Assessment Pipeline ==="
echo ""

# Check Python
python3 --version || { echo "ERROR: python3 not found"; exit 1; }

# Install dependencies
echo "Installing dependencies..."
pip install -q -r scripts/requirements.txt

mkdir -p data/inputs data/outputs

echo ""
echo "--- Phase 0: Fetch and build master control list ---"
echo ""

echo "[1/4] Fetching MCSB v2 controls..."
python3 scripts/fetch_mcsb_v2.py

echo ""
echo "[2/4] Loading MCSB v3 controls (requires data/inputs/mcsb_v3.xlsx)..."
if [ -f "data/inputs/mcsb_v3.xlsx" ]; then
    python3 scripts/load_mcsb_v3.py
else
    echo "SKIP: data/inputs/mcsb_v3.xlsx not found"
    echo "      Download from: https://github.com/MicrosoftDocs/SecurityBenchmarks"
fi

echo ""
echo "[3/4] Mapping v3 controls to v2 domains..."
if [ -f "data/outputs/mcsb_v3_raw.csv" ]; then
    python3 scripts/map_v3_to_v2_domains.py
else
    echo "SKIP: mcsb_v3_raw.csv not found (v3 load skipped)"
fi

echo ""
echo "[4/4] Building master control list..."
python3 scripts/build_master_controls.py

echo ""
echo "--- Phase 2: Parse coverage inputs ---"
echo ""

echo "[5/9] Parsing Optive CSV..."
if [ -f "data/inputs/optive_parsed.csv" ]; then
    python3 scripts/parse_optive_csv.py
else
    echo "SKIP: data/inputs/optive_parsed.csv not found"
fi

echo ""
echo "[6/9] Parsing Azure Policy JSON..."
if [ -f "data/inputs/az_policy.json" ]; then
    python3 scripts/parse_az_policy.py
else
    echo "SKIP: data/inputs/az_policy.json not found"
fi

echo ""
echo "[7/9] Parsing Azure Defender JSON..."
if [ -f "data/inputs/az_defender.json" ]; then
    python3 scripts/parse_az_defender.py
else
    echo "SKIP: data/inputs/az_defender.json not found"
fi

echo ""
echo "[8/9] Parsing ADO export..."
if [ -f "data/inputs/ado_export.json" ] || [ -f "data/inputs/ado_export.csv" ]; then
    python3 scripts/parse_ado_export.py
else
    echo "SKIP: data/inputs/ado_export.json or .csv not found"
fi

echo ""
echo "[9/9] Building gap matrix..."
python3 scripts/build_gap_matrix.py

echo ""
echo "=== Pipeline complete ==="
echo ""
echo "Outputs:"
echo "  data/outputs/master_controls.csv     — unified MCSB control list"
echo "  data/outputs/gap_matrix.csv          — all controls with coverage flags"
echo "  data/outputs/ado_items_to_create.csv — GAP controls needing new ADO items"
echo ""
echo "Next steps:"
echo "  1. Review data/outputs/mcsb_v3_manual_review.csv (Low-confidence mappings)"
echo "  2. Review data/outputs/ado_coverage.csv Medium-confidence matches"
echo "  3. Import ado/ado_import_template.csv into ADO (12 epics)"
echo "  4. Use ado_items_to_create.csv to create user stories under each epic"
