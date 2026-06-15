"""
ADO Import Configuration
------------------------
Edit the constants below to match your Azure DevOps environment.
ADO_PAT must be set as an environment variable — never hardcoded here.

Run order:
  1. export ADO_PAT=<your-pat>
  2. python parse_stories.py         → writes ado_stories.csv
  3. python import_to_ado.py         → creates Features + User Stories in ADO
"""

import os

# ---------------------------------------------------------------------------
# Required: set ADO_PAT as environment variable before running import
# ---------------------------------------------------------------------------
ADO_PAT = os.environ.get("ADO_PAT", "")

# ---------------------------------------------------------------------------
# Required: your Azure DevOps organization and project
# ---------------------------------------------------------------------------
ADO_ORG = "https://dev.azure.com/YOUR_ORG"      # e.g. https://dev.azure.com/contoso
ADO_PROJECT = "YOUR_PROJECT"                     # e.g. SecGap-Assessment

# ---------------------------------------------------------------------------
# Optional: area and iteration paths. Use project root if unsure.
# Format: "ProjectName\\Area\\Sub-area"  (double backslash in Python string)
# Leave as None to use project root (default).
# ---------------------------------------------------------------------------
AREA_PATH = None          # e.g. "SecGap-Assessment\\Security"
ITERATION_PATH = None     # e.g. "SecGap-Assessment\\Sprint 1"

# ---------------------------------------------------------------------------
# CSV output path (relative to scripts/ directory)
# ---------------------------------------------------------------------------
CSV_OUTPUT = "ado_stories.csv"

# ---------------------------------------------------------------------------
# ADO REST API version
# ---------------------------------------------------------------------------
API_VERSION = "7.1"

# ---------------------------------------------------------------------------
# Dry-run mode: set True to parse and print without calling ADO API
# ---------------------------------------------------------------------------
DRY_RUN = False

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate():
    errors = []
    if not ADO_PAT:
        errors.append("ADO_PAT environment variable not set. Run: export ADO_PAT=<your-pat>")
    if "YOUR_ORG" in ADO_ORG:
        errors.append("ADO_ORG not configured in ado_config.py")
    if "YOUR_PROJECT" in ADO_PROJECT:
        errors.append("ADO_PROJECT not configured in ado_config.py")
    return errors
