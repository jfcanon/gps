# Azure Infra Security Gap Assessment

## Objective

Map current Azure infrastructure security posture against MCSB v2 (preview) 12 security domains.
Identify gaps. Produce prioritized ADO work items for cloud engineering team.

## Primary Driver

**MCSB v2 (preview)** — Microsoft Cloud Security Benchmark  
Source: [Microsoft Learn - MCSB v2 preview](https://learn.microsoft.com/en-us/security/benchmark/azure/)

## Input Sources

| Source | Format | Status | Purpose |
|--------|--------|--------|---------|
| MCSB v2 (preview) | MS Learn / GitHub Excel | Reference | Primary control list — 12 domains |
| MCSB v3 (old) | GitHub Excel (118 controls) | Reference | Control cross-reference |
| Optive PDF report | CSV (parsed via docling → MCSB v3 format) | Ready | Previous assessment coverage |
| Azure Policy export | JSON | Raw | Current enforcement state |
| Azure Defender export | JSON | Raw | Current detection/coverage state |
| ADO items export | JSON/CSV | Raw | Cloud eng team existing work |

## MCSB v2 — 12 Security Domains

1. Network Security (NS)
2. Identity Management (IM)
3. Privileged Access (PA)
4. Data Protection (DP)
5. Asset Management (AM)
6. Logging and Threat Detection (LT)
7. Incident Response (IR)
8. Posture and Vulnerability Management (PV)
9. Endpoint Security (ES)
10. Backup and Recovery (BR)
11. DevOps Security (DS)
12. Governance and Strategy (GS)

## Approach

Skip Excel consolidation. Use Python pipeline:

```
MCSB v2 controls (rows)
  + Optive CSV (join on control ID)
  + Az Policy JSON (parse → coverage flag)
  + Defender JSON (parse → coverage flag)
  + ADO export (fuzzy match on control keywords)
  → gap_matrix.csv
  → ado_items_to_create.csv
```

## Output

- `data/outputs/gap_matrix.csv` — all controls with coverage flags
- `data/outputs/ado_items_to_create.csv` — net-new gaps only
- `ado/` — ADO work item templates (12 epics, features, user stories)

## Repo Structure

```
NewSecGap/
├── data/
│   ├── inputs/     # drop raw files here
│   └── outputs/    # generated gap analysis
├── scripts/        # Python processing pipeline
├── ado/            # ADO templates and exports
└── docs/           # MCSB domain reference docs
```
