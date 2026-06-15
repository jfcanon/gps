# Backup and Recovery (BR) — User Stories

4 user stories: 2 combined (v2+v3, one per resource) + 2 pure v2.
Phase 24 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-BR] Backup and Recovery — MCSB v2

---

## [SEC-BR] Backup and Recovery — 4 Controls, 4 Stories

### 1 Ensure Regular Automated Backups [1 combined]

**[SEC-1] Ensure Regular Automated Backups: Backup**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Backup coverage for all production workloads — backup policy assignment for production VMs, SQL databases (in-VM and Azure SQL), Blob Storage, Azure Files, and Key Vault, geo-redundant Recovery Services vault configuration, RPO and RTO definition per workload tier, and immutable vault enablement — so that BR-1 gaps in backup coverage scope and retention configuration are identified. Key Azure Policy built-ins applicable: ["Azure Backup should be enabled for Virtual Machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ⚠️ [No confirmed Azure Policy built-ins for SQL/Blob/Files/Key Vault backup coverage in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Azure Backup policy assignment scope and Recovery Services vault configuration manual audit.

**Acceptance Criteria:**
- Azure Backup BR-1 configuration assessed against MCSB baseline and production VMs without Backup policy enabled, workload types (SQL, Blob, Files, Key Vault) without backup policy assignment, or Recovery Services vaults without geo-redundant storage identified.
- Azure Policy compliance evaluated for: ["Azure Backup should be enabled for Virtual Machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference); ⚠️ SQL/Blob/Files/Key Vault backup built-in display names flagged for verification against current MCSB v2 preview policy list.
- Gap findings documented with remediation scope and affected workload backup policy assignments, Recovery Services vault geo-redundancy, immutable vault status, and RPO/RTO documentation completeness noted.

---

### 2 Protect Backup and Recovery Data [pure v2]

**[SEC-2] Protect Backup and Recovery Data**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess backup vault security configuration — immutable vault enablement, soft delete configuration (14-day retention minimum), CMK encryption of vault via Key Vault, Backup Operator RBAC separation (no production subscription Owner access for backup accounts), and cross-subscription restore restriction status — so that BR-2 gaps in backup data protection and access control are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for backup vault immutability and soft delete in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Recovery Services vault security settings and RBAC assignment manual audit.

**Acceptance Criteria:**
- Backup vault BR-2 configuration assessed against MCSB baseline and vaults without immutable vault enabled, soft delete configured below 14-day retention, CMK encryption absent, or Backup Operator accounts with production subscription Owner access identified.
- Azure Policy coverage for backup vault security controls evaluated; built-ins absent for this control — assessment relies on Recovery Services vault immutability settings, soft delete configuration, CMK key assignment, and RBAC role separation manual audit.
- Gap findings documented with remediation scope and affected vault immutability settings, soft delete retention configuration, CMK encryption status, RBAC role assignments, and quarterly access review records noted.

---

### 3 Monitor Backups [pure v2]

**[SEC-3] Monitor Backups**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Backup monitoring configuration — backup job failure alert configuration routing to Action Groups, backup reporting coverage via Azure Monitor Workbook, Recovery Services vault backup compliance report review cadence, alert trigger completeness (job failure, backup not run in more than 25 hours, policy non-compliance), and weekly backup health review scheduling — so that BR-3 gaps in backup monitoring visibility and alerting coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Backup monitoring configuration in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Azure Backup alert rule configuration and Monitor Workbook coverage manual audit.

**Acceptance Criteria:**
- Backup monitoring BR-3 configuration assessed against MCSB baseline and vaults without backup job failure alerts configured, missing Action Group routing, absent Azure Monitor Workbook backup reporting, or alert triggers not covering the 25-hour backup window and policy non-compliance scenarios identified.
- Azure Policy coverage for backup monitoring controls evaluated; built-ins absent for this control — assessment relies on Azure Backup alert rule configuration, Action Group routing, and backup compliance report review record manual audit.
- Gap findings documented with remediation scope and affected alert trigger configurations, Action Group routing, Monitor Workbook coverage, and weekly health review scheduling noted.

---

### 4 Regularly Test Backup [1 combined]

**[SEC-4] Regularly Test Backup: Site Recovery**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Site Recovery DR testing program — replication health monitoring status across all protected workloads, quarterly failover test execution evidence, RTO measurement against target per workload, failback validation in isolated environment, and semi-annual recovery plan documentation review — so that BR-4 gaps in DR testing cadence and RTO validation are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Site Recovery DR testing in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Site Recovery replication health dashboard and failover test records manual audit.

**Acceptance Criteria:**
- Site Recovery BR-4 configuration assessed against MCSB baseline and protected workloads with degraded replication health, absent quarterly failover test records, RTO measurements exceeding defined targets, or recovery plans without semi-annual review documentation identified.
- Azure Policy coverage for Site Recovery DR testing controls evaluated; built-ins absent for this resource — assessment relies on Site Recovery replication health status, failover test execution records, and recovery plan documentation manual audit.
- Gap findings documented with remediation scope and affected replication health status, failover test cadence, RTO measurement records, failback validation evidence, and recovery plan review documentation noted.
