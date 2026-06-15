# Logging and Threat Detection (LT) — User Stories

8 user stories: 3 combined (v2+v3, one per resource) + 5 pure v2.
Phase 20 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-LT] Logging and Threat Detection — MCSB v2

---

## [SEC-LT] Logging and Threat Detection — 7 Controls, 8 Stories

### 1 Enable Threat Detection Capabilities [1 combined]

**[SEC-1] Enable Threat Detection Capabilities: Defender for Cloud**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Microsoft Defender for Cloud plan coverage — all Defender for Cloud threat detection plans enabled (Servers P2, Storage, SQL, Containers, AppService, KeyVault, DNS, ARM, and DevOps), MDE auto-provisioning status for all VMs, and threat detection alert routing configuration to Sentinel — so that LT-1 gaps in comprehensive threat detection coverage and alert orchestration are identified. Key Azure Policy built-ins applicable: ["Microsoft Defender for Servers should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for Storage should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for SQL should be enabled for SQL Servers"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for Containers should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for App Service should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for Key Vault should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for DNS should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for Azure Resource Manager should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ⚠️ ["Microsoft Defender for DevOps should be enabled"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Defender for Cloud LT-1 configuration assessed against MCSB baseline and subscriptions with unconfigured Defender plans (Servers P2, Storage, SQL, Containers, AppService, KeyVault, DNS, ARM, DevOps), missing MDE auto-provisioning on VMs, or absent alert routing to Sentinel identified.
- Azure Policy compliance evaluated for: ["Microsoft Defender for Servers should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for Storage should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for SQL should be enabled for SQL Servers"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for Containers should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for App Service should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Microsoft Defender for Key Vault should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected plan configurations, VM inventory scope, and Sentinel routing configurations noted.

---

### 2 Enable Threat Detection for Identity and Access Management [pure v2]

**[SEC-2] Enable Threat Detection for Identity and Access Management**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure AD Identity Protection and security log coverage — active sign-in risk and user risk policies, Entra ID Audit and Sign-in logs routing to Sentinel, Sentinel analytics rules for impossible travel, password spray, legacy auth sign-in, and MFA fatigue, UEBA configuration status, and privileged role activation alert setup — so that LT-2 gaps in identity threat detection and anomaly monitoring are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure AD Identity Protection in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Azure AD risk policy configuration and Sentinel analytics rule manual audit.

**Acceptance Criteria:**
- Azure AD Identity Protection LT-2 configuration assessed against MCSB baseline and tenants with inactive sign-in or user risk policies, missing Entra ID log routing to Sentinel, absent analytics rules for critical threat patterns, or unconfigured UEBA and privileged activation alerting identified.
- Azure Policy coverage for identity threat detection controls evaluated; built-ins absent for this control — assessment relies on Azure AD Identity Protection risk policy configuration and Sentinel analytics rule coverage manual audit.
- Gap findings documented with remediation scope and affected risk policy types, log source routing paths, and analytics rule coverage noted.

---

### 3 Enable Logging for Security Investigation [pure v2]

**[SEC-3] Enable Logging for Security Investigation**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess diagnostic settings coverage across all resource types — Azure Policy DeployIfNotExists assignments for diagnostic settings to Log Analytics, Activity Log routing to Log Analytics workspace, resource log retention settings (90 days interactive and 1 year archive), and admin and key management operations log completeness — so that LT-3 gaps in comprehensive security log collection and retention are identified. Key Azure Policy built-ins applicable: ⚠️ ["Deploy Diagnostic Settings for specific resource types"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact initiative name), ["Resource logs in Key Vault should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Diagnostic settings LT-3 configuration assessed against MCSB baseline and resource types without DeployIfNotExists diagnostic policy assignments, missing Activity Log routing to Log Analytics, or retention configurations below 90-day interactive and 1-year archive thresholds identified.
- Azure Policy compliance evaluated for diagnostic settings deployment initiative coverage; ⚠️ DeployIfNotExists initiative display name flagged for verification against current MCSB v2 preview policy list.
- Gap findings documented with remediation scope and affected resource types, log routing paths, and retention configuration instances noted.

---

### 4 Enable Network Logging for Security Investigation [pure v2]

**[SEC-4] Enable Network Logging for Security Investigation**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess network logging configurations — NSG Flow Logs v2 enabled on all NSGs with Storage Account routing and Traffic Analytics, Azure Firewall diagnostic logs routing to Log Analytics, Application Gateway access and WAF logs forwarding, Defender for DNS query log coverage, and Network Watcher packet capture policy documentation — so that LT-4 gaps in network traffic visibility and threat investigation capability are identified. Key Azure Policy built-ins applicable: ["Flow logs should be configured for every network security group"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Network Watcher should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Network logging LT-4 configuration assessed against MCSB baseline and NSGs without Flow Logs v2 enabled, missing Traffic Analytics configuration, absent Azure Firewall or Application Gateway log routing, or undocumented Network Watcher packet capture policy identified.
- Azure Policy compliance evaluated for: ["Flow logs should be configured for every network security group"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Network Watcher should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected NSG instances, firewall diagnostic configurations, and log forwarding path coverage noted.

---

### 5 Centralize Security Log Management and Analysis [2 combined]

**[SEC-5] Centralize Security Log Management and Analysis: Sentinel**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Microsoft Sentinel SIEM configuration — workspace coverage and data connector assignment for all Azure log sources, analytics rules mapped to MCSB v2 domains, RBAC configurations limiting SOC analysts to read-only access, and incident assignment workflow status — so that LT-5 gaps in centralized log analysis and incident triage coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Sentinel SIEM configuration in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Sentinel workspace data connector and analytics rule coverage manual audit.

**Acceptance Criteria:**
- Sentinel LT-5 configuration assessed against MCSB baseline and workspaces with missing data connectors for Azure log sources, analytics rules not mapped to MCSB v2 domains, SOC analyst RBAC exceeding read-only scope, or absent incident assignment workflows identified.
- Azure Policy coverage for Sentinel SIEM configuration evaluated; built-ins absent for this resource — assessment relies on Sentinel data connector coverage, analytics rule mapping, and RBAC configuration manual audit.
- Gap findings documented with remediation scope and affected data connector sources, analytics rule domain mappings, and SOC RBAC configurations noted.

---

**[SEC-5] Centralize Security Log Management and Analysis: Monitor**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Monitor configuration for centralized log management — diagnostic settings deployment via DeployIfNotExists policy assignment scope, Log Analytics workspace consolidation (single workspace per region), alert rules configured for critical security events, and data collection rules coverage for Azure Monitor Agent — so that LT-5 gaps in unified log management and security alerting are identified. Key Azure Policy built-ins applicable: ⚠️ ["Deploy Diagnostic Settings for specific resource types"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact initiative name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Azure Monitor LT-5 configuration assessed against MCSB baseline and subscriptions with fragmented Log Analytics workspace deployment, missing DeployIfNotExists diagnostic policy assignments, or absent alert rules for critical security events identified.
- Azure Policy compliance evaluated for diagnostic settings deployment initiative coverage; ⚠️ DeployIfNotExists initiative display name flagged for verification against current MCSB v2 preview policy list.
- Gap findings documented with remediation scope and affected workspace consolidation, diagnostic policy assignment scope, and security alert rule configurations noted.

---

### 6 Configure Log Storage Retention [pure v2]

**[SEC-6] Configure Log Storage Retention**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess log retention configurations across storage tiers — Log Analytics workspace interactive retention (90 days minimum), Auxiliary Logs tier implementation for 1-year lower-cost retention, Azure Monitor Logs archive tier for 2-year compliance retention, Sentinel data retention alignment with workspace settings, and Storage Account WORM immutability configuration for archived security logs — so that LT-6 gaps in long-term log retention and audit compliance are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for log storage retention in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Log Analytics workspace and Storage Account retention settings manual audit.

**Acceptance Criteria:**
- Log retention LT-6 configuration assessed against MCSB baseline and workspaces with interactive retention below 90 days, missing Auxiliary or archive tier configuration for long-term retention, or absent WORM immutability on Storage Accounts holding archived security logs identified.
- Azure Policy coverage for log storage retention controls evaluated; built-ins absent for this control — assessment relies on Log Analytics workspace retention settings, archive tier assignment, and Storage Account immutability configuration manual audit.
- Gap findings documented with remediation scope and affected workspace retention tiers, archive configuration, and WORM immutability implementation details noted.

---

### 7 Use Approved Time Synchronization Sources [pure v2]

**[SEC-7] Use Approved Time Synchronization Sources**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess time synchronization coverage across compute resources — Windows Time (w32tm) configuration synced to Azure NTP service (168.63.129.16) across all Azure VMs, NTP sync verification for Arc-enabled servers, and time skew detection in Log Analytics (query threshold: >1 minute skew triggering alert) — so that LT-7 gaps in temporal consistency for Sentinel security event correlation accuracy are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for NTP time synchronization in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on VM NTP configuration and Log Analytics time skew query manual audit.

**Acceptance Criteria:**
- Time synchronization LT-7 configuration assessed against MCSB baseline and VMs without Azure NTP service (168.63.129.16) configuration, Arc-enabled servers with unverified NTP sync, or Log Analytics environments without time skew alerting identified.
- Azure Policy coverage for time synchronization controls evaluated; built-ins absent for this control — assessment relies on Windows Time service configuration and Log Analytics time skew query manual audit.
- Gap findings documented with remediation scope and affected VM NTP configurations, Arc server sync verification status, and time skew alert threshold settings noted.
