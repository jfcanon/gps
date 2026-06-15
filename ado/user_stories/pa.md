# Privileged Access (PA) — User Stories

8 user stories: 4 combined (v2+v3, one per resource) + 4 pure v2.
Phase 17 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-PA] Privileged Access — MCSB v2

---

## [SEC-PA] Privileged Access — 8 Controls, 8 Stories

### 1 Separate and Limit Highly Privileged Users [pure v2]

**[SEC-1] Separate and Limit Highly Privileged Users**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess the scope and configuration of highly privileged role assignments across the tenant — Global Administrator count and cloud-only status, Subscription Owner inventory, PIM coverage for eligible role assignments, and privileged role reduction exercise documentation — so that PA-1 gaps where standing privileged access exceeds MCSB baseline thresholds or where on-premises synced accounts hold privileged roles are identified. Key Azure Policy built-ins applicable: ["There should be more than one owner assigned to your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["A maximum of 3 owners should be designated for your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Privileged role assignment PA-1 configuration assessed across the tenant and deviations from MCSB privileged user count thresholds, cloud-only account requirements, and PIM eligibility coverage identified.
- Azure Policy compliance evaluated for: ["There should be more than one owner assigned to your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["A maximum of 3 owners should be designated for your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected privileged role assignments, synced accounts, and PIM configuration instances noted.

---

### 2 Avoid Standing Access for User Accounts and Permissions [1 combined]

**[SEC-2] Avoid Standing Access for User Accounts and Permissions: Automation**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Automation account identity and access configuration — system-assigned managed identity adoption replacing deprecated RunAs accounts, runbook execution scheduling for just-in-time privileged sessions, private endpoint network isolation for the Automation account, and audit log coverage for runbook executions — so that PA-2 gaps where standing privileged access persists through Automation RunAs accounts or always-on execution schedules are identified. Key Azure Policy built-ins applicable: ["Automation account variables should be encrypted"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ⚠️ ["Azure Automation accounts should disable public network access"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Automation PA-2 configuration assessed against MCSB baseline and accounts with active RunAs accounts, always-on privileged runbook schedules, or missing private endpoint identified.
- Azure Policy compliance evaluated for: ["Automation account variables should be encrypted"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) and applicable public network access controls.
- Gap findings documented with remediation scope and affected Automation account, RunAs credential, and runbook schedule configurations noted.

---

### 3 Manage Lifecycle of Identities and Entitlements [pure v2]

**[SEC-3] Manage Lifecycle of Identities and Entitlements**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess identity lifecycle management configuration — Entra ID Entitlement Management access package coverage and approval workflow status, SCIM-based automated provisioning and deprovisioning for connected applications, Joiner-Mover-Leaver process documentation and testing evidence, stale account detection threshold enforcement (90+ days inactive leading to auto-disable), and guest account expiry policy — so that PA-3 gaps in entitlement lifecycle automation and orphaned account risk are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for identity lifecycle management controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Entra ID Governance Entitlement Management and manual lifecycle process audit.

**Acceptance Criteria:**
- Identity lifecycle PA-3 configuration assessed across the tenant and missing access packages, SCIM provisioning gaps, undocumented JML processes, or stale accounts beyond the 90-day threshold identified.
- Azure Policy coverage for identity lifecycle controls evaluated; built-ins absent for this control — assessment relies on Entra ID Governance Entitlement Management and SCIM connector manual audit.
- Gap findings documented with remediation scope and affected access packages, SCIM connectors, and guest account expiry configurations noted.

---

### 4 Review and Reconcile User Access Regularly [pure v2]

**[SEC-4] Review and Reconcile User Access Regularly**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Entra ID Access Review configuration and cadence — quarterly privileged role review schedule, semi-annual group membership review coverage, reviewer assignment (line manager or resource owner), no-response action setting (auto-deny versus auto-approve), and Access Review outcome audit log routing — so that PA-4 gaps in regular access reconciliation coverage and auto-approve misconfiguration risk are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for access review scheduling or configuration in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Entra ID Governance Access Reviews manual audit.

**Acceptance Criteria:**
- Access review PA-4 configuration assessed across the tenant and privileged roles or group memberships without active quarterly or semi-annual review schedules, or reviews configured with auto-approve on no response, identified.
- Azure Policy coverage for access review controls evaluated; built-ins absent for this control — assessment relies on Entra ID Governance Access Reviews configuration manual audit.
- Gap findings documented with remediation scope and affected Access Review scope, reviewer assignments, and no-response action configurations noted.

---

### 5 Set Up Emergency Access [pure v2]

**[SEC-5] Set Up Emergency Access**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess emergency access (break-glass) account configuration — presence of two cloud-only Global Administrator break-glass accounts, absence of shared MFA methods with production accounts, split-custody password storage documentation, Conditional Access policy exclusion status, sign-in alert configuration for any break-glass usage, and quarterly validation test evidence — so that PA-5 gaps in emergency access readiness and monitoring coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for emergency access account configuration in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Entra ID account configuration and Conditional Access exclusion manual audit.

**Acceptance Criteria:**
- Emergency access PA-5 configuration assessed against MCSB baseline and tenants missing compliant break-glass accounts, with shared MFA methods, without Conditional Access exclusion, or lacking sign-in alerting identified.
- Azure Policy coverage for emergency access controls evaluated; built-ins absent for this control — assessment relies on Entra ID account configuration, Conditional Access, and monitoring manual audit.
- Gap findings documented with remediation scope and affected break-glass account configurations, CA policy exclusions, and sign-in alert settings noted.

---

### 6 Use Privileged Access Workstations [1 combined]

**[SEC-6] Use Privileged Access Workstations: Cloud Shell**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Cloud Shell privileged access workstation controls — Conditional Access policy coverage requiring compliant device or Bastion for Cloud Shell access, Cloud Shell storage account private endpoint configuration, RBAC access restrictions on the Cloud Shell storage account, and session audit logging enablement — so that PA-6 gaps where Cloud Shell is accessible from non-PAW devices or where Cloud Shell storage lacks network isolation are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Cloud Shell PAW enforcement in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — Conditional Access device compliance is an Entra ID control; Cloud Shell storage account network controls assessed via storage account policies.

**Acceptance Criteria:**
- Cloud Shell PA-6 configuration assessed against MCSB baseline and environments without compliant-device Conditional Access policy for Cloud Shell, missing storage account private endpoint, or absent session audit logging identified.
- Azure Policy coverage for Cloud Shell PAW controls evaluated; built-ins absent for this resource — Conditional Access device compliance is the primary assessment mechanism; storage account network controls assessed separately under NS-2.
- Gap findings documented with remediation scope and affected Cloud Shell storage account, Conditional Access policy, and audit log configurations noted.

---

### 7 Follow Just Enough Administration (Least Privilege) Principle [1 combined]

**[SEC-7] Follow Just Enough Administration (Least Privilege) Principle: Lighthouse**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Lighthouse managed tenant delegation configuration — role assignment least-privilege review across all active delegations, absence of Owner-level delegations (Contributor as maximum allowed role), quarterly delegation audit log review cadence, and customer-visible approval workflow documentation — so that PA-7 gaps where Lighthouse delegations grant excessive privilege or lack audit oversight are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure Lighthouse delegations should only be authorized to specific managing tenants"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Lighthouse PA-7 configuration assessed against MCSB baseline and delegations with Owner-level roles, missing least-privilege role review, or absent quarterly audit cadence identified.
- Azure Policy compliance evaluated for Lighthouse delegation scope controls; ⚠️ "Azure Lighthouse delegations should only be authorized to specific managing tenants" flagged for verification against current MCSB v2 preview policy list.
- Gap findings documented with remediation scope and affected Lighthouse delegation role assignments and managing tenant authorization configurations noted.

---

### 8 Choose Approval Process for Microsoft Support Access [1 combined]

**[SEC-8] Choose Approval Process for Microsoft Support Access: Customer Lockbox**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Customer Lockbox configuration for Microsoft support access approval — Lockbox enablement status at the tenant level, Lockbox Approver role assignment to designated security personnel, approval SLA awareness and auto-deny behavior within the 12-hour default window, and Lockbox request audit log routing to Microsoft Sentinel — so that PA-8 gaps where Microsoft support access bypasses customer approval or Lockbox request events lack security monitoring are identified. Key Azure Policy built-ins applicable: ["Customer Lockbox for Microsoft Azure should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Customer Lockbox PA-8 configuration assessed against MCSB baseline and tenants without Lockbox enabled, without designated Approver role assignments, or without Lockbox audit log routing to Sentinel identified.
- Azure Policy compliance evaluated for: ["Customer Lockbox for Microsoft Azure should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected Customer Lockbox enablement, Approver assignment, and audit log routing configurations noted.
