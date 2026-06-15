# Asset Management (AM) — User Stories

7 user stories: 6 combined (v2+v3, one per resource) + 1 pure v2.
Phase 19 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-AM] Asset Management — MCSB v2

---

## [SEC-AM] Asset Management — 5 Controls, 7 Stories

### 1 Track Asset Inventory and Their Risks [2 combined]

**[SEC-1] Track Asset Inventory and Their Risks: Resource Graph**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Resource Graph asset inventory coverage — cross-subscription query scope for all resource types, tag compliance reporting completeness, stale resource detection (orphaned disks, NICs, and public IPs), and security configuration drift query coverage — so that AM-1 gaps in asset visibility and risk tracking across the Azure estate are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Resource Graph asset inventory controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Azure Resource Graph cross-subscription queries and tag compliance manual audit.

**Acceptance Criteria:**
- Resource Graph AM-1 configuration assessed against MCSB baseline and subscriptions without cross-subscription inventory query coverage, missing tag compliance reporting, or stale resources (orphaned disks, NICs, PIPs) without detection workflow identified.
- Azure Policy coverage for asset inventory controls evaluated; built-ins absent for this resource — assessment relies on Resource Graph KQL query coverage and tag policy assignment manual audit.
- Gap findings documented with remediation scope and affected subscription scope, resource type inventory gaps, and stale resource configurations noted.

---

**[SEC-1] Track Asset Inventory and Their Risks: Migrate**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Migrate asset inventory and assessment security posture — discovered asset inventory accuracy, sensitivity classification of assessment data (IP and configuration data), migration readiness security review completeness, and dependency analysis data access restriction — so that AM-1 gaps in migration asset visibility and assessment data protection are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Migrate asset inventory controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Migrate project access controls and assessment data sensitivity manual audit.

**Acceptance Criteria:**
- Azure Migrate AM-1 configuration assessed against MCSB baseline and projects with incomplete asset discovery, unclassified assessment data sensitivity, or unrestricted dependency analysis access identified.
- Azure Policy coverage for Migrate asset inventory controls evaluated; built-ins absent for this resource — assessment relies on Migrate project RBAC and assessment data access manual audit.
- Gap findings documented with remediation scope and affected Migrate project, discovered asset scope, and dependency analysis access configurations noted.

---

### 2 Use Only Approved Services [1 combined]

**[SEC-2] Use Only Approved Services: Policy**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Policy configuration for approved service enforcement — allowed resource types initiative assignment at management group scope, deny effect coverage for unapproved resource types, allowed locations enforcement for data residency compliance, and Marketplace restriction policy status — so that AM-2 gaps where non-approved resource types or out-of-region deployments are permitted without policy control are identified. Key Azure Policy built-ins applicable: ["Allowed resource types"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Allowed locations"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Azure Policy AM-2 configuration assessed against MCSB baseline and management groups or subscriptions without allowed resource type initiatives, missing deny-effect assignments for unapproved types, or absent data residency location restrictions identified.
- Azure Policy compliance evaluated for: ["Allowed resource types"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Allowed locations"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected policy initiative scope, resource type allowlist, and location restriction configurations noted.

---

### 3 Ensure Security of Asset Lifecycle Management [2 combined]

**[SEC-3] Ensure Security of Asset Lifecycle Management: Resource Mover**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Resource Mover security controls for asset lifecycle operations — RBAC configuration for move operation authorization, security control validation post-move (NSG rules, private endpoint, and tag preservation), move collection audit log coverage, and rollback capability testing evidence — so that AM-3 gaps where resource moves bypass security validation or lack audit oversight are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Resource Mover asset lifecycle controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on move collection RBAC and post-move security validation manual audit.

**Acceptance Criteria:**
- Resource Mover AM-3 configuration assessed against MCSB baseline and move collections without least-privilege RBAC, missing post-move security control validation checklists, or absent audit logging identified.
- Azure Policy coverage for Resource Mover lifecycle controls evaluated; built-ins absent for this resource — assessment relies on move collection RBAC assignment and audit log configuration manual audit.
- Gap findings documented with remediation scope and affected Resource Mover collection, move operation RBAC, and post-move security validation configurations noted.

---

**[SEC-3] Ensure Security of Asset Lifecycle Management: DevTest Labs**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure DevTest Labs asset lifecycle security controls — approved VM image policy coverage (marketplace images only, no unapproved custom images), auto-shutdown policy enforcement, cost limit configuration, lab RBAC assignment (no Owner role for lab users), and artifact source security review — so that AM-3 gaps where lab environments deploy unapproved images or grant excessive management plane privilege are identified. Key Azure Policy built-ins applicable: ⚠️ ["DevTest Labs should use approved marketplace images"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- DevTest Labs AM-3 configuration assessed against MCSB baseline and labs without approved image policies, missing auto-shutdown enforcement, or with Owner role assigned to lab users identified.
- Azure Policy compliance evaluated for image allowlist controls applicable to DevTest Labs; ⚠️ "DevTest Labs should use approved marketplace images" flagged for display name verification.
- Gap findings documented with remediation scope and affected lab image policy, auto-shutdown configuration, cost limit, and RBAC assignment instances noted.

---

### 4 Limit Access to Asset Management [1 combined]

**[SEC-4] Limit Access to Asset Management: Resource Manager**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Resource Manager management plane access controls — RBAC least privilege compliance (no Owner at subscription scope for non-privileged users), CanNotDelete lock coverage on production resources, ARM template deployment audit log completeness, and absence of broad Contributor assignments at tenant root — so that AM-4 gaps in asset management plane access control and production resource protection are identified. Key Azure Policy built-ins applicable: ["Audit usage of custom RBAC roles"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Resource Manager AM-4 configuration assessed against MCSB baseline and subscriptions with Owner assigned to non-privileged users, missing CanNotDelete locks on production resources, or broad Contributor at tenant root identified.
- Azure Policy compliance evaluated for: ["Audit usage of custom RBAC roles"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected management plane RBAC assignments, resource lock coverage, and ARM deployment audit log configurations noted.

---

### 5 Use Only Approved Applications in Virtual Machine [pure v2]

**[SEC-5] Use Only Approved Applications in Virtual Machine**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess approved application controls across production virtual machines — Defender for Cloud Adaptive Application Controls allowlist configuration and coverage on production VMs, software inventory completeness via Azure Monitor Agent, unapproved software installation alert configuration, Windows AppLocker or WDAC policy deployment status, and Linux file integrity monitoring via Microsoft Defender for Endpoint — so that AM-5 gaps where VMs operate without application allowlist enforcement are identified. Key Azure Policy built-ins applicable: ["Adaptive application controls for defining safe applications should be enabled on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Allowlist rules in your adaptive application control policy should be updated"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Approved application AM-5 configuration assessed across production VMs and machines without Adaptive Application Controls allowlist configuration, missing software inventory via AMA, or lacking AppLocker/WDAC (Windows) or FIM (Linux) enforcement identified.
- Azure Policy compliance evaluated for: ["Adaptive application controls for defining safe applications should be enabled on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Allowlist rules in your adaptive application control policy should be updated"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected VM application control policy, software inventory coverage, and platform-specific enforcement configurations noted.
