# Identity Management (IM) — User Stories

10 user stories: 7 combined (v2+v3, one per resource) + 3 pure v2.
Phase 16 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-IM] Identity Management — MCSB v2

---

## [SEC-IM] Identity Management — 8 Controls, 10 Stories

### 1 Use Centralized Identity and Authentication System [1 combined]

**[SEC-1] Use Centralized Identity and Authentication System: Active Directory Domain Services**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Active Directory Domain Services hybrid identity posture — AAD Connect Health monitoring status, LDAP over TLS (port 636) enforcement, domain controller hardening baseline, Tier-0 asset Conditional Access coverage, and on-premises to Entra ID federation configuration — so that IM-1 gaps in centralized identity sync and hybrid authentication integrity are identified and documented. Key Azure Policy built-ins applicable: ⚠️ ["Azure Active Directory Domain Services managed domains should use TLS 1.2 only mode"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name; no dedicated AD DS policy-reference page confirmed in MCSB v2 preview).

**Acceptance Criteria:**
- Active Directory Domain Services IM-1 configuration assessed against MCSB baseline and deviations from hybrid identity sync security and domain controller hardening standards identified.
- Azure Policy compliance evaluated for TLS 1.2 enforcement on managed domain; gaps in policy automation for AD DS noted where built-ins are absent.
- Gap findings documented with remediation scope and affected domain controllers, sync configurations, and Entra ID federation settings noted.

---

### 2 Protect Identity and Authentication Systems [pure v2]

**[SEC-2] Protect Identity and Authentication Systems**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Entra ID Identity Protection configuration — user risk and sign-in risk policy thresholds, risky user and sign-in alert routing to Sentinel, password protection with banned password list, smart lockout policy, and AAD Connect Health monitoring coverage — so that IM-2 gaps in proactive identity threat detection and authentication resilience are identified. Key Azure Policy built-ins applicable: ["MFA should be enabled on accounts with owner permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["MFA should be enabled on accounts with write permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Identity Protection IM-2 configuration assessed against MCSB baseline and tenants without risk policies, Sentinel alert routing, or smart lockout enforcement identified.
- Azure Policy compliance evaluated for: ["MFA should be enabled on accounts with owner permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["MFA should be enabled on accounts with write permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected Identity Protection policy and alert configuration noted.

---

### 3 Manage Application Identities Securely and Automatically [2 combined]

**[SEC-3] Manage Application Identities Securely and Automatically: Bot Service**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Bot Service identity configuration — managed identity assignment for bot app authentication, absence of stored credentials in app settings, Azure AD token validation for Direct Line channel, and HTTPS enforcement across all bot channels — so that IM-3 gaps where bot workloads rely on static credentials or unauthenticated channel access are identified. Key Azure Policy built-ins applicable: ⚠️ ["Bot Service endpoint should be a valid HTTPS URI"](https://learn.microsoft.com/en-us/azure/bot-service/policy-reference) (training data — verify exact display name and IM-3 mapping against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Bot Service IM-3 configuration assessed against MCSB baseline and bot registrations without managed identity, with stored credentials, or with HTTP-accessible channels identified.
- Azure Policy compliance evaluated for HTTPS endpoint enforcement controls applicable to Bot Service; gaps in managed identity policy automation noted.
- Gap findings documented with remediation scope and affected Bot Service registration and channel configurations noted.

---

**[SEC-3] Manage Application Identities Securely and Automatically: Universal Print**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Universal Print identity configuration — managed identity assignment for print connector authentication, Azure AD group-based print queue access control, and absence of shared credentials for printer registration — so that IM-3 gaps where print connectors authenticate with static credentials or queues lack group-based access control are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Universal Print in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on connector managed identity and print queue RBAC manual audit.

**Acceptance Criteria:**
- Universal Print IM-3 configuration assessed against MCSB baseline and connectors without managed identity or queues without Azure AD group access control identified.
- Azure Policy coverage for Universal Print controls evaluated; built-ins absent for this resource — assessment relies on Defender for Cloud recommendations and manual configuration audit.
- Gap findings documented with remediation scope and affected print connector and queue access control configurations noted.

---

### 4 Authenticate Server and Services [2 combined]

**[SEC-4] Authenticate Server and Services: Attestation**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Attestation service identity and authentication posture — mTLS enforcement for attestation requests, policy signing certificate approval status, audit logging of attestation request events, and private endpoint configuration for the attestation endpoint — so that IM-4 gaps in service-to-service authentication integrity and attestation policy governance are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure Attestation providers should disable public network access"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Attestation IM-4 configuration assessed against MCSB baseline and providers without private endpoint, missing mTLS enforcement, or unsigned attestation policies identified.
- Azure Policy compliance evaluated for public network access controls applicable to Azure Attestation; gaps in built-in policy coverage noted.
- Gap findings documented with remediation scope and affected Attestation provider and policy signing configurations noted.

---

**[SEC-4] Authenticate Server and Services: Trusted Hardware Identity Management**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Trusted Hardware Identity Management service configuration — hardware identity certificate chain validation process, managed identity integration for THIM service operations, and audit logging coverage of certificate issuance and renewal events — so that IM-4 gaps in hardware certificate trust chain integrity and service identity management are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Trusted Hardware Identity Management in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on certificate chain and managed identity manual audit.

**Acceptance Criteria:**
- Trusted Hardware Identity Management IM-4 configuration assessed against MCSB baseline and instances with unvalidated certificate chains or missing managed identity integration identified.
- Azure Policy coverage for THIM controls evaluated; built-ins absent for this resource — assessment relies on Defender for Cloud recommendations and manual configuration audit.
- Gap findings documented with remediation scope and affected THIM certificate issuance and renewal audit log configurations noted.

---

### 5 Use Single Sign-On (SSO) for Application Access [1 combined]

**[SEC-5] Use Single Sign-On (SSO) for Application Access: API Management**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess API Management identity and SSO configuration — OAuth2/OIDC policy coverage for API consumer authentication, managed identity assignment for backend service calls, subscription key rotation policy and scope restrictions, and developer portal Entra ID integration status with local account usage — so that IM-5 gaps where APIs are accessible without federated identity or via over-scoped subscription keys are identified. Key Azure Policy built-ins applicable: ["API Management subscriptions should not be scoped to all APIs"](https://learn.microsoft.com/en-us/azure/api-management/policy-reference), ⚠️ ["API Management calls to API backends should be authenticated"](https://learn.microsoft.com/en-us/azure/api-management/policy-reference) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- API Management IM-5 configuration assessed against MCSB baseline and services with subscription keys scoped to all APIs, local developer portal accounts, or backends without authenticated managed identity calls identified.
- Azure Policy compliance evaluated for: ["API Management subscriptions should not be scoped to all APIs"](https://learn.microsoft.com/en-us/azure/api-management/policy-reference) and applicable backend authentication controls.
- Gap findings documented with remediation scope and affected API Management service, product, and backend connection configurations noted.

---

### 6 Use Strong Authentication Controls [pure v2]

**[SEC-6] Use Strong Authentication Controls**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess tenant-wide MFA and authentication control configuration — Conditional Access MFA policy coverage for all users and privileged roles, legacy authentication protocol block policy status, phishing-resistant MFA method (FIDO2/Windows Hello for Business) enforcement for privileged users, and Authenticator number matching and additional context enablement — so that IM-6 gaps in strong authentication coverage and legacy protocol exposure are identified. Key Azure Policy built-ins applicable: ["MFA should be enabled on accounts with owner permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["MFA should be enabled on accounts with write permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["MFA should be enabled on accounts with read permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Strong authentication IM-6 configuration assessed across the tenant and accounts without MFA Conditional Access coverage, legacy authentication policy gaps, or privileged users lacking phishing-resistant MFA methods identified.
- Azure Policy compliance evaluated for: ["MFA should be enabled on accounts with owner permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["MFA should be enabled on accounts with write permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["MFA should be enabled on accounts with read permissions on your subscription"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected Conditional Access policies, user populations, and authentication method configurations noted.

---

### 7 Restrict Resource Access Based on Conditions [1 combined]

**[SEC-7] Restrict Resource Access Based on Conditions: Spatial Anchors**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Spatial Anchors identity and access configuration — Conditional Access policy coverage for spatial anchor access token issuance, RBAC assignment audit across Spatial Anchors Account Owner, Reader, and Contributor roles, and diagnostic log configuration for anchor access events — so that IM-7 gaps in condition-based access enforcement and least-privilege RBAC for spatial anchor resources are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Spatial Anchors in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Conditional Access policy coverage and RBAC manual audit.

**Acceptance Criteria:**
- Spatial Anchors IM-7 configuration assessed against MCSB baseline and accounts without Conditional Access token issuance controls or with over-privileged RBAC assignments identified.
- Azure Policy coverage for Spatial Anchors controls evaluated; built-ins absent for this resource — assessment relies on Defender for Cloud recommendations and Conditional Access manual audit.
- Gap findings documented with remediation scope and affected Spatial Anchors account, access token policy, and RBAC configurations noted.

---

### 8 Restrict the Exposure of Credential and Secrets [pure v2]

**[SEC-8] Restrict the Exposure of Credential and Secrets**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess secrets and credential exposure posture across the environment — Key Vault usage coverage versus plaintext secrets in configs, code, environment variables, and ADO pipelines, Defender for DevOps secret scanning status in connected repositories, service principal secret expiry enforcement (90-day maximum), and storage shared key authentication disabled status — so that IM-8 gaps in credential hygiene and secret sprawl are identified and scoped for remediation. Key Azure Policy built-ins applicable: ["Key vaults should have soft delete enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key Vault secrets should have an expiration date set"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).

**Acceptance Criteria:**
- Secrets exposure IM-8 configuration assessed against MCSB baseline and environments with plaintext credentials, missing Key Vault adoption, disabled secret scanning, or service principals without expiry enforcement identified.
- Azure Policy compliance evaluated for: ["Key vaults should have soft delete enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key Vault secrets should have an expiration date set"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).
- Gap findings documented with remediation scope and affected secret storage configurations, repositories, service principals, and storage account authentication settings noted.
