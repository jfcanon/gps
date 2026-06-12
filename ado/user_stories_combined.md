# User Stories — Combined v2+v3 Controls

159 user stories: 118 combined (one per v3 resource, prefixed with its v2 control) + 41 pure v2.
All flat under their domain Feature. No nesting.

Title format (combined): [SEC-{CODE}-{N}] {v2_title}: {v3_resource_name}
Title format (pure v2):  [SEC-{CODE}-{N}] {v2_title}
Parent (all):            [SEC-{CODE}] {Domain Full Name} — MCSB v2
Tags (combined):         MCSB-v2; {CODE}; v3; v2-paired; azure-infra-sec
Tags (pure v2):          MCSB-v2; {CODE}; v2-native; azure-infra-sec

---

## [SEC-NS] Network Security — 10 Controls, 52 Stories

### NS-1 Establish Network Segmentation Boundaries [7 combined]

**[SEC-NS-1] Establish Network Segmentation Boundaries: Virtual Network**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-1 controls for Virtual Network: address space isolation, subnet design, NSG deny-all defaults, peering security, AVNM admin rules enforcement, and hub-spoke topology compliance.

**[SEC-NS-1] Establish Network Segmentation Boundaries: Virtual Network NAT**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-1 controls for Virtual Network NAT: outbound-only connectivity model, no inbound exposure via NAT, public IP prefix management, SNAT exhaustion monitoring.

**[SEC-NS-1] Establish Network Segmentation Boundaries: Virtual WAN**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-1 controls for Virtual WAN: hub segmentation between branches, virtual hub routing policies, secured hub via Firewall Manager integration, spoke isolation.

**[SEC-NS-1] Establish Network Segmentation Boundaries: Load Balancer**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-1 controls for Load Balancer: internal LB for backend pools (no public IP), backend pool subnet isolation, SKU compliance (Standard only, no Basic), health probe security.

**[SEC-NS-1] Establish Network Segmentation Boundaries: Traffic Manager**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-1 controls for Traffic Manager: endpoint health monitoring, HTTPS-only endpoint enforcement, no sensitive data in DNS responses, geographic routing isolation per region.

**[SEC-NS-1] Establish Network Segmentation Boundaries: Peering Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-1 controls for Azure Peering Service: route filtering, BGP community tagging, peering location security, monitoring for unauthorized route changes.

**[SEC-NS-1] Establish Network Segmentation Boundaries: NAT Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-1 controls for NAT Gateway: association with correct subnets, public IP prefix rotation policy, idle timeout tuning, SNAT port exhaustion alert.

---

### NS-2 Secure Cloud Native Services with Network Controls [27 combined]

**[SEC-NS-2] Secure Cloud Native Services: App Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for App Service: VNet integration, private endpoint, inbound access restrictions, HTTPS-only enforcement, TLS 1.2 minimum, FTP disabled.

**[SEC-NS-2] Secure Cloud Native Services: Cache for Redis**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Cache for Redis: private endpoint or VNet injection, non-SSL port (6379) disabled, TLS 1.2 minimum, no public network access, managed identity for client auth.

**[SEC-NS-2] Secure Cloud Native Services: Cognitive Search**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Cognitive Search: private endpoint, disable public network access, IP firewall rules, managed identity for data source auth, no shared access key exposure.

**[SEC-NS-2] Secure Cloud Native Services: Communication Services**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Communication Services: managed identity for service auth, private connectivity where available, data residency compliance, API access restriction.

**[SEC-NS-2] Secure Cloud Native Services: Communications Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Communications Gateway: network peering security, SBC connectivity hardening, TLS for SIP signaling, access restrictions to admin plane.

**[SEC-NS-2] Secure Cloud Native Services: Container Apps**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Container Apps: VNet integration, internal-only ingress (no public FQDN for internal apps), private DNS zone, environment-level network isolation.

**[SEC-NS-2] Secure Cloud Native Services: Data Factory**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Data Factory: managed private endpoints for all linked services, private endpoint for ADF itself, self-hosted IR in VNet, disable public network access.

**[SEC-NS-2] Secure Cloud Native Services: Database Migration Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Database Migration Service: VNet-integrated deployment, private endpoint, outbound-only connectivity to source/target, disable public access.

**[SEC-NS-2] Secure Cloud Native Services: Databricks**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Databricks: VNet injection (no-public-IP mode), private endpoints for workspace and storage, NSG rules per Databricks requirements, secure cluster connectivity.

**[SEC-NS-2] Secure Cloud Native Services: Digital Twins**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Digital Twins: private endpoint, disable public network access, RBAC over API keys, event routing via private Event Grid topic.

**[SEC-NS-2] Secure Cloud Native Services: Event Grid**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Event Grid: private endpoint for topics/domains, disable public network access, managed identity for event delivery, subscriber HTTPS endpoint enforcement.

**[SEC-NS-2] Secure Cloud Native Services: Event Hubs**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Event Hubs: private endpoint, disable public network access, managed identity (no shared access signatures), IP firewall, TLS 1.2 minimum.

**[SEC-NS-2] Secure Cloud Native Services: File Sync**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure File Sync: storage firewall rules, private endpoint for sync service endpoint, TLS for all data transfer, registered server auth via Azure AD.

**[SEC-NS-2] Secure Cloud Native Services: Functions**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Functions: VNet integration, private endpoints for storage triggers, inbound access restrictions, HTTPS-only, FTP disabled, managed identity for bindings.

**[SEC-NS-2] Secure Cloud Native Services: HPC Cache**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure HPC Cache: VNet deployment, subnet isolation, no public endpoint, storage target access via private routing, client subnet restrictions.

**[SEC-NS-2] Secure Cloud Native Services: Logic Apps**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Logic Apps (Standard): VNet integration, private endpoint, IP restriction for trigger/callback access, managed identity for connector auth, no hardcoded credentials.

**[SEC-NS-2] Secure Cloud Native Services: Machine Learning Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Machine Learning: VNet-isolated workspace, private endpoint, no public workspace access, compute cluster/instance in VNet, no public IP on compute.

**[SEC-NS-2] Secure Cloud Native Services: Managed Lustre**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Managed Lustre: VNet integration, subnet isolation, no public endpoint, NSG rules for client access restriction, storage backend via private routing.

**[SEC-NS-2] Secure Cloud Native Services: Notification Hubs**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Notification Hubs: namespace IP firewall, managed identity for backend API connections, TLS for push notification delivery, no SAS key exposure.

**[SEC-NS-2] Secure Cloud Native Services: Remote Rendering**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Remote Rendering: VNet-based session connectivity, managed identity auth, restrict session access to authorized clients, TLS for streaming.

**[SEC-NS-2] Secure Cloud Native Services: Service Bus**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Service Bus: private endpoint, disable public network access, managed identity (no SAS keys for app auth), IP firewall rules, TLS 1.2 minimum.

**[SEC-NS-2] Secure Cloud Native Services: SignalR Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure SignalR Service: private endpoint, disable public network access, managed identity for upstream auth, serverless mode connectivity via private link.

**[SEC-NS-2] Secure Cloud Native Services: Spring Apps**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Spring Apps: VNet injection, private endpoint, disable public test endpoint, outbound UDR via Azure Firewall, app-level network isolation.

**[SEC-NS-2] Secure Cloud Native Services: Web PubSub**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Web PubSub: private endpoint, disable public network access, managed identity for upstream webhook auth, TLS for client connections.

**[SEC-NS-2] Secure Cloud Native Services: Batch**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Batch: VNet pool deployment, no public IP on compute nodes, private endpoint for Batch account, managed identity on pools (no storage keys).

**[SEC-NS-2] Secure Cloud Native Services: Cognitive Services**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Cognitive Services (AI Services): private endpoint, disable public network access, managed identity for client auth, VNet service endpoint where private endpoint not supported.

**[SEC-NS-2] Secure Cloud Native Services: Content Delivery Network**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-2 controls for Azure Content Delivery Network: HTTPS-only delivery rules, custom domain TLS (managed cert or Key Vault), WAF policy via Front Door CDN, origin access control (restrict origin to CDN only).

---

### NS-3 Deploy Firewall at Edge of Enterprise Network [3 combined]

**[SEC-NS-3] Deploy Firewall at Edge of Enterprise Network: Firewall**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-3 controls for Azure Firewall: Premium SKU with IDPS (Alert+Deny), Threat Intelligence enabled, centralized hub deployment, policy hierarchy (parent + child), diagnostic logging to Log Analytics.

**[SEC-NS-3] Deploy Firewall at Edge of Enterprise Network: Firewall Manager**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-3 controls for Azure Firewall Manager: centralized policy management across hubs, secured virtual hub configuration, DDoS plan association, route intent enforcement for spoke traffic.

**[SEC-NS-3] Deploy Firewall at Edge of Enterprise Network: Stack Edge**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-3 controls for Azure Stack Edge: physical edge local firewall configuration, VPN for cloud connectivity, local user access restriction (no default accounts), firmware update management.

---

### NS-4 Deploy Intrusion Detection/Prevention Systems [pure v2]

**[SEC-NS-4] Deploy Intrusion Detection/Prevention Systems**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v2-native; azure-infra-sec
Description: Enable Azure Firewall Premium IDPS in Alert+Deny mode across all hub firewalls. Signature updates automatic. Custom signature support where available. Alert integration to Sentinel. Review IDPS alert cadence and false-positive tuning policy quarterly.

---

### NS-5 Deploy DDoS Protection [2 combined]

**[SEC-NS-5] Deploy DDoS Protection: DDoS Protection**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-5 controls for Azure DDoS Protection: Network Protection Standard plan associated with all VNets containing public IPs, DDoS diagnostic logs → Log Analytics, metric alerts for DDoS attack start/end events.

**[SEC-NS-5] Deploy DDoS Protection: Public IP**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-5 controls for Public IP: DDoS Network Protection Standard association, monitoring for DDoS attack events, unnecessary PIPs identified and removed, SKU compliance (Standard only — no Basic PIPs).

---

### NS-6 Deploy Web Application Firewall [3 combined]

**[SEC-NS-6] Deploy Web Application Firewall: Application Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-6 controls for Application Gateway: WAF v2 in Prevention mode, OWASP CRS 3.2, bot protection ruleset enabled, SSL offload with TLS 1.2+ only, custom error pages, WAF diagnostic logging to Sentinel.

**[SEC-NS-6] Deploy Web Application Firewall: Front Door**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-6 controls for Azure Front Door: WAF policy in Prevention mode, managed ruleset (DefaultRuleSet latest), bot management enabled, DDoS protection, HTTPS redirect enforced, origin access control.

**[SEC-NS-6] Deploy Web Application Firewall: Web Application Firewall**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-6 controls for Azure Web Application Firewall (standalone policy): policy mode set to Prevention, rule group review (disable unnecessary rules), custom rules for org-specific threats, exclusion list governed.

---

### NS-7 Simplify Network Security Configuration [1 combined]

**[SEC-NS-7] Simplify Network Security Configuration: Network Watcher**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-7 controls for Network Watcher: NSG flow logs v2 enabled on all NSGs → Storage + Traffic Analytics, connection monitor for critical service paths, packet capture policy, effective routes validation.

---

### NS-8 Detect and Disable Insecure Services and Protocols [pure v2]

**[SEC-NS-8] Detect and Disable Insecure Services and Protocols**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v2-native; azure-infra-sec
Description: Enumerate and disable TLS 1.0/1.1, SSLv3, unencrypted HTTP, FTP, Telnet, and SMBv1 across all Azure services. Azure Policy: enforce TLS minimum version. App Service: HTTPS-only and TLS 1.2. Database services: SSL required. Defender for Cloud recommendations for insecure protocols reviewed.

---

### NS-9 Connect On-Premises or Cloud Network Privately [6 combined]

**[SEC-NS-9] Connect On-Premises or Cloud Network Privately: VPN Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-9 controls for VPN Gateway: IKEv2 protocol, BGP authentication (MD5), certificate-based auth, VPN diagnostic logs → Log Analytics, gateway SKU compliance (no Basic SKU).

**[SEC-NS-9] Connect On-Premises or Cloud Network Privately: Private Link**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-9 controls for Azure Private Link: service endpoint vs private endpoint gap assessment, DNS zone group configuration, network policies on private endpoint subnet, approval workflow for cross-tenant connections.

**[SEC-NS-9] Connect On-Premises or Cloud Network Privately: Bastion**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-9 controls for Azure Bastion: Premium SKU, shareable link disabled, session recording enabled, audit logging to Log Analytics, restricted RBAC for Bastion resource.

**[SEC-NS-9] Connect On-Premises or Cloud Network Privately: Virtual Desktop**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-9 controls for Azure Virtual Desktop: private endpoint for host pool, RDP Shortpath enabled (direct UDP), session host VNet isolation, MFA via Conditional Access for WVD access.

**[SEC-NS-9] Connect On-Premises or Cloud Network Privately: Nutanix on Azure**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-9 controls for Nutanix Cloud Clusters on Azure: dedicated VNet, no public IP on Nutanix nodes, Azure Firewall egress control, Nutanix security hardening for management plane.

**[SEC-NS-9] Connect On-Premises or Cloud Network Privately: VMware Solution**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-9 controls for Azure VMware Solution: ExpressRoute private connectivity (no public internet path), NSX-T microsegmentation for VM workloads, management network isolation, no public access to vCenter/NSX.

---

### NS-10 Ensure Domain Name System (DNS) Security [1 combined]

**[SEC-NS-10] Ensure Domain Name System (DNS) Security: DNS**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: MCSB-v2; NS; v3; v2-paired; azure-infra-sec
Description: Assess NS-10 controls for Azure DNS: Private DNS zones for all private endpoints, no public DNS zone for internal resources, conditional forwarder via DNS Private Resolver, Defender for DNS monitoring for tunneling and malicious domain queries.

---

## [SEC-IM] Identity Management — 8 Controls, 10 Stories

### IM-1 Use Centralized Identity and Authentication System [1 combined]

**[SEC-IM-1] Use Centralized Identity and Authentication System: Active Directory Domain Services**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v3; v2-paired; azure-infra-sec
Description: Assess IM-1 controls for Active Directory Domain Services: AAD Connect health monitoring, hybrid identity sync security, LDAP over TLS (636), domain controller hardening, Tier-0 asset protection, on-premises → Entra ID federation validation.

---

### IM-2 Protect Identity and Authentication Systems [pure v2]

**[SEC-IM-2] Protect Identity and Authentication Systems**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v2-native; azure-infra-sec
Description: Enable Azure AD Identity Protection: user risk and sign-in risk policies (High → block, Medium → MFA). Risky user and sign-in alerts routed to Sentinel. Password protection (banned password list). Smart lockout policy enforced. AAD Connect Health monitoring active.

---

### IM-3 Manage Application Identities Securely and Automatically [2 combined]

**[SEC-IM-3] Manage Application Identities Securely and Automatically: Bot Service**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v3; v2-paired; azure-infra-sec
Description: Assess IM-3 controls for Bot Service: managed identity for bot app auth (no stored credentials in app settings), Azure AD token validation for Direct Line, HTTPS enforcement on all bot channels.

**[SEC-IM-3] Manage Application Identities Securely and Automatically: Universal Print**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v3; v2-paired; azure-infra-sec
Description: Assess IM-3 controls for Universal Print: managed identity for print connector authentication, Azure AD group-based print queue access control, no shared credentials for printer registration.

---

### IM-4 Authenticate Server and Services [2 combined]

**[SEC-IM-4] Authenticate Server and Services: Attestation**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v3; v2-paired; azure-infra-sec
Description: Assess IM-4 controls for Azure Attestation: mTLS for attestation requests, policy signing with approved certificates, audit logging of attestation requests, private endpoint for attestation service endpoint.

**[SEC-IM-4] Authenticate Server and Services: Trusted Hardware Identity Management**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v3; v2-paired; azure-infra-sec
Description: Assess IM-4 controls for Trusted Hardware Identity Management: hardware identity certificate chain validation, managed identity integration for THIM service, audit logging of certificate issuance and renewal.

---

### IM-5 Use Single Sign-On (SSO) for Application Access [1 combined]

**[SEC-IM-5] Use Single Sign-On (SSO) for Application Access: API Management**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v3; v2-paired; azure-infra-sec
Description: Assess IM-5 controls for API Management: OAuth2/OIDC for API consumer SSO, managed identity for backend service auth, subscription key rotation policy, developer portal Azure AD integration (no local accounts).

---

### IM-6 Use Strong Authentication Controls [pure v2]

**[SEC-IM-6] Use Strong Authentication Controls**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v2-native; azure-infra-sec
Description: Enforce MFA via Conditional Access for all users (no per-user MFA legacy). Block legacy authentication protocols via CA policy. Phishing-resistant MFA (FIDO2/Windows Hello for Business) for all privileged users. Number matching + additional context for Authenticator push notifications.

---

### IM-7 Restrict Resource Access Based on Conditions [1 combined]

**[SEC-IM-7] Restrict Resource Access Based on Conditions: Spatial Anchors**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v3; v2-paired; azure-infra-sec
Description: Assess IM-7 controls for Azure Spatial Anchors: Conditional Access policies for spatial anchor access tokens, RBAC for account management (Spatial Anchors Account Owner/Reader/Contributor), audit logging of anchor access.

---

### IM-8 Restrict the Exposure of Credential and Secrets [pure v2]

**[SEC-IM-8] Restrict the Exposure of Credential and Secrets**
Parent: [SEC-IM] Identity Management — MCSB v2
Tags: MCSB-v2; IM; v2-native; azure-infra-sec
Description: All secrets stored in Key Vault (no plaintext in configs, code, env vars, ADO pipelines). Secret scanning in repos via Defender for DevOps / GitHub Advanced Security. Service principal secrets: 90-day expiry, automated rotation. Storage shared key auth disabled where feasible.

---

## [SEC-PA] Privileged Access — 8 Controls, 8 Stories

### PA-1 Separate and Limit Highly Privileged Users [pure v2]

**[SEC-PA-1] Separate and Limit Highly Privileged Users**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v2-native; azure-infra-sec
Description: Inventory all Global Admin, Subscription Owner, and other high-privilege role holders. Target: <5 Global Admins. Cloud-only privileged accounts (no sync from on-premises AD). PIM for all eligible role assignments. Privileged role reduction exercise tracked in ADO.

---

### PA-2 Avoid Standing Access for User Accounts and Permissions [1 combined]

**[SEC-PA-2] Avoid Standing Access: Automation**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v3; v2-paired; azure-infra-sec
Description: Assess PA-2 controls for Azure Automation: system-assigned managed identity replacing deprecated RunAs accounts, JIT runbook execution scheduling (no always-on privileged sessions), Automation account network isolation (private endpoint), audit logging of runbook executions.

---

### PA-3 Manage Lifecycle of Identities and Entitlements [pure v2]

**[SEC-PA-3] Manage Lifecycle of Identities and Entitlements**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v2-native; azure-infra-sec
Description: Entitlement Management: access packages for resource access with approval workflow. Automated provisioning/deprovisioning via SCIM. Joiner-Mover-Leaver process defined and tested. Stale account detection (90+ days inactive → auto-disable). Guest account expiry policy (30 days unless renewed).

---

### PA-4 Review and Reconcile User Access Regularly [pure v2]

**[SEC-PA-4] Review and Reconcile User Access Regularly**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v2-native; azure-infra-sec
Description: Azure AD Access Reviews: quarterly for privileged roles, semi-annual for group memberships. Reviewer = line manager or resource owner. Auto-deny on no response (not auto-approve). Review results feed into deprovisioning workflow. Audit log of all review outcomes.

---

### PA-5 Set Up Emergency Access [pure v2]

**[SEC-PA-5] Set Up Emergency Access**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v2-native; azure-infra-sec
Description: Two break-glass accounts: Global Admin, cloud-only, no MFA method shared with production accounts. Passwords stored split between two physically separate secure locations. Excluded from all Conditional Access policies. Sign-in usage monitored (alert on any sign-in). Tested and validated quarterly.

---

### PA-6 Use Privileged Access Workstations [1 combined]

**[SEC-PA-6] Use Privileged Access Workstations: Cloud Shell**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v3; v2-paired; azure-infra-sec
Description: Assess PA-6 controls for Azure Cloud Shell: Cloud Shell launched only from PAW or Bastion (CA policy: require compliant device for Cloud Shell access), Cloud Shell storage account with private endpoint, RBAC on storage account, session audit logging enabled.

---

### PA-7 Follow Just Enough Administration (Least Privilege) Principle [1 combined]

**[SEC-PA-7] Follow Just Enough Administration (Least Privilege): Lighthouse**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v3; v2-paired; azure-infra-sec
Description: Assess PA-7 controls for Azure Lighthouse: managed tenant delegations reviewed for least-privilege roles, no Owner delegation (Contributor max), delegation audit logs reviewed quarterly, customer-visible delegation approval workflow.

---

### PA-8 Choose Approval Process for Microsoft Support Access [1 combined]

**[SEC-PA-8] Choose Approval Process for Microsoft Support Access: Customer Lockbox**
Parent: [SEC-PA] Privileged Access — MCSB v2
Tags: MCSB-v2; PA; v3; v2-paired; azure-infra-sec
Description: Assess PA-8 controls for Customer Lockbox: Lockbox enabled at tenant level, Lockbox Approver role assigned to designated security personnel, approval SLA defined (default 12h before auto-deny), Lockbox request audit log routed to Sentinel.

---

## [SEC-DP] Data Protection — 8 Controls, 29 Stories

### DP-1 Discover, Classify, and Label Sensitive Data [3 combined]

**[SEC-DP-1] Discover, Classify, and Label Sensitive Data: Information Protection**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-1 controls for Microsoft Information Protection: sensitivity labels (Public/Internal/Confidential/Restricted), auto-labeling policies for known sensitive patterns, label inheritance for data copied to Azure storage.

**[SEC-DP-1] Discover, Classify, and Label Sensitive Data: Purview**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-1 controls for Microsoft Purview: data catalog scan coverage (Storage, SQL, Synapse, ADLS), classification rules, sensitive data discovery report, DLP policy enforcement, insider risk management integration.

**[SEC-DP-1] Discover, Classify, and Label Sensitive Data: Data Share**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-1 controls for Azure Data Share: data classification before sharing (no Confidential/Restricted data in unapproved shares), recipient identity validation, snapshot access review, shared dataset sensitivity labeling.

---

### DP-2 Monitor Anomalies and Threats Targeting Sensitive Data [3 combined]

**[SEC-DP-2] Monitor Anomalies and Threats Targeting Sensitive Data: Data Explorer**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-2 controls for Azure Data Explorer: anomalous query detection via Defender for Databases, row-level security on sensitive tables, query audit logging to Log Analytics, access pattern baselining.

**[SEC-DP-2] Monitor Anomalies and Threats Targeting Sensitive Data: OpenAI**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-2 controls for Azure OpenAI: content filtering enabled (all harm categories), data exfiltration via model responses monitored, input/output logging to Log Analytics, managed identity auth (no API keys in code).

**[SEC-DP-2] Monitor Anomalies and Threats Targeting Sensitive Data: Intelligent Recommendations**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-2 controls for Azure Intelligent Recommendations: data access audit logging, managed identity for model training data access, anomalous recommendation pattern monitoring, no PII in recommendation metadata.

---

### DP-3 Encrypt Sensitive Data in Transit [6 combined]

**[SEC-DP-3] Encrypt Sensitive Data in Transit: Database for MariaDB**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-3 controls for Azure Database for MariaDB: TLS 1.2 minimum enforced (ssl_enforce_enabled=ON), disable non-SSL connections, certificate pinning for client connections, TLS version audit via Azure Policy.

**[SEC-DP-3] Encrypt Sensitive Data in Transit: Database for MySQL Flexible Server**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-3 controls for Azure Database for MySQL Flexible Server: TLS 1.2+ required, disable unencrypted connections, HTTPS-only connection strings in application configs, minimal TLS version parameter audit.

**[SEC-DP-3] Encrypt Sensitive Data in Transit: Database for PostgreSQL Flexible Server**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-3 controls for Azure Database for PostgreSQL Flexible Server: TLS minimum version enforced, ssl_mode=REQUIRE for all client connections, disable plaintext connections, certificate validation on client side.

**[SEC-DP-3] Encrypt Sensitive Data in Transit: Cosmos DB for PostgreSQL**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-3 controls for Azure Cosmos DB for PostgreSQL: TLS 1.2 enforcement, SSL required for all client connections, certificate validation, no plaintext PostgreSQL wire protocol connections.

**[SEC-DP-3] Encrypt Sensitive Data in Transit: Stream Analytics**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-3 controls for Azure Stream Analytics: TLS for all input/output connections (Event Hub, Service Bus, SQL, Storage), managed identity for source/sink auth, no plaintext credentials in job configuration.

**[SEC-DP-3] Encrypt Sensitive Data in Transit: Media Services**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-3 controls for Azure Media Services: HTTPS-only streaming delivery, DRM (PlayReady/Widevine/FairPlay) for content protection, managed identity for storage account access, TLS for live encoder ingest connections.

---

### DP-4 Enable Data at Rest Encryption by Default [7 combined]

**[SEC-DP-4] Enable Data at Rest Encryption by Default: Storage**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-4 controls for Azure Storage: AES-256 encryption at rest (PMK default), CMK option assessment, disable allow-blob-public-access, infrastructure encryption for Confidential data, immutability for compliance tiers.

**[SEC-DP-4] Enable Data at Rest Encryption by Default: SQL**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-4 controls for Azure SQL Database: Transparent Data Encryption (TDE) with PMK (default) or CMK review, SQL Auditing enabled → Log Analytics, Always Encrypted for highly sensitive columns, no unencrypted database exports.

**[SEC-DP-4] Enable Data at Rest Encryption by Default: SQL IaaS**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-4 controls for SQL Server on Azure VMs: Azure Disk Encryption (ADE) or EncryptionAtHost on VM disks, TDE on SQL databases, encrypted backups, Key Vault for encryption key management.

**[SEC-DP-4] Enable Data at Rest Encryption by Default: Analysis Services**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-4 controls for Azure Analysis Services: model data encrypted at rest, managed identity for data source connections (no stored credentials), row-level security on sensitive models, audit logging.

**[SEC-DP-4] Enable Data at Rest Encryption by Default: App Configuration**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-4 controls for Azure App Configuration: encryption at rest (default AES-256), CMK for configurations classified Confidential/Restricted, managed identity access (no connection strings), private endpoint.

**[SEC-DP-4] Enable Data at Rest Encryption by Default: Center for SAP Solutions**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-4 controls for Azure Center for SAP Solutions: SAP HANA database encryption at rest, managed disk encryption on all SAP VMs, backup encryption via Azure Backup CMK, data classification for SAP landscape.

**[SEC-DP-4] Enable Data at Rest Encryption by Default: Data Lake Analytics**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-4 controls for Azure Data Lake Analytics: ADLS Gen1 encryption at rest (HSM-backed keys), job data encryption, managed identity for compute-to-storage access, no unencrypted job output storage.

---

### DP-5 Use Customer-Managed Key When Required [5 combined]

**[SEC-DP-5] Use Customer-Managed Key When Required: Cosmos DB**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-5 controls for Azure Cosmos DB: CMK for encryption at rest (configured at account creation), managed identity for Key Vault access, private endpoint, disable public network access, role-based access (no master keys in apps).

**[SEC-DP-5] Use Customer-Managed Key When Required: Synapse Analytics**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-5 controls for Azure Synapse Analytics: workspace CMK via managed identity and Key Vault, dedicated SQL pool TDE with CMK, encryption key rotation policy, double encryption for Confidential data.

**[SEC-DP-5] Use Customer-Managed Key When Required: Data Manager for Energy**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-5 controls for Azure Data Manager for Energy: CMK for data-at-rest encryption, customer-owned key management via Key Vault, OSDU data platform encryption compliance, key rotation cadence.

**[SEC-DP-5] Use Customer-Managed Key When Required: Managed Instance for Apache Cassandra**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-5 controls for Azure Managed Instance for Apache Cassandra: CMK for data-at-rest encryption via Key Vault, managed identity, private endpoint, disk encryption on Cassandra nodes.

**[SEC-DP-5] Use Customer-Managed Key When Required: NetApp Files**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-5 controls for Azure NetApp Files: volume encryption via NetApp Encryption (NVE), CMK via Azure Key Vault where supported, SMB Kerberos for in-transit NFS/SMB security, capacity pool encryption.

---

### DP-6 Use a Secure Key Management Process [3 combined]

**[SEC-DP-6] Use a Secure Key Management Process: Key Vault**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-6 controls for Azure Key Vault: RBAC model (not legacy access policies), soft delete + purge protection enabled, private endpoint, network firewall deny-public, key rotation policy (RSA-2048+, 1-year rotation), all operations audit logged.

**[SEC-DP-6] Use a Secure Key Management Process: Key Vault Managed HSM**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-6 controls for Azure Key Vault Managed HSM: FIPS 140-2 Level 3 validation, built-in RBAC (no legacy access policies), purge protection enabled, private endpoint, HSM key backup/restore policy and tested.

**[SEC-DP-6] Use a Secure Key Management Process: Dedicated HSM**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-6 controls for Azure Dedicated HSM: customer-managed FIPS 140-2 Level 3 device, VNet integration (no public access), physical access controls validated, HSM zeroization policy documented, BYOL key management audited.

---

### DP-7 Use a Secure Certificate Management Process [pure v2]

**[SEC-DP-7] Use a Secure Certificate Management Process**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v2-native; azure-infra-sec
Description: All TLS certificates managed via Key Vault (App Service, API Management, Application Gateway cert bindings from KV). Certificate expiry monitoring: alert at 30-day and 7-day. Auto-renewal for ACM/DigiCert integrated certs. No self-signed certificates in production. Full certificate inventory maintained.

---

### DP-8 Ensure Security of Key and Certificate Repository [1 combined]

**[SEC-DP-8] Ensure Security of Key and Certificate Repository: Data Box**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: MCSB-v2; DP; v3; v2-paired; azure-infra-sec
Description: Assess DP-8 controls for Azure Data Box: physical chain of custody documentation, disk-level encryption during transit (BitLocker), NIST SP 800-88 data wipe on return to Microsoft, BitLocker keys stored in Key Vault, shipment tracking and tamper-evidence review.

---

## [SEC-AM] Asset Management — 5 Controls, 7 Stories

### AM-1 Track Asset Inventory and Their Risks [2 combined]

**[SEC-AM-1] Track Asset Inventory and Their Risks: Resource Graph**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: MCSB-v2; AM; v3; v2-paired; azure-infra-sec
Description: Assess AM-1 controls for Azure Resource Graph: cross-subscription inventory queries for all resource types, tag compliance reporting, stale resource detection (orphaned disks/NICs/PIPs), security configuration drift queries.

**[SEC-AM-1] Track Asset Inventory and Their Risks: Migrate**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: MCSB-v2; AM; v3; v2-paired; azure-infra-sec
Description: Assess AM-1 controls for Azure Migrate: discovered asset inventory accuracy, assessment data sensitivity (contains IP/config data), migration readiness security review, dependency analysis data access restriction.

---

### AM-2 Use Only Approved Services [1 combined]

**[SEC-AM-2] Use Only Approved Services: Policy**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: MCSB-v2; AM; v3; v2-paired; azure-infra-sec
Description: Assess AM-2 controls for Azure Policy (resource allowlist angle): allowed resource types initiative at management group, deny unapproved resource types, allowed locations enforcement (data residency), Marketplace restriction policy.

---

### AM-3 Ensure Security of Asset Lifecycle Management [2 combined]

**[SEC-AM-3] Ensure Security of Asset Lifecycle Management: Resource Mover**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: MCSB-v2; AM; v3; v2-paired; azure-infra-sec
Description: Assess AM-3 controls for Azure Resource Mover: RBAC for move operations, security control validation post-move (NSG, private endpoint, tags), move collection audit logging, rollback capability tested.

**[SEC-AM-3] Ensure Security of Asset Lifecycle Management: DevTest Labs**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: MCSB-v2; AM; v3; v2-paired; azure-infra-sec
Description: Assess AM-3 controls for Azure DevTest Labs: approved VM image policy (marketplace images only — no custom unapproved images), auto-shutdown policy enforced, cost limit enforcement, lab RBAC (no Owner for lab users), artifact source security.

---

### AM-4 Limit Access to Asset Management [1 combined]

**[SEC-AM-4] Limit Access to Asset Management: Resource Manager**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: MCSB-v2; AM; v3; v2-paired; azure-infra-sec
Description: Assess AM-4 controls for Azure Resource Manager: management plane RBAC least privilege (no Owner at subscription scope for non-privileged users), CanNotDelete locks on production resources, ARM template deployment audit, no broad Contributor at tenant root.

---

### AM-5 Use Only Approved Applications in Virtual Machine [pure v2]

**[SEC-AM-5] Use Only Approved Applications in Virtual Machine**
Parent: [SEC-AM] Asset Management — MCSB v2
Tags: MCSB-v2; AM; v2-native; azure-infra-sec
Description: Defender for Cloud Adaptive Application Controls: allowlist configuration on production VMs. Software inventory via Azure Monitor Agent (AMA). Detect and alert on unapproved software installations. Windows: AppLocker or WDAC policy. Linux: file integrity monitoring via MDE.

---

## [SEC-LT] Logging and Threat Detection — 7 Controls, 7 Stories

### LT-1 Enable Threat Detection Capabilities [1 combined]

**[SEC-LT-1] Enable Threat Detection Capabilities: Defender for Cloud**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v3; v2-paired; azure-infra-sec
Description: Assess LT-1 controls for Microsoft Defender for Cloud: all Defender plans enabled (Servers P2, Storage, SQL, Containers, AppService, KeyVault, DNS, ARM, DevOps), MDE auto-provisioning for all VMs, threat detection alert routing to Sentinel.

---

### LT-2 Enable Threat Detection for Identity and Access Management [pure v2]

**[SEC-LT-2] Enable Threat Detection for Identity and Access Management**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v2-native; azure-infra-sec
Description: Azure AD Identity Protection: sign-in risk and user risk policies active. Entra ID Audit + Sign-in logs → Sentinel. Sentinel analytics rules: impossible travel, password spray, legacy auth sign-in, MFA fatigue. UEBA (User Entity Behavior Analytics) enabled. Privileged role activation alerts configured.

---

### LT-3 Enable Logging for Security Investigation [pure v2]

**[SEC-LT-3] Enable Logging for Security Investigation**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v2-native; azure-infra-sec
Description: Azure Policy DeployIfNotExists: deploy diagnostic settings on all resource types → Log Analytics. Azure Activity Log → Log Analytics workspace. Resource log retention: 90 days interactive + 1 year archive. Admin operations and key management operations logged. Remediation tasks executed for non-compliant resources.

---

### LT-4 Enable Network Logging for Security Investigation [pure v2]

**[SEC-LT-4] Enable Network Logging for Security Investigation**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v2-native; azure-infra-sec
Description: NSG Flow Logs v2 enabled on all NSGs → Storage Account + Traffic Analytics enabled. Azure Firewall diagnostic logs → Log Analytics. Application Gateway access/WAF logs forwarded. DNS query logs via Defender for DNS. Network Watcher packet capture policy documented.

---

### LT-5 Centralize Security Log Management and Analysis [2 combined]

**[SEC-LT-5] Centralize Security Log Management and Analysis: Sentinel**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v3; v2-paired; azure-infra-sec
Description: Assess LT-5 controls for Microsoft Sentinel: SIEM workspace configuration, data connector coverage (all Azure log sources), analytics rules mapped to MCSB v2 domains, RBAC for SOC analysts (read-only), incident assignment workflow.

**[SEC-LT-5] Centralize Security Log Management and Analysis: Monitor**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v3; v2-paired; azure-infra-sec
Description: Assess LT-5 controls for Azure Monitor: diagnostic settings deployment via Azure Policy (DeployIfNotExists), Log Analytics workspace consolidation (single workspace per region), alert rules for critical security events, data collection rules (DCRs) for AMA.

---

### LT-6 Configure Log Storage Retention [pure v2]

**[SEC-LT-6] Configure Log Storage Retention**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v2-native; azure-infra-sec
Description: Log Analytics workspace retention: 90 days interactive. Auxiliary Logs tier for 1-year retention at lower cost. Azure Monitor Logs archive tier for 2-year compliance retention. Sentinel data retention aligned with workspace settings. Storage Account WORM immutability for archived security logs.

---

### LT-7 Use Approved Time Synchronization Sources [pure v2]

**[SEC-LT-7] Use Approved Time Synchronization Sources**
Parent: [SEC-LT] Logging and Threat Detection — MCSB v2
Tags: MCSB-v2; LT; v2-native; azure-infra-sec
Description: Azure VMs: Windows Time (w32tm) synced to Azure NTP service (168.63.129.16). Verify all VMs in Log Analytics have consistent time (query: time skew >1min alert). Arc-enabled servers: NTP sync verification. Correct timestamps on all security logs required for Sentinel correlation rule accuracy.

---

## [SEC-IR] Incident Response — 4 Controls, 4 Stories (all pure v2)

### IR-1 through IR-4 [all pure v2]

**[SEC-IR-1] Establish an Incident Response Plan and Handling**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: MCSB-v2; IR; v2-native; azure-infra-sec
Description: IR plan documented covering PICERL phases (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned). Runbooks for top threat scenarios: ransomware, account compromise, data exfiltration. Sentinel playbooks (Logic Apps) for automated containment. IR team contacts and escalation path documented. Annual IR plan review scheduled.

**[SEC-IR-2] Preparation: Setup Incident Notification**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: MCSB-v2; IR; v2-native; azure-infra-sec
Description: Security contact (email + phone) configured in Defender for Cloud subscription settings. Defender for Cloud alert notification enabled for all severity levels. Action Groups: email + SMS + Teams webhook for High severity alerts. Sentinel incident notification Action Group configured. Escalation matrix documented and tested.

**[SEC-IR-3] Detection and Analysis: Create Incidents Based on High Quality Alerts**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: MCSB-v2; IR; v2-native; azure-infra-sec
Description: Sentinel analytics rules reviewed and tuned for all MCSB v2 domains. Alert suppression for known false positives documented with approval. Alert quality metric: false positive rate <20%. Incident correlation rules in Sentinel (multiple alerts → single incident). UEBA entity insights used in triage. Threat intelligence (MDTI) integrated.

**[SEC-IR-4] Detection and Analysis: Investigate an Incident**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: MCSB-v2; IR; v2-native; azure-infra-sec
Description: Sentinel investigation graph available and SOC team trained. Log queries documented for common scenarios (lateral movement, data exfiltration, privilege escalation). Defender for Endpoint timeline and live response capability tested. Evidence collection SOP documented. Chain of custody documentation for forensic artifacts.

---

## [SEC-PV] Posture and Vulnerability Management — 7 Controls, 7 Stories

### PV-1 Run Automated Vulnerability Scans [1 combined]

**[SEC-PV-1] Run Automated Vulnerability Scans: Defender for Cloud**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: MCSB-v2; PV; v3; v2-paired; azure-infra-sec
Description: Assess PV-1 controls for Microsoft Defender for Cloud (vulnerability assessment / Secure Score angle): Defender for Servers P2 with integrated VA (Qualys or MDE-based), Secure Score ≥70% target, Critical CVE (CVSS ≥9.0) patch SLA 48h, High CVE (7.0-8.9) 7-day SLA, container image scanning via Defender for Containers.

---

### PV-2 Run Automated OS Patch Management [pure v2]

**[SEC-PV-2] Run Automated OS Patch Management**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: MCSB-v2; PV; v2-native; azure-infra-sec
Description: Azure Update Manager: patch assessment and deployment schedules for all VMs (Windows + Linux). Maintenance windows defined per environment. Patch compliance baseline: critical patches within 48h. Monthly patch compliance report. Arc-enabled servers covered by same Update Manager policy.

---

### PV-3 Establish Secure Configurations for Compute Resources [pure v2]

**[SEC-PV-3] Establish Secure Configurations for Compute Resources**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: MCSB-v2; PV; v2-native; azure-infra-sec
Description: CIS Benchmark Level 1 applied as baseline for all Windows and Linux VMs. Golden VM images with hardened OS (pre-hardened, no unnecessary services). Azure Machine Configuration (Guest Policy) for continuous OS configuration assessment. Container base images: distroless or hardened. AKS security profile (AppArmor, seccomp) enabled.

---

### PV-4 Audit and Enforce Secure Configurations for Compute Resources [pure v2]

**[SEC-PV-4] Audit and Enforce Secure Configurations for Compute Resources**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: MCSB-v2; PV; v2-native; azure-infra-sec
Description: Azure Policy Machine Configuration: audit and enforce CIS benchmarks on VMs. Remediation tasks automated for non-compliant resources. Compliance target: ≥90% compliant VMs. Defender for Cloud recommendation remediation workflow. Container security: OPA Gatekeeper policies on AKS (deny privileged pods, require resource limits).

---

### PV-5 Perform Vulnerability Assessments [1 combined]

**[SEC-PV-5] Perform Vulnerability Assessments: Advisor**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: MCSB-v2; PV; v3; v2-paired; azure-infra-sec
Description: Assess PV-5 controls for Azure Advisor: security recommendations review and remediation tracking (ADO integration), recommendation suppression governance (no suppression without approval), integration with Defender for Cloud security recommendation feed.

---

### PV-6 Rapidly and Automatically Remediate Vulnerabilities [pure v2]

**[SEC-PV-6] Rapidly and Automatically Remediate Vulnerabilities**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: MCSB-v2; PV; v2-native; azure-infra-sec
Description: Defender for Cloud one-click fix and automated remediation for applicable recommendations. Azure Policy remediation tasks scheduled for non-compliant resources. Vulnerability → ADO work item automation for Critical/High CVE findings. Container image rebuild automation on base image CVE detection (via ACR Task triggers).

---

### PV-7 Conduct Regular Red Team Operations [pure v2]

**[SEC-PV-7] Conduct Regular Red Team Operations**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: MCSB-v2; PV; v2-native; azure-infra-sec
Description: Annual red team exercise against Azure environment. Scope: external attack surface, identity attack paths, lateral movement from compromised workload. Purple team follow-up (detection coverage gap remediation). Defender for Cloud attack path analysis and exposure management reviewed. Attack surface reduction metrics tracked.

---

## [SEC-ES] Endpoint Security — 3 Controls, 15 Stories

### ES-1 Use Endpoint Detection and Response (EDR) [5 combined]

**[SEC-ES-1] Use Endpoint Detection and Response (EDR): Virtual Machines (Linux)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-1 controls for Virtual Machines (Linux): MDE for Linux deployed via Defender for Cloud auto-provisioning, EDR in Block mode, MDE telemetry → Sentinel connector, real-time protection and threat detection active, onboarding compliance ≥99%.

**[SEC-ES-1] Use Endpoint Detection and Response (EDR): Virtual Machines (Windows)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-1 controls for Virtual Machines (Windows): MDE deployed via Defender for Cloud auto-provisioning, EDR in Block mode, MDE connected to Sentinel via data connector, Defender Antivirus real-time protection, tamper protection enabled, onboarding compliance ≥99%.

**[SEC-ES-1] Use Endpoint Detection and Response (EDR): Virtual Machine Scale Sets**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-1 controls for Virtual Machine Scale Sets: MDE extension deployed in VMSS model definition, auto-provisioning ensures new instances onboarded automatically, uniform EDR telemetry from all scale set instances, VMSS security baseline.

**[SEC-ES-1] Use Endpoint Detection and Response (EDR): Arc-enabled Servers**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-1 controls for Azure Arc-enabled Servers: MDE onboarding via Arc policy extension, EDR telemetry to same Sentinel workspace as Azure VMs, patch management via Azure Update Manager, hybrid endpoint inventory in Defender for Cloud.

**[SEC-ES-1] Use Endpoint Detection and Response (EDR): Arc-enabled Kubernetes**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-1 controls for Azure Arc-enabled Kubernetes: Defender for Containers on Arc-managed cluster, runtime threat detection for workloads, Kubernetes audit log forwarded to Sentinel, cluster security posture in Defender for Cloud.

---

### ES-2 Use Modern Anti-Malware Software [pure v2]

**[SEC-ES-2] Use Modern Anti-Malware Software**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v2-native; azure-infra-sec
Description: Microsoft Defender Antivirus real-time protection enabled on all Windows VMs (cloud-delivered protection on). Defender for Endpoint antimalware on Linux VMs. Scheduled scan policy configured. Antimalware exclusions documented, reviewed, and minimized (no broad folder exclusions). Coverage compliance report reviewed weekly.

---

### ES-3 Ensure Anti-Malware Software and Signatures Updated [9 combined]

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: Container Registry**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Azure Container Registry: Defender for Containers registry scanning, no known Critical CVEs in images tagged for production, Notary v2 content trust (signed images only pulled), pull-through cache security policy.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: Container Instances**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Azure Container Instances: images sourced from trusted ACR only (no Docker Hub), vulnerability scan pre-deployment, no privileged containers, runtime security coverage via Defender for Containers.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: Kubernetes Service (AKS)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Azure Kubernetes Service: Defender for Containers runtime protection, image scanning at registry and runtime, OPA Gatekeeper policies (deny latest tag, no privileged pods, require resource limits), AppArmor/seccomp profiles on nodes.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: Kubernetes Service on Azure Stack HCI**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for AKS on Azure Stack HCI: Defender for Containers on HCI-managed cluster, container image scanning, Arc-managed security policy enforcement, HCI node update and patch management.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: Red Hat OpenShift (ARO)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Azure Red Hat OpenShift: Defender for Containers integration with ARO cluster, container image registry scanning, OCP Security Context Constraints (SCCs) enforced, MDE for node-level EDR on ARO compute.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: Defender for IoT**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Microsoft Defender for IoT: OT sensor deployment on OT/ICS networks, device inventory completeness, anomaly detection for ICS/SCADA protocols (Modbus, DNP3, EtherNet/IP), alert integration to Sentinel.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: IoT Hub**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Azure IoT Hub: device attestation (TPM/X.509 certificates), DPS enrollment group security, per-device credentials (no shared symmetric keys), Defender for IoT integration for device anomaly detection.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: IoT Central**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Azure IoT Central: device credential security (X.509 preferred over SAS), role-based access for operators vs administrators, data export encryption, Defender for IoT integration for device fleet monitoring.

**[SEC-ES-3] Ensure Anti-Malware Software and Signatures Updated: Sphere**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: MCSB-v2; ES; v3; v2-paired; azure-infra-sec
Description: Assess ES-3 controls for Azure Sphere: OS security update enforcement (automatic updates mandatory), certificate-based device authentication, application allow-listing (signed apps only), Sphere Security Service fleet monitoring.

---

## [SEC-BR] Backup and Recovery — 4 Controls, 4 Stories

### BR-1 Ensure Regular Automated Backups [1 combined]

**[SEC-BR-1] Ensure Regular Automated Backups: Backup**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: MCSB-v2; BR; v3; v2-paired; azure-infra-sec
Description: Assess BR-1 controls for Azure Backup: policy coverage for all production VMs, SQL databases (in-VM + Azure SQL), Blob Storage, Azure Files, and Key Vault; geo-redundant Recovery Services vault; RPO/RTO defined per workload tier; immutable vault enabled.

---

### BR-2 Protect Backup and Recovery Data [pure v2]

**[SEC-BR-2] Protect Backup and Recovery Data**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: MCSB-v2; BR; v2-native; azure-infra-sec
Description: Backup vault: immutable vault enabled, soft delete (14-day retention), CMK for vault encryption via Key Vault. Separate RBAC for Backup Operator role (no production subscription Owner access). Cross-subscription restore restrictions enforced. Backup data access reviewed quarterly.

---

### BR-3 Monitor Backups [pure v2]

**[SEC-BR-3] Monitor Backups**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: MCSB-v2; BR; v2-native; azure-infra-sec
Description: Azure Backup alerts configured for failed backup jobs → Action Group notification. Backup report via Azure Monitor Workbook. Recovery Services vault backup compliance report reviewed. Alert triggers: job failure, backup not run in >25h, policy non-compliance. Weekly backup health review meeting scheduled.

---

### BR-4 Regularly Test Backup [1 combined]

**[SEC-BR-4] Regularly Test Backup: Site Recovery**
Parent: [SEC-BR] Backup and Recovery — MCSB v2
Tags: MCSB-v2; BR; v3; v2-paired; azure-infra-sec
Description: Assess BR-4 controls for Azure Site Recovery: replication health monitoring, quarterly failover test execution, RTO measurement vs target, failback validation in isolated environment, recovery plan documentation reviewed semi-annually.

---

## [SEC-DS] DevOps Security — 6 Controls, 6 Stories (all pure v2)

### DS-1 through DS-6 [all pure v2]

**[SEC-DS-1] Conduct Threat Modeling**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: MCSB-v2; DS; v2-native; azure-infra-sec
Description: Threat modeling using STRIDE methodology for all new infrastructure and application designs. Microsoft Threat Modeling Tool or OWASP Threat Dragon. Design-phase review (not post-deployment). Threat model artifacts stored in repo. Annual review cadence for existing systems.

**[SEC-DS-2] Ensure Software Supply Chain Security**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: MCSB-v2; DS; v2-native; azure-infra-sec
Description: Dependency scanning (Dependabot or Defender for DevOps) in all pipelines. Software Composition Analysis (SCA) as CI gate. SBOM generation for all container builds. Trusted registry only (ACR with Notary v2 content trust). Package allowlist for npm/PyPI/NuGet. Third-party library review process documented.

**[SEC-DS-3] Secure DevOps Infrastructure**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: MCSB-v2; DS; v2-native; azure-infra-sec
Description: Azure DevOps: MFA enforced for all users, no PAT in code (secret scanning active), PAT expiry ≤90 days. Pipeline service connections use Workload Identity Federation (no stored secrets). ADO audit log → Sentinel. Private build agents in VNet. ADO organization policy review (external access, project isolation).

**[SEC-DS-4] Integrate Static Application Security Testing**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: MCSB-v2; DS; v2-native; azure-infra-sec
Description: SAST tools in CI pipeline: CodeQL for application code, Checkov for IaC (Terraform/Bicep/ARM). Block merge on Critical SAST findings (no exceptions). Secret detection via pre-commit hooks and pipeline scanning. Defender for DevOps IaC scanning integrated. SAST result triage and suppression governance.

**[SEC-DS-5] Integrate Dynamic Application Security Testing**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: MCSB-v2; DS; v2-native; azure-infra-sec
Description: DAST scan on staging environment before production deploy (OWASP ZAP or equivalent). API security testing (OWASP API Top 10). Block production release on Critical DAST findings. DAST scan results tracked in ADO. Cadence: every release for all internet-facing services.

**[SEC-DS-6] Enforce Security of Workload Throughout DevOps Lifecycle**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: MCSB-v2; DS; v2-native; azure-infra-sec
Description: Security gates in CI/CD pipeline: SAST, DAST, dependency scan, container image scan, IaC scan — all mandatory before production deploy. Branch protection: PR review required + pipeline pass. Production deploy approval gate (second approver). Drift detection: live infrastructure vs IaC state comparison (weekly).

---

## [SEC-GS] Governance and Strategy — 10 Controls, 10 Stories

### GS-1 Align Organization Roles, Responsibilities, and Accountabilities [1 combined]

**[SEC-GS-1] Align Organization Roles, Responsibilities, and Accountabilities: Cost Management**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v3; v2-paired; azure-infra-sec
Description: Assess GS-1 controls for Azure Cost Management: RBAC for cost visibility (Cost Management Reader for engineering, no write access), budget alerts per subscription/department, cost anomaly detection, departmental cost chargeback RACI aligned with security domain owners.

---

### GS-2 Define and Implement Enterprise Segmentation Strategy [pure v2]

**[SEC-GS-2] Define and Implement Enterprise Segmentation Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v2-native; azure-infra-sec
Description: Management group hierarchy aligned to business units and environments. Separate subscriptions for prod/dev/sandbox. Landing zone design enforced via Azure Blueprints or Terraform. Separation of duties: DevOps cannot approve own PRs or deploy to prod without second approval. Segmentation policy documented and reviewed annually.

---

### GS-3 Define and Implement Data Protection Strategy [pure v2]

**[SEC-GS-3] Define and Implement Data Protection Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v2-native; azure-infra-sec
Description: Data classification policy: 4 tiers (Public, Internal, Confidential, Restricted). Encryption requirements per tier defined. Data residency requirements documented. Key management policy (CMK for Confidential/Restricted). DLP policy coverage goal. Data protection strategy reviewed annually and after regulatory changes.

---

### GS-4 Define and Implement Network Security Strategy [pure v2]

**[SEC-GS-4] Define and Implement Network Security Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v2-native; azure-infra-sec
Description: Network security strategy document: zero-trust network principles, private-by-default for all PaaS, hub-spoke topology standard, internet egress only via Azure Firewall Premium. Network governance via AVNM security admin rules. Strategy reviewed annually and after major architecture changes.

---

### GS-5 Define and Implement Security Posture Management Strategy [1 combined]

**[SEC-GS-5] Define and Implement Security Posture Management Strategy: Policy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v3; v2-paired; azure-infra-sec
Description: Assess GS-5 controls for Azure Policy (posture management angle): MCSB v2 initiative assigned at management group, Regulatory Compliance dashboard reviewed monthly, Secure Score target ≥70%, risk acceptance process documented, deviation approval workflow.

---

### GS-6 Define and Implement Identity and Privileged Access Strategy [pure v2]

**[SEC-GS-6] Define and Implement Identity and Privileged Access Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v2-native; azure-infra-sec
Description: Identity strategy: Entra ID as sole IdP, PIM for all privileged roles, zero standing access, phishing-resistant MFA (FIDO2) for all admins. Roadmap: passwordless adoption for all privileged users by end of year. Identity governance maturity model. Strategy reviewed and updated annually.

---

### GS-7 Define and Implement Logging, Threat Detection and IR Strategy [pure v2]

**[SEC-GS-7] Define and Implement Logging, Threat Detection and IR Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v2-native; azure-infra-sec
Description: Logging strategy: centralized Sentinel workspace, log retention policy (90d interactive + 1yr archive), threat detection coverage map per MCSB v2 domain. IR strategy: Sentinel as SOAR, playbook library, MTTD and MTTR metrics tracked. Strategy reviewed annually and after major incidents.

---

### GS-8 Define and Implement Backup and Recovery Strategy [1 combined]

**[SEC-GS-8] Define and Implement Backup and Recovery Strategy: Managed Applications**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v3; v2-paired; azure-infra-sec
Description: Assess GS-8 controls for Azure Managed Applications: publisher identity verification before deployment, managed resource group lock (deny customer modification), application definition security review, managed identity for automation within managed app.

---

### GS-9 Define and Implement Endpoint Security Strategy [pure v2]

**[SEC-GS-9] Define and Implement Endpoint Security Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v2-native; azure-infra-sec
Description: Endpoint security strategy: MDE on all VMs, EDR telemetry to Sentinel, patch SLAs (Critical 48h, High 7d), Defender for Containers for container workloads. Endpoint lifecycle: golden image, hardened baseline, decommission process. PAW strategy for all privileged users. Strategy reviewed annually.

---

### GS-10 Define and Implement DevOps Security Strategy [pure v2]

**[SEC-GS-10] Define and Implement DevOps Security Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: MCSB-v2; GS; v2-native; azure-infra-sec
Description: DevSecOps strategy: shift-left security (SAST/DAST in CI), IaC security scanning, supply chain security (SBOM, signed images via Notary v2), security champion program. Security gates: no Critical findings shipped. Roadmap: zero-secret pipelines, signed commits, SLSA Level 2 target. Reviewed annually.
