---
title: Azure Security Baseline for Cosmos DB
description: Azure Security Baseline for Cosmos DB
author: msmbaldwin
ms.service: security
ms.topic: conceptual
ms.date: 01/27/2021
ms.author: mbaldwin
ms.custom: subject-security-benchmark

---

# Azure Security Baseline for Cosmos DB
[!INCLUDE[appliesto-all-apis](includes/appliesto-all-apis.md)]

The Azure Security Baseline for Cosmos DB contains recommendations that will help you improve the security posture of your deployment.

The baseline for this service is drawn from the [Azure Security Benchmark version 2.0](https://docs.microsoft.com/en-us/azure/security/benchmarks/overview), which provides recommendations on how you can secure your cloud solutions on Azure with our best practices guidance.

For more information, see [Azure Security Baselines overview](https://docs.microsoft.com/en-us/azure/security/benchmarks/security-baselines-overview).

The [Azure Security Baseline for Cosmos DB benchmark version 1.0](https://docs.microsoft.com/en-us/azure/cosmos-db/security-baseline) is also available.

## Network Security

*For more information, see [Security Control: Network Security](https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security).*

### NS-1: Implement security for internal traffic

**Guidance**: You can isolate your Azure Cosmos DB account within its own virtual network and secure it with either a network security group (NSG) and/or Azure Firewall.Azure Cosmos DB supports IP-based access controls for inbound firewall support. You can set an IP firewall on the Azure Cosmos account by using the Azure portal, Azure Resource Manager templates, or through the Azure CLI or Azure PowerShell.

Enable NSG flow logs and send logs into an Azure Storage Account for traffic audits. You may also send NSG flow logs to a Log Analytics workspace and use Traffic Analytics to provide insights into traffic flow in your Azure cloud. Some advantages of Traffic Analytics are the ability to visualize network activity and identify hot spots, identify security threats, understand traffic flow patterns, and pinpoint network misconfigurations.

Use Azure Security Center Adaptive Network Hardening to recommend network security group configurations that limit ports and source IPs based with the reference to external network traffic rules.

- [How to create a Network Security Group with a Security Config](https://docs.microsoft.com/azure/virtual-network/tutorial-filter-network-traffic)

- [How to configure IP firewall in Cosmos DB](https://docs.microsoft.com/azure/cosmos-db/how-to-configure-firewall)

- [How to Enable NSG Flow Logs](https://docs.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-portal)

- [How to Enable and use Traffic Analytics](https://docs.microsoft.com/azure/network-watcher/traffic-analytics)

- [Adaptive Network Hardening in Azure Security Center](https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-network-hardening)

**Responsibility**: Customer

### NS-2: Connect private networks together

**Guidance**: Use Azure ExpressRoute or Azure virtual private network (VPN)  to create private connections between Azure datacenters and on-premises infrastructure in a colocation environment. ExpressRoute connections do not go over the public internet , and they offer more reliability, faster speeds, and lower latencies than typical internet connections. For point-to-site VPN and site-to-site VPN, you can connect on-premises devices or networks to a virtual network using any combination of these VPN options and Azure ExpressRoute.

To connect two or more virtual networks in Azure together, use virtual network peering or Private Link. Network traffic between peered virtual networks is private and is kept on the Azure backbone network.

- [What are the ExpressRoute connectivity models](https://docs.microsoft.com/en-us/azure/expressroute/expressroute-connectivity-models)

- [Azure VPN overview](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways)

- [Virtual network peering](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview)

- [Azure Private Link Overview](https://docs.microsoft.com/en-us/azure/private-link/private-link-service-overview)

**Responsibility**: Customer

### NS-3: Establish private network access to Azure services

**Guidance**: By using Azure Private Link, you can connect to an Azure Cosmos DB account via a Private Endpoint. Traffic between your virtual network and the service traverses over the Microsoft backbone network, eliminating exposure from the public Internet.

You can also use Service Endpoints to secure your Azure Cosmos account. By enabling a Service Endpoint, you can configure Azure Cosmos accounts to allow access from only a specific subnet of an Azure virtual network. Once the Azure Cosmos DB Service Endpoint is enabled, you can limit access to an Azure Cosmos account with connections from a subnet in a  virtual network.

- [Azure Private Link Overview](https://docs.microsoft.com/azure/private-link/private-link-overview)

- [How to configure a Private Endpoint for Azure Cosmos DB](https://docs.microsoft.com/azure/cosmos-db/how-to-configure-private-endpoints)

- [How to configure a VNet Service Endpoint in Azure Cosmos DB](https://docs.microsoft.com/en-us/azure/cosmos-db/how-to-configure-vnet-service-endpoint)

**Responsibility**: Customer

### NS-4: Protect applications and services from external network attacks

**Guidance**: Protect Azure resources against attacks from external networks, including distributed denial of service (DDoS) Attacks, application specific attacks, and unsolicited and potentially malicious internet traffic. Azure includes native capabilities for this:
-	Use Azure Firewall to protect applications and services against potentially malicious traffic from the internet and other external locations.

-	Use Web Application Firewall (WAF) capabilities in Azure Application Gateway, Azure Front Door, and Azure Content Delivery Network (CDN) to protect your applications, services, and APIs against application layer attacks.

-	Protect your assets against DDoS attacks by enabling DDoS standard protection on your Azure virtual networks.

-	Use Azure Security Center to detect misconfiguration risks related to the above.

- [How to configure IP firewall in Cosmos DB](https://docs.microsoft.com/azure/cosmos-db/how-to-configure-firewall)

- [How to deploy Azure WAF](https://docs.microsoft.com/en-us/azure/web-application-firewall/overview)

- [Manage Azure DDoS Protection Standard using the Azure portal](https://docs.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection)

**Responsibility**: Customer

### NS-5: Deploy intrusion detection/intrusion prevention systems (IDS/IPS)

**Guidance**: Use Azure Firewall threat intelligence-based filtering to alert on and/or block traffic to and from known malicious IP addresses and domains.

Use Advanced Threat Protection (ATP) for Azure Cosmos DB to provide an additional layer of security intelligence that detects unusual and potentially harmful attempts to access or exploit Azure Cosmos accounts. This layer of protection allows you to address threats and integrate them with central security monitoring systems.

- [How to configure IP firewall in Cosmos DB](https://docs.microsoft.com/azure/cosmos-db/how-to-configure-firewall)

- [How to configure Cosmos DB Advanced Threat Protection](https://docs.microsoft.com/azure/cosmos-db/cosmos-db-advanced-threat-protection)

**Responsibility**: Customer

### NS-6: Simplify network security rules

**Guidance**: Simplify network security rules by leveraging service tags and application security groups (ASGs).

Use Virtual Network service tags to define network access controls on network security groups or Azure Firewall. You can use service tags in place of specific IP addresses when creating security rules. By specifying the service tag name in the source or destination field of a rule, you can allow or deny the traffic for the corresponding service. Microsoft manages the address prefixes encompassed by the service tag and automatically updates the service tag as addresses change.

You can also use application security groups to help simplify complex security configuration. Instead of defining policy based on explicit IP addresses in network security groups, application security groups enable you to configure network security as a natural extension of an application's structure, allowing you to group virtual machines and define network security policies based on those groups.

- [Understand and use service tags](https://docs.microsoft.com/en-us/azure/virtual-network/service-tags-overview)

- [Understand and use application security groups](https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview#application-security-groups)

**Responsibility**: Customer

### NS-7: Secure Domain Name Service (DNS)

**Guidance**: Follow the best practices for DNS security to mitigate against common attacks like dangling DNS, DNS amplifications attacks, DNS poisoning and spoofing, etc.

When Azure DNS is used as your authoritative DNS service, ensure DNS zones and records are protected from accidental or malicious modification using Azure RBAC and resource locks.

- [Azure DNS overview](https://docs.microsoft.com/en-us/azure/dns/dns-overview)

- [Secure Domain Name System (DNS) Deployment Guide](https://csrc.nist.gov/publications/detail/sp/800-81/2/final)

- [Prevent dangling DNS entries and avoid subdomain takeover](https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)

**Responsibility**: Customer


## Identity Management

*For more information, see [Security Control: Logging and Monitoring](https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management).*

### IM-1: Standardize Azure Active Directory as the central identity and authentication system

**Guidance**:Azure Active Directory (Azure AD) is Azure's default identity and access management service. You should standardize on Azure AD to govern your organization’s identity and access management in:
- Microsoft cloud resources, such as the Azure portal, Azure Storage, Azure Virtual Machines (Linux and Windows), Azure Key Vault, PaaS, and SaaS applications.

- Your organization's resources, such as applications on Azure or your corporate network resources.

Securing Azure AD should be a high priority in your organization’s cloud security practice. Azure AD provides an identity secure score to help you assess your identity security posture relative to Microsoft’s best practice recommendations. Use the score to gauge how closely your configuration matches best practice recommendations, and to make improvements in your security posture.

Note: Azure AD supports external identity providers, which allow users without a Microsoft account to sign in to their applications and resources with their external identity.

- [Tenancy in Azure AD](../../active-directory/develop/single-and-multi-tenant-apps.md)

- [How to create and configure an Azure AD instance](../../active-directory/fundamentals/active-directory-access-create-new-tenant.md)

- [Define Azure AD tenants](https://azure.microsoft.com/resources/securing-azure-environments-with-azure-active-directory/)  

- [Use external identity providers for an application](../../active-directory/external-identities/identity-providers.md)

**Responsibility**: Customer

### IM-2: Manage application identities securely and automatically

**Guidance**: For non-human accounts such as services or automation, use Azure managed identities, instead of creating a more powerful human account to access resources or execute code. Azure managed identities can authenticate to Azure services and resources that support Azure AD authentication. Authentication is enabled through pre-defined access grant rules, avoiding hard-coded credentials in source code or configuration files.

- [How to use system-assigned managed identities to access Azure Cosmos DB data](https://docs.microsoft.com/en-us/azure/cosmos-db/managed-identity-based-authentication)

-[Tutorial: Use a Windows VM system-assigned managed identity to access Azure Cosmos DB](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/tutorial-windows-vm-access-cosmos-db)

**Responsibility**: Customer

### IM-3: Use Azure AD single sign-on (SSO) for application access

**Guidance**: Azure AD provides identity and access management to Azure resources, cloud applications, and on-premises applications. Identity and access management applies to enterprise identities such as employees, as well as external identities such as partners, vendors, and suppliers.

Use Azure AD single sign-on (SSO) to manage and secure access to your organization’s data and resources on-premises and in the cloud. Connect all your users, applications, and devices to Azure AD for seamless, secure access, and greater visibility and control.

- [Understand application SSO with Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/what-is-single-sign-on)

**Responsibility**: Customer

### IM-4: Use strong authentication controls for all Azure Active Directory based access

**Guidance**: Azure AD supports strong authentication controls through multi-factor authentication (MFA) and strong passwordless methods.  
- Multi-factor authentication: Enable Azure AD MFA and follow Azure Security Center identity and access management recommendations for your MFA setup. MFA can be enforced on all users, select users, or at the per-user level based on sign-in conditions and risk factors.

- Passwordless authentication: Three passwordless authentication options are available: Windows Hello for Business, Microsoft Authenticator app,  and on-premises authentication methods such as smart cards.

For administrator and privileged users, ensure the highest level of the strong authentication method is used, followed by rolling out the appropriate strong authentication policy to other users.

If legacy password-based authentication is still used for Azure AD authentication, please be aware that cloud-only accounts (user accounts created directly in Azure) have a default baseline password policy. And hybrid accounts (user accounts that come from on-premises Active Directory) follow the on-premises password policies. When using password-based authentication, Azure AD provides a password protection capability that prevents users from setting passwords that are easy to guess. Microsoft provides a global list of banned passwords that is updated based on telemetry, and customers can augment the list based on their needs (e.g. branding, cultural references, etc.). This password protection can be used for cloud-only and hybrid accounts.

Note: Authentication based on password credentials alone is susceptible to popular attack methods. For higher security, use strong authentication such as MFA and a strong password policy. For third-party applications and marketplace services that may have default passwords, you should change them during initial service setup.

- [How to enable MFA in Azure](https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted)

- [Introduction to passwordless authentication options for Azure Active Directory](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless)

- [Azure AD default password policy](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-sspr-policy#password-policies-that-only-apply-to-cloud-user-accounts)

- [Eliminate bad passwords using Azure AD Password Protection](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad)

**Responsibility**: Customer

### IM-5: Monitor and alert on account anomalies

**Guidance**: Azure AD provides the following data sources:
-	Sign-ins – The sign-ins report provides information about the usage of managed applications and user sign-in activities.

-	Audit logs - Provides traceability through logs for all changes made through various features in Azure AD. Examples of logged changes audit logs include adding or removing users, apps, groups, roles, and policies.

-	Risky sign-ins - A risky sign-in is an indicator for a sign-in attempt that might have been performed by someone who is not the legitimate owner of a user account.

-	Users flagged for risk - A risky user is an indicator for a user account that might have been compromised.

These data sources can be integrated with Azure Monitor, Azure Sentinel or third party SIEM systems.

Azure Security Center can also alert on certain suspicious activities such as an excessive number of failed authentication attempts, and deprecated accounts in the subscription.

Azure Advanced Threat Protection (ATP) is a security solution that can use on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions.

- [Audit activity reports in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs)

- [How to view Azure AD risky sign-ins](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)

- [How to identify Azure AD users flagged for risky activity](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)

- [How to monitor users' identity and access activity in Azure Security Center](https://docs.microsoft.com/en-us/azure/security-center/security-center-identity-access)

- [Alerts in Azure Security Center's threat intelligence protection module](https://docs.microsoft.com/en-us/azure/security-center/alerts-reference)

- [How to integrate Azure activity logs into Azure Monitor](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)

- [Connect data from Azure AD Identity Protection](https://docs.microsoft.com/en-us/azure/sentinel/connect-azure-ad-identity-protection)

- [Azure Advanced Threat Protection](https://docs.microsoft.com/en-us/defender-for-identity/what-is)

**Responsibility**: Customer

### IM-6: Restrict Azure resource access based on conditions

**Guidance**: Use Azure AD conditional access for more granular access control based on user-defined conditions, such as requiring user logins from certain IP ranges to use MFA. A granular authentication session management can also be used through Azure AD conditional access policy for different use cases.

- [Azure Conditional Access overview](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview)

- [Common Conditional Access policies](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common)

- [Configure authentication session management with Conditional Access](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-session-lifetime)

**Responsibility**: Customer

### IM-7: Eliminate unintended credential exposure

**Guidance**: Implement Azure DevOps Credential Scanner to identify credentials within the code. Credential Scanner also encourages moving discovered credentials to more secure locations such as Azure Key Vault.

For GitHub, you can use native secret scanning feature to identify credentials or other form of secrets within the code.

- [How to setup Credential Scanner](https://secdevtools.azurewebsites.net/helpcredscan.html)

- [GitHub secret scanning](https://docs.github.com/github/administering-a-repository/about-secret-scanning)

**Responsibility**: Customer

### IM-8: Secure user access to legacy applications

**Guidance**: Ensure you have modern access controls and session monitoring for legacy applications and the data they store and process. While VPNs are commonly used to access legacy applications, they often have only basic access control and limited session monitoring.

Azure AD Application Proxy enables you to publish legacy on-premises applications to remote users with single sign-on (SSO) while explicitly validating the trustworthiness of both remote users and devices with Azure AD Conditional Access.

Alternatively, Microsoft Cloud App Security is a cloud access security broker (CASB) service that can provide controls for monitoring a user’s application sessions and blocking actions (for both legacy on-premises applications and cloud software as a service (SaaS) applications).

- [Azure AD Application Proxy](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/application-proxy#what-is-application-proxy)

- [Microsoft Cloud App Security best practices](https://docs.microsoft.com/en-us/cloud-app-security/best-practices)

**Responsibility**: Customer

### PA-1: Protect and limit highly privileged users

**Guidance**: Limit the number of highly privileged user accounts, and protect these accounts at an elevated level.
The most critical built-in roles in Azure AD are Global Administrator and the Privileged Role Administrator, because users assigned to these two roles can delegate administrator roles. With these privileges, users can directly or indirectly read and modify every resource in your Azure environment:

- Global Administrator: Users with this role have access to all administrative features in Azure AD, as well as services that use Azure AD identities.

- Privileged Role Administrator: Users with this role can manage role assignments in Azure AD, as well as within Azure AD Privileged Identity Management (PIM). In addition, this role allows management of all aspects of PIM and administrative units.

Note: You may have other critical roles that need to be governed if you use custom roles with certain privileged permissions assigned. And you may also want to apply similar controls to the administrator account of critical business assets.  

You can enable just-in-time (JIT) privileged access to Azure resources and Azure AD using Azure AD Privileged Identity Management (PIM). JIT grants temporary permissions to perform privileged tasks only when users need it. PIM can also generate security alerts when there is suspicious or unsafe activity in your Azure AD organization.

- [Administrator role permissions in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)

- [Use Azure Privileged Identity Management security alerts](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts)

- [Securing privileged access for hybrid and cloud deployments in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning)

**Responsibility**: Customer

### PA-2: Restrict administrative access to business-critical systems

**Guidance**: Isolate access to business-critical systems by restricting which accounts are granted privileged access to the subscriptions and management groups they are in.
Ensure that you also restrict access to the management, identity, and security systems that have administrative access to your business critical assets, such as Active Directory Domain Controllers (DCs), security tools, and system management tools with agents installed on business critical systems. Attackers who compromise these management and security systems can immediately weaponize them to compromise business critical assets.

All types of access controls should be aligned to your enterprise segmentation strategy to ensure consistent access control.

Ensure to assign separate privileged accounts that are distinct from the standard user accounts used for email, browsing, and productivity tasks.

- [Azure Components and Reference model](https://docs.microsoft.com/en-us/security/compass/microsoft-security-compass-introduction#azure-components-and-reference-model-2151)

- [Management Group Access](https://docs.microsoft.com/en-us/azure/governance/management-groups/overview#management-group-access)

- [Azure subscription administrators](https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/add-change-subscription-administrator)

**Responsibility**: Customer

### PA-3: Review and reconcile user access regularly

**Guidance**: Review user accounts and access assignment regularly to ensure the accounts and their level of access are valid. You can use Azure AD access reviews to review group memberships, access to enterprise applications, and role assignments. Azure AD reporting can provide logs to help discover stale accounts. You can also use Azure AD Privileged Identity Management to create an access review report workflow that facilitates the review process.
In addition, Azure Privileged Identity Management can be configured to alert when an excessive number of administrator accounts are created, and to identify administrator accounts that are stale or improperly configured.

Note: Some Azure services support local users and roles that aren't managed through Azure AD. You must manage these users separately.

- [Create an access review of Azure resource roles in Privileged Identity Management(PIM)](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-start-access-review)

- [How to use Azure AD identity and access reviews](https://docs.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)

**Responsibility**: Customer

### PA-4: Set up emergency access in Azure AD

**Guidance**: To prevent being accidentally locked out of your Azure AD organization, set up an emergency access account for access when normal administrative accounts cannot be used. Emergency access accounts are usually highly privileged, and they should not be assigned to specific individuals. Emergency access accounts are limited to emergency or "break glass"' scenarios where normal administrative accounts can't be used.
You should ensure that the credentials (such as password, certificate, or smart card) for emergency access accounts are kept secure and known only to individuals who are authorized to use them only in an emergency.

- [Manage emergency access accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

**Responsibility**: Customer

### PA-5: Automate entitlement management

**Guidance**: Use Azure AD entitlement management features to automate access request workflows, including access assignments, reviews, and expiration. Dual or multi-stage approval is also supported.

- [What are Azure AD access reviews](https://docs.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)

- [What is Azure AD entitlement management](https://docs.microsoft.com/en-us/azure/active-directory/governance/entitlement-management-overview)

**Responsibility**: Customer

### PA-6: Use privileged access workstations

**Guidance**: Secured, isolated workstations are critically important for the security of sensitive roles like administrators, developers, and critical service operators. Use highly secured user workstations and/or Azure Bastion for administrative tasks. Use Azure Active Directory, Microsoft Defender Advanced Threat Protection (ATP), and/or Microsoft Intune to deploy a secure and managed user workstation for administrative tasks. The secured workstations can be centrally managed to enforce secured configuration, including strong authentication, software and hardware baselines, and restricted logical and network access.

- [Understand privileged access workstations](https://4sysops.com/archives/understand-the-microsoft-privileged-access-workstation-paw-security-model/)

- [Deploy a privileged access workstation](https://docs.microsoft.com/en-us/security/compass/privileged-access-deployment)

**Responsibility**: Customer

### PA-7: Follow just enough administration (least privilege principle)

**Guidance**: Azure role-based access control (Azure RBAC) allows you to manage Azure resource access through role assignments. You can assign these roles to users, group service principals, and managed identities. There are pre-defined built-in roles for certain resources, and these roles can be inventoried or queried through tools such as Azure CLI, Azure PowerShell, and the Azure portal. The privileges you assign to resources through Azure RBAC should always be limited to what's required by the roles. Limited privileges complement the just in time (JIT) approach of Azure AD Privileged Identity Management (PIM), and those privileges should be reviewed periodically.
Use built-in roles to allocate permission and only create custom role when required.

- [What is Azure role-based access control (Azure RBAC)](https://docs.microsoft.com/en-us/azure/role-based-access-control/overview)

- [How to configure Azure RBAC](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

- [How to use Azure AD identity and access reviews](https://docs.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)

**Responsibility**: Customer

### PA-8: Choose approval process for Microsoft support

**Guidance**: In support scenarios where Microsoft needs to access customer data, Customer Lockbox provides a capability for you to explicitly review and approve or reject each customer data access request.

- [Understand Customer Lockbox](https://docs.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview)

**Responsibility**: Customer

## Data protection

### DP-1: Discovery, classify and label sensitive data

**Guidance**: Use tags to assist in tracking Azure Cosmos DB instances that store or process sensitive information.

- [How to create and use tags](https://docs.microsoft.com/azure/azure-resource-manager/resource-group-using-tags)

**Responsibility**: Customer

### DP-2: Protect sensitive data

**Guidance**: Protect sensitive data by restricting access using Azure role-based access control (Azure RBAC), network-based access controls, and specific controls in Azure services (such as encryption in SQL and other databases).

To ensure consistent access control, all types of access control should be aligned to your enterprise segmentation strategy. The enterprise segmentation strategy should also be informed by the location of sensitive or business critical data and systems.

For the underlying platform, which is managed by Microsoft, Microsoft treats all customer content as sensitive and guards against customer data loss and exposure. To ensure customer data within Azure remains secure, Microsoft has implemented some default data protection controls and capabilities.

- [Azure role-based access control in Azure Cosmos DB](https://docs.microsoft.com/en-us/azure/cosmos-db/role-based-access-control)

- [Azure Cosmos DB datasebase security overview](https://docs.microsoft.com/en-us/azure/cosmos-db/database-security)

**Responsibility**: Shared

### DP-3: Monitor for unauthorized transfer of sensitive data

**Guidance**: Monitor for unauthorized transfer of data to locations outside of enterprise visibility and control. This typically involves monitoring for anomalous activities (large or unusual transfers) that could indicate unauthorized data exfiltration.

Advanced Threat Protection (ATP) for Azure Cosmos DB can alert on anomalous transfer of information that might indicate unauthorized transfers of sensitive information.

- [Enable Azure Cosmos DB ATP](https://docs.microsoft.com/en-us/azure/cosmos-db/cosmos-db-advanced-threat-protection?tabs=azure-portal)

**Responsibility**: Shared

### DP-4: Encrypt sensitive information in transit

**Guidance**: To complement access controls, data in transit should be protected against ‘out of band’ attacks (e.g. traffic capture) using encryption to ensure that attackers cannot easily read or modify the data.

All connections to Azure Cosmos DB support HTTPS. Any accounts created after July 29th, 2020 have a minimum TLS version of TLS 1.2 by default. You can request that the minimum TLS version of your accounts created before July 29th, 2020 be upgraded to TLS 1.2 by contacting [azurecosmosdbtls@service.microsoft.com](mailto:azurecosmosdbtls@service.microsoft.com).

- [TLS 1.2 enforcement on Azure Cosmos DB](https://devblogs.microsoft.com/cosmosdb/tls-1-2-enforcement/)

- [TLS 1.3 reference](https://devblogs.microsoft.com/premier-developer/microsoft-tls-1-3-support-reference/)

**Responsibility**: Shared

### DP-5: Encrypt sensitive data at rest

**Guidance**: To complement access controls, data at rest should be protected against ‘out of band’ attacks (such as accessing underlying storage) using encryption. This helps ensure that attackers cannot easily read or modify the data.

All user data stored in Cosmos DB is encrypted at rest by default. There are no controls to turn it off. Azure Cosmos DB uses AES-256 encryption on all regions where the account is running.

By default, Microsoft manages the keys that are used to encrypt the data in your Azure Cosmos account. You can optionally choose to add a second layer of encryption with your own keys.

- [Understanding encryption at rest with Azure Cosmos DB](https://docs.microsoft.com/azure/cosmos-db/database-encryption-at-rest)

- [Understanding key management for encryption at rest with Azure Cosmos DB](https://docs.microsoft.com/azure/cosmos-db/cosmos-db-security-controls)

- [How to configure customer-managed keys for your Azure Cosmos DB account](https://docs.microsoft.com/azure/cosmos-db/how-to-setup-cmk)

**Responsibility**: Shared
