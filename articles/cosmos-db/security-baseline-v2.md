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

The baseline for this service is drawn from the [Azure Security Benchmark version 1.0](../security/benchmarks/overview.md), which provides recommendations on how you can secure your cloud solutions on Azure with our best practices guidance.

For more information, see [Azure Security Baselines overview](../security/benchmarks/security-baselines-overview.md).

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
