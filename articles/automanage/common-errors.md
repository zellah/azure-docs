---
title: Troubleshoot common Azure Automanage onboarding errors
description: Common Automanage onboarding errors and how to troubleshoot them
author: asinn826
ms.service: virtual-machines
ms.subservice: automanage
ms.workload: infrastructure
ms.topic: conceptual
ms.date: 01/14/2021
ms.author: alsin
---

# Troubleshoot common Automanage onboarding errors
Automanage may fail to onboard a machine onto the service. This document explains how to troubleshoot deployment failures, shares some common reasons why deployments may fail, and describes potential next steps on mitigation.

## Troubleshooting deployment failures
Onboarding a machine to Automanage will result in an Azure Resource Manager deployment being created. If onboarding fails, it may be helpful to consult the deployment for further details as to why it failed. There are links to the deployments in the failure detail flyout, pictured below.

:::image type="content" source="media\automanage-common-errors\failure-flyout.png" alt-text="Automanage failure detail flyout.":::

### Check the deployments for the resource group containing the failed VM
The failure flyout will contain a link to the deployments within the resource group that contains the machine that failed onboarding and a prefix name you can use to filter deployments with. Clicking the link will take you to the deployments blade, where you can then filter deployments to see Automanage deployments to your machine. If you're deploying across multiple regions, ensure that you click on the deployment in the correct region.

### Check the deployments for the subscription containing the failed VM
If you don't see any failures in the resource group deployment, then your next step would be to look at the deployments in your subscription containing the VM that failed onboarding. Click the **Deployments for subscription** link in the failure flyout and filter deployments using the **Automanage-DefaultResourceGroup** filter. Use the resource group name from the failure blade to filter deployments. The deployment name will be suffixed with a region name. If you're deploying across multiple regions, ensure that you click on the deployment in the correct region.

### Check deployments in a subscription linked to a Log Analytics workspace
If you don't see any failed deployments in the resource group or subscription containing your failed VM, and if your failed VM is connected to a Log Analytics workspace in a different subscription, then go to the subscription linked to your Log Analytics workspace and check for failed deployments.

## Common deployment errors

Error |  Mitigation
:-----|:-------------|
Automanage account insufficient permissions error | This may happen if you have recently moved a subscription containing a new Automanage Account into a new tenant. Steps to resolve this are located [here](./repair-automanage-account.md).
Workspace region not matching region mapping requirements | Automanage was unable to onboard your machine but the Log Analytics workspace that the machine is currently linked to is not mapped to a supported Automation region. Ensure that your existing Log Analytics workspace and Automation account are located in a [supported region mapping](https://docs.microsoft.com/azure/automation/how-to/region-mappings).
"The assignment has failed; there is no additional information available" | Please open a case with Microsoft Azure support.

## Next steps

* [Learn more about Azure Automanage](./automanage-virtual-machines.md)

> [!div class="nextstepaction"]
> [Enable Automanage for virtual machines in the Azure portal](quick-create-virtual-machines-portal.md)

