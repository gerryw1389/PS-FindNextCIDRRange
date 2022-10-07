## Introduction

"Same as [FindNextCIDRRange](https://github.com/gamullen/FindNextCIDRRange), but with Powershell". This repo contains the code for a [Powershell Function App](https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-powershell?tabs=portal) that is meant to be a HTTP triggered. The function is set to Query a VNET in Azure with a desired CIDR range and receive a response from the Azure Vnet API of the next available block.

### Goal

Exact same function as [FindNextCIDRRange](https://github.com/gamullen/FindNextCIDRRange) but written in Powershell instead of C# so it is slower but a more familiar language to scripters. More details can be found on my [blog](https://automationadmin.com/2022/08/tf-get-next-subnet).

### Variations From C# Version

1. This version introduces a new parameter `previousblock` so that it can be called from Terraform multiple times. The idea is that if you want to build multiple subnets at once, you would pass this parameter so that the VNET will provide the NEXT cidr block instead of the same one over and over. I will try and write a module example on this shortly.

### Terraform Notes

1. You can use the [code](https://github.com/gerryw1389/terraform-examples/tree/main/2022-10-07-tf-deploy-ps-function-app) here to deploy this app using Terraform.

1. You can also see the associated [blog post](https://automationadmin.com/2022/10/tf-deploy-ps-function-app) for more details.

### Other Code Used

1. [Indented.Net.IP](https://github.com/indented-automation/Indented.Net.IP/)
2. [BornToBeRoot/PowerShell](https://github.com/BornToBeRoot/PowerShell/)

### DISCLAIMER 

Please do not use these scripts in a production environment without reading them over first. Please see the MIT [license](./LICENSE) for more information.