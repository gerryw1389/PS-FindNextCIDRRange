## Introduction

"Same as [FindNextCIDRRange](https://github.com/gamullen/FindNextCIDRRange), but with Powershell". This repo contains the code for a [Powershell Function App](https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-powershell?tabs=portal) that is meant to be a HTTP triggered. The function is set to Query a VNET in Azure with a desired CIDR range and receive a response from the Azure Vnet API of the next available block.

### Goal

Exact same function as https://github.com/gamullen/FindNextCIDRRange but written in Powershell instead of C# so it is slower but a more familiar language to scripters. More details can be found on my [blog](https://automationadmin.com/2022/08/tf-get-next-subnet).

### Code Used

1. [Indented.Net.IP](https://github.com/indented-automation/Indented.Net.IP/)
2. [BornToBeRoot/PowerShell](https://github.com/BornToBeRoot/PowerShell/)
