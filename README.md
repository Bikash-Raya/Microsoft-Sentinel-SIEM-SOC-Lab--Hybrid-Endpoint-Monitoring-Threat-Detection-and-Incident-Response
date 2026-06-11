<div align="center">

# 🛡️ Microsoft Sentinel – SIEM/SOC Lab: Hybrid Endpoint Monitoring, Threat Detection & Incident Response


![Domain](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-blue?style=for-the-badge)
![Infrastructure](https://img.shields.io/badge/Infrastructure-Hybrid%20Cloud%20%26%20On--Prem-green?style=for-the-badge)
![Virtualization](https://img.shields.io/badge/Platform-VMware%20%2B%20Azure-orange?style=for-the-badge)

<img src="https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Azure%20Arc-Hybrid%20Management-0078D4?style=flat-square" />
<img src="https://img.shields.io/badge/Azure%20Monitor%20Agent-AMA-green?style=flat-square" />
<img src="https://img.shields.io/badge/OS-Windows%20%7C%20Linux-red?style=flat-square" />
<img src="https://img.shields.io/badge/Networking-VMware%20NAT-orange?style=flat-square" />

---

**Prepared by:** Bikash Raya
**Project Type:** SIEM/SOC Lab – Hybrid Endpoint Monitoring & Threat Detection

</div>

---


## 📁 Repository Structure

| File | Description |
| --- | --- |
| [Sentinel-SOC-Lab-Report.pdf](./Sentinel-SOC-Lab-Report.pdf) | Complete project documentation with Screenshots|
| README.md | Project overview |

---
## 📋 Overview

This repository documents the design and implementation of a hybrid Security Information and Event Management (SIEM) laboratory using Microsoft Sentinel.

The lab simulates a hybrid infrastructure consisting of:

* 💻 Windows 11 Workstation (VMware – On-Premises)
* 🐧 Ubuntu 22.04 LTS Server (VMware – On-Premises)
* ☁️ Windows Server 2025 Datacenter (Microsoft Azure – Cloud)
* 🔗 Azure Arc for hybrid machine management
* 📊 Microsoft Sentinel as the central SIEM platform
* 📡 Azure Monitor Agent (AMA) for telemetry collection
* 🗂️ Log Analytics Workspace for centralized log storage
* 🔐 Role-Based Access Control (RBAC) for secure administration

---

## 🛠️ Technologies Used

* Microsoft Sentinel
* Microsoft Azure
* Azure Arc
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Data Collection Rules (DCR)
* Data Collection Endpoint (DCE)
* Microsoft Defender Portal
* VMware Workstation
* Windows Server 2025
* Windows 11
* Ubuntu 22.04 LTS
* KQL (Kusto Query Language)
* PowerShell
* Bash / Linux CLI

---

## 🧪 Lab Components

| System | Role | Hosting |
| --- | --- | --- |
| WIN11-LAB-01 | On-Premises Workstation (RDP Target) | VMware Workstation |
| Ubuntu 22.04 LTS | On-Premises Linux Server | VMware Workstation |
| Azure-VM-WIN-SR | Cloud Windows Server | Microsoft Azure |
| Sentinel-LAW | Log Analytics Workspace | Microsoft Azure |
| Sentinel-DCE | Data Collection Endpoint | Microsoft Azure |
| Sentinel-RG-Lab | Azure Resource Group | Microsoft Azure |

---

## 🌐 Solution Architecture

```
[Endpoints]
     ↓
[Azure Arc (for on-prem)]
     ↓
[Azure Monitor Agent (AMA)]
     ↓
[Data Collection Rules (DCR)]
     ↓
[Data Collection Endpoint (DCE)]
     ↓
[Log Analytics Workspace (Sentinel-LAW)]
     ↓
[Microsoft Sentinel]
     ↓
[Analytics Rules → Alerts → Incidents]
```

---

## 🔐 Microsoft Sentinel Infrastructure

* Created dedicated Resource Group: **Sentinel-RG-Lab**
* Deployed Log Analytics Workspace: **Sentinel-LAW**
* Configured Data Collection Endpoint: **Sentinel-DCE**
* Enabled Microsoft Sentinel on the workspace
* Registered **Microsoft.Insights** resource provider via Azure CLI

---

## 🖥️ Endpoint Deployment

### Windows 11 VM (WIN11-LAB-01)

* VMware Workstation deployment
* Enabled Remote Desktop Protocol (RDP)
* Configured Windows Firewall to allow RDP and outbound HTTPS
* Enabled Windows Security Auditing via `auditpol`

### Ubuntu 22.04 LTS VM

* VMware Workstation deployment
* Applied system updates
* Installed and configured `rsyslog`
* Generated test syslog entries to validate logging

### Azure Windows Server 2025

* Provisioned in Microsoft Azure
* Deployed with System-Assigned Managed Identity
* Joined to Sentinel-LAW for telemetry ingestion

---

## 🔗 Azure Arc Onboarding

* Generated onboarding scripts from Azure Portal
* Executed on both Windows 11 and Ubuntu VMs
* Fixed PowerShell execution policy issue on Windows:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

* Azure Connected Machine Agent installed automatically
* Both VMs registered as Azure Arc resources

---

## 📡 Azure Monitor Agent & Data Collection Rules

| Endpoint | AMA Installation Method |
| --- | --- |
| Windows 11 VM | PowerShell script |
| Ubuntu VM | Bash script via terminal |
| Azure Windows Server 2025 | Azure Extension (automated) |

### Data Collection Rules Created

* **Windows-DCR** — Collects Security, System, and Application Event Logs (Event IDs: 4624, 4625, 4648)
* **Linux-DCR** — Collects Syslog (auth, authpriv, daemon, kern, user) at info level and above

---

## 🔐 Role-Based Access Control (RBAC)

| Role | Scope | Purpose |
| --- | --- | --- |
| Monitoring Reader | Resource Group | View monitoring data, logs, and metrics |
| Log Analytics Contributor | Workspace | Read/write access to Log Analytics |
| Microsoft Sentinel Contributor | Workspace | Manage analytics rules, incidents, and playbooks |

---

## 📊 Telemetry Validation

### Heartbeat Validation

```kql
Heartbeat
| project TimeGenerated, Computer, OSType, OSName
| summarize LastSeen=max(TimeGenerated), OS=any(OSType) by Computer
| sort by LastSeen desc
```

✅ All three endpoints reported heartbeat within the last 5 minutes

### Syslog Validation

```kql
Syslog
| take 10
```

✅ Logs from Ubuntu VM confirmed — SSH attempts, system startups, cron jobs

### Cross-Platform Validation

```kql
union SecurityEvent, Syslog
| where TimeGenerated > ago(30m)
| summarize count() by Computer
```

✅ Both Windows SecurityEvents and Linux Syslog confirmed active

---

## 🚨 Threat Detection — Failed RDP Login Rule

A **Scheduled Analytics Rule** was created to detect potential brute-force RDP attacks.

| Property | Value |
| --- | --- |
| Rule Name | Failed_RDP_Logins |
| Severity | Medium |
| Tactic | Initial Access |
| Technique | T1110 – Brute Force |
| Query Frequency | Every 5 minutes |
| Lookback Period | 5 minutes |
| Threshold | >3 failed attempts per user/computer |

**Detection Query:**

```kql
Event
| where EventID == 4625
| extend Account = tostring(parse_json(EventData).TargetUserName)
| summarize FailedAttempts = count() by Account, Computer
| where FailedAttempts > 3
```

---

## 🛡️ Alert & Incident Validation

1. Multiple failed RDP login attempts made using invalid credentials
2. Event ID **4625** entries appeared in the Event table
3. Analytics rule triggered within 5 minutes
4. Alert generated in Microsoft Sentinel
5. Incident automatically created with Medium severity

**Incident Details:**

* **Title:** Multiple failed RDP logins detected
* **Entities:** Host (WIN11-VM), User (attempted username)
* **Status:** New → Resolved

---

## 🔍 Incident Response

The generated incident was reviewed and confirmed as authorized lab testing activity.

> Investigation completed. Failed authentication attempts were generated as part of authorized Microsoft Sentinel lab testing. Detection rule functioned as expected, alert was generated successfully, and no malicious activity was identified. Incident resolved.

---

## 🛡️ Troubleshooting & Validation

### Issues Encountered

#### PowerShell Execution Policy Blocked Script
* Azure Arc onboarding script blocked on Windows 11
* Resolved by setting execution policy to `RemoteSigned` for current user

#### Microsoft.Insights Provider Not Registered
* DCE creation failed due to unregistered resource provider
* Registered via Azure CLI: `az provider register --namespace Microsoft.Insights`

### Validation Performed

* Confirmed Heartbeat from all three endpoints
* Verified Syslog ingestion from Ubuntu VM
* Validated Windows Security Event log collection
* Confirmed end-to-end alert and incident pipeline

---

## 🎯 Skills Demonstrated

* Microsoft Sentinel Deployment & Configuration
* Azure Arc Hybrid Machine Onboarding
* Azure Monitor Agent (AMA) Installation
* Data Collection Rules & Endpoint Configuration
* Log Analytics KQL Querying
* RBAC Implementation (Least Privilege)
* Windows Security Auditing
* Linux Syslog Configuration
* Custom Threat Detection Rule Creation
* Security Incident Investigation & Response
* VMware Virtualization
* Cross-Platform Log Management

---

## 🎯 Key Takeaway

> This project demonstrates practical experience in deploying a hybrid SIEM environment using Microsoft Sentinel, onboarding Windows and Linux endpoints via Azure Arc, configuring centralized log collection with AMA and DCR, building custom threat detection analytics rules, and performing end-to-end incident investigation and response across a hybrid cloud infrastructure.

---

## 🔗 Connect With Me

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/bikash-raya/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Bikash-Raya)

</div>

---

<div align="center">

⭐ If you find this project useful, feel free to star the repository ⭐

</div>
