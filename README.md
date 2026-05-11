# 🔍 Lab 3 — Splunk SIEM & Log Analysis

> **SOC Skills · Security Monitoring · Log Analysis · Threat Detection**

---

## Overview

This lab builds a functional Security Information and Event Management (SIEM) environment using **Splunk Enterprise (Free License)** deployed on an **Azure Ubuntu VM**, ingesting Windows Security Event Logs from an Active Directory server. By the end of this lab, you have a working SOC analyst workstation: live log ingestion, SPL-powered threat detection queries, a security dashboard, and an automated brute-force alert.

| Field | Value |
|---|---|
| **Certification Alignment** | CompTIA Security+ · CySA+ · Splunk Core Certified User |
| **Tools Used** | Splunk Enterprise (Free), Azure VM, Splunk Universal Forwarder |
| **Estimated Time** | 4–6 hours across multiple sessions |
| **Estimated Cost** | $0 — Splunk Free license covers all lab objectives |
| **Career Relevance** | SOC Analyst (Tier 1–3) · Security Engineer · Incident Responder |

---

## Architecture

The diagram below illustrates the complete log ingestion pipeline built in this lab. The Windows Server VM (Active Directory) acts as the **log source**. The Splunk Universal Forwarder agent installed on that VM compresses, encrypts, and ships Windows Event Logs over TCP **port 9997** to the Splunk Indexer running on a separate Ubuntu VM. Splunk indexes and stores the events, making them searchable through the **web UI on port 8000**.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Azure Virtual Network (VNet)                  │
│                                                                      │
│  ┌────────────────────────┐            ┌────────────────────────┐   │
│  │  Windows Server VM     │            │  Ubuntu VM             │   │
│  │  (Lab 1 — AD/DC)       │            │  (Splunk Indexer)      │   │
│  │                        │            │                        │   │
│  │  ┌──────────────────┐  │  TCP 9997  │  ┌──────────────────┐ │   │
│  │  │ Splunk Universal │  │──────────▶ │  │ Splunk Enterprise│ │   │
│  │  │ Forwarder        │  │  (VNet     │  │ (Free License)   │ │   │
│  │  │                  │  │   only)    │  │                  │ │   │
│  │  │  inputs.conf:    │  │            │  │  Index:          │ │   │
│  │  │  • Security Log  │  │            │  │  windows_logs    │ │   │
│  │  │  • System Log    │  │            │  │                  │ │   │
│  │  │  • App Log       │  │            │  │  Port 8000       │ │   │
│  │  └──────────────────┘  │            │  │  (Web UI)        │ │   │
│  │                        │            │  └──────────────────┘ │   │
│  │  Event IDs Captured:   │            │                        │   │
│  │  4624 · 4625 · 4740    │            │  ┌──────────────────┐ │   │
│  └────────────────────────┘            │  │  Dashboards &    │ │   │
│                                        │  │  Alerts Engine   │ │   │
│                                        │  └──────────────────┘ │   │
│                                        └────────────────────────┘   │
│                                                    │                 │
└────────────────────────────────────────────────────│─────────────────┘
                                                     │ Port 8000
                                                     ▼
                                          ┌─────────────────────┐
                                          │  Analyst Workstation │
                                          │  (Your Browser)      │
                                          │                      │
                                          │  • SPL Searches      │
                                          │  • Dashboards        │
                                          │  • Alerts            │
                                          └─────────────────────┘
```

### Data Flow Summary

```
Windows Event Log → Universal Forwarder → TCP 9997 → Splunk Indexer → index=windows_logs → SPL Search → Dashboard / Alert
```

### NSG Port Rules

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| `22` | TCP | Your IP only | SSH into Ubuntu Splunk VM |
| `8000` | TCP | Your IP only | Splunk Web UI |
| `9997` | TCP | VNet range only (`10.0.0.0/16`) | Universal Forwarder log ingestion |

---

## Prerequisites

- Completed **Lab 1** (Windows Server / Active Directory VM on Azure) — or use Splunk's built-in sample data
- An Azure subscription (free tier eligible)
- A temporary email address for Splunk registration (see Step 1)

---

## Key Concepts

### What is a SIEM?
A SIEM (Security Information and Event Management) platform centralizes logs from across your entire environment — servers, workstations, firewalls, cloud services — and makes them searchable in one place. Its two core functions are **correlation** (connecting events across systems to surface attack patterns) and **alerting** (automatically notifying analysts when suspicious conditions are met).

### Splunk Processing Language (SPL)
SPL is the query language for Splunk. It works as a pipeline: start with a search, then pipe results through commands that filter, transform, and visualize.

```spl
index=windows_logs EventCode=4625 | stats count by Account_Name | sort -count
```
↑ This finds all failed logins, counts them per username, and sorts highest to lowest.

### Windows Security Event IDs

| Event ID | Description | Security Relevance |
|---|---|---|
| `4624` | Successful logon | Baseline — establishes who logged in and how |
| `4625` | Failed logon attempt | Spike = possible brute force or password spray |
| `4740` | Account locked out | Multiple lockouts across accounts = password spray |

### Splunk Indexes
An index is a named storage bucket — like a database table. In this lab you create one called `windows_logs`. Separating data sources into discrete indexes enables fine-grained control over retention, permissions, and storage.

### Universal Forwarder
A lightweight agent installed on the log source (your Windows Server VM). It monitors Windows Event Logs, compresses and encrypts the data, and ships it to your Splunk indexer over port 9997. Minimal CPU/RAM footprint — designed to run invisibly on production servers.

---

## Step 1 — Deploy Splunk on Azure

### 1.1 — Create the Ubuntu VM

| Setting | Value |
|---|---|
| **OS** | Ubuntu 22.04 LTS |
| **Size** | Standard_B2s (2 vCPU, 4 GB RAM minimum) |
| **Disk** | 30 GB minimum |
| **Inbound ports** | 22, 8000 (your IP), 9997 (VNet range only) |

### 1.2 — Register and Download Splunk

Splunk requires a free account to download. Use a temporary email address to avoid registering with personal details.

1. Go to [temp-mail.org](https://temp-mail.org/en/) — a temporary address is auto-generated. Copy it.
2. Go to [splunk.com/en_us/download/splunk-enterprise.html](https://www.splunk.com/en_us/download/splunk-enterprise.html)
3. Register using the temp-mail address and any dummy information for the remaining fields
4. Check the temp-mail inbox for the confirmation link and activate your account
5. Download **Splunk Enterprise for Linux (.deb package)**

### 1.3 — Install Splunk on the Ubuntu VM

SSH into your Ubuntu VM:

```bash
# macOS / Linux
ssh yourusername@YOUR_VM_PUBLIC_IP

# Windows — use PuTTY (putty.org), enter the VM's public IP, port 22
```

Run the following commands inside the SSH session:

```bash
# Download Splunk Enterprise (v10.2.2 — update URL if newer version is available)
wget -O splunk-10.2.2-linux-amd64.deb \
  "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"

# NOTE: If this wget returns a 404, log into splunk.com → Free Trials and Downloads
# → Linux .deb → copy the current wget command from the download page.

# Install the package
sudo dpkg -i splunk-10.2.2-linux-amd64.deb

# Start Splunk — you will be prompted to set admin credentials
sudo /opt/splunk/bin/splunk start --accept-license

# Enable auto-start on VM reboot
sudo /opt/splunk/bin/splunk enable boot-start
```

Access the web UI at: `http://<YOUR_VM_PUBLIC_IP>:8000`

---

## Step 2 — Configure Data Inputs

### 2.1 — Enable Receiving Port in Splunk

1. Log into the Splunk web UI
2. **Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port**
3. Enter `9997` → Save
4. **Settings → Indexes → Create New Index** → name it `windows_logs` → Save

### 2.2 — Install the Universal Forwarder on Windows Server

> ⚠️ The following steps run on your **Windows Server VM (Lab 1)**, not the Splunk Ubuntu VM.

1. On the Windows Server VM, open a browser and go to: `splunk.com/en_us/download/universal-forwarder.html`
2. Download the **Windows 64-bit installer**
3. Run the installer:
   - **Deployment Server:** enter your Splunk VM's **private IP** and port `8089`
   - **Receiving Indexer:** enter your Splunk VM's **private IP** and port `9997`
4. Complete installation with default settings

### 2.3 — Configure inputs.conf

`inputs.conf` tells the forwarder which Windows Event Logs to collect. Create or edit this file at the exact path below:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

> Open Notepad as Administrator and save to that location. Create the `local` folder if it doesn't exist.

```ini
[WinEventLog://Security]
# Authentication events — logins, failures, lockouts
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1

[WinEventLog://System]
# OS-level events — service starts/stops, driver failures
disabled = 0

[WinEventLog://Application]
# Application-level events
disabled = 0
```

After saving, restart the forwarder in PowerShell (run as Administrator):

```powershell
Restart-Service SplunkForwarder
```

> **No Lab 1 VM yet?** Splunk includes built-in sample data. Go to **Search → Data Summary** and use the sample indexes to complete the SPL exercises below while you build out the AD environment.

---

## Step 3 — SPL Searches

All searches run in the **Search & Reporting** app. Paste each query into the search bar and set your time range using the time picker.

### Confirm Data Ingestion

```spl
index=windows_logs | head 100
```
Returns the first 100 events. If this returns results, your forwarder is working. If empty, verify the `SplunkForwarder` service is running on the Windows VM.

---

### Failed Login Attempts — EventCode 4625

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name
| sort -count
```

> **Detection logic:** A count of 5+ failed attempts for one account in a short window is a potential brute force indicator.

---

### Successful Logins — EventCode 4624

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name, Logon_Type
| sort -count
```

**Logon Type Reference:**

| Logon Type | Meaning |
|---|---|
| `2` | Interactive (physical keyboard) |
| `3` | Network (file share, network resource) |
| `5` | Service account (automated — usually expected) |
| `10` | Remote Interactive (RDP session) |

---

### Account Lockout Events — EventCode 4740

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4740
| table _time, Account_Name, Caller_Computer_Name
| sort -_time
```

> **Detection logic:** Multiple lockouts across different accounts originating from the same `Caller_Computer_Name` is a strong indicator of a **password spray attack**.

---

### Top 10 Failed Login Usernames — Threat Hunting

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h
| stats count as failures by Account_Name
| sort -failures
| head 10
```

> **Detection logic:**
> - Accounts with 20+ failures in 24 hours → investigate for brute force
> - Usernames that don't exist in AD → active **account enumeration**

---

### After-Hours Login Detection

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, Account_Name, Workstation_Name, Logon_Type
| sort -_time
```

> **Detection logic:** After-hours `Logon_Type=5` (service accounts) is normal and expected. After-hours `Logon_Type=2` or `Logon_Type=10` from regular user accounts warrants review.

---

## Step 4 — Build a Security Dashboard

1. In Splunk, click **Dashboards → Create New Dashboard**
2. Name: `Windows Security Overview` → click **Create Dashboard**
3. Add each panel below using **Add Panel → New Search**

| Panel | Search | Visualization |
|---|---|---|
| Failed Logins — Last 24h | `EventCode=4625` with `stats count by Account_Name` | Bar chart |
| Account Lockouts — Last 7d | `EventCode=4740` with `table` output | Events list |
| Login Activity Over Time | `EventCode=4624` with `timechart count` | Line chart |
| Top Source IPs — After Hours | After-hours search with `stats count by Workstation_Name` | Column chart |

---

## Step 5 — Create an Automated Alert

Automated alerts let Splunk do the watching so analysts focus on responding, not polling dashboards.

First, validate the search works:

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count as failures by Account_Name
| where failures > 10
```

Then save it as an alert:

1. Click **Save As → Alert**
2. Fill in the following:

| Field | Value |
|---|---|
| **Name** | `Potential Brute Force — High Failure Count` |
| **Alert Type** | Scheduled |
| **Run Every** | 15 minutes |
| **Trigger Condition** | Number of Results is greater than 0 |
| **Trigger Actions** | Add to Triggered Alerts |

3. Click **Save**

> **Threshold tuning note:** Setting the threshold at 10 failures is a starting point. In production, you tune this over time based on observed false positive rates. An alert that fires too broadly creates analyst fatigue. An alert that fires too narrowly misses real attacks.

---

## Verification Checklist

| Check | How to Verify |
|---|---|
| Data flowing into Splunk | `index=windows_logs \| head 10` returns recent events |
| Failed login search works | Run `EventCode=4625` search — if no results, type the wrong password on the Windows VM a few times, then re-run |
| Dashboard displays data | `Windows Security Overview` shows populated charts |
| Alert is active | **Settings → Searches, Reports, and Alerts** — alert appears as **Enabled** |

---

## Skills Demonstrated

| Skill | Real-World Application |
|---|---|
| SIEM deployment and configuration | Every enterprise Splunk deployment starts with getting data in — this lab covers the full pipeline |
| Splunk Universal Forwarder setup | The standard method for feeding logs to Splunk in enterprise environments |
| SPL query writing | The core analyst skill — separates analysts who find threats from those who watch dashboards |
| Security dashboard creation | Provides persistent visibility into authentication posture without manual queries |
| Brute force detection | One of the most common Tier 1 SOC investigations |
| Automated alerting | How real SOC detection works — scheduled searches that fire on defined conditions |
| Account lockout analysis | A lockout trail can surface an active password spray in progress |

---


