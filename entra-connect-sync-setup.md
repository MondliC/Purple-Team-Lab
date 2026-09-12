# Microsoft Entra Connect Sync Lab Setup

## Overview

This document captures the setup used to synchronize an on-premises Active Directory lab with Microsoft Entra ID using **Microsoft Entra Connect Sync** and **Password Hash Synchronization (PHS)**.

The lab was built as part of a hybrid identity security project, extending an existing Active Directory environment into Microsoft Entra ID.

## Architecture

```text
On-Premises / Azure Lab

DC01
Active Directory Domain Services
Domain: corp.lab
Private IP: 10.0.1.4
        |
        | AD / DNS / LDAP / Kerberos / SMB
        v
SYNC01
Microsoft Entra Connect Sync
Private IP: 10.0.1.5
        |
        | HTTPS 443
        v
Microsoft Entra ID
Hybrid identities
```

## Environment

- **Domain Controller:** DC01
- **AD domain:** `corp.lab`
- **NetBIOS domain:** `CORP`
- **Sync server:** SYNC01
- **Synchronization method:** Microsoft Entra Connect Sync
- **Authentication method:** Password Hash Synchronization
- **VNet:** LAB-VNET
- **Server subnet:** SERVER-SUBNET
- **DC01 private IP:** `10.0.1.4`
- **SYNC01 private IP:** `10.0.1.5`

---

# 1. Prepare SYNC01

A dedicated Windows Server VM named `SYNC01` was deployed for Microsoft Entra Connect Sync.

The sync service was intentionally kept off the domain controller so that:

- DC01 remains focused on AD DS and DNS.
- Entra Connect has a dedicated host.
- The lab better reflects a production-style hybrid identity design.

## Confirm connectivity to DC01

From SYNC01:

```powershell
Test-NetConnection dc01.corp.lab -Port 53
Test-NetConnection dc01.corp.lab -Port 88
Test-NetConnection dc01.corp.lab -Port 389
Test-NetConnection dc01.corp.lab -Port 445
```

Expected result:

```text
TcpTestSucceeded : True
```

---

# 2. Join SYNC01 to the AD Domain

SYNC01 was joined to:

```text
corp.lab
```

A domain account with permission to join computers to the domain was used.

After restart, verify:

```powershell
(Get-CimInstance Win32_ComputerSystem).Domain
```

Expected:

```text
corp.lab
```

Domain controller discovery can also be tested with:

```powershell
nltest /dsgetdc:corp.lab
```

---

# 3. Configure Internet Access for SYNC01

Initially, outbound HTTPS failed:

```powershell
Test-NetConnection login.microsoftonline.com -Port 443
```

The Azure subnet was configured as a **private subnet with no default outbound access**.

For this lab, default outbound access was temporarily enabled so SYNC01 could reach Microsoft Entra endpoints over TCP 443.

After the change and VM restart/deallocation cycle, outbound connectivity was tested again:

```powershell
Test-NetConnection login.microsoftonline.com -Port 443
```

Expected:

```text
TcpTestSucceeded : True
```

> For a production environment, an explicit outbound method such as Azure NAT Gateway or Azure Firewall would be preferred over relying on default outbound access.

---

# 4. Configure DNS Correctly

One of the main setup issues was DNS.

SYNC01 initially used Azure-provided DNS:

```text
168.63.129.16
```

This allowed public DNS resolution but did not know about the private AD DNS zone:

```text
corp.lab
```

As a result, the following failed:

```powershell
nltest /dsgetdc:corp.lab
Resolve-DnsName _ldap._tcp.dc._msdcs.corp.lab -Type SRV
Resolve-DnsName dc01.corp.lab
```

## Fix

The VNet DNS configuration was changed from Azure-provided DNS to custom DNS:

```text
10.0.1.4
```

This points LAB-VNET clients to DC01 for DNS.

After restarting SYNC01, verify:

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4
```

Expected:

```text
ServerAddresses : {10.0.1.4}
```

Verify AD DNS SRV records:

```powershell
Resolve-DnsName _ldap._tcp.dc._msdcs.corp.lab -Type SRV
```

Example result:

```text
NameTarget : dc01.corp.lab
Port       : 389
```

Verify domain controller discovery:

```powershell
nltest /dsgetdc:corp.lab
```

---

# 5. Install Microsoft Entra Connect Sync

Microsoft Entra Connect Sync was downloaded and installed on SYNC01.

During installation:

- **Customize** was selected instead of Express Settings.
- Default installation components were used.
- No external SQL Server was configured.
- No custom service account was configured.

---

# 6. Configure the Sign-In Method

The selected sign-in method was:

```text
Password Hash Synchronization
```

Seamless Single Sign-On was not enabled during the initial deployment.

This keeps the initial lab configuration simple while still providing hybrid identity authentication.

---

# 7. Connect Microsoft Entra ID

A Microsoft Entra tenant administrator account was used to connect Entra Connect Sync to the tenant.

A personal Microsoft account was initially attempted and returned:

```text
AADSTS50020
```

The fix was to authenticate using an account that belongs to the Microsoft Entra tenant and has the required administrative role.

---

# 8. Connect the Active Directory Forest

The on-premises forest was added as:

```text
corp.lab
```

The AD NetBIOS domain name was confirmed as:

```text
CORP
```

The Enterprise Admin credential format used successfully was:

```text
CORP\adminclementon
```

Entra Connect then successfully added:

```text
corp.lab (Active Directory)
```

---

# 9. Add an Alternate UPN Suffix

The original AD user UPN suffix was:

```text
@corp.lab
```

Because `.lab` is not a publicly verified Microsoft Entra domain, a valid Entra tenant suffix was added to Active Directory as an alternate UPN suffix.

On DC01:

```text
Server Manager
  -> Tools
  -> Active Directory Domains and Trusts
```

Right-click the top-level **Active Directory Domains and Trusts** node and open **Properties**.

Add the Entra tenant domain, for example:

```text
<tenant>.onmicrosoft.com
```

Equivalent PowerShell:

```powershell
Set-ADForest -Identity "corp.lab" -UPNSuffixes @{Add="<tenant>.onmicrosoft.com"}
```

Verify:

```powershell
Get-ADForest corp.lab | Select-Object -ExpandProperty UPNSuffixes
```

---

# 10. Update Lab User UPNs

Users intended for synchronization were updated from:

```text
user@corp.lab
```

to:

```text
user@<tenant>.onmicrosoft.com
```

This was done in:

```text
Active Directory Users and Computers
  -> User Properties
  -> Account
  -> User logon name
```

The AD domain itself remains:

```text
corp.lab
```

Only the user sign-in suffix was changed.

---

# 11. Configure Domain and OU Filtering

The sync scope was restricted using:

```text
Sync selected domains and OUs
```

Only the OU containing the intended lab users was selected.

This prevents unnecessary synchronization of:

- Built-in users
- Administrative accounts
- Unrelated service accounts
- Unneeded computers
- Other lab objects

> In this lab, some service accounts were synchronized for testing. In a production environment, service accounts should only be synchronized when there is a clear requirement.

---

# 12. Final Configuration

The final configuration included:

- `corp.lab` AD connector
- Microsoft Entra tenant connector
- Password Hash Synchronization
- Selected OU synchronization
- Synchronization process enabled immediately after installation
- Staging mode disabled

The option below was left enabled:

```text
Start the synchronization process when configuration completes
```

Staging mode was left disabled.

---

# 13. Verify Synchronization

On SYNC01:

```powershell
Get-ADSyncScheduler
```

A manual delta sync can be triggered with:

```powershell
Start-ADSyncSyncCycle -PolicyType Delta
```

In Microsoft Entra ID:

```text
Entra admin center
  -> Users
  -> All users
```

Synced users should show:

```text
On-premises sync: Yes
```

Cloud-only users should remain:

```text
On-premises sync: No
```

Example synchronized lab identities included:

- Alice Mokoena
- Bob Ndlovu
- Lerato Molefe
- Naledi Maseko
- Sipho Khumalo
- Thabo Dlamini

---

# Troubleshooting Notes

## Problem: Entra Connect could not find `corp.lab`

### Symptom

```text
The forest 'corp.lab' doesn't exist
```

### Root cause

SYNC01 was using Azure-provided DNS instead of DC01.

### Fix

Set LAB-VNET DNS to:

```text
10.0.1.4
```

Then restart SYNC01.

---

## Problem: AD forest credentials failed

### Symptom

```text
The domain specified in the credentials does not exist or cannot be contacted
```

### Fix

After fixing DNS, use the NetBIOS-qualified credential format:

```text
CORP\adminclementon
```

Confirm the NetBIOS domain with:

```powershell
nltest /domain_trusts
```

---

## Problem: Microsoft account sign-in failed

### Symptom

```text
AADSTS50020
```

### Cause

A personal Microsoft account was used instead of a Microsoft Entra tenant account.

### Fix

Use a tenant account with the required Microsoft Entra administrative role.

---

## Problem: TCP 443 to Microsoft endpoints failed

### Cause

The Azure subnet was configured with no default outbound access.

### Fix used in this lab

Default outbound access was enabled for the lab subnet.

### Production recommendation

Use an explicit outbound architecture such as:

- Azure NAT Gateway
- Azure Firewall
- Controlled proxy / secure web gateway

---

# Security Considerations

For a production deployment:

1. Do not expose SYNC01 directly to the internet for inbound administration.
2. Restrict outbound traffic to required Microsoft endpoints where practical.
3. Use least-privileged accounts during configuration.
4. Keep Entra Connect fully patched and monitored.
5. Scope synchronization to only required OUs.
6. Avoid synchronizing legacy or service identities unless necessary.
7. Monitor synchronization health and failures.
8. Protect Tier 0 infrastructure such as DC01 and the Entra Connect server.
9. Consider dedicated administrative accounts for hybrid identity management.
10. Review whether Password Hash Synchronization, Pass-through Authentication, or another sign-in method best fits the environment.

---

# Result

The final setup successfully synchronized selected on-premises Active Directory users from:

```text
corp.lab
```

to Microsoft Entra ID using Microsoft Entra Connect Sync and Password Hash Synchronization.

The environment now contains hybrid identities that can be used in the next phase of the project for identity-focused detection and investigation.

```text
DC01 / Active Directory
        |
        | AD identities
        v
SYNC01 / Entra Connect
        |
        | Password Hash Sync
        v
Microsoft Entra ID
        |
        v
Hybrid Identity Security Testing
```

## Next Phase

Planned next steps include:

- Deploy Microsoft Defender for Identity on DC01.
- Validate identity sensor health.
- Correlate on-premises AD activity with Microsoft Defender XDR.
- Investigate hybrid identity attack paths.
- Extend Microsoft Sentinel detections with cloud identity context.
- Compare on-premises authentication signals with Entra sign-in activity.
- Document identity attack, detection, remediation, and retest scenarios.

---

## Project Context

This setup forms part of a broader Active Directory Purple Team Detection Lab.

Phase 1 focused on:

- Active Directory enumeration
- Authentication testing
- Kerberos / NTLM related activity
- Windows Security Events
- Microsoft Sentinel detections
- MITRE ATT&CK mapping

Phase 2 introduces hybrid identity by synchronizing AD users into Microsoft Entra ID and adding additional Microsoft identity security controls.
