# Scenario 8: SMB Share Enumeration and Access Validation

## Scenario Overview

Scenario 8 demonstrates SMB share enumeration and access validation after successful Active Directory authentication.

This scenario continues from Scenario 7, where the account `CORP\thabo.dlamini` was used from Kali-Red to perform post-authentication Active Directory enumeration. In Scenario 8, the same valid domain account was used to enumerate and test access to SMB shares on the domain controller.

The scenario was executed in an authorised lab environment as part of a purple team Active Directory detection engineering project.

## Objective

The objectives of this scenario were to:

- Use valid Active Directory credentials from Kali-Red.
- Enumerate SMB shares on the domain controller.
- Test access to domain shares such as `NETLOGON`.
- Test access control against administrative shares such as `C$` and `ADMIN$`.
- Enable and validate file share auditing on DC01.
- Confirm Microsoft Sentinel visibility into SMB share access events.
- Document Event ID `5140` and `5145` evidence.
- Assess the activity from a security analyst perspective.

## Lab Context

| Component | Description |
|---|---|
| Attacker host | Kali-Red |
| Source IP | `10.0.2.4` |
| Domain controller | `DC01.corp.lab` |
| Domain controller IP | `10.0.1.4` |
| Domain | `corp.lab` |
| Account used | `CORP\thabo.dlamini` |
| Protocol | SMB |
| Main Windows Event IDs | `5140`, `5145` |
| Supporting Event ID | `4624` |
| Logon Type | `3` - Network logon |
| MITRE ATT&CK tactic | Discovery |
| Scenario status | Completed successfully |

## Attack Story

The scenario follows this attack path:

```text
Password spray
        ↓
Successful authentication
        ↓
Post-authentication AD enumeration
        ↓
SMB share enumeration
        ↓
Share access validation
        ↓
Access denied against administrative shares
```

The key analyst question for this scenario is:

```text
After obtaining valid credentials, did the account enumerate or access SMB shares on the domain controller?
```

## Activity Performed from Kali-Red

The valid domain account used for testing was:

```text
CORP\thabo.dlamini
```

The following command was used to test access to the `NETLOGON` share:

```bash
smbclient //10.0.1.4/NETLOGON -U 'CORP\thabo.dlamini'
```

Inside the SMB session, safe read-only commands were used:

```text
ls
pwd
exit
```

The `pwd` command confirmed access to:

```text
\\10.0.1.4\NETLOGON\
```

Administrative shares were also tested:

```bash
smbclient //10.0.1.4/C$ -U 'CORP\thabo.dlamini'
```

```bash
smbclient //10.0.1.4/ADMIN$ -U 'CORP\thabo.dlamini'
```

The expected result for a standard user was access denied.

## Kali-Red Results

| Test | Result |
|---|---|
| `NETLOGON` access | Successful |
| `ls` inside `NETLOGON` | Successful |
| `pwd` showed `\\10.0.1.4\NETLOGON\` | Successful |
| `C$` access | Access denied |
| `ADMIN$` access | Access denied |
| Standard user permissions | Working correctly |

## Audit Policy Configuration

Initially, Sentinel did not show Event ID `5140` or `5145`, even though the SMB activity was successful from Kali-Red.

This indicated that file share auditing was not fully enabled on DC01.

The following audit policy checks were performed on DC01:

```powershell
auditpol /get /category:"Object Access"
```

File share auditing was then enabled:

```powershell
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

The configuration was confirmed with:

```powershell
auditpol /get /subcategory:"File Share"
auditpol /get /subcategory:"Detailed File Share"
```

Expected result:

```text
Success and Failure
```

## Sentinel Evidence

After enabling auditing and retesting the SMB access, Microsoft Sentinel successfully showed file share access events.

Observed events:

| Event ID | Description |
|---|---|
| `5140` | A network share object was accessed |
| `5145` | A network share object was checked to see whether the client can be granted desired access |

Observed details:

| Field | Value |
|---|---|
| Account | `CORP\thabo.dlamini` |
| Computer | `DC01.corp.lab` |
| Event IDs | `5140`, `5145` |
| Activity | Network share access |
| Scenario result | Successful |

## Validation Query

The following query was used to validate SMB share access events in Microsoft Sentinel:

```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID in (5140, 5145)
| where Account has "thabo.dlamini"
| project
    TimeGenerated,
    EventID,
    Activity,
    Account,
    Computer,
    IpAddress,
    ShareName,
    RelativeTargetName,
    AccessMask,
    AccessList
| order by TimeGenerated desc
```

## Broader Troubleshooting Query

When file share events were not visible initially, the following broader query was used:

```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where Account has "thabo.dlamini"
| where EventID in (4624, 4627, 4634, 4648, 5140, 5145)
| project
    TimeGenerated,
    EventID,
    Activity,
    Account,
    Computer,
    IpAddress,
    LogonType,
    AuthenticationPackageName,
    ShareName,
    RelativeTargetName
| order by TimeGenerated desc
```

## Detection Query

The following query can be used as a detection query for SMB share access and enumeration activity:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (5140, 5145)
| where Account !endswith "$"
| where ShareName has_any ("NETLOGON", "SYSVOL", "ADMIN$", "C$")
| project
    TimeGenerated,
    EventID,
    Activity,
    Account,
    Computer,
    IpAddress,
    ShareName,
    RelativeTargetName,
    AccessMask,
    AccessList
| order by TimeGenerated desc
```

## Lab-Specific Detection Query

For this lab, the query can be tightened to the known account and domain controller:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (5140, 5145)
| where Account has "thabo.dlamini"
| where Computer has "DC01"
| project
    TimeGenerated,
    EventID,
    Activity,
    Account,
    Computer,
    IpAddress,
    ShareName,
    RelativeTargetName,
    AccessMask,
    AccessList
| order by TimeGenerated desc
```

## Analytics Rule Details

| Field | Value |
|---|---|
| Rule name | `LAB - SMB Share Enumeration After Successful AD Logon` |
| Severity | Medium |
| Query frequency | 5 minutes or 10 minutes |
| Lookup period | 1 hour |
| Main data source | `SecurityEvent` |
| Main event IDs | `5140`, `5145` |
| Supporting event | `4624` |
| Entity mapping | Account, Host, IP |

## MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Discovery | Network Share Discovery | The account was used to enumerate and access SMB shares. |
| Discovery | File and Directory Discovery | The account listed content within the `NETLOGON` share. |
| Initial Access / Persistence | Valid Accounts | The activity was performed using valid domain credentials. |

## Evidence Captured

| Evidence Item | Status |
|---|---|
| Kali `NETLOGON` access attempt | Captured |
| Kali `ls` command inside `NETLOGON` | Captured |
| Kali `pwd` output showing `NETLOGON` path | Captured |
| Kali `C$` access denied result | Captured |
| Kali `ADMIN$` access denied result | Captured |
| DC01 file share auditing enabled | Captured |
| Sentinel Event ID `5140` evidence | Captured |
| Sentinel Event ID `5145` evidence | Captured |
| Account `CORP\thabo.dlamini` identified | Captured |
| Host `DC01.corp.lab` identified | Captured |

## Analyst Assessment

This activity is suspicious because a valid Active Directory account was used from an internal host to enumerate and access SMB shares on a domain controller.

In a real enterprise environment, this may indicate that an attacker has obtained valid credentials and is attempting to discover accessible network shares, scripts, policies, configuration files, or other sensitive resources.

The successful access to `NETLOGON` is expected for many domain users, but the activity becomes more suspicious when it occurs after password spraying, successful authentication, and Active Directory enumeration.

The denied access attempts to `C$` and `ADMIN$` are also useful evidence because they show the account attempted to access administrative shares but did not have the required privileges.

## Incident Classification

Recommended incident closure for the lab:

| Field | Value |
|---|---|
| Classification | True Positive |
| Reason | Suspicious activity / SMB share enumeration simulation |
| Status | Closed |
| Environment | Authorised lab simulation |

## Incident Closure Comment

```text
Confirmed true positive lab simulation. The account CORP\thabo.dlamini was used from Kali-Red to access SMB shares on DC01. The account successfully accessed the NETLOGON share and listed its contents, while attempts to access administrative shares such as C$ and ADMIN$ were denied. Microsoft Sentinel collected Event ID 5140 and 5145 logs, confirming visibility into SMB network share access activity.
```

## Result

| Validation Item | Status |
|---|---|
| Valid domain account used | Successful |
| SMB share access attempted | Successful |
| `NETLOGON` accessed | Successful |
| `C$` access denied | Successful |
| `ADMIN$` access denied | Successful |
| File Share auditing enabled | Successful |
| Detailed File Share auditing enabled | Successful |
| Event ID `5140` observed | Successful |
| Event ID `5145` observed | Successful |
| Account identified as `CORP\thabo.dlamini` | Successful |
| Host identified as `DC01.corp.lab` | Successful |
| Scenario outcome | Completed successfully |

## Final Conclusion

Scenario 8 was completed successfully.

The account `CORP\thabo.dlamini` was used from Kali-Red to perform SMB share enumeration and access validation against `DC01`. The account successfully accessed the `NETLOGON` share and listed its contents. Attempts to access administrative shares such as `C$` and `ADMIN$` were denied, confirming that standard user permissions were enforced.

After enabling File Share and Detailed File Share auditing on DC01, Microsoft Sentinel successfully collected Event ID `5140` and `5145`, confirming visibility into SMB network share access activity.
