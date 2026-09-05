# Scenario 9: Kerberoasting Detection Using Kerberos Service Ticket Events

## Scenario Overview

Scenario 9 demonstrates Kerberoasting detection in an Active Directory lab environment.

This scenario continues from the previous attack chain where a valid domain account was used for post-authentication enumeration and SMB share discovery. In this scenario, the valid account `CORP\thabo.dlamini` was used from Kali-Red to identify a Service Principal Name (SPN) account and request a Kerberos service ticket.

The goal was to confirm whether the domain controller generated Event ID `4769` and whether Microsoft Sentinel could ingest and detect Kerberos service ticket request activity associated with potential Kerberoasting behavior.

The scenario was executed in an authorised lab environment as part of a purple team Active Directory detection engineering project.

## Objective

The objectives of this scenario were to:

- Configure a lab service account with a Service Principal Name.
- Use valid domain credentials from Kali-Red.
- Discover SPN-enabled accounts using Impacket.
- Request a Kerberos service ticket for the SPN account.
- Generate Windows Security Event ID `4769`.
- Confirm local logging on DC01.
- Confirm Microsoft Sentinel ingestion of Event ID `4769`.
- Build a detection query for possible Kerberoasting activity.
- Map the activity to MITRE ATT&CK.
- Document the attack simulation, detection evidence, and analyst assessment.

## Lab Context

| Component | Description |
|---|---|
| Attacker host | Kali-Red |
| Source IP | `10.0.2.4` |
| Domain controller | `DC01.corp.lab` |
| Domain controller IP | `10.0.1.4` |
| Domain | `corp.lab` |
| Requesting account | `CORP\thabo.dlamini` |
| Service account | `svc_sql` |
| SPN configured | `MSSQLSvc/DC01.corp.lab:1433` |
| Tool used | `impacket-GetUserSPNs` |
| Main Windows Event ID | `4769` |
| Event meaning | A Kerberos service ticket was requested |
| MITRE ATT&CK tactic | Credential Access |
| MITRE ATT&CK technique | Kerberoasting |
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
SPN account discovery
        ↓
Kerberos service ticket request
        ↓
Kerberoasting detection
```

The key analyst question for this scenario is:

```text
Was a valid domain account used to request Kerberos service tickets for SPN-enabled service accounts?
```

## Why This Scenario Matters

Kerberoasting is an Active Directory attack technique where an authenticated domain user requests Kerberos service tickets for accounts with Service Principal Names.

The requested ticket can be extracted and attacked offline. The defensive goal in this scenario is not to perform password cracking, but to detect the service ticket request activity that may indicate Kerberoasting.

This scenario is important because any authenticated domain user can request service tickets for SPN accounts, making detection and monitoring important in enterprise Active Directory environments.

## SPN Configuration on DC01

The service account used in this lab was:

```text
svc_sql
```

The following command was used on DC01 to check existing SPNs:

```powershell
setspn -L CORP\svc_sql
```

An SPN was then added for the service account:

```powershell
setspn -S MSSQLSvc/DC01.corp.lab:1433 CORP\svc_sql
```

The SPN was confirmed with:

```powershell
setspn -L CORP\svc_sql
```

Expected SPN value:

```text
MSSQLSvc/DC01.corp.lab:1433
```

## Kali-Red Activity

The valid domain account used to perform the Kerberoasting simulation was:

```text
CORP\thabo.dlamini
```

The following command was used from Kali-Red to identify SPN-enabled accounts:

```bash
impacket-GetUserSPNs corp.lab/thabo.dlamini:'REDACTED_PASSWORD' -dc-ip 10.0.1.4
```

The output confirmed that an SPN-enabled account existed:

```text
svc_sql
MSSQLSvc/DC01.corp.lab:1433
```

The following command was used to request the Kerberos service ticket:

```bash
impacket-GetUserSPNs corp.lab/thabo.dlamini:'REDACTED_PASSWORD' -dc-ip 10.0.1.4 -request
```

The command returned Kerberos ticket/hash output, confirming that the Kerberoasting simulation was successful.

> Note: Passwords and Kerberos hashes must be redacted before screenshots are added to documentation, GitHub, or public posts.

## Expected Windows Event

The main Windows Security event for this scenario is:

| Event ID | Description |
|---|---|
| `4769` | A Kerberos service ticket was requested |

Expected event details:

| Field | Expected Value |
|---|---|
| Event ID | `4769` |
| Requesting account | `thabo.dlamini` |
| Service account | `svc_sql` |
| SPN | `MSSQLSvc/DC01.corp.lab:1433` |
| Source IP | `10.0.2.4` or `::ffff:10.0.2.4` |
| Computer | `DC01.corp.lab` |

## DC01 Local Event Validation

Initially, Sentinel did not show Event ID `4769`. To validate whether the issue was with logging or ingestion, Event ID `4769` was checked locally on DC01.

The following PowerShell query was used:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4769
    StartTime=(Get-Date).AddHours(-2)
} | Select-Object -First 10 TimeCreated, Id, ProviderName, Message
```

This confirmed that DC01 generated Event ID `4769` locally.

## Kerberos Audit Policy

The following audit policy was checked on DC01:

```powershell
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

The expected result was:

```text
Success and Failure
```

If not enabled, the following command can be used:

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

## Sentinel Troubleshooting

When Event ID `4769` did not appear in the `SecurityEvent` table initially, the event was checked in other tables.

The following query successfully showed the event in Microsoft Sentinel:

```kql
WindowsEvent
| where TimeGenerated > ago(6h)
| where EventID == 4769
| project
    TimeGenerated,
    EventID,
    Provider,
    Computer,
    EventData
| order by TimeGenerated desc
```

This confirmed that Microsoft Sentinel was ingesting the Kerberos service ticket event.

## Sentinel Evidence

Microsoft Sentinel showed the following evidence:

| Field | Value |
|---|---|
| Event ID | `4769` |
| Computer | `DC01.corp.lab` |
| Channel | `Security` |
| Source | `Microsoft-Windows-Security-Auditing` |
| Target/requesting account | `thabo.dlamini@CORP.LAB` |
| Event meaning | A Kerberos service ticket was requested |

The final Sentinel evidence confirmed that the event was searchable using indicators such as:

```text
svc_sql
MSSQLSvc
thabo.dlamini
10.0.2.4
```

## Validation Query

The following query can be used to validate Event ID `4769` in the `SecurityEvent` table if the event is parsed there:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| project
    TimeGenerated,
    Account,
    ServiceName,
    IpAddress,
    ClientAddress,
    TicketEncryptionType,
    Status,
    Computer,
    Activity
| order by TimeGenerated desc
```

If the event is landing in `WindowsEvent`, use this query:

```kql
WindowsEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| extend EventDataText = tostring(EventData)
| where EventDataText has_any ("svc_sql", "MSSQLSvc", "thabo.dlamini", "10.0.2.4")
| project
    TimeGenerated,
    EventID,
    Provider,
    Computer,
    EventData
| order by TimeGenerated desc
```

## Detection Query

The following detection query can be used to identify Kerberos service ticket requests for SPN accounts.

### SecurityEvent Version

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| where isnotempty(ServiceName)
| where ServiceName !endswith "$"
| summarize
    TicketRequests = count(),
    RequestedServices = make_set(ServiceName, 50),
    UniqueServices = dcount(ServiceName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account, ClientAddress, IpAddress, bin(TimeGenerated, 10m)
| where UniqueServices >= 1 or TicketRequests >= 1
| project
    TimeGenerated,
    Account,
    ClientAddress,
    IpAddress,
    TicketRequests,
    UniqueServices,
    RequestedServices,
    FirstSeen,
    LastSeen
| order by TimeGenerated desc
```

### WindowsEvent Version

Use this version if Event ID `4769` is being ingested into the `WindowsEvent` table:

```kql
WindowsEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| extend EventDataText = tostring(EventData)
| extend TargetUserName = extract(@"<Data Name=""TargetUserName"">([^<]*)</Data>", 1, EventDataText)
| extend ServiceName = extract(@"<Data Name=""ServiceName"">([^<]*)</Data>", 1, EventDataText)
| extend IpAddressParsed = extract(@"<Data Name=""IpAddress"">([^<]*)</Data>", 1, EventDataText)
| extend TicketEncryptionType = extract(@"<Data Name=""TicketEncryptionType"">([^<]*)</Data>", 1, EventDataText)
| extend Status = extract(@"<Data Name=""Status"">([^<]*)</Data>", 1, EventDataText)
| where isnotempty(ServiceName)
| where ServiceName !endswith "$"
| summarize
    TicketRequests = count(),
    RequestedServices = make_set(ServiceName, 50),
    UniqueServices = dcount(ServiceName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by TargetUserName, IpAddressParsed, bin(TimeGenerated, 10m)
| where UniqueServices >= 1 or TicketRequests >= 1
| project
    TimeGenerated,
    TargetUserName,
    IpAddressParsed,
    TicketRequests,
    UniqueServices,
    RequestedServices,
    FirstSeen,
    LastSeen
| order by TimeGenerated desc
```

## Lab-Specific Detection Query

For this lab, the detection can be tightened to the known account, service account, and Kali-Red IP:

```kql
WindowsEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| extend EventDataText = tostring(EventData)
| extend TargetUserName = extract(@"<Data Name=""TargetUserName"">([^<]*)</Data>", 1, EventDataText)
| extend ServiceName = extract(@"<Data Name=""ServiceName"">([^<]*)</Data>", 1, EventDataText)
| extend IpAddressParsed = extract(@"<Data Name=""IpAddress"">([^<]*)</Data>", 1, EventDataText)
| extend TicketEncryptionType = extract(@"<Data Name=""TicketEncryptionType"">([^<]*)</Data>", 1, EventDataText)
| extend Status = extract(@"<Data Name=""Status"">([^<]*)</Data>", 1, EventDataText)
| where EventDataText has_any ("svc_sql", "MSSQLSvc", "thabo.dlamini", "10.0.2.4")
| project
    TimeGenerated,
    EventID,
    TargetUserName,
    ServiceName,
    IpAddressParsed,
    TicketEncryptionType,
    Status,
    Computer,
    Provider
| order by TimeGenerated desc
```

## Analytics Rule Details

| Field | Value |
|---|---|
| Rule name | `LAB - Possible Kerberoasting Activity Against AD Service Accounts` |
| Severity | Medium |
| Query frequency | 5 minutes or 10 minutes |
| Lookup period | 1 hour |
| Main event ID | `4769` |
| Primary data source | `SecurityEvent` or `WindowsEvent` |
| Entity mapping | Account, Host, IP |

## Analytics Rule Description

```text
Detects Kerberos service ticket requests for Service Principal Name accounts. This may indicate Kerberoasting activity where a valid domain account requests service tickets that could be used for offline password cracking.
```

## Entity Mapping

| Sentinel Entity | Field |
|---|---|
| Account | `TargetUserName` or `Account` |
| Host | `Computer` |
| IP | `IpAddressParsed`, `IpAddress`, or `ClientAddress` |

## MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | A valid domain account requested a Kerberos service ticket for an SPN account. |
| Credential Access | Brute Force / Offline Password Cracking | The requested ticket/hash could be attacked offline. |
| Discovery | Account Discovery | The attacker first identified SPN-enabled service accounts. |

Recommended primary mapping:

```text
Credential Access → T1558.003 Kerberoasting
```

## Evidence Captured

| Evidence Item | Status |
|---|---|
| SPN created for `svc_sql` | Captured |
| `MSSQLSvc/DC01.corp.lab:1433` configured | Captured |
| Impacket found the SPN account | Captured |
| Impacket requested the Kerberos service ticket | Captured |
| Kerberos ticket/hash output generated | Captured |
| DC01 locally generated Event ID `4769` | Captured |
| Sentinel ingested Event ID `4769` | Captured |
| Account `thabo.dlamini` identified | Captured |
| Service account `svc_sql` identified | Captured |
| Domain controller `DC01.corp.lab` identified | Captured |

## Analyst Assessment

This activity is suspicious because a valid domain account requested Kerberos service tickets for an SPN-enabled service account.

In a real enterprise environment, this may indicate Kerberoasting activity. An attacker with valid credentials could request service tickets for service accounts and attempt to crack the returned ticket material offline.

The risk is higher when the targeted service account has a weak password, excessive privileges, or membership in privileged groups.

In this lab, the service account `svc_sql` was intentionally configured with an SPN to generate Kerberoasting telemetry and validate Sentinel visibility.

## Incident Classification

Recommended incident closure for the lab:

| Field | Value |
|---|---|
| Classification | True Positive |
| Reason | Suspicious activity / Kerberoasting simulation |
| Status | Closed |
| Environment | Authorised lab simulation |

## Incident Closure Comment

```text
Confirmed true positive lab simulation. A Service Principal Name was configured for the svc_sql account, and Kali-Red used the valid CORP\thabo.dlamini account to request a Kerberos service ticket using Impacket. DC01 generated Event ID 4769, and Microsoft Sentinel ingested the event. This activity represents Kerberos service ticket request behavior associated with possible Kerberoasting.
```

## Result

| Validation Item | Status |
|---|---|
| SPN account configured | Successful |
| SPN discovered with Impacket | Successful |
| Kerberos service ticket requested | Successful |
| Kerberos ticket/hash returned | Successful |
| Event ID `4769` generated locally on DC01 | Successful |
| Event ID `4769` ingested into Sentinel | Successful |
| Kerberoasting detection evidence collected | Successful |
| MITRE ATT&CK mapping added | Successful |
| Scenario outcome | Completed successfully |

## Final Conclusion

Scenario 9 was completed successfully.

A Service Principal Name was configured for the `svc_sql` account using `MSSQLSvc/DC01.corp.lab:1433`. Kali-Red used the valid domain account `CORP\thabo.dlamini` to identify the SPN account and request a Kerberos service ticket using Impacket.

DC01 generated Windows Security Event ID `4769`, and Microsoft Sentinel ingested the event. This confirmed visibility into Kerberos service ticket request activity associated with potential Kerberoasting behavior.

This scenario demonstrates how Kerberos service ticket telemetry can be used to detect credential access activity in an Active Directory environment.
