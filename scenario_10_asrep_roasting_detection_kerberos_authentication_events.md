# Scenario 10: AS-REP Roasting Detection Using Kerberos Authentication Events

## Scenario Overview

Scenario 10 demonstrates AS-REP roasting detection in an Active Directory lab environment.

This scenario continues from Scenario 9, where Kerberoasting was simulated and detected using Kerberos service ticket telemetry. In Scenario 10, a dedicated lab account was configured so that Kerberos pre-authentication was not required. Kali-Red then requested AS-REP data for that account using Impacket.

The goal was to confirm whether the domain controller generated Event ID `4768`, whether Microsoft Sentinel ingested the event, and whether the event data could be parsed to identify `PreAuthType`, ticket encryption type, source IP, and target account.

The scenario was executed in an authorised lab environment as part of a purple team Active Directory detection engineering project.

## Objective

The objectives of this scenario were to:

- Configure a dedicated Active Directory lab account with Kerberos pre-authentication disabled.
- Use Kali-Red to request AS-REP data for the vulnerable account.
- Generate Windows Security Event ID `4768`.
- Confirm Microsoft Sentinel visibility into Kerberos TGT request activity.
- Parse `PreAuthType` from the event data.
- Parse `TicketEncryptionType` from the event data.
- Identify the target account and source IP address.
- Create a Microsoft Sentinel analytics rule for possible AS-REP roasting.
- Map the activity to MITRE ATT&CK.
- Document the attack simulation, detection logic, evidence, and analyst assessment.

## Lab Context

| Component | Description |
|---|---|
| Attacker host | Kali-Red |
| Source IP | `10.0.2.4` or `::ffff:10.0.2.4` |
| Domain controller | `DC01.corp.lab` |
| Domain controller IP | `10.0.1.4` |
| Domain | `corp.lab` |
| AS-REP test account | `svc_legacy` |
| Comparison accounts | `thabo.dlamini`, `svc_sql` |
| Tool used | `impacket-GetNPUsers` |
| Main Windows Event ID | `4768` |
| Event meaning | A Kerberos authentication ticket was requested |
| Key field | `PreAuthType` |
| Expected PreAuthType | `0` |
| MITRE ATT&CK tactic | Credential Access |
| MITRE ATT&CK technique | AS-REP Roasting |
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
Kerberoasting
        ↓
AS-REP roasting
```

The key analyst question for this scenario is:

```text
Was a Kerberos authentication ticket requested for an account that does not require Kerberos pre-authentication?
```

## Why This Scenario Matters

AS-REP roasting targets Active Directory accounts that have Kerberos pre-authentication disabled.

When an account does not require pre-authentication, an attacker can request authentication data for that account and attempt offline password cracking against the returned material.

The defensive goal in this scenario is not to crack the password. The goal is to detect the Kerberos authentication request pattern and identify accounts where pre-authentication was not used.

## Lab Account Configuration

The dedicated lab account used for AS-REP roasting was:

```text
svc_legacy
```

The account was configured with:

```text
Do not require Kerberos preauthentication = Enabled
```

This can be configured in Active Directory Users and Computers:

```text
Active Directory Users and Computers
→ svc_legacy
→ Properties
→ Account
→ Account options
→ Do not require Kerberos preauthentication
```

Alternatively, this can be configured with PowerShell:

```powershell
Set-ADAccountControl -Identity svc_legacy -DoesNotRequirePreAuth $true
```

The configuration can be confirmed with:

```powershell
Get-ADUser svc_legacy -Properties DoesNotRequirePreAuth | Select-Object SamAccountName, DoesNotRequirePreAuth
```

Expected result:

```text
SamAccountName    DoesNotRequirePreAuth
--------------    ---------------------
svc_legacy        True
```

## Kali-Red Activity

A users file was created on Kali-Red containing test accounts:

```text
svc_legacy
thabo.dlamini
svc_sql
```

The following Impacket command was used to test AS-REP roasting:

```bash
impacket-GetNPUsers corp.lab/ -usersfile users.txt -dc-ip 10.0.1.4 -no-pass
```

The output showed that:

```text
svc_legacy returned a Kerberos AS-REP hash
```

The other accounts did not return AS-REP hashes because they still required Kerberos pre-authentication:

```text
thabo.dlamini doesn't have UF_DONT_REQUIRE_PREAUTH set
svc_sql doesn't have UF_DONT_REQUIRE_PREAUTH set
```

This confirmed that only the intentionally configured account, `svc_legacy`, was vulnerable to AS-REP roasting behavior in the lab.

> Note: Passwords and AS-REP hashes must be redacted before screenshots are added to documentation, GitHub, or public posts.

## Expected Windows Event

The main Windows Security event for this scenario is:

| Event ID | Description |
|---|---|
| `4768` | A Kerberos authentication ticket was requested |

Expected event details:

| Field | Expected Value |
|---|---|
| Event ID | `4768` |
| Target account | `svc_legacy` |
| Source IP | `10.0.2.4` or `::ffff:10.0.2.4` |
| PreAuthType | `0` |
| Status | `0x0` |
| Computer | `DC01.corp.lab` |

## Sentinel Validation Query

The following query was used to look for Event ID `4768` activity related to the AS-REP test account:

```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4768
| extend EventDataText = tostring(EventData)
| where EventDataText has_any ("svc_legacy", "10.0.2.4", "::ffff:10.0.2.4")
| project
    TimeGenerated,
    EventID,
    Activity,
    Account,
    ServiceName,
    IpAddress,
    ClientAddress,
    PreAuthType,
    TicketEncryptionType,
    Status,
    Computer,
    EventData
| order by TimeGenerated desc
```

If the parsed fields are not visible in `SecurityEvent`, the raw event data can be inspected:

```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4768
| extend EventDataText = tostring(EventData)
| where EventDataText has "svc_legacy"
| project
    TimeGenerated,
    Computer,
    EventID,
    Activity,
    EventData
| order by TimeGenerated desc
```

## Parsing PreAuthType and TicketEncryptionType

In this lab, some important fields were stored inside the `EventData` XML. The following query was used to parse the key fields:

```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4768
| extend EventDataText = tostring(EventData)
| extend TargetUserName = extract(@"<Data Name=""TargetUserName"">([^<]*)</Data>", 1, EventDataText)
| extend TargetDomainName = extract(@"<Data Name=""TargetDomainName"">([^<]*)</Data>", 1, EventDataText)
| extend IpAddressParsed = extract(@"<Data Name=""IpAddress"">([^<]*)</Data>", 1, EventDataText)
| extend PreAuthTypeParsed = extract(@"<Data Name=""PreAuthType"">([^<]*)</Data>", 1, EventDataText)
| extend TicketEncryptionTypeParsed = extract(@"<Data Name=""TicketEncryptionType"">([^<]*)</Data>", 1, EventDataText)
| extend StatusParsed = extract(@"<Data Name=""Status"">([^<]*)</Data>", 1, EventDataText)
| where TargetUserName has "svc_legacy"
| project
    TimeGenerated,
    EventID,
    Activity,
    TargetUserName,
    TargetDomainName,
    IpAddressParsed,
    PreAuthTypeParsed,
    TicketEncryptionTypeParsed,
    StatusParsed,
    Computer
| order by TimeGenerated desc
```

## Detection Query

The following query can be used as the general Sentinel detection query for possible AS-REP roasting:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4768
| extend EventDataText = tostring(EventData)
| extend TargetUserName = extract(@"<Data Name=""TargetUserName"">([^<]*)</Data>", 1, EventDataText)
| extend TargetDomainName = extract(@"<Data Name=""TargetDomainName"">([^<]*)</Data>", 1, EventDataText)
| extend IpAddressParsed = extract(@"<Data Name=""IpAddress"">([^<]*)</Data>", 1, EventDataText)
| extend PreAuthTypeParsed = extract(@"<Data Name=""PreAuthType"">([^<]*)</Data>", 1, EventDataText)
| extend TicketEncryptionTypeParsed = extract(@"<Data Name=""TicketEncryptionType"">([^<]*)</Data>", 1, EventDataText)
| extend StatusParsed = extract(@"<Data Name=""Status"">([^<]*)</Data>", 1, EventDataText)
| where PreAuthTypeParsed == "0"
| where StatusParsed == "0x0"
| where TargetUserName !endswith "$"
| project
    TimeGenerated,
    EventID,
    TargetUserName,
    TargetDomainName,
    IpAddressParsed,
    PreAuthTypeParsed,
    TicketEncryptionTypeParsed,
    StatusParsed,
    Computer,
    Activity
| order by TimeGenerated desc
```

## Lab-Specific Detection Query

For the lab, the query can be tightened to the known AS-REP test account and Kali-Red source IP:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4768
| extend EventDataText = tostring(EventData)
| extend TargetUserName = extract(@"<Data Name=""TargetUserName"">([^<]*)</Data>", 1, EventDataText)
| extend TargetDomainName = extract(@"<Data Name=""TargetDomainName"">([^<]*)</Data>", 1, EventDataText)
| extend IpAddressParsed = extract(@"<Data Name=""IpAddress"">([^<]*)</Data>", 1, EventDataText)
| extend PreAuthTypeParsed = extract(@"<Data Name=""PreAuthType"">([^<]*)</Data>", 1, EventDataText)
| extend TicketEncryptionTypeParsed = extract(@"<Data Name=""TicketEncryptionType"">([^<]*)</Data>", 1, EventDataText)
| extend StatusParsed = extract(@"<Data Name=""Status"">([^<]*)</Data>", 1, EventDataText)
| where TargetUserName =~ "svc_legacy"
| where IpAddressParsed has "10.0.2.4"
| where PreAuthTypeParsed == "0"
| where StatusParsed == "0x0"
| project
    TimeGenerated,
    EventID,
    TargetUserName,
    TargetDomainName,
    IpAddressParsed,
    PreAuthTypeParsed,
    TicketEncryptionTypeParsed,
    StatusParsed,
    Computer,
    Activity
| order by TimeGenerated desc
```

## Ticket Encryption Type Reference

Common Kerberos ticket encryption values:

| Value | Meaning |
|---|---|
| `0x17` | RC4-HMAC |
| `0x12` | AES256 |
| `0x11` | AES128 |

For this scenario, the strongest detection evidence is:

```text
Event ID 4768 + PreAuthType 0 + svc_legacy + source IP 10.0.2.4
```

## Analytics Rule Details

| Field | Value |
|---|---|
| Rule name | `LAB - Possible AS-REP Roasting Against Active Directory Account` |
| Severity | Medium |
| Query frequency | 5 minutes or 10 minutes |
| Lookup period | 1 hour |
| Main event ID | `4768` |
| Primary data source | `SecurityEvent` |
| Entity mapping | Account, Host, IP |

## Analytics Rule Description

```text
Detects Kerberos TGT requests where pre-authentication was not used. This may indicate AS-REP roasting activity against an Active Directory account configured with Kerberos pre-authentication disabled.
```

## Incident Title Format

```text
Possible AS-REP Roasting against {{TargetUserName}} from {{IpAddressParsed}}
```

## Alert Description Format

```text
A Kerberos authentication ticket request was observed where pre-authentication was not used. The target account was {{TargetUserName}}, and the request originated from {{IpAddressParsed}}. This may indicate AS-REP roasting activity against an account with Kerberos pre-authentication disabled.
```

## Entity Mapping

| Sentinel Entity | Field |
|---|---|
| Account | `TargetUserName` |
| Host | `Computer` |
| IP | `IpAddressParsed` |

## Custom Details

| Custom Detail Name | Field |
|---|---|
| TargetUser | `TargetUserName` |
| TargetDomain | `TargetDomainName` |
| SourceIP | `IpAddressParsed` |
| PreAuthType | `PreAuthTypeParsed` |
| TicketEncryptionType | `TicketEncryptionTypeParsed` |
| Status | `StatusParsed` |
| EventID | `EventID` |

## MITRE ATT&CK Mapping

Primary mapping:

```text
Credential Access → T1558.004 AS-REP Roasting
```

Detailed mapping:

| Tactic | Technique | Relevance |
|---|---|---|
| Credential Access | T1558 - Steal or Forge Kerberos Tickets | The scenario involves Kerberos ticket-related credential access activity. |
| Credential Access | T1558.004 - AS-REP Roasting | The target account had Kerberos pre-authentication disabled and returned AS-REP material. |
| Discovery | Account Discovery | A users file was used to identify which accounts were vulnerable to AS-REP roasting. |

## Evidence Captured

| Evidence Item | Status |
|---|---|
| `svc_legacy` configured with pre-authentication disabled | Captured |
| Users file created on Kali-Red | Captured |
| Impacket `GetNPUsers` command executed | Captured |
| `svc_legacy` returned AS-REP hash output | Captured |
| `thabo.dlamini` confirmed not vulnerable | Captured |
| `svc_sql` confirmed not vulnerable | Captured |
| Event ID `4768` query prepared | Captured |
| PreAuthType parsing query prepared | Captured |
| Detection rule created | Captured |
| MITRE mapping added | Captured |

## Analyst Assessment

This activity is suspicious because a Kerberos authentication ticket request was made for an account that did not require Kerberos pre-authentication.

In a real enterprise environment, this may indicate AS-REP roasting. An attacker could request AS-REP material for the account and attempt offline password cracking.

The risk is higher if the affected account has a weak password, service account privileges, administrative rights, or access to sensitive systems.

In this lab, the `svc_legacy` account was intentionally configured with Kerberos pre-authentication disabled to generate AS-REP roasting telemetry and validate Sentinel detection logic.

## Incident Classification

Recommended incident closure for the lab:

| Field | Value |
|---|---|
| Classification | True Positive |
| Reason | Suspicious activity / AS-REP roasting simulation |
| Status | Closed |
| Environment | Authorised lab simulation |

## Incident Closure Comment

```text
Confirmed true positive lab simulation. The account svc_legacy was intentionally configured with Kerberos pre-authentication disabled. Kali-Red used Impacket GetNPUsers to request AS-REP material for the account, and the request generated Kerberos authentication telemetry associated with Event ID 4768. The detection rule identified PreAuthType 0 activity, which is consistent with possible AS-REP roasting behavior.
```

## Result

| Validation Item | Status |
|---|---|
| AS-REP test account configured | Successful |
| Kerberos pre-authentication disabled for `svc_legacy` | Successful |
| Users file created on Kali-Red | Successful |
| Impacket `GetNPUsers` executed | Successful |
| AS-REP hash returned for `svc_legacy` | Successful |
| Non-vulnerable accounts confirmed | Successful |
| Event ID `4768` detection query prepared | Successful |
| PreAuthType parsing logic created | Successful |
| Analytics rule created | Successful |
| MITRE ATT&CK mapping added | Successful |
| Scenario outcome | Completed successfully |

## Final Conclusion

Scenario 10 was completed successfully.

The `svc_legacy` account was configured with Kerberos pre-authentication disabled. Kali-Red used Impacket `GetNPUsers` to request AS-REP material for the account, and the tool returned AS-REP hash output. Other tested accounts, including `thabo.dlamini` and `svc_sql`, did not have the `UF_DONT_REQUIRE_PREAUTH` setting enabled, confirming that only the intended lab account was vulnerable.

This scenario demonstrates how Event ID `4768`, combined with `PreAuthType` value `0`, can be used to detect possible AS-REP roasting activity in an Active Directory environment.
