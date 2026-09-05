# Scenario 6: Password Spray Followed by Successful Active Directory Logon

## Scenario Overview

Scenario 6 builds on Scenario 5.

In Scenario 5, Microsoft Sentinel successfully detected multiple failed network logon attempts against several Active Directory accounts from a single internal source IP address. Scenario 6 extends the detection by checking whether the same source IP later performs a successful authentication.

This represents a more realistic attack chain where an attacker performs password spraying and eventually discovers valid credentials.

The scenario was executed in an authorised lab environment as part of a purple team Active Directory detection engineering project.

## Objective

The main objectives of this scenario were to:

- Simulate password spraying activity against Active Directory.
- Generate failed logon events using Windows Security Event ID `4625`.
- Generate a successful network logon using Windows Security Event ID `4624`.
- Correlate failed logons and successful logons from the same source IP address.
- Detect when a password spraying attempt may have resulted in valid credential discovery.
- Create a Microsoft Sentinel analytics rule for this behavior.
- Validate that Microsoft Sentinel generates an incident.
- Document the detection logic, evidence, analyst assessment, and recommended closure.

## Lab Context

| Component | Description |
|---|---|
| SIEM | Microsoft Sentinel |
| Data source | Windows Security Events |
| Target environment | Active Directory lab domain |
| Detection table | `SecurityEvent` |
| Failed logon Event ID | `4625` |
| Successful logon Event ID | `4624` |
| Logon Type | `3` - Network logon |
| Source IP | `10.0.2.4` |
| MITRE ATT&CK tactic | Credential Access |
| MITRE ATT&CK technique | Brute Force / Password Spraying |
| Additional technique | Valid Accounts |
| Recommended severity | High |

## Attack Story

The simulated attack flow is:

```text
Internal host performs failed authentication attempts against multiple AD accounts
        ↓
Microsoft Sentinel detects password spraying behavior
        ↓
Same source IP performs a successful network logon
        ↓
Successful logon may indicate that valid credentials were discovered
        ↓
Sentinel correlates the failed and successful authentication activity
```

## Why This Scenario Matters

A password spray detection is useful on its own, but the risk increases when a successful login follows shortly after the failed attempts.

In a real enterprise environment, this could indicate that an attacker has moved from credential guessing to valid credential usage.

This scenario helps detect the point where an authentication attack may have become an active account compromise.

## Attack Simulation Summary

The test involved two stages:

### Stage 1: Failed Authentication Attempts

Multiple failed network logon attempts were generated against several Active Directory accounts from the same internal source IP address.

Expected telemetry:

```text
Event ID: 4625
Logon Type: 3
Source IP: 10.0.2.4
```

### Stage 2: Successful Authentication

After the failed authentication attempts, one successful network logon was generated from the same source IP address using an authorised lab account.

Expected telemetry:

```text
Event ID: 4624
Logon Type: 3
Source IP: 10.0.2.4
```

## Kali-Red Test Command

From Kali-Red, confirm the source IP address:

```bash
ip addr
```

Then generate a successful SMB authentication to the domain controller:

```bash
smbclient -L //10.0.1.4 -U 'CORP\alice.mokoena'
```

When prompted, enter the correct password for the authorised lab account.

If `smbclient` is not installed:

```bash
sudo apt update
sudo apt install smbclient -y
```

## Expected Successful Logon Event

The successful authentication should generate the following event on the domain controller:

```text
Event ID: 4624
Logon Type: 3
Source IP: 10.0.2.4
Account: CORP\alice.mokoena
```

## Quick Validation Query

Use this query to confirm that the successful logon event was ingested into Microsoft Sentinel:

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where IpAddress == "10.0.2.4"
| project TimeGenerated, Account, Computer, IpAddress, LogonType, AuthenticationPackageName
| order by TimeGenerated desc
```

## Detection Logic

The detection logic correlates failed logon activity with a successful logon from the same source IP address.

```kql
let FailedLogons =
SecurityEvent
| where EventID == 4625
| where LogonType == 3
| where isnotempty(IpAddress)
| where IpAddress !in ("-", "127.0.0.1", "::1")
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(Account),
    FailedAccounts = make_set(Account, 20),
    FirstFailedAttempt = min(TimeGenerated),
    LastFailedAttempt = max(TimeGenerated)
    by IpAddress, bin(TimeGenerated, 10m)
| where TargetedAccounts >= 5;

let SuccessfulLogons =
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where isnotempty(IpAddress)
| where IpAddress !in ("-", "127.0.0.1", "::1")
| project
    SuccessTime = TimeGenerated,
    IpAddress,
    SuccessfulAccount = Account,
    Computer,
    AuthenticationPackageName;

FailedLogons
| join kind=inner SuccessfulLogons on IpAddress
| where SuccessTime between (LastFailedAttempt .. LastFailedAttempt + 30m)
| project
    TimeGenerated,
    IpAddress,
    FailedAttempts,
    TargetedAccounts,
    FailedAccounts,
    SuccessfulAccount,
    FirstFailedAttempt,
    LastFailedAttempt,
    SuccessTime,
    Computer,
    AuthenticationPackageName
```

## Detection Threshold

The rule triggers when the following conditions are met:

```text
TargetedAccounts >= 5
```

and

```text
A successful logon from the same source IP occurs within 30 minutes after the failed attempts
```

## Analytics Rule Details

| Field | Value |
|---|---|
| Rule name | LAB - Password Spray Followed by Successful Active Directory Logon |
| Severity | High |
| Tactic | Credential Access |
| Technique | Brute Force / Password Spraying |
| Additional mapping | Valid Accounts |
| Query frequency | 5 minutes or 10 minutes |
| Lookup period | 1 hour |
| Entity mapping | IP, Account, Host |

## Analytics Rule Description

```text
Detects multiple failed network logon attempts against several Active Directory accounts from the same internal source IP address, followed by a successful network logon from that same source IP. This may indicate that a password spraying attempt resulted in valid credential discovery.
```

## Entity Mapping

| Sentinel Entity | Field |
|---|---|
| IP | `IpAddress` |
| Account | `SuccessfulAccount` |
| Host | `Computer` |

## Expected Results

If the scenario works correctly, Microsoft Sentinel should show:

- Multiple failed logon attempts from `10.0.2.4`.
- Multiple targeted Active Directory accounts.
- A successful logon from the same source IP.
- A correlated detection result linking the failed attempts to the successful login.
- A Sentinel incident with High severity.

## Evidence to Capture

Capture screenshots of the following:

1. The failed password spray results from Scenario 5.
2. The successful `4624` logon query result.
3. The correlation query result.
4. The Microsoft Sentinel analytics rule.
5. The generated Sentinel incident.
6. The incident entity mapping showing the source IP and successful account.
7. The incident closure classification.

## Evidence Summary Template

| Evidence Item | Expected Value |
|---|---|
| Failed logon Event ID | `4625` |
| Successful logon Event ID | `4624` |
| Logon Type | `3` |
| Source IP | `10.0.2.4` |
| Failed attempts | Multiple |
| Targeted accounts | Five or more |
| Successful account | Authorised lab account |
| Detection result | Failed attempts followed by success |
| Sentinel incident | Created |

## Analyst Assessment

This activity is suspicious because a single internal host first generated failed authentication attempts against multiple Active Directory accounts and then successfully authenticated shortly afterwards.

In a real environment, this could indicate that a password spraying attempt successfully discovered valid credentials.

The successful authentication is the most important part of this scenario because it changes the investigation priority. Failed attempts may indicate attempted credential access, but a successful authentication after those failures may indicate possible account compromise.

## MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Credential Access | Brute Force / Password Spraying | The source IP attempted authentication against multiple accounts. |
| Defense Evasion / Persistence / Initial Access | Valid Accounts | A successful logon after failed attempts may indicate valid credentials were obtained. |

## Incident Classification

Recommended incident closure:

| Field | Value |
|---|---|
| Classification | True Positive |
| Reason | Suspicious activity / Password spray followed by successful logon |
| Status | Closed |
| Environment | Authorised lab simulation |

## Incident Closure Comment

```text
Confirmed true positive lab simulation. Multiple failed network logon attempts were generated from internal source IP 10.0.2.4 against several Active Directory accounts. Shortly after the failed attempts, a successful network logon was observed from the same source IP. Microsoft Sentinel successfully correlated the failed and successful authentication activity, indicating a password spray followed by possible valid credential usage.
```

## Result

| Validation Item | Status |
|---|---|
| Failed logon telemetry generated | Successful |
| Event ID 4625 observed | Successful |
| Successful logon telemetry generated | Pending evidence |
| Event ID 4624 observed | Pending evidence |
| Same source IP correlation | Pending evidence |
| Multiple targeted accounts identified | Successful |
| Sentinel analytics rule created | Pending |
| Sentinel incident generated | Pending |
| MITRE mapping added | Successful |

## Final Conclusion

Scenario 6 demonstrates how Microsoft Sentinel can correlate failed authentication activity with a later successful logon from the same source IP address.

This scenario represents a more realistic credential access chain than failed logons alone. It helps identify cases where password spraying may have resulted in valid credential discovery and successful authentication into the Active Directory environment.
