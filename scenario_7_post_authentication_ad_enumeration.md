# Scenario 7: Post-Authentication Active Directory Enumeration

## Scenario Overview

Scenario 7 demonstrates post-authentication Active Directory enumeration using valid domain credentials from Kali-Red.

This scenario continues from the earlier credential access chain where failed authentication activity and successful logon activity were tested. After a successful authentication, the next realistic attacker behavior is to enumerate the domain to discover users, groups, and privileged accounts.

The scenario was executed in an authorised lab environment as part of a purple team Active Directory detection engineering project.

## Objective

The objectives of this scenario were to:

- Use a valid Active Directory account from Kali-Red.
- Authenticate to the domain controller over the network.
- Generate Windows Security Event ID `4624`.
- Confirm the source IP address of Kali-Red in Microsoft Sentinel.
- Enumerate domain users.
- Enumerate privileged group membership.
- Identify whether the activity could represent post-authentication discovery.
- Document the detection opportunity and analyst interpretation.

## Lab Context

| Component | Description |
|---|---|
| Attacker host | Kali-Red |
| Source IP | `10.0.2.4` |
| Domain controller | `DC01.corp.lab` |
| Domain controller IP | `10.0.1.4` |
| Domain | `corp.lab` |
| Account used | `CORP\thabo.dlamini` |
| Authentication package | NTLM |
| Main Windows Event ID | `4624` |
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
Valid account usage
        ↓
Active Directory user enumeration
        ↓
Privileged group membership discovery
```

The key analyst question for this scenario is:

```text
After successful authentication, did the account perform discovery activity against Active Directory?
```

## Activity Performed from Kali-Red

The valid domain account used for testing was:

```text
CORP\thabo.dlamini
```

The following command was used to enumerate members of the `Domain Admins` group:

```bash
net rpc group members "Domain Admins" -U 'CORP\thabo.dlamini' -S 10.0.1.4
```

The output showed privileged group members:

```text
CORP\adminclementon
CORP\svc_sql
```

The following command was used to enumerate domain users:

```bash
net rpc user -U 'CORP\thabo.dlamini' -S 10.0.1.4
```

The output showed multiple domain users, including:

```text
adminclementon
alice.mokoena
bob.ndlovu
Guest
krbtgt
lerato.molefe
naledi.maseko
sipho.khumalo
svc_sql
thabo.dlamini
```

## Sentinel Evidence

Microsoft Sentinel showed successful network logon activity from Kali-Red to the domain controller.

Observed event details:

| Field | Value |
|---|---|
| Event ID | `4624` |
| Account | `CORP\thabo.dlamini` |
| Computer | `DC01.corp.lab` |
| Source IP | `10.0.2.4` |
| Logon Type | `3` |
| Authentication Package | `NTLM` |

## Validation Query

The following query was used to confirm successful logon activity from Kali-Red:

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where Account has "thabo.dlamini"
| project
    TimeGenerated,
    Account,
    Computer,
    IpAddress,
    LogonType,
    AuthenticationPackageName,
    Activity
| order by TimeGenerated desc
```

## Detection Opportunity

Post-authentication enumeration can be difficult to detect using only Event ID `4624`, because a successful network logon can also occur during normal administrative or user activity.

However, in this lab, the activity becomes suspicious because:

- The authentication came from Kali-Red.
- A valid domain account was used.
- The account performed domain user enumeration.
- The account enumerated privileged group membership.
- The activity followed earlier credential access scenarios.
- The activity could represent attacker discovery after valid credential usage.

## Detection Query

This query can be used as a basic correlation query for post-authentication enumeration activity:

```kql
let SuccessfulLogons =
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where IpAddress == "10.0.2.4"
| project
    LogonTime = TimeGenerated,
    Account,
    IpAddress,
    Computer,
    AuthenticationPackageName;

let EnumerationActivity =
SecurityEvent
| where EventID in (4662, 4798, 4799, 5140, 5145)
| project
    EnumerationTime = TimeGenerated,
    EventID,
    Activity,
    Account,
    Computer,
    IpAddress,
    ObjectName,
    ObjectType,
    ShareName,
    RelativeTargetName;

SuccessfulLogons
| join kind=leftouter EnumerationActivity on Account
| where EnumerationTime between (LogonTime .. LogonTime + 30m) or isempty(EnumerationTime)
| project
    LogonTime,
    EnumerationTime,
    Account,
    IpAddress,
    Computer,
    EventID,
    Activity,
    ObjectName,
    ObjectType,
    ShareName,
    RelativeTargetName,
    AuthenticationPackageName
| order by LogonTime desc
```

## Analytics Rule Details

| Field | Value |
|---|---|
| Rule name | `LAB - Post-Authentication Active Directory Enumeration from Internal Host` |
| Severity | Medium |
| Query frequency | 5 minutes or 10 minutes |
| Lookup period | 1 hour |
| Main data source | `SecurityEvent` |
| Main event | `4624` |
| Logon type | `3` |

## MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Discovery | Account Discovery | The account was used to enumerate domain users. |
| Discovery | Permission Groups Discovery | The account was used to enumerate the `Domain Admins` group. |
| Initial Access / Persistence | Valid Accounts | The activity was performed using valid domain credentials. |

## Evidence Captured

| Evidence Item | Status |
|---|---|
| Kali command showing domain user enumeration | Captured |
| Kali command showing Domain Admins enumeration | Captured |
| Sentinel Event ID `4624` evidence | Captured |
| Source IP `10.0.2.4` identified | Captured |
| Account `CORP\thabo.dlamini` identified | Captured |
| Domain controller `DC01.corp.lab` identified | Captured |

## Analyst Assessment

This activity is suspicious because a valid domain account was used from an internal host to enumerate Active Directory users and privileged group membership.

In a real enterprise environment, this may indicate that an attacker has obtained valid credentials and is performing post-authentication discovery to understand the domain structure, identify users, and locate high-value or privileged accounts.

The activity should be reviewed in context with previous authentication events. If it follows failed authentication attempts, password spraying, or unusual source IP activity, the severity should be increased.

## Incident Classification

Recommended incident closure for the lab:

| Field | Value |
|---|---|
| Classification | True Positive |
| Reason | Suspicious activity / Post-authentication enumeration simulation |
| Status | Closed |
| Environment | Authorised lab simulation |

## Incident Closure Comment

```text
Confirmed true positive lab simulation. The account CORP\thabo.dlamini successfully authenticated from Kali-Red to DC01 using NTLM network logon activity. After authentication, the account was used to enumerate domain users and Domain Admins group membership. This activity represents post-authentication Active Directory discovery using valid credentials.
```

## Result

| Validation Item | Status |
|---|---|
| Valid domain account used | Successful |
| Successful network logon generated | Successful |
| Event ID `4624` observed | Successful |
| Source IP identified as `10.0.2.4` | Successful |
| Account identified as `CORP\thabo.dlamini` | Successful |
| Domain users enumerated | Successful |
| Domain Admins group enumerated | Successful |
| Post-authentication discovery demonstrated | Successful |

## Final Conclusion

Scenario 7 was completed successfully.

The account `CORP\thabo.dlamini` was used from Kali-Red to authenticate to the domain controller and enumerate Active Directory users and privileged group membership. Microsoft Sentinel captured the successful network logon as Event ID `4624`, showing the source IP address as `10.0.2.4` and the target host as `DC01.corp.lab`.

This scenario demonstrates how valid account usage can be followed by post-authentication discovery activity in an Active Directory environment.
