# Scenario 5: Internal Password Spray Detection Against Active Directory

## Scenario Overview

This scenario simulates an internal password spraying attempt against Active Directory from a controlled lab host. The objective was to generate failed authentication telemetry, collect the events into Microsoft Sentinel, and validate whether a custom analytics rule could detect multiple failed logon attempts against several domain accounts from the same source IP address.

The scenario was executed in an authorised lab environment as part of a purple team Active Directory detection engineering project.

## Objective

The main objectives of this scenario were to:

- Simulate internal password spraying behavior against Active Directory.
- Generate Windows Security Event ID `4625` failed logon events.
- Confirm that the domain controller telemetry was collected into Microsoft Sentinel.
- Build and test a Sentinel analytics rule for password spraying behavior.
- Validate that Sentinel creates an incident when the detection threshold is met.
- Document the source IP, targeted accounts, failed attempts, and analyst assessment.

## Lab Context

| Component | Description |
|---|---|
| SIEM | Microsoft Sentinel |
| Data source | Windows Security Events |
| Target environment | Active Directory lab domain |
| Detection table | `SecurityEvent` |
| Main Event ID | `4625` |
| Logon Type | `3` - Network logon |
| Source IP identified | `10.0.2.4` |
| MITRE ATT&CK tactic | Credential Access |
| Incident severity | Medium |

## Attack Simulation Summary

The test generated multiple failed network logon attempts against several Active Directory accounts from a single internal source IP address.

The simulated activity represents a common password spraying pattern where an attacker attempts authentication against many accounts using one or a small number of passwords. This technique is often used to avoid immediate account lockout while still attempting to identify valid credentials.

In this lab, the activity originated from:

```text
10.0.2.4
```

The failed authentication attempts were recorded as Windows Security Event ID:

```text
4625 - An account failed to log on
```

The logon type observed was:

```text
Logon Type 3 - Network logon
```

## Detection Logic

The Microsoft Sentinel analytics rule was designed to detect multiple failed network logon attempts from the same source IP address against multiple unique accounts within a short time window.

```kql
SecurityEvent
| where EventID == 4625
| where LogonType == 3
| where isnotempty(IpAddress)
| where IpAddress !in ("-", "127.0.0.1", "::1")
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(Account),
    Accounts = make_set(Account, 20),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IpAddress, bin(TimeGenerated, 5m)
| where TargetedAccounts >= 5
| project
    TimeGenerated,
    IpAddress,
    FailedAttempts,
    TargetedAccounts,
    Accounts,
    FirstAttempt,
    LastAttempt
```

## Detection Threshold

The rule triggers when:

```text
TargetedAccounts >= 5
```

This means the rule looks for five or more unique accounts receiving failed authentication attempts from the same source IP address within a five-minute window.

## Sentinel Incident Generated

Microsoft Sentinel successfully generated an incident titled:

```text
LAB - Potential Internal Password Spray Against Active Directory
```

The incident details showed:

| Field | Value |
|---|---|
| Incident title | LAB - Potential Internal Password Spray Against Active Directory |
| Severity | Medium |
| Status | New |
| Product | Microsoft Sentinel |
| Entity | 10.0.2.4 |
| Tactic | Credential Access |
| Incident number | 4 |

## Query Results

The detection query returned multiple grouped time windows showing failed authentication attempts against multiple accounts from the same source IP address.

| Time Window | Source IP | Failed Attempts | Targeted Accounts |
|---|---|---:|---:|
| 2026/09/05 13:30 | 10.0.2.4 | 7 | 7 |
| 2026/09/05 13:40 | 10.0.2.4 | 7 | 7 |
| 2026/09/05 13:50 | 10.0.2.4 | 6 | 6 |

## Evidence Summary

The evidence confirms that the rule detected password spraying behavior because:

- Multiple failed authentication attempts were generated.
- The failed attempts used Event ID `4625`.
- The attempts were network logons using Logon Type `3`.
- The same source IP address, `10.0.2.4`, targeted multiple accounts.
- The activity occurred within short five-minute time windows.
- The number of targeted accounts exceeded the configured threshold.
- Microsoft Sentinel created an incident and mapped it to Credential Access.

## Analyst Assessment

This activity is suspicious because a single internal host attempted authentication against multiple domain accounts within a short period of time.

In a real enterprise environment, this could indicate that an attacker has gained internal network access and is attempting to identify valid credentials by testing passwords across several domain accounts.

This behavior is consistent with password spraying because the pattern focuses on multiple accounts rather than repeated attempts against one account.

## MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Credential Access | Brute Force / Password Spraying | The activity involved failed authentication attempts against multiple accounts from one source IP address. |

## Incident Classification

Recommended incident closure:

| Field | Value |
|---|---|
| Classification | True Positive |
| Reason | Suspicious activity / Password spray simulation |
| Status | Closed |
| Environment | Authorised lab simulation |

## Incident Closure Comment

```text
Confirmed true positive lab simulation. Multiple failed network logon attempts were generated from internal source IP 10.0.2.4 against multiple Active Directory accounts within short time windows. Microsoft Sentinel analytics rule successfully detected the behavior and generated an incident for potential internal password spraying.
```

## Result

| Validation Item | Status |
|---|---|
| Failed logon telemetry generated | Successful |
| Event ID 4625 observed | Successful |
| Logon Type 3 observed | Successful |
| Multiple targeted accounts identified | Successful |
| Source IP identified | Successful |
| Sentinel analytics rule triggered | Successful |
| Sentinel incident created | Successful |
| MITRE tactic mapped | Successful |

## Final Conclusion

Scenario 5 was successful.

The lab generated telemetry consistent with an internal Active Directory password spraying attempt. Microsoft Sentinel collected the failed authentication events, the custom analytics rule matched the defined threshold, and an incident was created with the source IP address identified as `10.0.2.4`.

This scenario demonstrates how failed logon telemetry can be used to detect early credential access activity in an Active Directory environment.
