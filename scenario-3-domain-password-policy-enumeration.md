# Scenario 3 — Domain Password Policy Enumeration

## Overview

This scenario demonstrates how an authenticated, low-privileged Active Directory user can enumerate the domain password and account lockout policy.

The assessment was performed from **KALI-RED01** against the domain controller **DC01** in the isolated `corp.lab` environment.

The objective was to determine whether a standard domain account could retrieve password-policy information that could influence subsequent credential-based attack decisions.

---

## Scenario Information

| Item | Value |
|---|---|
| Scenario | 3 |
| Name | Domain Password Policy Enumeration |
| Environment | Isolated Active Directory lab |
| Domain | `corp.lab` |
| Domain Controller | `DC01` |
| DC IP Address | `10.0.1.4` |
| Attacker Host | `KALI-RED01` |
| Authenticated User | `thabo.dlamini` |
| Primary Tool | NetExec |
| Protocol | SMB / TCP 445 |
| Assessment Type | Credentialed Active Directory Enumeration |

> **Credential handling:** Passwords are intentionally omitted from this document. Any screenshots published externally should have credentials redacted.

---

## Objective

The objectives of this scenario were to:

- Validate access to DC01 using a standard domain account.
- Enumerate the `corp.lab` domain password policy.
- Identify password complexity, history, age, and lockout settings.
- Determine whether the policy could expose the environment to password-guessing attacks.
- Use the results to inform later controlled authentication testing.

---

## Attack Narrative

Following initial Active Directory enumeration and acquisition of valid credentials for `thabo.dlamini`, the simulated attacker authenticated to DC01 over SMB.

The attacker then queried the domain password policy using NetExec. This represented a credentialed reconnaissance step: rather than immediately attempting additional passwords, the attacker first collected information about the authentication controls protecting domain accounts.

The enumeration successfully returned the domain's password and account-lockout configuration.

---

## Execution

### 1. Validate the Domain Credentials

The standard domain account was first used to verify authentication against DC01:

```bash
netexec smb 10.0.1.4 -u 'thabo.dlamini' -p '<REDACTED>'
```

Authentication succeeded against `corp.lab`.

### 2. Enumerate the Password Policy

The following command was then used:

```bash
netexec smb 10.0.1.4 -u 'thabo.dlamini' -p '<REDACTED>' --pass-pol
```

NetExec successfully returned the password-policy configuration for the domain.

---

## Observed Results

The following controls were observed during testing:

| Policy | Observed Value |
|---|---|
| Minimum password length | 7 characters |
| Password history length | 24 |
| Maximum password age | Approximately 42 days |
| Password complexity | Enabled |
| Minimum password age | Approximately 1 day |
| Reset account lockout counter | 10 minutes |
| Locked account duration | 10 minutes |
| Account lockout threshold | **None** |
| Forced logoff time | Not set |

The most significant observation was:

```text
Account Lockout Threshold: None
```

This indicated that the domain-wide policy did not define a failed authentication threshold at which an account would automatically be locked.

---

## Evidence

### Evidence 1 — Successful Credentialed Password-Policy Enumeration

**Screenshot:** `scenario3-password-policy.png`

The screenshot should demonstrate:

- KALI-RED01 as the assessment host.
- Target `10.0.1.4`.
- DC01 and `corp.lab` identification.
- Successful authentication as `thabo.dlamini`.
- NetExec `--pass-pol` output.
- Password complexity enabled.
- Minimum password length of 7.
- Account lockout threshold set to `None`.

> Redact the plaintext password from the screenshot before adding it to a public repository.

Example Markdown placement:

```markdown
![Scenario 3 - Domain Password Policy Enumeration](./screenshots/scenario3-password-policy.png)
```

---

## Finding

### No Account Lockout Threshold Configured

**Severity:** Medium

Credentialed enumeration identified that the `corp.lab` domain did not have an account lockout threshold configured.

Although password complexity was enabled and password history was configured, the absence of a lockout threshold means repeated failed authentication attempts are not constrained by an automatic account lockout after a defined number of failures.

This could increase the environment's exposure to password guessing and password-spraying activity if other compensating controls are not present.

### Security Impact

An attacker possessing a valid foothold or network access to exposed authentication services could use the policy information to better understand the domain's authentication controls.

The combination of:

- Enumeratable domain accounts,
- A relatively low minimum password length,
- No configured account lockout threshold,

could increase credential-attack risk.

The enumeration itself does not constitute domain compromise. Instead, it provides information that may support later stages of an attack chain.

---

## Attack Flow

```text
KALI-RED01
     |
     | Valid low-privilege credentials
     v
SMB / TCP 445
     |
     v
DC01 (corp.lab)
     |
     +-- Password length: 7
     +-- Password history: 24
     +-- Complexity: Enabled
     +-- Maximum age: ~42 days
     +-- Lockout threshold: NONE
     |
     v
Authentication Controls Identified
     |
     v
Information Used to Inform
Later Credential Testing
```

---

## Detection Considerations

Password-policy enumeration should be considered in context rather than treated as malicious by itself. Standard authenticated users may legitimately be able to retrieve portions of domain policy information.

The more useful detection opportunity comes from correlating this reconnaissance with subsequent behavior, such as:

- Enumeration of multiple domain users.
- Enumeration of privileged groups.
- Authentication failures across multiple accounts.
- Multiple targeted accounts from the same source IP.
- Password-spraying patterns over a short period.

This scenario therefore provides context for later detection scenarios rather than serving as a standalone high-confidence alert.

---

## Recommendations

1. Review whether the absence of an account lockout threshold aligns with the organization's authentication strategy.
2. Implement appropriate protection against repeated authentication attempts using controls suited to the environment.
3. Use strong password requirements and discourage weak or predictable passwords.
4. Monitor repeated failed authentication attempts across multiple accounts.
5. Correlate authentication failures by source IP, target account count, and time window.
6. Apply additional protection to privileged and service accounts.
7. Consider modern authentication and identity-protection controls where applicable.

---

## MITRE ATT&CK Mapping

The activity in this scenario is best treated as reconnaissance/discovery supporting later credential-access activity. Exact ATT&CK mapping should be selected based on the specific enumeration mechanism and subsequent actions rather than assuming that retrieving a password policy alone represents password spraying.

The later controlled password-spraying scenario can be mapped directly to:

- **Tactic:** Credential Access
- **Technique:** Brute Force (`T1110`)
- **Sub-technique:** Password Spraying (`T1110.003`)

---

## Outcome

**Scenario Status: SUCCESSFUL**

A standard authenticated `corp.lab` user successfully enumerated the domain password policy from KALI-RED01.

The assessment identified an important configuration weakness: **no account lockout threshold was configured**.

The results provided the information necessary to safely design the subsequent lab stages involving domain-user enumeration and controlled authentication testing.

---

## Scenario Progression

```text
Scenario 1
Initial Active Directory Enumeration
        |
        v
Scenario 2
Domain/User Reconnaissance
        |
        v
Scenario 3
Password Policy Enumeration  [COMPLETE]
        |
        v
Scenario 4
Credentialed User & Privilege Enumeration
        |
        v
Scenario 5
Controlled Password Spray + Sentinel Detection
```
