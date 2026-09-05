# Scenario 4 — Credentialed Domain User & Privileged Group Enumeration

## Overview

This scenario demonstrates how a compromised low-privileged Active Directory account can be used to enumerate domain users, groups, and privileged group membership in the isolated `corp.lab` environment.

The assessment was performed from **KALI-RED01** against **DC01** using the valid standard-domain credentials for `thabo.dlamini`.

The scenario builds directly on Scenario 3. After learning the domain password policy, the simulated attacker performed credentialed Active Directory discovery to identify users and high-value accounts.

---

## Scenario Information

| Item | Value |
|---|---|
| Scenario | 4 |
| Name | Credentialed Domain User & Privileged Group Enumeration |
| Environment | Isolated Active Directory lab |
| Domain | `corp.lab` |
| Domain Controller | `DC01` |
| DC IP Address | `10.0.1.4` |
| Attacker Host | `KALI-RED01` |
| Compromised User | `thabo.dlamini` |
| Tools | NetExec, Impacket |
| Protocols | SMB / LDAP / Kerberos-related AD queries |
| Assessment Type | Credentialed Active Directory Enumeration |

> **Credential handling:** Passwords are omitted from this document. Redact plaintext credentials from screenshots before publishing the project.

---

## Objectives

The objectives of Scenario 4 were to:

- Enumerate domain accounts using a standard authenticated user.
- Identify service-style and potentially high-value accounts.
- Enumerate Active Directory groups.
- Query membership of the `Domain Admins` group.
- Determine whether any service account possessed excessive privileges.
- Check whether the identified service account exposed an SPN-based Kerberos attack path.
- Build intelligence for subsequent attack scenarios.

---

## Attack Narrative

Following successful password-policy enumeration in Scenario 3, the simulated attacker continued operating as the compromised standard user `thabo.dlamini`.

Instead of blindly selecting targets, the attacker performed credentialed Active Directory enumeration.

The process revealed multiple domain accounts, including a service-style account named:

```text
svc_sql
```

LDAP enumeration was then used to investigate privileged groups. Querying `Domain Admins` revealed that `svc_sql` was a member of the group.

This represented a significant privilege-management weakness: compromise of the service account could potentially provide domain-level privileges.

The attacker subsequently checked for user accounts with Service Principal Names (SPNs). No entries were returned, meaning the environment did not expose an SPN-based path through `svc_sql` at the time of testing.

---

# Execution

## 1. Enumerate Domain Users

NetExec was used over SMB with the compromised standard account:

```bash
netexec smb 10.0.1.4 \
  -u 'thabo.dlamini' \
  -p '<REDACTED>' \
  --users
```

The results were saved as an evidence artifact:

```bash
netexec smb 10.0.1.4 \
  -u 'thabo.dlamini' \
  -p '<REDACTED>' \
  --users | tee scenario4-domain-users.txt
```

### Accounts Discovered

The enumeration returned:

```text
adminclementon
Guest
krbtgt
alice.mokoena
bob.ndlovu
lerato.molefe
thabo.dlamini
sipho.khumalo
naledi.maseko
svc_sql
```

The `svc_sql` account was considered particularly interesting because its naming convention suggested that it was intended for a SQL-related service.

The name alone was not treated as evidence of a vulnerability. Further enumeration was performed to determine the account's privileges.

---

## 2. Enumerate Domain Groups

The installed NetExec version indicated that group enumeration had moved from the SMB protocol to LDAP.

LDAP was therefore used:

```bash
netexec ldap 10.0.1.4 \
  -u 'thabo.dlamini' \
  -p '<REDACTED>' \
  --groups
```

This successfully exposed Active Directory groups to the authenticated standard user.

Among the groups identified was:

```text
Domain Admins
```

---

## 3. Enumerate Domain Admin Membership

The `Domain Admins` group was queried directly:

```bash
netexec ldap 10.0.1.4 \
  -u 'thabo.dlamini' \
  -p '<REDACTED>' \
  --groups 'Domain Admins'
```

The query returned:

```text
adminclementon
svc_sql
```

This confirmed that `svc_sql` possessed **Domain Admin membership**.

---

## 4. Check for Service Principal Names

Because `svc_sql` appeared to be a service account, the next step was to determine whether it had a Service Principal Name associated with it.

Impacket's `GetUserSPNs` was used:

```bash
impacket-GetUserSPNs 'corp.lab/thabo.dlamini' -dc-ip 10.0.1.4
```

The result was:

```text
No entries found!
```

Therefore, no user-based SPN target was identified during this stage of the assessment.

This negative result was retained as part of the evidence rather than modifying the environment during the scenario.

---

# Key Findings

## Finding 1 — Domain Account Enumeration Available to Standard User

**Severity:** Informational / Contextual

A standard authenticated domain user was able to enumerate domain accounts.

This information could assist an attacker in identifying valid usernames and constructing a target list for later credential attacks.

The enumeration included normal users, built-in accounts, and a service-style account.

---

## Finding 2 — Excessive Privileges Assigned to `svc_sql`

**Severity:** High

Credentialed LDAP enumeration identified:

```text
svc_sql
    |
    +-- Member of: Domain Admins
```

A service-style account possessing Domain Admin privileges represents a significant privilege-management risk.

If the credentials or authentication material associated with this account were compromised, an attacker could potentially inherit highly privileged access to the Active Directory domain.

### Security Impact

Potential consequences could include:

- Privileged access to domain resources.
- Modification of Active Directory objects.
- Creation or modification of accounts and groups.
- Changes to security policy.
- Access to domain controllers.
- Lateral movement using privileged credentials.
- Potential domain compromise.

The scenario did **not** demonstrate compromise of `svc_sql`; it demonstrated discovery of the excessive privilege relationship.

---

## Finding 3 — No User SPNs Identified

**Severity:** Informational

The SPN enumeration returned:

```text
No entries found!
```

No SPN-bearing user account was identified during this test.

Therefore, the scenario did not proceed into an SPN-based Kerberos credential attack.

---

# Attack Flow

```text
KALI-RED01
     |
     | Valid credentials
     | thabo.dlamini
     v
DC01 / corp.lab
     |
     +----------------------------+
     |                            |
     v                            v
SMB User Enumeration        LDAP Group Enumeration
     |                            |
     v                            v
Domain users discovered      Domain Admins
     |                            |
     |                            +-- adminclementon
     |                            |
     +--> svc_sql <---------------+-- svc_sql
             |
             v
      HIGH-VALUE ACCOUNT
             |
             | SPN enumeration
             v
       No entries found
```

---

# Evidence

## Evidence 1 — Domain User Enumeration

**Suggested filename:**

```text
scenario4-domain-users.png
```

Evidence demonstrates successful enumeration of domain accounts from KALI-RED01 using `thabo.dlamini`.

Suggested Markdown placement:

```markdown
![Scenario 4 - Domain User Enumeration](./screenshots/scenario4-domain-users.png)
```

---

## Evidence 2 — Domain Group Enumeration

**Suggested filename:**

```text
scenario4-domain-groups.png
```

Evidence demonstrates that the standard authenticated account could enumerate Active Directory groups over LDAP.

```markdown
![Scenario 4 - Domain Group Enumeration](./screenshots/scenario4-domain-groups.png)
```

---

## Evidence 3 — Domain Admin Membership Discovery

**Suggested filename:**

```text
scenario4-domain-admin-members.png
```

This is the strongest evidence for Scenario 4.

The LDAP query revealed:

```text
adminclementon
svc_sql
```

as members of `Domain Admins`.

```markdown
![Scenario 4 - Domain Admin Membership](./screenshots/scenario4-domain-admin-members.png)
```

---

## Evidence 4 — SPN Enumeration

**Suggested filename:**

```text
scenario4-spn-enumeration.png
```

The Impacket query returned:

```text
No entries found!
```

```markdown
![Scenario 4 - SPN Enumeration](./screenshots/scenario4-spn-enumeration.png)
```

> Ensure passwords visible in terminal history or command lines are redacted before screenshots are published.

---

# Detection Considerations

Credentialed Active Directory enumeration can be difficult to classify as malicious in isolation because legitimate administrators and applications may perform similar directory queries.

Detection should therefore focus on context and behavioral correlation.

Useful signals include:

- LDAP enumeration originating from unusual endpoints.
- A standard workstation querying privileged groups.
- Rapid enumeration of large numbers of users or groups.
- Discovery activity followed by authentication attempts against the identified accounts.
- Authentication failures against multiple accounts from the same source.
- Service-account authentication from unexpected hosts.

In this lab, Scenario 4 becomes particularly meaningful when correlated with Scenario 5, where the discovered accounts are subsequently targeted by controlled authentication attempts.

---

# Recommendations

## Privileged Account Management

Remove `svc_sql` from `Domain Admins` unless there is an explicitly documented and unavoidable requirement.

Apply the principle of least privilege:

```text
Service Requirement
        |
        v
Minimum Required Permissions
        |
        X
Domain Admin by Default
```

Additional recommendations:

1. Review all service-account group memberships.
2. Remove unnecessary privileged group assignments.
3. Use dedicated service identities where appropriate.
4. Prevent interactive use of service accounts where possible.
5. Use strong, managed credentials for service identities.
6. Monitor privileged group membership changes.
7. Alert when service accounts are added to highly privileged groups.
8. Regularly review `Domain Admins`, `Enterprise Admins`, and other privileged groups.
9. Monitor authentication activity involving privileged service accounts.
10. Correlate reconnaissance with subsequent credential-access behavior.

---

# MITRE ATT&CK Mapping

Relevant discovery behavior can be mapped to Active Directory account and permission discovery techniques, depending on the exact activity being documented.

Potential mappings include:

- **Account Discovery — Domain Account (`T1087.002`)**
- **Permission Groups Discovery — Domain Groups (`T1069.002`)**

The SPN query was reconnaissance for a potential Kerberos-related attack path, but because no SPN-bearing user was identified and no Kerberoasting attack was performed, the scenario should not be documented as a successful Kerberoasting attack.

---

# Purple-Team Value

Scenario 4 demonstrates an important distinction between an attack technique and a security finding.

The enumeration itself provided intelligence:

```text
Who exists?
      |
      v
What groups exist?
      |
      v
Who is privileged?
      |
      v
Which accounts are valuable?
```

The actual security weakness identified was the excessive privilege assigned to `svc_sql`.

This provides a realistic progression into subsequent scenarios:

```text
Reconnaissance
      |
      v
Credentialed Enumeration
      |
      v
High-Value Target Discovery
      |
      v
Credential Attack
      |
      v
Windows Security Telemetry
      |
      v
Sentinel Detection
```

---

# Outcome

**Scenario Status: SUCCESSFUL**

Using only the compromised standard account `thabo.dlamini`, the assessment successfully:

- Enumerated domain users.
- Identified `svc_sql`.
- Enumerated Active Directory groups.
- Queried `Domain Admins`.
- Confirmed `svc_sql` had Domain Admin privileges.
- Tested for user SPNs.
- Confirmed that no SPN-bearing user accounts were returned.

The primary security finding was the **excessive Domain Admin privilege assigned to `svc_sql`**.

---

# Scenario Progression

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
Password Policy Enumeration
        |
        v
Scenario 4
Credentialed User & Privilege Enumeration  [COMPLETE]
        |
        v
Scenario 5
Controlled Password Spray
        |
        v
DC01 Event ID 4625
        |
        v
Microsoft Sentinel
        |
        v
KQL Detection + Analytics Rule
```
