# Phase 2 — Hybrid Identity Attack Simulation & Detection Engineering

## Overview

Phase 2 expands the original Active Directory detection lab into a **hybrid identity security assessment** that connects on-premises AD activity with Microsoft Entra ID, workload identities, Microsoft Sentinel, and identity attack-path analysis.

The goal is to move beyond isolated attack simulations and build a complete purple-team workflow:

**Attack path → Identity telemetry → Sentinel detection → Investigation → Remediation → Retest**

The environment already includes:

- `DC01` — Windows Server 2022 Domain Controller for `corp.lab`
- `SYNC01` — Microsoft Entra Connect Sync using Password Hash Synchronization
- Microsoft Entra ID
- Microsoft Sentinel
- Kali Linux attacker workstation
- AzureHound / BloodHound CE
- Entra audit and sign-in telemetry

Selected `corp.lab` identities are synchronized to Entra ID, providing the foundation for hybrid identity testing.

## Phase 2 Objectives

Phase 2 focuses on:

- validating Entra ID attack paths;
- testing service-principal and application ownership relationships;
- comparing Entra directory roles with Azure RBAC assignments;
- correlating on-premises authentication activity with cloud identity telemetry;
- building Microsoft Sentinel detections for identity abuse;
- validating remediation through before/after testing;
- using AzureHound and BloodHound CE to visualize attack-path changes;
- producing evidence suitable for a technical assessment and portfolio presentation.

## Telemetry

Primary Sentinel data sources used in Phase 2:

- `AuditLogs`
- `SigninLogs`
- `AADNonInteractiveUserSignInLogs`
- `AADServicePrincipalSignInLogs`
- `SecurityEvent`

Telemetry validation confirmed that Entra audit activity and service-principal sign-ins are reaching Sentinel.

## Scenario Status

| Scenario | Description | Status |
|---|---|---|
| 01 | Hybrid account compromise and cross-plane correlation | Planned |
| 02 | Service Principal Ownership Abuse | ✅ Attack path validated |
| 03 | Entra roles vs Azure RBAC privilege analysis | Planned |
| 04 | Entra Connect / hybrid identity security assessment | Planned |
| 05 | Kerberos and lateral movement correlation | Planned |
| 06 | Identity incident response, remediation and retest | Planned |

## Scenario 02

Scenario 02 validates whether a low-privileged Entra user who owns an application can add a new application credential and authenticate as that application's service principal.

**Validated chain:**

```text
sp-owner-lab
      |
      | owns
      v
PT-ServicePrincipal-Lab
      |
      | adds client secret
      v
Application credential modified
      |
      | AuditLogs
      v
Credential-management event recorded
      |
      | client credentials flow
      v
Successful service-principal authentication
      |
      | AADServicePrincipalSignInLogs
      v
Microsoft Graph sign-in recorded
```

Full write-up:

[Scenario 02 — Service Principal Ownership Abuse](./scenario-02-service-principal-ownership-abuse.md)

## Detection Engineering Goal

The strongest Phase 2 detections should correlate multiple identity events rather than alert on a single administrative action.

For Scenario 02, the target detection is:

**Application credential change → successful service-principal authentication shortly afterwards**

This helps distinguish normal credential rotation from potentially suspicious credential creation followed by immediate use.

## Remediation & Retesting

Each Phase 2 scenario should end with:

1. a documented finding;
2. detection evidence;
3. remediation;
4. repeat testing;
5. before/after attack-path comparison.

For identity relationships, AzureHound/BloodHound should be recollected after remediation to verify that the risky path has been reduced or removed.

## Deliverables

Phase 2 deliverables will include:

- documented attack scenarios;
- KQL hunting and detection queries;
- Sentinel analytic rules and incidents;
- attack-path diagrams;
- Entra roles vs Azure RBAC mapping;
- remediation evidence;
- before/after BloodHound graphs;
- final hybrid identity assessment presentation.

## Current Priority

Complete Scenario 02 by creating and validating the Sentinel analytic rule, generating the incident during a controlled retest, removing the temporary credential and unnecessary ownership, and recollecting AzureHound data for before/after evidence.
