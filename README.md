# Active Directory Purple Team Detection Lab

## Overview

This project simulates an enterprise-style **Active Directory and hybrid identity environment** where controlled attack activity is generated, investigated, detected, remediated, and retested using **Microsoft Sentinel and Microsoft Entra ID**.

The defensive workflow is:

**Attack → Telemetry → Sentinel → KQL investigation → Detection rule → Alert/Incident → Remediation → Retest**

## Environment

* Windows Server 2022 Domain Controller
* Active Directory Domain Services
* Microsoft Entra ID
* Microsoft Entra Connect Sync
* Kali Linux attacker machine
* Microsoft Sentinel
* Log Analytics
* Azure Monitor Agent
* AzureHound / BloodHound CE
* KQL

## What I Built

* Active Directory lab in Microsoft Azure
* Windows Security Event ingestion into Sentinel
* Hybrid identity synchronization with Entra Connect
* Multiple controlled attack scenarios
* Custom KQL investigation queries
* Microsoft Sentinel analytics rules
* Entra audit and sign-in telemetry validation
* MITRE ATT&CK mappings
* Detection tuning and false-positive analysis
* Attack-path validation and remediation testing

## Phase 1 — Active Directory Detection Engineering

Phase 1 focused on controlled Active Directory attacks and Microsoft Sentinel detection engineering.

Scenarios included:

* Active Directory reconnaissance
* Failed authentication
* Password spraying
* Credentialed enumeration
* Kerberos activity
* Account and privilege discovery
* Suspicious authentication behaviour

One of the biggest lessons from Phase 1 was that a detection that works in a lab may be too noisy in production. NTLM, SMB, Kerberos and authentication telemetry require behavioural context, correlation and tuning.

## Phase 2 — Hybrid Identity Security Assessment

Phase 2 extends the project into Microsoft Entra ID and hybrid identity attack paths.

The goal is to connect:

**On-prem AD identity → Entra ID → workload identities → Sentinel telemetry → detection → remediation → attack-path retest**

Current Phase 2 focus areas include:

* Entra application and service-principal ownership abuse
* Entra roles vs Azure RBAC mapping
* Hybrid account compromise and cross-plane correlation
* Entra Connect security assessment
* Identity-focused Sentinel detections
* AzureHound / BloodHound attack-path analysis
* Before/after remediation evidence

### Phase 2 Documentation

- [Phase 2 Overview](./phase-2/README.md)
- [Scenario 02 — Service Principal Ownership Abuse](./phase-2/scenario-02-service-principal-ownership-abuse.md)

### Current Progress

**Scenario 02 — Service Principal Ownership Abuse:** ✅ Attack path validated

A controlled low-privileged application owner successfully added a new client secret to an owned Entra application and used it to authenticate as the application's service principal. Microsoft Sentinel captured both the credential-management activity and the successful service-principal sign-in.

The next milestone is to create the correlated Sentinel analytic rule, generate an incident during a controlled retest, remediate the ownership/credential path, and capture AzureHound/BloodHound before-and-after evidence.

## Skills Demonstrated

`Microsoft Sentinel` `KQL` `Active Directory` `Microsoft Entra ID` `Microsoft Graph` `AzureHound` `BloodHound` `Threat Hunting` `Detection Engineering` `Incident Investigation` `MITRE ATT&CK` `Purple Teaming`

## Disclaimer

All testing is performed in an authorised lab environment created specifically for cybersecurity research and detection engineering.
