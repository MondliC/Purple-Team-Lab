# Active Directory Purple Team Detection Lab

## Overview

This project simulates an enterprise-style **Active Directory environment** where controlled attack activity is generated and monitored using **Microsoft Sentinel**.

The objective is to understand the full defensive workflow:

**Attack → Windows telemetry → Sentinel → KQL investigation → Detection rule → Alert → Tuning**

## Environment

* Windows Server 2022 Domain Controller
* Active Directory Domain Services
* Kali Linux attacker machine
* Microsoft Sentinel
* Log Analytics
* Azure Monitor Agent
* KQL

## What I Built

* Active Directory lab in Microsoft Azure
* Windows Security Event ingestion into Sentinel
* Multiple controlled attack scenarios
* Custom KQL investigation queries
* Microsoft Sentinel analytics rules
* MITRE ATT&CK mappings
* Detection tuning and false-positive analysis

## Detection Scenarios

The project includes scenarios covering:

* Active Directory reconnaissance
* Failed authentication
* Password spraying
* Credentialed enumeration
* Kerberos activity
* Account and privilege discovery
* Suspicious authentication behaviour

Each scenario is documented separately with its detection logic, evidence, and lessons learned.

## Key Learning

One of the biggest lessons from this project is that a detection that works well in a lab may be too noisy in production.

Authentication protocols such as **NTLM and SMB** can generate large amounts of legitimate activity, so useful detections need behavioural context and tuning rather than simply alerting on individual events.

## Phase 2

The next phase will expand the lab into a **hybrid identity environment** using:

* Microsoft Entra ID
* Hybrid users
* Microsoft Defender for Identity
* Microsoft Sentinel

The goal is to investigate how on-premises Active Directory activity connects to cloud identity signals and attack paths.

## Skills Demonstrated

`Microsoft Sentinel` `KQL` `Active Directory` `Microsoft Entra ID` `Threat Hunting` `Detection Engineering` `Incident Investigation` `MITRE ATT&CK` `Purple Teaming`

## Disclaimer

All testing is performed in an authorised lab environment created specifically for cybersecurity research and detection engineering.
