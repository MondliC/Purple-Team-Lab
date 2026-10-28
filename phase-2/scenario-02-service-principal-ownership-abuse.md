# Phase 2 — Scenario 02: Service Principal Ownership Abuse

## Objective

Validate whether a low-privileged Microsoft Entra ID user who owns an application can add a new client secret, authenticate as the application's service principal, and generate observable telemetry in Microsoft Sentinel.

This scenario demonstrates why application ownership is a meaningful privileged relationship. Ownership does not automatically grant Global Administrator or Azure Owner; the impact depends on the permissions already assigned to the application/service principal.

## Lab Scope

- **Application:** `PT-ServicePrincipal-Lab`
- **Controlled owner:** `sp-owner-lab`
- **Environment:** Microsoft Entra ID + Microsoft Sentinel
- **Attack host:** Kali Linux / PowerShell
- **Telemetry:** `AuditLogs`, `AADServicePrincipalSignInLogs`

No new privileged Microsoft Graph application permissions or Azure RBAC roles were granted for this test.

## Attack Path

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

## Execution Summary

### 1. Application ownership

`sp-owner-lab` was configured as an owner of `PT-ServicePrincipal-Lab`.

The account remained a normal Entra member and was not assigned a privileged Entra directory role for the scenario.

### 2. Credential creation

While signed in as `sp-owner-lab`, a temporary client secret was added to the application.

Microsoft Sentinel recorded successful `ApplicationManagement` activity including:

```text
Update application
Update application – Certificates and secrets management
Update service principal
```

### 3. Audit validation

```kusto
AuditLogs
| where TimeGenerated > ago(1h)
| where Category =~ "ApplicationManagement"
| where TargetResources has "PT-ServicePrincipal-Lab"
| extend
    InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorName = tostring(InitiatedBy.user.displayName),
    InitiatorId = tostring(InitiatedBy.user.id)
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatorName,
    InitiatorUPN,
    InitiatorId,
    CorrelationId
| order by TimeGenerated desc
```

The results confirmed that the controlled application owner performed the credential-management operation.

### 4. Service-principal authentication

The new client secret was used from the Kali test host to request an OAuth 2.0 token using the client credentials flow.

Example structure:

```powershell
$TenantId = "<TENANT-ID>"
$ClientId = "<APPLICATION-CLIENT-ID>"
$ClientSecret = "<TEMPORARY-SECRET-VALUE>"

$body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
    grant_type    = "client_credentials"
}

$response = Invoke-RestMethod `
    -Method POST `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Body $body `
    -ContentType "application/x-www-form-urlencoded"
```

The request returned a Bearer token with a normal expiry period, confirming successful app-only authentication.

> Real client secrets and access tokens must never be stored in source control.

### 5. Sentinel sign-in validation

```kusto
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1h)
| where ServicePrincipalName =~ "PT-ServicePrincipal-Lab"
| project
    TimeGenerated,
    ServicePrincipalName,
    ServicePrincipalId,
    AppId,
    ResourceDisplayName,
    IPAddress,
    ResultType,
    ResultDescription,
    ServicePrincipalCredentialKeyId
| order by TimeGenerated desc
```

Observed:

```text
ServicePrincipalName: PT-ServicePrincipal-Lab
ResourceDisplayName: Microsoft Graph
ResultType: 0
```

`ResultType = 0` confirmed successful authentication.

## Detection Engineering

The target detection correlates an application credential change with successful authentication from the same service principal shortly afterwards.

```kusto
let CredentialChanges =
AuditLogs
| where TimeGenerated > ago(1d)
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Update application – Certificates and secrets management"
| extend
    InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
    AppName = tostring(TargetResources[0].displayName),
    ChangeTime = TimeGenerated
| project ChangeTime, AppName, InitiatorUPN, CorrelationId;

CredentialChanges
| join kind=inner (
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | project
        SignInTime = TimeGenerated,
        ServicePrincipalName,
        ServicePrincipalId,
        AppId,
        IPAddress,
        ResourceDisplayName,
        ResultType
) on $left.AppName == $right.ServicePrincipalName
| where SignInTime between (ChangeTime .. ChangeTime + 30m)
| project
    ChangeTime,
    SignInTime,
    InitiatorUPN,
    AppName,
    AppId,
    IPAddress,
    ResourceDisplayName,
    ResultType,
    CorrelationId
| order by SignInTime desc
```

### Sentinel Analytic Rule

**Name:** `Entra Application Credential Added Followed by Service Principal Sign-in`

Suggested settings:

| Setting | Value |
|---|---|
| Severity | High |
| Rule type | Scheduled |
| Query frequency | 5 minutes |
| Lookup period | 1 hour |
| Trigger threshold | Greater than 0 |
| Incident creation | Enabled |

Suggested mappings:

- Account → `InitiatorUPN`
- IP → `IPAddress`

## Security Impact

The scenario proves that a normal user with application ownership can control the workload identity by adding a new credential.

The real impact depends on the service principal's existing access, for example:

- Microsoft Graph application permissions;
- Entra directory roles;
- Azure RBAC roles;
- internal API access;
- automation/deployment rights;
- access to sensitive data.

This test deliberately did **not** grant new privileged permissions.

## Remediation

For an unauthorized change:

1. Remove the temporary client secret/certificate.
2. Remove unnecessary application owners.
3. Review remaining credentials.
4. Review Microsoft Graph permissions.
5. Review Entra directory roles.
6. Review Azure RBAC assignments.
7. Investigate recent service-principal sign-ins.
8. Recollect AzureHound data.
9. Verify the removed credential can no longer authenticate.

## AzureHound / BloodHound Retest

Before remediation:

```text
sp-owner-lab
      |
      +---- Owns ----> PT-ServicePrincipal-Lab
```

After remediation, the ownership relationship should be removed and the old credential should fail authentication.

## Evidence Checklist

- [x] Controlled low-privileged owner configured.
- [x] Temporary client secret created.
- [x] `AuditLogs` captured credential-management activity.
- [x] Initiating account identified.
- [x] Credential successfully obtained an app-only token.
- [x] `AADServicePrincipalSignInLogs` captured successful authentication.
- [ ] Sentinel analytic rule created.
- [ ] Sentinel incident generated during controlled retest.
- [ ] Temporary credential removed.
- [ ] Owner relationship removed.
- [ ] Old credential confirmed unusable.
- [ ] AzureHound/BloodHound before/after evidence captured.

## References

- Microsoft Entra — Security operations for applications  
  https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications
- Microsoft identity platform — OAuth 2.0 client credentials flow  
  https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
- Azure Monitor — `AADServicePrincipalSignInLogs`  
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
- Microsoft Sentinel — Scheduled analytics rules  
  https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview

## Status

**Attack execution:** ✅ Validated  
**Audit telemetry:** ✅ Validated  
**Service-principal authentication telemetry:** ✅ Validated  
**Detection rule:** ⏳ Next  
**Incident generation:** ⏳ Next  
**Remediation/retest:** ⏳ Next  
**AzureHound before/after:** ⏳ Next
