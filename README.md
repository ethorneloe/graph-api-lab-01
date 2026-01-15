# Microsoft Graph API Authentication Guide - PowerShell Edition

This guide provides comprehensive instructions for connecting to the Microsoft Graph API using PowerShell with various authentication methods and Microsoft Entra ID (formerly Azure AD).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installing Required Modules](#installing-required-modules)
- [Creating an App Registration in Entra](#creating-an-app-registration-in-entra)
- [Assigning API Permissions](#assigning-api-permissions)
- [Granting Admin Consent](#granting-admin-consent)
- [Authentication Methods](#authentication-methods)
  - [1. Client Secret Authentication](#1-client-secret-authentication)
  - [2. Certificate-Based Authentication](#2-certificate-based-authentication)
  - [3. Managed Identity Authentication](#3-managed-identity-authentication)
- [Certificate Generation](#certificate-generation)
  - [Self-Signed Certificate](#self-signed-certificate)
  - [Internal PKI Certificate](#internal-pki-certificate)
- [Complete PowerShell Examples](#complete-powershell-examples)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **PowerShell 7.2 or later** (PowerShell Core recommended for cross-platform support)
- An Azure subscription with an active tenant
- Appropriate permissions to create app registrations in Entra ID
- Administrator rights to install PowerShell modules

---

## Installing Required Modules

Install the necessary PowerShell modules for working with Microsoft Graph and Azure:

```powershell
# Install Microsoft Graph PowerShell SDK (v2.0+)
Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force

# Install Azure PowerShell modules
Install-Module Az.Accounts -Scope CurrentUser -Repository PSGallery -Force
Install-Module Az.Resources -Scope CurrentUser -Repository PSGallery -Force

# Verify installations
Get-Module Microsoft.Graph* -ListAvailable
Get-Module Az.* -ListAvailable

# Import modules
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Applications
Import-Module Az.Accounts
Import-Module Az.Resources
```

### Module Versions

This guide uses the following module versions (or later):
- **Microsoft.Graph**: v2.0+
- **Az.Accounts**: v2.12+
- **Az.Resources**: v6.0+

Check your versions:

```powershell
(Get-Module Microsoft.Graph -ListAvailable).Version | Select-Object -First 1
(Get-Module Az.Accounts -ListAvailable).Version | Select-Object -First 1
```

---

## Creating an App Registration in Entra

### Using PowerShell with Microsoft Graph SDK

```powershell
# Connect to Microsoft Graph with appropriate scopes
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Create the app registration
$appParams = @{
    DisplayName = "GraphAPI-Service-App"
    SignInAudience = "AzureADMyOrg"  # Single tenant
    Description = "Service application for Microsoft Graph API access"
}

$app = New-MgApplication @appParams

# Display important values
Write-Host "Application created successfully!" -ForegroundColor Green
Write-Host "Application (Client) ID: $($app.AppId)" -ForegroundColor Cyan
Write-Host "Object ID: $($app.Id)" -ForegroundColor Cyan

# Get tenant ID
$context = Get-MgContext
Write-Host "Tenant ID: $($context.TenantId)" -ForegroundColor Cyan

# Store these values for later use
$clientId = $app.AppId
$tenantId = $context.TenantId
$objectId = $app.Id

# Export to a secure file (optional)
$appInfo = @{
    ClientId = $clientId
    TenantId = $tenantId
    ObjectId = $objectId
    CreatedDate = Get-Date
}
$appInfo | ConvertTo-Json | Out-File "app-registration.json"
```

### Using Azure PowerShell (Az Module)

```powershell
# Connect to Azure
Connect-AzAccount

# Get current context
$context = Get-AzContext
$tenantId = $context.Tenant.Id

# Create app registration using Azure AD
$app = New-AzADApplication -DisplayName "GraphAPI-Service-App"

Write-Host "Application (Client) ID: $($app.AppId)" -ForegroundColor Cyan
Write-Host "Tenant ID: $tenantId" -ForegroundColor Cyan
```

### Alternative: Using Azure Portal

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID**
3. Select **App registrations** > **+ New registration**
4. Configure:
   - **Name**: "GraphAPI-Service-App"
   - **Supported account types**: "Accounts in this organizational directory only"
   - **Redirect URI**: Leave blank for service apps
5. Click **Register**
6. Note the **Application (client) ID** and **Directory (tenant) ID**

---

## Assigning API Permissions

### Using Microsoft Graph PowerShell SDK

```powershell
# Ensure you're connected
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Microsoft Graph Resource ID
$graphResourceId = "00000003-0000-0000-c000-000000000000"

# Get Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphResourceId'"

# Define permissions you want to add
# User.Read.All - Read all users' full profiles
$userReadAllPermission = $graphSp.AppRoles | Where-Object { $_.Value -eq "User.Read.All" }

# Mail.Send - Send mail as any user
$mailSendPermission = $graphSp.AppRoles | Where-Object { $_.Value -eq "Mail.Send" }

# Directory.Read.All - Read directory data
$directoryReadPermission = $graphSp.AppRoles | Where-Object { $_.Value -eq "Directory.Read.All" }

# Get the application
$app = Get-MgApplication -Filter "appId eq '$clientId'"

# Build the required resource access
$requiredResourceAccess = @{
    ResourceAppId = $graphResourceId
    ResourceAccess = @(
        @{
            Id = $userReadAllPermission.Id
            Type = "Role"  # "Role" for Application permissions, "Scope" for Delegated
        },
        @{
            Id = $mailSendPermission.Id
            Type = "Role"
        },
        @{
            Id = $directoryReadPermission.Id
            Type = "Role"
        }
    )
}

# Update the application with required permissions
Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccess

Write-Host "API permissions added successfully!" -ForegroundColor Green
Write-Host "Permissions added:" -ForegroundColor Yellow
Write-Host "  - User.Read.All (Application)" -ForegroundColor White
Write-Host "  - Mail.Send (Application)" -ForegroundColor White
Write-Host "  - Directory.Read.All (Application)" -ForegroundColor White
```

### Common Graph API Permissions

Here's a reference table of commonly used permissions:

| Permission | ID | Type | Description |
|------------|----|----- |-------------|
| User.Read.All | `df021288-bdef-4463-88db-98f22de89214` | Application | Read all users' profiles |
| User.ReadWrite.All | `741f803b-c850-494e-b5df-cde7c675a1ca` | Application | Read and write all users' profiles |
| Mail.Send | `b633e1c5-b582-4048-a93e-9f11b44c7e96` | Application | Send mail as any user |
| Mail.Read | `810c84a8-4a9e-49e6-bf7d-12d183f40d01` | Application | Read mail in all mailboxes |
| Directory.Read.All | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` | Application | Read directory data |
| Directory.ReadWrite.All | `19dbc75e-c2e2-444c-a770-ec69d8559fc7` | Application | Read and write directory data |
| Group.Read.All | `5b567255-7703-4780-807c-7be8301ae99b` | Application | Read all groups |
| Group.ReadWrite.All | `62a82d76-70ea-41e2-9197-370581804d09` | Application | Read and write all groups |

### Using Azure PowerShell for Permissions

```powershell
# Connect to Azure
Connect-AzAccount

# Add Microsoft Graph API permissions
$graphResourceId = "00000003-0000-0000-c000-000000000000"

# User.Read.All application permission
Add-AzADAppPermission -ObjectId $objectId `
    -ApiId $graphResourceId `
    -PermissionId "df021288-bdef-4463-88db-98f22de89214" `
    -Type "Role"

# Mail.Send application permission
Add-AzADAppPermission -ObjectId $objectId `
    -ApiId $graphResourceId `
    -PermissionId "b633e1c5-b582-4048-a93e-9f11b44c7e96" `
    -Type "Role"

Write-Host "Permissions added successfully!" -ForegroundColor Green
```

---

## Granting Admin Consent

API permissions with **Application** type require administrator consent.

### Required Roles

To grant admin consent, you need one of these roles:
- **Global Administrator** (can consent to all permissions)
- **Privileged Role Administrator** (can consent to all permissions)
- **Cloud Application Administrator** (can consent to most permissions)
- **Application Administrator** (can consent to most permissions)

### Using Microsoft Graph PowerShell SDK

```powershell
# Connect with appropriate permissions
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

# Get the service principal for your app (create if doesn't exist)
$servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$clientId'"

if (-not $servicePrincipal) {
    Write-Host "Creating service principal..." -ForegroundColor Yellow
    $servicePrincipal = New-MgServicePrincipal -AppId $clientId
}

# Get Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Get the app roles we want to consent to
$app = Get-MgApplication -Filter "appId eq '$clientId'"
$requiredPermissions = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq "00000003-0000-0000-c000-000000000000" }

# Grant consent for each application permission
foreach ($permission in $requiredPermissions.ResourceAccess) {
    if ($permission.Type -eq "Role") {  # Application permission
        $appRole = $graphSp.AppRoles | Where-Object { $_.Id -eq $permission.Id }

        # Check if already granted
        $existingGrant = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id |
            Where-Object { $_.AppRoleId -eq $permission.Id -and $_.ResourceId -eq $graphSp.Id }

        if (-not $existingGrant) {
            $params = @{
                PrincipalId = $servicePrincipal.Id
                ResourceId = $graphSp.Id
                AppRoleId = $permission.Id
            }

            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id -BodyParameter $params
            Write-Host "Granted admin consent for: $($appRole.Value)" -ForegroundColor Green
        } else {
            Write-Host "Already granted: $($appRole.Value)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`nAdmin consent granted successfully!" -ForegroundColor Green
```

### Alternative: Grant All Permissions at Once

```powershell
# This is a simpler approach using Azure CLI from PowerShell
$appId = $clientId  # Your app's client ID

# Execute Azure CLI command
az ad app permission admin-consent --id $appId

Write-Host "Admin consent granted for all requested permissions!" -ForegroundColor Green
```

### Verify Granted Permissions

```powershell
# Get service principal
$sp = Get-MgServicePrincipal -Filter "appId eq '$clientId'"

# Get all app role assignments
$assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id

Write-Host "`nGranted Application Permissions:" -ForegroundColor Cyan
foreach ($assignment in $assignments) {
    $resource = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId
    $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
    Write-Host "  - $($appRole.Value) on $($resource.DisplayName)" -ForegroundColor White
}
```

---

## Authentication Methods

### 1. Client Secret Authentication

Client secrets are password-like credentials for your application.

#### Creating a Client Secret with PowerShell

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Get the application
$app = Get-MgApplication -Filter "appId eq '$clientId'"

# Create a new client secret (valid for 2 years)
$passwordCred = @{
    DisplayName = "Production Secret"
    EndDateTime = (Get-Date).AddYears(2)
}

$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordCred

# IMPORTANT: Save this secret value immediately - it cannot be retrieved later!
Write-Host "`nClient Secret Created Successfully!" -ForegroundColor Green
Write-Host "Secret ID: $($secret.KeyId)" -ForegroundColor Cyan
Write-Host "Secret Value: $($secret.SecretText)" -ForegroundColor Yellow
Write-Host "Expires: $($secret.EndDateTime)" -ForegroundColor Cyan
Write-Host "`n⚠️  SAVE THIS SECRET NOW - It cannot be retrieved later!" -ForegroundColor Red

# Optionally save to secure file (be careful with this!)
$secretInfo = @{
    SecretId = $secret.KeyId
    SecretValue = $secret.SecretText
    ExpiresOn = $secret.EndDateTime
    CreatedDate = Get-Date
} | ConvertTo-Json

# Save to file (ensure this file is secured and not committed to source control)
$secretInfo | Out-File "client-secret-INFO.json" -Force
Write-Host "`nSecret information saved to: client-secret-INFO.json" -ForegroundColor Yellow
```

#### Using Azure PowerShell to Create Secret

```powershell
# Connect to Azure
Connect-AzAccount

# Create a new client secret
$secret = New-AzADAppCredential -ApplicationId $clientId -EndDate (Get-Date).AddYears(2)

Write-Host "Secret Value: $($secret.SecretText)" -ForegroundColor Yellow
Write-Host "Save this secret immediately!" -ForegroundColor Red
```

#### Connecting to Graph API with Client Secret

```powershell
# Method 1: Using Microsoft.Graph module with client credentials

$tenantId = "YOUR_TENANT_ID"
$clientId = "YOUR_CLIENT_ID"
$clientSecret = "YOUR_CLIENT_SECRET"

# Create credential object
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

# Connect to Microsoft Graph
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Verify connection
$context = Get-MgContext
Write-Host "Connected to tenant: $($context.TenantId)" -ForegroundColor Green
Write-Host "Using app: $($context.ClientId)" -ForegroundColor Green

# Example: Get users
$users = Get-MgUser -Top 10
$users | Select-Object DisplayName, UserPrincipalName, Id

# Disconnect when done
Disconnect-MgGraph
```

#### Advanced: Using MSAL for Token Acquisition

```powershell
# Install MSAL.PS if not already installed
Install-Module MSAL.PS -Scope CurrentUser

# Acquire token using client secret
$tokenParams = @{
    ClientId = $clientId
    TenantId = $tenantId
    ClientSecret = (ConvertTo-SecureString $clientSecret -AsPlainText -Force)
}

$token = Get-MsalToken @tokenParams

Write-Host "Access Token acquired!" -ForegroundColor Green
Write-Host "Token expires: $($token.ExpiresOn)" -ForegroundColor Cyan

# Use token with Invoke-RestMethod for Graph API calls
$headers = @{
    "Authorization" = "Bearer $($token.AccessToken)"
    "Content-Type" = "application/json"
}

$users = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers $headers
$users.value | Select-Object displayName, userPrincipalName
```

---

### 2. Certificate-Based Authentication

Certificate-based authentication is more secure than client secrets and recommended for production environments.

#### Creating and Uploading a Certificate

```powershell
# Step 1: Create a self-signed certificate (for testing) or use PKI cert
$cert = New-SelfSignedCertificate `
    -Subject "CN=GraphAPI-ServiceApp" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2) `
    -FriendlyName "Graph API Service Certificate"

Write-Host "Certificate created with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

# Step 2: Export the certificate

# Export with private key (PFX) - for application use
$certPassword = ConvertTo-SecureString -String "YourSecurePassword123!" -Force -AsPlainText
$pfxPath = ".\GraphAPI-Cert.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $certPassword
Write-Host "Certificate with private key exported to: $pfxPath" -ForegroundColor Cyan

# Export public key (CER) - for uploading to Azure
$cerPath = ".\GraphAPI-Cert.cer"
Export-Certificate -Cert $cert -FilePath $cerPath
Write-Host "Public key certificate exported to: $cerPath" -ForegroundColor Cyan

# Step 3: Upload certificate to app registration using Microsoft Graph

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Get the application
$app = Get-MgApplication -Filter "appId eq '$clientId'"

# Read the certificate file as Base64
$cerBytes = [System.IO.File]::ReadAllBytes($cerPath)
$cerBase64 = [System.Convert]::ToBase64String($cerBytes)

# Create certificate credential
$certCred = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $cerBase64
    DisplayName = "Graph API Service Certificate"
}

# Add certificate to application
Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($certCred)

Write-Host "`nCertificate uploaded successfully!" -ForegroundColor Green
Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor Cyan
Write-Host "Expires: $($cert.NotAfter)" -ForegroundColor Cyan
```

#### Alternative: Upload Existing Certificate

```powershell
# If you have an existing certificate file
$cerPath = "C:\Path\To\Your\Certificate.cer"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)

Connect-MgGraph -Scopes "Application.ReadWrite.All"
$app = Get-MgApplication -Filter "appId eq '$clientId'"

$cerBytes = [System.IO.File]::ReadAllBytes($cerPath)
$cerBase64 = [System.Convert]::ToBase64String($cerBytes)

$certCred = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $cerBase64
    DisplayName = "Production Certificate"
}

Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($certCred)
Write-Host "Certificate uploaded successfully!" -ForegroundColor Green
```

#### Connecting to Graph API with Certificate

```powershell
# Method 1: Using certificate thumbprint (certificate must be in cert store)

$tenantId = "YOUR_TENANT_ID"
$clientId = "YOUR_CLIENT_ID"
$certThumbprint = "YOUR_CERTIFICATE_THUMBPRINT"

# Connect using certificate
Connect-MgGraph -TenantId $tenantId -ClientId $clientId -CertificateThumbprint $certThumbprint

# Verify connection
$context = Get-MgContext
Write-Host "Connected using certificate authentication!" -ForegroundColor Green
Write-Host "Tenant: $($context.TenantId)" -ForegroundColor Cyan
Write-Host "App: $($context.ClientId)" -ForegroundColor Cyan

# Example: Get users
$users = Get-MgUser -Top 10
$users | Select-Object DisplayName, UserPrincipalName

# Disconnect when done
Disconnect-MgGraph
```

#### Using Certificate from File (PFX)

```powershell
# Method 2: Load certificate from PFX file

$tenantId = "YOUR_TENANT_ID"
$clientId = "YOUR_CLIENT_ID"
$certPath = "C:\Path\To\GraphAPI-Cert.pfx"
$certPassword = "YourSecurePassword123!"

# Load certificate from file
$certPasswordSecure = ConvertTo-SecureString -String $certPassword -AsPlainText -Force
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, $certPasswordSecure)

# Connect using certificate object
Connect-MgGraph -TenantId $tenantId -ClientId $clientId -Certificate $cert

Write-Host "Connected using certificate from file!" -ForegroundColor Green

# Use the connection
$users = Get-MgUser -Top 5
$users | Format-Table DisplayName, UserPrincipalName
```

#### Using MSAL with Certificate

```powershell
# Install MSAL.PS if needed
Install-Module MSAL.PS -Scope CurrentUser

# Load certificate
$certPath = "C:\Path\To\GraphAPI-Cert.pfx"
$certPassword = ConvertTo-SecureString "YourSecurePassword123!" -AsPlainText -Force
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, $certPassword)

# Acquire token using certificate
$tokenParams = @{
    ClientId = $clientId
    TenantId = $tenantId
    ClientCertificate = $cert
}

$token = Get-MsalToken @tokenParams

Write-Host "Access Token acquired using certificate!" -ForegroundColor Green

# Use token for Graph API calls
$headers = @{
    "Authorization" = "Bearer $($token.AccessToken)"
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers $headers -Method Get
$response.value | Select-Object displayName, userPrincipalName | Format-Table
```

---

### 3. Managed Identity Authentication

Managed identities eliminate the need to store credentials. Available for Azure VMs, App Services, Functions, and other Azure resources.

#### Enabling Managed Identity with PowerShell

**For Azure VM:**

```powershell
# Connect to Azure
Connect-AzAccount

# Enable system-assigned managed identity on VM
$resourceGroup = "MyResourceGroup"
$vmName = "MyVM"

Update-AzVM -ResourceGroupName $resourceGroup -VM (Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName) -IdentityType SystemAssigned

# Get the managed identity principal ID
$vm = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName
$principalId = $vm.Identity.PrincipalId

Write-Host "Managed Identity enabled!" -ForegroundColor Green
Write-Host "Principal ID: $principalId" -ForegroundColor Cyan
```

**For Azure App Service:**

```powershell
# Enable system-assigned managed identity on App Service
$resourceGroup = "MyResourceGroup"
$appName = "MyAppService"

Set-AzWebApp -ResourceGroupName $resourceGroup -Name $appName -AssignIdentity $true

# Get the principal ID
$app = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appName
$principalId = $app.Identity.PrincipalId

Write-Host "Managed Identity enabled for App Service!" -ForegroundColor Green
Write-Host "Principal ID: $principalId" -ForegroundColor Cyan
```

**For Azure Function App:**

```powershell
# Enable system-assigned managed identity on Function App
$resourceGroup = "MyResourceGroup"
$functionAppName = "MyFunctionApp"

Update-AzFunctionApp -ResourceGroupName $resourceGroup -Name $functionAppName -IdentityType SystemAssigned

# Get the principal ID
$functionApp = Get-AzFunctionApp -ResourceGroupName $resourceGroup -Name $functionAppName
$principalId = $functionApp.IdentityPrincipalId

Write-Host "Managed Identity enabled for Function App!" -ForegroundColor Green
Write-Host "Principal ID: $principalId" -ForegroundColor Cyan
```

#### Assigning Graph API Permissions to Managed Identity

```powershell
# Connect to Microsoft Graph with appropriate permissions
Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All"

# Your managed identity's principal ID (from above)
$managedIdentityPrincipalId = "YOUR_MANAGED_IDENTITY_PRINCIPAL_ID"

# Get the managed identity's service principal
$managedIdentitySp = Get-MgServicePrincipal -ServicePrincipalId $managedIdentityPrincipalId

# Get Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Define the permissions you want to assign
$permissions = @(
    "User.Read.All",
    "Mail.Send",
    "Directory.Read.All"
)

# Assign each permission
foreach ($permissionName in $permissions) {
    # Find the app role
    $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $permissionName -and $_.AllowedMemberTypes -contains "Application" }

    if ($appRole) {
        # Check if already assigned
        $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentitySp.Id |
            Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }

        if (-not $existingAssignment) {
            # Assign the permission
            $assignmentParams = @{
                PrincipalId = $managedIdentitySp.Id
                ResourceId = $graphSp.Id
                AppRoleId = $appRole.Id
            }

            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentitySp.Id -BodyParameter $assignmentParams
            Write-Host "Assigned permission: $permissionName" -ForegroundColor Green
        } else {
            Write-Host "Permission already assigned: $permissionName" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Permission not found: $permissionName" -ForegroundColor Red
    }
}

Write-Host "`nAll permissions assigned to managed identity!" -ForegroundColor Green
```

#### Verify Managed Identity Permissions

```powershell
# Get all permissions assigned to the managed identity
$assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentitySp.Id

Write-Host "`nAssigned Permissions:" -ForegroundColor Cyan
foreach ($assignment in $assignments) {
    $resource = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId
    $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
    Write-Host "  - $($appRole.Value) on $($resource.DisplayName)" -ForegroundColor White
}
```

#### Using Managed Identity in PowerShell Scripts

**On Azure VM or App Service (where managed identity is enabled):**

```powershell
# Method 1: Using Connect-MgGraph with managed identity
Connect-MgGraph -Identity

# Verify connection
$context = Get-MgContext
Write-Host "Connected using managed identity!" -ForegroundColor Green
Write-Host "Tenant: $($context.TenantId)" -ForegroundColor Cyan

# Use Graph API
$users = Get-MgUser -Top 10
$users | Select-Object DisplayName, UserPrincipalName | Format-Table

# Disconnect when done
Disconnect-MgGraph
```

#### Using Managed Identity with REST API

```powershell
# This script runs on Azure resource with managed identity enabled

# Get access token from Azure Instance Metadata Service (IMDS)
$resourceUri = "https://graph.microsoft.com"
$tokenAuthUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$resourceUri"

$response = Invoke-RestMethod -Uri $tokenAuthUri -Method Get -Headers @{Metadata="true"}
$accessToken = $response.access_token

Write-Host "Access token acquired using managed identity!" -ForegroundColor Green

# Use the token to call Graph API
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

$users = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$top=10" -Headers $headers -Method Get
$users.value | Select-Object displayName, userPrincipalName | Format-Table
```

#### Advanced: User-Assigned Managed Identity

```powershell
# Create user-assigned managed identity
$resourceGroup = "MyResourceGroup"
$identityName = "MyUserAssignedIdentity"
$location = "eastus"

$identity = New-AzUserAssignedIdentity -ResourceGroupName $resourceGroup -Name $identityName -Location $location
$clientId = $identity.ClientId
$principalId = $identity.PrincipalId

Write-Host "User-assigned managed identity created!" -ForegroundColor Green
Write-Host "Client ID: $clientId" -ForegroundColor Cyan
Write-Host "Principal ID: $principalId" -ForegroundColor Cyan

# Assign to VM
$vm = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName
Update-AzVM -ResourceGroupName $resourceGroup -VM $vm -IdentityType UserAssigned -IdentityId $identity.Id

# Connect using user-assigned managed identity
Connect-MgGraph -Identity -ClientId $clientId
```

---

## Certificate Generation

### Self-Signed Certificate

Self-signed certificates are useful for development and testing environments.

#### Creating Self-Signed Certificate with PowerShell

```powershell
# Create a self-signed certificate with proper settings
$certParams = @{
    Subject = "CN=GraphAPI-ServiceApp"
    CertStoreLocation = "Cert:\CurrentUser\My"
    KeyExportPolicy = "Exportable"
    KeySpec = "Signature"
    KeyLength = 2048
    KeyAlgorithm = "RSA"
    HashAlgorithm = "SHA256"
    NotAfter = (Get-Date).AddYears(2)
    FriendlyName = "Graph API Service Certificate"
    TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")  # Client Authentication EKU
}

$cert = New-SelfSignedCertificate @certParams

Write-Host "`nCertificate Created Successfully!" -ForegroundColor Green
Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor Cyan
Write-Host "Subject: $($cert.Subject)" -ForegroundColor Cyan
Write-Host "Valid From: $($cert.NotBefore)" -ForegroundColor Cyan
Write-Host "Valid Until: $($cert.NotAfter)" -ForegroundColor Cyan

# Export certificate with private key (PFX)
$certPassword = Read-Host "Enter password for PFX file" -AsSecureString
$pfxPath = ".\GraphAPI-Cert.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $certPassword

Write-Host "`nCertificate exported to: $pfxPath" -ForegroundColor Green

# Export public key only (CER) for uploading to Azure
$cerPath = ".\GraphAPI-Cert.cer"
Export-Certificate -Cert $cert -FilePath $cerPath

Write-Host "Public key exported to: $cerPath" -ForegroundColor Green
Write-Host "`nUpload $cerPath to your Azure app registration" -ForegroundColor Yellow
```

#### Complete Script with Upload to Azure

```powershell
# Complete workflow: Create certificate and upload to app registration

# 1. Create certificate
$cert = New-SelfSignedCertificate `
    -Subject "CN=GraphAPI-ServiceApp" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2) `
    -FriendlyName "Graph API Service Certificate"

Write-Host "Certificate created: $($cert.Thumbprint)" -ForegroundColor Green

# 2. Export certificates
$certPassword = ConvertTo-SecureString -String "YourSecurePassword123!" -Force -AsPlainText
$pfxPath = ".\GraphAPI-Cert.pfx"
$cerPath = ".\GraphAPI-Cert.cer"

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $certPassword | Out-Null
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null

Write-Host "Certificates exported" -ForegroundColor Green

# 3. Upload to Azure app registration
Connect-MgGraph -Scopes "Application.ReadWrite.All"

$app = Get-MgApplication -Filter "appId eq '$clientId'"
$cerBytes = [System.IO.File]::ReadAllBytes($cerPath)
$cerBase64 = [System.Convert]::ToBase64String($cerBytes)

$certCred = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $cerBase64
    DisplayName = "Graph API Service Certificate"
}

Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($certCred)

Write-Host "`nComplete setup:" -ForegroundColor Green
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Cyan
Write-Host "  PFX File: $pfxPath" -ForegroundColor Cyan
Write-Host "  Password: YourSecurePassword123!" -ForegroundColor Yellow
Write-Host "  Uploaded to Azure: Yes" -ForegroundColor Green

# 4. Save configuration
$config = @{
    TenantId = $tenantId
    ClientId = $clientId
    CertificateThumbprint = $cert.Thumbprint
    CertificatePath = $pfxPath
    CreatedDate = Get-Date
    ExpiryDate = $cert.NotAfter
} | ConvertTo-Json

$config | Out-File "cert-config.json"
Write-Host "`nConfiguration saved to: cert-config.json" -ForegroundColor Cyan
```

---

### Internal PKI Certificate

For production environments, use certificates issued by your organization's internal PKI.

#### Requesting Certificate from Enterprise CA

```powershell
# Method 1: Using Get-Certificate cmdlet (requires enterprise CA)

$certParams = @{
    Template = "WebServer"  # Or your custom template name
    SubjectName = "CN=GraphAPI-ServiceApp,O=YourOrganization,C=US"
    CertStoreLocation = "Cert:\LocalMachine\My"
    DnsName = "graphapi-service.contoso.com"
}

$cert = Get-Certificate @certParams

if ($cert.Status -eq "Issued") {
    Write-Host "Certificate issued successfully!" -ForegroundColor Green
    Write-Host "Thumbprint: $($cert.Certificate.Thumbprint)" -ForegroundColor Cyan

    # Export the certificate
    $certPassword = Read-Host "Enter password for PFX export" -AsSecureString
    $pfxPath = ".\GraphAPI-PKI-Cert.pfx"
    Export-PfxCertificate -Cert $cert.Certificate -FilePath $pfxPath -Password $certPassword

    $cerPath = ".\GraphAPI-PKI-Cert.cer"
    Export-Certificate -Cert $cert.Certificate -FilePath $cerPath

    Write-Host "Certificates exported successfully!" -ForegroundColor Green
} else {
    Write-Host "Certificate request status: $($cert.Status)" -ForegroundColor Yellow
}
```

#### Using certreq.exe for Certificate Request

```powershell
# Method 2: Using certreq.exe for more control

# Create INF file for certificate request
$infContent = @"
[NewRequest]
Subject = "CN=GraphAPI-ServiceApp,O=YourOrganization,C=US"
KeyLength = 2048
KeyAlgorithm = RSA
HashAlgorithm = SHA256
MachineKeySet = TRUE
Exportable = TRUE
RequestType = PKCS10
KeyUsage = 0xa0
FriendlyName = "Graph API Service Certificate"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2 ; Client Authentication

[RequestAttributes]
CertificateTemplate = "WebServer"
"@

# Save INF file
$infPath = ".\cert-request.inf"
$infContent | Out-File -FilePath $infPath -Encoding ASCII

# Create certificate request
$reqPath = ".\cert-request.req"
certreq -new $infPath $reqPath

Write-Host "Certificate request created: $reqPath" -ForegroundColor Green

# Submit to CA (replace with your CA details)
$caConfig = "CA-SERVER\YourCA-Name"
$cerPath = ".\GraphAPI-PKI-Cert.cer"

certreq -submit -config $caConfig $reqPath $cerPath

# Accept and install certificate
certreq -accept $cerPath

Write-Host "Certificate installed successfully!" -ForegroundColor Green

# Find the certificate in the store
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*GraphAPI-ServiceApp*" } |
    Sort-Object NotBefore -Descending |
    Select-Object -First 1

Write-Host "Certificate Thumbprint: $($cert.Thumbprint)" -ForegroundColor Cyan

# Export for use
$certPassword = Read-Host "Enter password for PFX export" -AsSecureString
$pfxPath = ".\GraphAPI-PKI-Cert.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $certPassword

Write-Host "Certificate exported to: $pfxPath" -ForegroundColor Green
```

#### Alternative: Web Enrollment (GUI-based)

```powershell
# Open web enrollment page
$caServer = "ca-server.contoso.com"
Start-Process "https://$caServer/certsrv"

Write-Host "Opening web enrollment interface..." -ForegroundColor Yellow
Write-Host "Steps:" -ForegroundColor Cyan
Write-Host "1. Click 'Request a certificate'" -ForegroundColor White
Write-Host "2. Click 'Advanced certificate request'" -ForegroundColor White
Write-Host "3. Fill in the form with:" -ForegroundColor White
Write-Host "   - Name: GraphAPI-ServiceApp" -ForegroundColor White
Write-Host "   - Key Size: 2048" -ForegroundColor White
Write-Host "   - Template: WebServer or custom template" -ForegroundColor White
Write-Host "4. Mark key as exportable" -ForegroundColor White
Write-Host "5. Submit and download" -ForegroundColor White
```

#### Script to Upload PKI Certificate to Azure

```powershell
# Upload enterprise PKI certificate to Azure app registration

# Load the certificate
$cerPath = "C:\Path\To\GraphAPI-PKI-Cert.cer"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)

Write-Host "Certificate Details:" -ForegroundColor Cyan
Write-Host "  Subject: $($cert.Subject)" -ForegroundColor White
Write-Host "  Issuer: $($cert.Issuer)" -ForegroundColor White
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
Write-Host "  Valid Until: $($cert.NotAfter)" -ForegroundColor White

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Get application
$app = Get-MgApplication -Filter "appId eq '$clientId'"

# Read and encode certificate
$cerBytes = [System.IO.File]::ReadAllBytes($cerPath)
$cerBase64 = [System.Convert]::ToBase64String($cerBytes)

# Create certificate credential
$certCred = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $cerBase64
    DisplayName = "Enterprise PKI Certificate"
}

# Upload to Azure
Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($certCred)

Write-Host "`nCertificate uploaded to Azure successfully!" -ForegroundColor Green
Write-Host "You can now authenticate using thumbprint: $($cert.Thumbprint)" -ForegroundColor Cyan
```

---

## Complete PowerShell Examples

### Example 1: Complete Setup from Scratch

```powershell
<#
.SYNOPSIS
    Complete setup of Azure app registration with certificate authentication
.DESCRIPTION
    This script creates an app registration, assigns permissions, creates a certificate,
    and tests the connection.
#>

# Configuration
$appName = "GraphAPI-Service-App"
$permissions = @("User.Read.All", "Mail.Send", "Directory.Read.All")

# Step 1: Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

# Step 2: Create app registration
Write-Host "`nCreating app registration..." -ForegroundColor Cyan
$app = New-MgApplication -DisplayName $appName
$clientId = $app.AppId
$tenantId = (Get-MgContext).TenantId

Write-Host "App created successfully!" -ForegroundColor Green
Write-Host "  Client ID: $clientId" -ForegroundColor White
Write-Host "  Tenant ID: $tenantId" -ForegroundColor White

# Step 3: Create service principal
Write-Host "`nCreating service principal..." -ForegroundColor Cyan
$sp = New-MgServicePrincipal -AppId $clientId

# Step 4: Assign permissions
Write-Host "`nAssigning Graph API permissions..." -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

$resourceAccess = @()
foreach ($permName in $permissions) {
    $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName }
    $resourceAccess += @{
        Id = $appRole.Id
        Type = "Role"
    }
}

$requiredResourceAccess = @{
    ResourceAppId = "00000003-0000-0000-c000-000000000000"
    ResourceAccess = $resourceAccess
}

Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccess

# Step 5: Grant admin consent
Write-Host "`nGranting admin consent..." -ForegroundColor Cyan
foreach ($permName in $permissions) {
    $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName }
    $params = @{
        PrincipalId = $sp.Id
        ResourceId = $graphSp.Id
        AppRoleId = $appRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $params | Out-Null
    Write-Host "  Granted: $permName" -ForegroundColor Green
}

# Step 6: Create certificate
Write-Host "`nCreating certificate..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate `
    -Subject "CN=$appName" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

$certThumbprint = $cert.Thumbprint
Write-Host "Certificate created: $certThumbprint" -ForegroundColor Green

# Export certificate
$certPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath ".\$appName.pfx" -Password $certPassword | Out-Null
Export-Certificate -Cert $cert -FilePath ".\$appName.cer" | Out-Null

# Step 7: Upload certificate to Azure
Write-Host "`nUploading certificate to Azure..." -ForegroundColor Cyan
$cerBytes = [System.IO.File]::ReadAllBytes(".\$appName.cer")
$cerBase64 = [System.Convert]::ToBase64String($cerBytes)

$certCred = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $cerBase64
}

Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($certCred)
Write-Host "Certificate uploaded!" -ForegroundColor Green

# Step 8: Disconnect and wait for propagation
Disconnect-MgGraph
Write-Host "`nWaiting for changes to propagate (30 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Step 9: Test connection
Write-Host "`nTesting connection with certificate..." -ForegroundColor Cyan
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $certThumbprint

$users = Get-MgUser -Top 5
Write-Host "`nSuccessfully retrieved users:" -ForegroundColor Green
$users | Format-Table DisplayName, UserPrincipalName

# Step 10: Save configuration
$config = @{
    AppName = $appName
    ClientId = $clientId
    TenantId = $tenantId
    CertificateThumbprint = $certThumbprint
    CertificatePath = ".\$appName.pfx"
    CertificatePassword = "P@ssw0rd123!"
    Permissions = $permissions
    CreatedDate = Get-Date
} | ConvertTo-Json

$config | Out-File "app-config.json"

Write-Host "`n✓ Setup complete!" -ForegroundColor Green
Write-Host "Configuration saved to: app-config.json" -ForegroundColor Cyan
Write-Host "`nTo connect in the future, use:" -ForegroundColor Yellow
Write-Host "Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $certThumbprint" -ForegroundColor White

Disconnect-MgGraph
```

### Example 2: Connect and Perform Operations

```powershell
<#
.SYNOPSIS
    Connect to Microsoft Graph and perform common operations
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [string]$CertificateThumbprint
)

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

# Verify connection
$context = Get-MgContext
Write-Host "✓ Connected successfully!" -ForegroundColor Green
Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor White
Write-Host "  App: $($context.AppName)" -ForegroundColor White
Write-Host "  Scopes: $($context.Scopes -join ', ')" -ForegroundColor White

# Example 1: Get users
Write-Host "`n--- Getting Users ---" -ForegroundColor Cyan
$users = Get-MgUser -Top 10 -Property DisplayName,UserPrincipalName,Mail,Department
$users | Format-Table DisplayName, UserPrincipalName, Department

# Example 2: Get groups
Write-Host "`n--- Getting Groups ---" -ForegroundColor Cyan
$groups = Get-MgGroup -Top 10 -Property DisplayName,Mail,GroupTypes
$groups | Format-Table DisplayName, Mail

# Example 3: Get specific user details
Write-Host "`n--- Getting User Details ---" -ForegroundColor Cyan
$user = $users[0]
$userDetails = Get-MgUser -UserId $user.Id -Property *
Write-Host "User: $($userDetails.DisplayName)" -ForegroundColor White
Write-Host "  UPN: $($userDetails.UserPrincipalName)" -ForegroundColor Gray
Write-Host "  Job Title: $($userDetails.JobTitle)" -ForegroundColor Gray
Write-Host "  Department: $($userDetails.Department)" -ForegroundColor Gray

# Example 4: Send email (requires Mail.Send permission)
Write-Host "`n--- Sending Test Email ---" -ForegroundColor Cyan
$emailParams = @{
    Message = @{
        Subject = "Test Email from Graph API"
        Body = @{
            ContentType = "Text"
            Content = "This is a test email sent using Microsoft Graph API with PowerShell."
        }
        ToRecipients = @(
            @{
                EmailAddress = @{
                    Address = $user.Mail
                }
            }
        )
    }
    SaveToSentItems = $true
}

try {
    Send-MgUserMail -UserId $user.Id -BodyParameter $emailParams
    Write-Host "✓ Email sent successfully to $($user.Mail)" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to send email: $($_.Exception.Message)" -ForegroundColor Red
}

# Disconnect
Disconnect-MgGraph
Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Cyan
```

### Example 3: Using Client Secret

```powershell
<#
.SYNOPSIS
    Connect using client secret and perform operations
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [string]$ClientSecret
)

# Create credential
$secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)

# Connect
Write-Host "Connecting to Microsoft Graph with client secret..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential

Write-Host "✓ Connected successfully!" -ForegroundColor Green

# Perform operations
$users = Get-MgUser -Top 5
Write-Host "`nRetrieved $($users.Count) users:" -ForegroundColor Cyan
$users | Format-Table DisplayName, UserPrincipalName

# Disconnect
Disconnect-MgGraph
```

### Example 4: Managed Identity (Run on Azure Resource)

```powershell
<#
.SYNOPSIS
    Connect using managed identity and perform operations
.DESCRIPTION
    This script should be run on an Azure resource with managed identity enabled
#>

# Connect using managed identity
Write-Host "Connecting using Managed Identity..." -ForegroundColor Cyan
Connect-MgGraph -Identity

$context = Get-MgContext
Write-Host "✓ Connected successfully!" -ForegroundColor Green
Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor White
Write-Host "  Auth Type: Managed Identity" -ForegroundColor White

# Get users
$users = Get-MgUser -Top 10
Write-Host "`nRetrieved $($users.Count) users:" -ForegroundColor Cyan
$users | Format-Table DisplayName, UserPrincipalName

# Disconnect
Disconnect-MgGraph
```

---

## Security Best Practices

### 1. Credential Management

```powershell
# NEVER hardcode credentials in scripts
# BAD:
$clientSecret = "my-secret-value"

# GOOD: Use Azure Key Vault
Install-Module Az.KeyVault -Scope CurrentUser

Connect-AzAccount
$secret = Get-AzKeyVaultSecret -VaultName "MyKeyVault" -Name "GraphAPISecret" -AsPlainText

# GOOD: Use environment variables
$clientSecret = $env:GRAPH_CLIENT_SECRET

# GOOD: Use Windows Credential Manager
$cred = Get-StoredCredential -Target "GraphAPI"
$clientSecret = $cred.GetNetworkCredential().Password
```

### 2. Certificate Security

```powershell
# Store certificates securely
# GOOD: Use certificate store instead of files
$cert = Get-ChildItem Cert:\CurrentUser\My\$thumbprint

# GOOD: If using files, secure them with ACLs
$pfxPath = "C:\Secure\Certificates\app-cert.pfx"
$acl = Get-Acl $pfxPath
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "$env:USERDOMAIN\$env:USERNAME",
    "Read",
    "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl $pfxPath $acl

# GOOD: Use strong passwords for PFX files
Add-Type -AssemblyName System.Web
$certPassword = [System.Web.Security.Membership]::GeneratePassword(32, 8)
$securePassword = ConvertTo-SecureString $certPassword -AsPlainText -Force
```

### 3. Least Privilege

```powershell
# Only request necessary permissions
# BAD: Requesting Directory.ReadWrite.All when only reading
$permissions = @("Directory.ReadWrite.All")

# GOOD: Use specific read-only permission
$permissions = @("Directory.Read.All")

# GOOD: Use specific permissions instead of broad ones
$permissions = @("User.Read.All", "Group.Read.All")  # Instead of Directory.Read.All
```

### 4. Secret Rotation

```powershell
# Script to rotate client secrets
$app = Get-MgApplication -Filter "appId eq '$clientId'"

# Create new secret
$newSecret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "Production Secret $(Get-Date -Format 'yyyy-MM')"
    EndDateTime = (Get-Date).AddMonths(6)
}

Write-Host "New secret created. Update your applications with:" -ForegroundColor Yellow
Write-Host $newSecret.SecretText -ForegroundColor Cyan

# After updating all applications, remove old secrets
$oldSecrets = Get-MgApplication -ApplicationId $app.Id |
    Select-Object -ExpandProperty PasswordCredentials |
    Where-Object { $_.EndDateTime -lt (Get-Date).AddDays(30) }

foreach ($oldSecret in $oldSecrets) {
    Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $oldSecret.KeyId
    Write-Host "Removed old secret: $($oldSecret.DisplayName)" -ForegroundColor Green
}
```

### 5. Monitoring and Auditing

```powershell
# Monitor sign-in logs
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Get sign-ins for your app
$signIns = Get-MgAuditLogSignIn -Filter "appId eq '$clientId'" -Top 50
$signIns | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, Status | Format-Table

# Check for failed sign-ins
$failures = $signIns | Where-Object { $_.Status.ErrorCode -ne 0 }
if ($failures) {
    Write-Host "⚠ Warning: Found $($failures.Count) failed sign-in attempts" -ForegroundColor Red
    $failures | Format-Table CreatedDateTime, UserPrincipalName, @{L="Error";E={$_.Status.FailureReason}}
}
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: "Insufficient privileges to complete the operation"

```powershell
# Check current permissions
$sp = Get-MgServicePrincipal -Filter "appId eq '$clientId'"
$assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id

Write-Host "Current permissions:" -ForegroundColor Cyan
foreach ($assignment in $assignments) {
    $resource = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId
    $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
    Write-Host "  - $($appRole.Value)" -ForegroundColor White
}

# Solution: Grant missing permissions
# (See "Granting Admin Consent" section)
```

#### Issue 2: Certificate not found

```powershell
# List all certificates in user store
Get-ChildItem Cert:\CurrentUser\My | Format-Table Thumbprint, Subject, NotAfter

# List all certificates in machine store
Get-ChildItem Cert:\LocalMachine\My | Format-Table Thumbprint, Subject, NotAfter

# Search for specific certificate
$thumbprint = "YOUR_THUMBPRINT"
$cert = Get-ChildItem Cert:\CurrentUser\My\$thumbprint -ErrorAction SilentlyContinue
if (-not $cert) {
    $cert = Get-ChildItem Cert:\LocalMachine\My\$thumbprint -ErrorAction SilentlyContinue
}

if ($cert) {
    Write-Host "Certificate found in: $($cert.PSParentPath)" -ForegroundColor Green
} else {
    Write-Host "Certificate not found. Import it first." -ForegroundColor Red
}

# Import certificate if needed
$pfxPath = "C:\Path\To\Certificate.pfx"
$certPassword = Read-Host "Enter certificate password" -AsSecureString
Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $certPassword
```

#### Issue 3: Token acquisition fails

```powershell
# Enable debug logging
$DebugPreference = "Continue"
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint -Debug

# Check Azure AD connectivity
Test-NetConnection login.microsoftonline.com -Port 443

# Verify certificate validity
$cert = Get-ChildItem Cert:\CurrentUser\My\$thumbprint
Write-Host "Certificate Details:" -ForegroundColor Cyan
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
Write-Host "  Valid From: $($cert.NotBefore)" -ForegroundColor White
Write-Host "  Valid Until: $($cert.NotAfter)" -ForegroundColor White
Write-Host "  Is Valid: $($cert.Verify())" -ForegroundColor $(if($cert.Verify()){"Green"}else{"Red"})
```

#### Issue 4: Permission propagation delay

```powershell
# After granting permissions, wait for propagation
Write-Host "Waiting for permission propagation..." -ForegroundColor Yellow

$maxAttempts = 10
$attempt = 0
$success = $false

while ($attempt -lt $maxAttempts -and -not $success) {
    $attempt++
    Write-Host "Attempt $attempt of $maxAttempts..." -ForegroundColor Cyan

    try {
        Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint
        $users = Get-MgUser -Top 1
        $success = $true
        Write-Host "✓ Connection successful!" -ForegroundColor Green
    } catch {
        Write-Host "✗ Connection failed: $($_.Exception.Message)" -ForegroundColor Red
        if ($attempt -lt $maxAttempts) {
            Start-Sleep -Seconds 30
        }
    }
}

if (-not $success) {
    Write-Host "Failed to connect after $maxAttempts attempts" -ForegroundColor Red
}
```

### Diagnostic Script

```powershell
<#
.SYNOPSIS
    Comprehensive diagnostic script for Microsoft Graph authentication
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint
)

Write-Host "=== Microsoft Graph Authentication Diagnostics ===" -ForegroundColor Cyan
Write-Host ""

# Check 1: PowerShell version
Write-Host "[1] PowerShell Version:" -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
Write-Host "  Version: $psVersion" -ForegroundColor White
if ($psVersion.Major -ge 7) {
    Write-Host "  ✓ PowerShell 7+ detected" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Consider upgrading to PowerShell 7+" -ForegroundColor Yellow
}

# Check 2: Required modules
Write-Host "`n[2] Required Modules:" -ForegroundColor Yellow
$requiredModules = @("Microsoft.Graph.Authentication", "Az.Accounts")
foreach ($module in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $module
    if ($installed) {
        Write-Host "  ✓ $module installed (v$($installed[0].Version))" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $module NOT installed" -ForegroundColor Red
    }
}

# Check 3: Network connectivity
Write-Host "`n[3] Network Connectivity:" -ForegroundColor Yellow
$endpoints = @(
    "login.microsoftonline.com",
    "graph.microsoft.com"
)
foreach ($endpoint in $endpoints) {
    $result = Test-NetConnection $endpoint -Port 443 -WarningAction SilentlyContinue
    if ($result.TcpTestSucceeded) {
        Write-Host "  ✓ $endpoint reachable" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $endpoint NOT reachable" -ForegroundColor Red
    }
}

# Check 4: Certificate (if provided)
if ($CertificateThumbprint) {
    Write-Host "`n[4] Certificate Check:" -ForegroundColor Yellow
    $cert = Get-ChildItem Cert:\CurrentUser\My\$CertificateThumbprint -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\LocalMachine\My\$CertificateThumbprint -ErrorAction SilentlyContinue
    }

    if ($cert) {
        Write-Host "  ✓ Certificate found" -ForegroundColor Green
        Write-Host "    Subject: $($cert.Subject)" -ForegroundColor White
        Write-Host "    Valid Until: $($cert.NotAfter)" -ForegroundColor White

        if ($cert.NotAfter -lt (Get-Date)) {
            Write-Host "  ✗ Certificate EXPIRED" -ForegroundColor Red
        } else {
            Write-Host "  ✓ Certificate valid" -ForegroundColor Green
        }

        if ($cert.Verify()) {
            Write-Host "  ✓ Certificate verification successful" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ Certificate verification failed" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ✗ Certificate NOT found" -ForegroundColor Red
    }
}

# Check 5: App registration
Write-Host "`n[5] App Registration Check:" -ForegroundColor Yellow
try {
    Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome
    $app = Get-MgApplication -Filter "appId eq '$ClientId'"

    if ($app) {
        Write-Host "  ✓ App registration found" -ForegroundColor Green
        Write-Host "    Display Name: $($app.DisplayName)" -ForegroundColor White
        Write-Host "    Object ID: $($app.Id)" -ForegroundColor White

        # Check permissions
        $perms = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq "00000003-0000-0000-c000-000000000000" }
        if ($perms) {
            Write-Host "  ✓ Graph API permissions configured" -ForegroundColor Green
            Write-Host "    Permission count: $($perms.ResourceAccess.Count)" -ForegroundColor White
        }
    } else {
        Write-Host "  ✗ App registration NOT found" -ForegroundColor Red
    }

    Disconnect-MgGraph
} catch {
    Write-Host "  ✗ Failed to check app registration: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Diagnostics Complete ===" -ForegroundColor Cyan
```

---

## Additional Resources

- [Microsoft Graph PowerShell SDK Documentation](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Microsoft Graph REST API Reference](https://learn.microsoft.com/en-us/graph/api/overview)
- [Azure PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/azure/)
- [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Certificate Credentials in Microsoft Identity Platform](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)
- [Managed Identities for Azure Resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/)

---

## License

See [LICENSE](LICENSE) file for details.
