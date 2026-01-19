# graph-api-lab-01

# Lab goals
Use the Microsoft PowerShell Graph SDK and Az module to:
1. Explore how to connect to the Graph API using a client secret, a certificate, and a managed identity in an automation account.
2. Create required objects in Azure such as an app registration, managed identity, and an Automation Account runbook.


# Part 1 - Install PowerShell modules
Before continuing make sure the `Microsoft.Graph` and `Az` modules are installed.

1. Run `Get-Module -ListAvailable Microsoft.Graph*`
2. If no recent Graph modules are listed, run `Install-Module Microsoft.Graph -Repository PSGallery -Scope CurrentUser`

3. Run `get-module -ListAvailable Az*`
4. If no recent Az modules are listed, run `Install-Module Az -Repository PSGallery -Scope CurrentUser`

# Part 2 - Create a new app registration and assign API permissions
In order to connect to the Graph API as an application, we must first register an application in Entra and assign required API permissions. For this exercise, we will do this graphically in the portal.

### Create a new app registration

1. Log into the Azure portal with an account that has access to create a new app registration and navigate to the `App registrations` section.
<img width="477" height="279" alt="image" src="https://github.com/user-attachments/assets/c89f2160-371a-4a07-a1ec-d2ee6227ab85" />
<br />
<br />

3. Create a new app registration with the name `graph-api-lab-01`.
<img width="939" height="833" alt="image" src="https://github.com/user-attachments/assets/83683b1c-985c-46ee-8d78-12bb12b1085e" />
<br />
<br />

4. Now take note of the `Application (client) ID` and the `Directory (tenant) ID` from the overview section.
<img width="758" height="369" alt="image" src="https://github.com/user-attachments/assets/0b953841-91aa-40e2-87c0-81a36f511af9" />
<br />
<br />

### Assign API permissions

1. Select the `API permissions` section, and then click on `Add a permission`.  Note that you need a `Global Administrator` or `Privileged Role Administrator` role assignment to configure app-level API permissions for Microsoft Graph.
<img width="747" height="675" alt="image" src="https://github.com/user-attachments/assets/c9c78bfd-2595-4fbc-926e-f3f271b24985" />
<br />
<br />

2. Select Microsoft Graph.
<img width="820" height="358" alt="image" src="https://github.com/user-attachments/assets/b2697e26-410b-48e8-ab59-b70a9bfe83fa" />
<br />
<br />

3. Select `Application permissions`.
<img width="523" height="369" alt="image" src="https://github.com/user-attachments/assets/29356e60-63a5-40b3-a394-d5a398a0755f" />
<br />
<br />

4. Type in `user.read.all`, select the corresponding api permission, and then click on `Add permissions`.
<img width="355" height="372" alt="image" src="https://github.com/user-attachments/assets/ae322e99-d8d4-4b8a-929e-95dfaf22ee95" />
<br />
<br />

5. Click on `Grant admin consent for <YourTenantName>` and select `Yes` when prompted.
<img width="1029" height="267" alt="image" src="https://github.com/user-attachments/assets/8f649d97-73e2-491a-a24b-fb6f172b131a" />
<img width="753" height="133" alt="image" src="https://github.com/user-attachments/assets/0f85da13-6d09-4961-8423-df9eb5aec819" />
<br />
<br />

6. The permission will now show as granted.
<img width="1015" height="266" alt="image" src="https://github.com/user-attachments/assets/1ede006e-0d7e-49f4-8069-18af2618a839" />
<br />
<br />

# Part 3 - Create a client secret and retrieve user information
1. Select the `Certificates and Secrets` section, then select `Client secrets` and click on `New client secret`.
<img width="724" height="547" alt="image" src="https://github.com/user-attachments/assets/22efa8f7-1889-4600-88a3-91c3b72b3716" />
<br />
<br />

2. Name the secret `Secret` and use the default expiration setting.
<img width="891" height="341" alt="image" src="https://github.com/user-attachments/assets/376d10e5-3484-412a-a5be-8e5ab910ea15" />
<br />
<br />

3. The secret will now be visible in the portal.  Take note of this and store it safely.
<img width="995" height="232" alt="image" src="https://github.com/user-attachments/assets/0d0aed86-459b-4777-9dfa-369d345bf47c" />
<br />
<br />

4. In your PowerShell session edit and run the following to connect to your tenant with the new app registration and the new client secret.  You should see a message that says `Welcome to Microsoft Graph!` along with some output relating to your session and documentation links.
```
$clientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

$secureSecret = Read-Host "Enter client secret" -AsSecureString
$cred = [pscredential]::new($clientId, $secureSecret)

Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $cred
```

5. Retrieve information for a random user by running the following. You should see user details output in the console.
```
Get-MgUser -Top 50 | Get-Random | Select DisplayName, UserPrincipalName
```
6. Disconnect your session by running `Disconnect-MgGraph`.

# Part 4 - Configure a certificate and retrieve user information
## Option 1 - Self-signed certificate

1. Run the following command to generage a new self-signed certificate.
```
$cert = New-SelfSignedCertificate `
  -Subject "CN=graph-api-lab-01" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -KeyExportPolicy Exportable `
  -NotAfter (Get-Date).AddYears(2)

```

2. Confirm the certificate was created by running `Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -like "*graph-api-lab-01*"`.

3. Run the following to export the public cert.  We will upload this to the new app registration later.
`Export-Certificate -Cert $cert -FilePath "C:\temp\graph-api-lab-01.cer"`

4. Navigate to the certificates and secrets section select `Upload certificate`.
<img width="738" height="679" alt="image" src="https://github.com/user-attachments/assets/81d85681-dcc2-4867-a850-b76539ab11a9" />
<br />
<br />

5. Browse to `C:\temp` and add the new certificate.
<img width="600" height="189" alt="image" src="https://github.com/user-attachments/assets/890e03a0-0f8d-4676-89af-90a1b8f3cbf1" />
<img width="605" height="192" alt="image" src="https://github.com/user-attachments/assets/923fcdbd-1517-49c4-8ebc-76e119265a08" />
<img width="584" height="267" alt="image" src="https://github.com/user-attachments/assets/637bc366-fcb4-4f2e-8e8a-8a75e47f1d01" />
<br />
<br />

6. The certificate should now be visible.
<img width="1021" height="218" alt="image" src="https://github.com/user-attachments/assets/ce3e62cd-dceb-4285-ba4a-9d0f08b1791c" />
<br />
<br />

7. Using the thumbprint of the certificate, run the following to connect to Graph.
```
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$clientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$thumbprint = "ABC123"

Connect-MgGraph `
  -TenantId $tenantId `
  -ClientId $clientId `
  -CertificateThumbprint $thumbprint `
  -NoWelcome

```

5. Retrieve information for a random user by running the following `Get-MgUser -Top 50 | Get-Random | Select DisplayName, UserPrincipalName`.
6. You should see user details output in the console.  Once confirmed disconnect your session by running `Disconnect-MgGraph`.

## Option 2 - Create a certificate using internal PKI (Windows Certificate Services shown here)
Note that this is a rough guide only for demonstration purposes.  The exact steps will depend on the certificate templates available and the certificate services configuration specific to your environment.

1. Use windows button+r, type `mmc`.
<img width="393" height="200" alt="image" src="https://github.com/user-attachments/assets/4e199fd5-6ecc-4f47-9ff2-21444b95d2bf" />
<br />
<br />

2. Add a new snap-in.
<img width="378" height="354" alt="image" src="https://github.com/user-attachments/assets/ab0ec5da-a738-4e33-80cf-fff151ccfe9b" />
<br />
<br />

3. Select `Certificates` and click on `Add`.
<img width="531" height="356" alt="image" src="https://github.com/user-attachments/assets/e8359ea1-2aa1-417c-9ca1-b57f4a3d567b" />
<img width="664" height="470" alt="image" src="https://github.com/user-attachments/assets/3fedf5d6-8dcd-4c1f-bfef-56f377bb0c42" />
<br />
<br />

4.  Create a custom request.
<img width="840" height="412" alt="image" src="https://github.com/user-attachments/assets/a8ed4cab-107f-448a-91f3-1990a4785793" />
<br />
<br />

5. Proceed without an enrollment policy.
<img width="624" height="457" alt="image" src="https://github.com/user-attachments/assets/dbf12f81-6505-41f2-b051-87980af655bc" />
<br />
<br />

6. Defaults are fine for this example.
<img width="619" height="456" alt="image" src="https://github.com/user-attachments/assets/9592b770-9d46-4aef-b2d6-95892e6edc6b" />
<br />
<br />

7. Select the details drop down and then click on `Properties`.
<img width="622" height="304" alt="image" src="https://github.com/user-attachments/assets/e3bda1cd-99af-494d-a599-9cbb87200927" />
<br />
<br />

8. Configure a friendly name.
<img width="489" height="191" alt="image" src="https://github.com/user-attachments/assets/e53c3c04-2744-46bb-bf1d-9be0fadd1cba" />
<br />
<br />

9. Add some details like Common Name, Country, Locality as required.
<img width="492" height="466" alt="image" src="https://github.com/user-attachments/assets/39ecbec8-4235-4967-ac7c-cca54df9a131" />
<br />
<br />

10. Add `Digital signature` and `Key encipherment` for the Key usage.
<img width="468" height="345" alt="image" src="https://github.com/user-attachments/assets/07c92760-8ce7-4f98-8c30-f7f3c5b089e3" />
<br />
<br />

11. Add `Client Authentication` and `Server Authentication` in the Extended Key Usage section.
<img width="476" height="446" alt="image" src="https://github.com/user-attachments/assets/9354e4a9-78bf-41db-b1d7-d9a436a1250c" />
<br />
<br />

12. Set the following for the Private Key settings.
<img width="493" height="267" alt="image" src="https://github.com/user-attachments/assets/c713b507-7162-4864-b674-f6cbe6bcb528" />
<br />
<br />

13. Go back through all the settings and confirm they look ok.  Once done click `OK`.
<img width="489" height="494" alt="image" src="https://github.com/user-attachments/assets/d4d85d80-efe4-4dde-bee4-8bb652fca531" />
<br />
<br />

14. Now click on `Next`.
<img width="620" height="445" alt="image" src="https://github.com/user-attachments/assets/58b48b0d-6886-4a7c-b362-d03594bea171" />
<br />
<br />

15.  Select a location for the offline request and click on `Finish`.
<img width="620" height="453" alt="image" src="https://github.com/user-attachments/assets/b78cb4c2-6a86-4a9d-b9d3-2a4bb10f75dc" />

<br />
<br />

16. Using an account that has access to enroll for certificates with a suitable certificate template, run the following.
```
Certreq -attrib "CertificateTemplate:YourCertificateTemplate" -submit  "C:\temp\graph-api-lab-01-internal-pki.req"
```

17. You should be prompted to save the certificate issued by the pki server.  From there import this back into your certificates store on the machine you created the request on.
<img width="570" height="299" alt="image" src="https://github.com/user-attachments/assets/a8d31f4f-9d52-4386-a7d4-de1c85502005" />

18. Follow the same steps in `Option 1 - Self-signed certificate` earlier to upload and connect with the certificate thumbprint.

# Part 5 - Create an automation account with a system-assigned managed identity
An automation account allows us to create PowerShell runbooks, which can be executed in the context of a system-assigned managed identity.  Managed identities are a secure approach within Entra as they do not require rotation of a secret or certificate.  Note that in order to complete these instructions you will need to authenticate with an account that has access to create resources in Azure and to assign API permissions to the Graph API.

1. Connect to your subscription using the Az module. 
```
Connect-AzAccount
Set-AzContext -Subscription "your-subscription-name"
```
2. Edit the snippet below as required, and run it to create the new automation account. This will also create the system-assigned managed identity.
```
# Variables
$resourceGroup = "rg-graph-api-lab-01"
$location = "australiaeast"
$automationAccount = "aa-graph-api-lab-01"

# Create resources
New-AzResourceGroup -Name $resourceGroup -Location $location

New-AzAutomationAccount `
    -ResourceGroupName $resourceGroup `
    -Name $automationAccount `
    -Location $location `
    -Plan Basic `
    -AssignSystemIdentity
```
3. Grant API permissions to the system-assigned managed identity.  Earlier we granted API permissions graphically, but for this exercise we will use the Az module.
```
$identity = (Get-AzAutomationAccount -ResourceGroupName $resourceGroup -Name $automationAccount).Identity.PrincipalId
Write-Host "Managed Identity Object ID: $identity"

Connect-MgGraph
# Assign User.Read.All permission to the managed identity
$appRoleId = "df021288-bdef-4463-88db-98f22de89214" # User.Read.All
$resourceId = (Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'").Id

New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $identity `
    -PrincipalId $identity `
    -AppRoleId $appRoleId `
    -ResourceId $resourceId

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
```

4. Run the code below to create a new runbook that uses the managed identity to connect to the Graph API.
```
# Create the runbook script content
$runbookContent = @'
# Connect to Microsoft Graph using managed identity
Connect-MgGraph -Identity

# Get users
$users = Get-MgUser -Top 10 -Property DisplayName, UserPrincipalName, Id

# Output results
foreach ($user in $users) {
    Write-Output "Name: $($user.DisplayName), UPN: $($user.UserPrincipalName)"
}

Disconnect-MgGraph
'@

# Save to temporary file
$tempFile = "$env:TEMP\Get-EntraUsers.ps1"
$runbookContent | Out-File -FilePath $tempFile -Encoding UTF8

# Import the runbook with content
Import-AzAutomationRunbook `
    -ResourceGroupName $resourceGroup `
    -AutomationAccountName $automationAccount `
    -Name "Get-EntraUsers" `
    -Type PowerShell `
    -Path $tempFile `
    -Published

# Clean up temp file
Remove-Item $tempFile
```

5. Create a new job to execute the runbook.
```
$job = Start-AzAutomationRunbook `
    -ResourceGroupName $resourceGroup `
    -AutomationAccountName $automationAccount `
    -Name "Get-EntraUsers"

# Display the job ID
Write-Host "Job ID: $($job.JobId)"
```

6. Wait a minute or so and run the following. If the job is not yet completed, wait another minute or so and run this again.
```
Get-AzAutomationJob `
    -ResourceGroupName $resourceGroup `
    -AutomationAccountName $automationAccount `
    -Id $job.JobId | Select-Object Status, StartTime, EndTime
```
7. View the output of the job.  You should see user data.
```
Get-AzAutomationJobOutput `
    -ResourceGroupName $resourceGroup `
    -AutomationAccountName $automationAccount `
    -Id $job.JobId `
    -Stream Output | Get-AzAutomationJobOutputRecord | Select-Object -ExpandProperty Value
```

# Review

In this lab we created an app registration, assigned it Graph API permissions, and then used it to connect to Entra with a client secret and a certificate.  We also created an automation account with a system-assigned managed identity, assigned the managed identity Graph API permissions, and deployed a new runbook that executes in the context of the managed identity to extract user data.

















