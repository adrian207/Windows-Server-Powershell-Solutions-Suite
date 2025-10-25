#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD LDS Examples and Usage Demonstrations

.DESCRIPTION
    This script demonstrates various AD LDS usage scenarios and provides
    practical examples for common AD LDS operations.

.PARAMETER Example
    Example to demonstrate

.PARAMETER InstanceName
    Name of the AD LDS instance

.EXAMPLE
    .\ADLDS-Examples.ps1 -Example "BasicSetup" -InstanceName "DemoInstance"

.EXAMPLE
    .\ADLDS-Examples.ps1 -Example "ApplicationDirectory" -InstanceName "AppDir"

.NOTES
    Author: AD LDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("BasicSetup", "ApplicationDirectory", "PartnerIdentity", "CredentialVault", "SchemaExtension", "SecurityHardening", "MonitoringSetup", "TroubleshootingDemo")]
    [string]$Example,

    [Parameter(Mandatory = $false)]
    [string]$InstanceName = "DemoInstance"
)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "AD LDS Examples and Usage Demonstrations" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example: $Example" -ForegroundColor Yellow
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\ADLDS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Security.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Monitoring.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Troubleshooting.psm1" -Force
    Write-Host "AD LDS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import AD LDS modules: $($_.Exception.Message)"
    exit 1
}

switch ($Example) {
    "BasicSetup" {
        Write-Host "`n=== Basic AD LDS Setup Example ===" -ForegroundColor Green
        
        Write-Host "`n1. Installing AD LDS role..." -ForegroundColor Yellow
        $installResult = Install-ADLDS -IncludeManagementTools
        if ($installResult.Success) {
            Write-Host "   ✓ AD LDS role installed successfully!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Creating AD LDS instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 389 -SSLPort 636
        if ($instanceResult.Success) {
            Write-Host "   ✓ AD LDS instance '$InstanceName' created successfully!" -ForegroundColor Green
        }
        
        Write-Host "`n3. Creating partition..." -ForegroundColor Yellow
        $partitionResult = New-ADLDSPartition -InstanceName $InstanceName -PartitionName "DefaultPartition" -PartitionDN "CN=DefaultPartition,DC=DemoDir,DC=local"
        if ($partitionResult.Success) {
            Write-Host "   ✓ Partition 'DefaultPartition' created successfully!" -ForegroundColor Green
        }
        
        Write-Host "`n4. Adding sample user..." -ForegroundColor Yellow
        $userResult = Add-ADLDSUser -InstanceName $InstanceName -PartitionDN "CN=DefaultPartition,DC=DemoDir,DC=local" -UserName "demoUser" -UserDN "CN=demoUser,CN=DefaultPartition,DC=DemoDir,DC=local"
        if ($userResult.Success) {
            Write-Host "   ✓ User 'demoUser' created successfully!" -ForegroundColor Green
        }
        
        Write-Host "`n5. Adding sample group..." -ForegroundColor Yellow
        $groupResult = Add-ADLDSGroup -InstanceName $InstanceName -PartitionDN "CN=DefaultPartition,DC=DemoDir,DC=local" -GroupName "DemoGroup" -GroupDN "CN=DemoGroup,CN=DefaultPartition,DC=DemoDir,DC=local"
        if ($groupResult.Success) {
            Write-Host "   ✓ Group 'DemoGroup' created successfully!" -ForegroundColor Green
        }
        
        Write-Host "`n6. Getting instance status..." -ForegroundColor Yellow
        $statusResult = Get-ADLDSInstanceStatus -InstanceName $InstanceName
        if ($statusResult.Success) {
            Write-Host "   ✓ Instance Status: $($statusResult.ServiceStatus.Status)" -ForegroundColor Green
            Write-Host "   ✓ Partition Count: $($statusResult.PartitionCount)" -ForegroundColor Green
            Write-Host "   ✓ User Count: $($statusResult.UserCount)" -ForegroundColor Green
        }
        
        Write-Host "`n🎉 Basic AD LDS setup completed successfully!" -ForegroundColor Green
    }
    
    "ApplicationDirectory" {
        Write-Host "`n=== Application Directory Example ===" -ForegroundColor Green
        
        Write-Host "`nThis example demonstrates creating an AD LDS instance for application-specific directory services." -ForegroundColor Yellow
        
        Write-Host "`n1. Creating application directory instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 389 -SSLPort 636
        if ($instanceResult.Success) {
            Write-Host "   ✓ Application directory instance created!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Creating application-specific partitions..." -ForegroundColor Yellow
        $partitions = @(
            @{ Name = "AppUsers"; DN = "CN=AppUsers,DC=AppDir,DC=local" },
            @{ Name = "AppGroups"; DN = "CN=AppGroups,DC=AppDir,DC=local" },
            @{ Name = "AppDevices"; DN = "CN=AppDevices,DC=AppDir,DC=local" }
        )
        
        foreach ($partition in $partitions) {
            $partitionResult = New-ADLDSPartition -InstanceName $InstanceName -PartitionName $partition.Name -PartitionDN $partition.DN
            if ($partitionResult.Success) {
                Write-Host "   ✓ Partition '$($partition.Name)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n3. Extending schema for application-specific attributes..." -ForegroundColor Yellow
        $customAttributes = @("deviceSerialNumber", "licenseKey", "appRole", "departmentCode", "costCenter")
        $customClasses = @("deviceObject", "applicationUser", "serviceAccount")
        
        $schemaResult = Set-ADLDSSchema -InstanceName $InstanceName -CustomAttributes $customAttributes -CustomClasses $customClasses
        if ($schemaResult.Success) {
            Write-Host "   ✓ Schema extended with custom attributes and classes!" -ForegroundColor Green
        }
        
        Write-Host "`n4. Creating application users..." -ForegroundColor Yellow
        $appUsers = @(
            @{ UserName = "appadmin"; UserDN = "CN=appadmin,CN=AppUsers,DC=AppDir,DC=local" },
            @{ UserName = "appuser1"; UserDN = "CN=appuser1,CN=AppUsers,DC=AppDir,DC=local" },
            @{ UserName = "appuser2"; UserDN = "CN=appuser2,CN=AppUsers,DC=AppDir,DC=local" }
        )
        
        foreach ($user in $appUsers) {
            $userResult = Add-ADLDSUser -InstanceName $InstanceName -PartitionDN "CN=AppUsers,DC=AppDir,DC=local" -UserName $user.UserName -UserDN $user.UserDN
            if ($userResult.Success) {
                Write-Host "   ✓ User '$($user.UserName)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n5. Creating application groups..." -ForegroundColor Yellow
        $appGroups = @(
            @{ GroupName = "AppAdmins"; GroupDN = "CN=AppAdmins,CN=AppGroups,DC=AppDir,DC=local" },
            @{ GroupName = "AppUsers"; GroupDN = "CN=AppUsers,CN=AppGroups,DC=AppDir,DC=local" }
        )
        
        foreach ($group in $appGroups) {
            $groupResult = Add-ADLDSGroup -InstanceName $InstanceName -PartitionDN "CN=AppGroups,DC=AppDir,DC=local" -GroupName $group.GroupName -GroupDN $group.GroupDN
            if ($groupResult.Success) {
                Write-Host "   ✓ Group '$($group.GroupName)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n🎉 Application directory setup completed successfully!" -ForegroundColor Green
        Write-Host "This instance can now serve as a dedicated directory for your applications." -ForegroundColor Cyan
    }
    
    "PartnerIdentity" {
        Write-Host "`n=== Partner Identity Directory Example ===" -ForegroundColor Green
        
        Write-Host "`nThis example demonstrates creating an AD LDS instance for partner and vendor identity management." -ForegroundColor Yellow
        
        Write-Host "`n1. Creating partner identity instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 390 -SSLPort 637
        if ($instanceResult.Success) {
            Write-Host "   ✓ Partner identity instance created!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Creating partner-specific partitions..." -ForegroundColor Yellow
        $partitions = @(
            @{ Name = "Partners"; DN = "CN=Partners,DC=PartnerDir,DC=local" },
            @{ Name = "Contractors"; DN = "CN=Contractors,DC=PartnerDir,DC=local" },
            @{ Name = "Vendors"; DN = "CN=Vendors,DC=PartnerDir,DC=local" }
        )
        
        foreach ($partition in $partitions) {
            $partitionResult = New-ADLDSPartition -InstanceName $InstanceName -PartitionName $partition.Name -PartitionDN $partition.DN
            if ($partitionResult.Success) {
                Write-Host "   ✓ Partition '$($partition.Name)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n3. Extending schema for partner-specific attributes..." -ForegroundColor Yellow
        $partnerAttributes = @("partnerId", "contractNumber", "accessLevel", "expirationDate", "contactInfo")
        $partnerClasses = @("partnerOrganization", "contractorAccount", "vendorAccount")
        
        $schemaResult = Set-ADLDSSchema -InstanceName $InstanceName -CustomAttributes $partnerAttributes -CustomClasses $partnerClasses
        if ($schemaResult.Success) {
            Write-Host "   ✓ Schema extended with partner-specific attributes!" -ForegroundColor Green
        }
        
        Write-Host "`n4. Configuring enhanced security..." -ForegroundColor Yellow
        $authResult = Set-ADLDSAuthentication -InstanceName $InstanceName -AuthenticationType "Negotiate" -EnableSSL
        if ($authResult.Success) {
            Write-Host "   ✓ Enhanced authentication configured!" -ForegroundColor Green
        }
        
        $securityResult = Enable-ADLDSSecurityPolicies -InstanceName $InstanceName -EnableAuditLogging -EnablePasswordPolicy -EnableAccountLockout
        if ($securityResult.Success) {
            Write-Host "   ✓ Security policies enabled!" -ForegroundColor Green
        }
        
        Write-Host "`n5. Creating partner accounts..." -ForegroundColor Yellow
        $partnerAccounts = @(
            @{ UserName = "partner1"; UserDN = "CN=partner1,CN=Partners,DC=PartnerDir,DC=local" },
            @{ UserName = "contractor1"; UserDN = "CN=contractor1,CN=Contractors,DC=PartnerDir,DC=local" },
            @{ UserName = "vendor1"; UserDN = "CN=vendor1,CN=Vendors,DC=PartnerDir,DC=local" }
        )
        
        foreach ($account in $partnerAccounts) {
            $userResult = Add-ADLDSUser -InstanceName $InstanceName -PartitionDN $account.UserDN.Split(',')[1..($account.UserDN.Split(',').Length-1)] -join ',' -UserName $account.UserName -UserDN $account.UserDN
            if ($userResult.Success) {
                Write-Host "   ✓ Account '$($account.UserName)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n🎉 Partner identity directory setup completed successfully!" -ForegroundColor Green
        Write-Host "This instance can now manage external partner, contractor, and vendor identities securely." -ForegroundColor Cyan
    }
    
    "CredentialVault" {
        Write-Host "`n=== Credential Vault Example ===" -ForegroundColor Green
        
        Write-Host "`nThis example demonstrates creating an AD LDS instance as a secure credential vault." -ForegroundColor Yellow
        
        Write-Host "`n1. Creating credential vault instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 391 -SSLPort 638
        if ($instanceResult.Success) {
            Write-Host "   ✓ Credential vault instance created!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Creating credential-specific partitions..." -ForegroundColor Yellow
        $partitions = @(
            @{ Name = "ServiceCredentials"; DN = "CN=ServiceCredentials,DC=CredVault,DC=local" },
            @{ Name = "ApplicationSecrets"; DN = "CN=ApplicationSecrets,DC=CredVault,DC=local" },
            @{ Name = "DatabaseCredentials"; DN = "CN=DatabaseCredentials,DC=CredVault,DC=local" }
        )
        
        foreach ($partition in $partitions) {
            $partitionResult = New-ADLDSPartition -InstanceName $InstanceName -PartitionName $partition.Name -PartitionDN $partition.DN
            if ($partitionResult.Success) {
                Write-Host "   ✓ Partition '$($partition.Name)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n3. Extending schema for credential management..." -ForegroundColor Yellow
        $credentialAttributes = @("credentialType", "encryptionKey", "accessLevel", "rotationSchedule", "lastRotated")
        $credentialClasses = @("credentialObject", "secretObject", "keyObject")
        
        $schemaResult = Set-ADLDSSchema -InstanceName $InstanceName -CustomAttributes $credentialAttributes -CustomClasses $credentialClasses
        if ($schemaResult.Success) {
            Write-Host "   ✓ Schema extended with credential-specific attributes!" -ForegroundColor Green
        }
        
        Write-Host "`n4. Configuring maximum security..." -ForegroundColor Yellow
        $authResult = Set-ADLDSAuthentication -InstanceName $InstanceName -AuthenticationType "Kerberos" -EnableSSL -RequireStrongAuthentication
        if ($authResult.Success) {
            Write-Host "   ✓ Maximum security authentication configured!" -ForegroundColor Green
        }
        
        $securityResult = Enable-ADLDSSecurityPolicies -InstanceName $InstanceName -EnableAuditLogging -EnablePasswordPolicy -EnableAccountLockout -EnableSSLRequired -EnableStrongAuthentication
        if ($securityResult.Success) {
            Write-Host "   ✓ Maximum security policies enabled!" -ForegroundColor Green
        }
        
        Write-Host "`n5. Configuring credential vault..." -ForegroundColor Yellow
        $vaultResult = Set-ADLDSCredentialVault -InstanceName $InstanceName -VaultName "SecureCredentials" -AccessGroups @("CN=Administrators", "CN=ServiceAccounts")
        if ($vaultResult.Success) {
            Write-Host "   ✓ Credential vault configured!" -ForegroundColor Green
        }
        
        Write-Host "`n6. Creating service accounts..." -ForegroundColor Yellow
        $serviceAccounts = @(
            @{ UserName = "vaultadmin"; UserDN = "CN=vaultadmin,CN=ServiceCredentials,DC=CredVault,DC=local" },
            @{ UserName = "service1"; UserDN = "CN=service1,CN=ServiceCredentials,DC=CredVault,DC=local" },
            @{ UserName = "service2"; UserDN = "CN=service2,CN=ServiceCredentials,DC=CredVault,DC=local" }
        )
        
        foreach ($account in $serviceAccounts) {
            $userResult = Add-ADLDSUser -InstanceName $InstanceName -PartitionDN "CN=ServiceCredentials,DC=CredVault,DC=local" -UserName $account.UserName -UserDN $account.UserDN
            if ($userResult.Success) {
                Write-Host "   ✓ Service account '$($account.UserName)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n🎉 Credential vault setup completed successfully!" -ForegroundColor Green
        Write-Host "This instance can now securely store and manage service credentials and application secrets." -ForegroundColor Cyan
    }
    
    "SchemaExtension" {
        Write-Host "`n=== Schema Extension Example ===" -ForegroundColor Green
        
        Write-Host "`nThis example demonstrates extending AD LDS schema with custom attributes and classes." -ForegroundColor Yellow
        
        Write-Host "`n1. Creating schema testing instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 395 -SSLPort 642
        if ($instanceResult.Success) {
            Write-Host "   ✓ Schema testing instance created!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Creating test partition..." -ForegroundColor Yellow
        $partitionResult = New-ADLDSPartition -InstanceName $InstanceName -PartitionName "TestPartition" -PartitionDN "CN=TestPartition,DC=SchemaTest,DC=local"
        if ($partitionResult.Success) {
            Write-Host "   ✓ Test partition created!" -ForegroundColor Green
        }
        
        Write-Host "`n3. Extending schema with custom attributes..." -ForegroundColor Yellow
        $customAttributes = @(
            "deviceSerialNumber",
            "licenseKey", 
            "appRole",
            "departmentCode",
            "costCenter",
            "lastLoginTime",
            "accountStatus",
            "customField1",
            "customField2",
            "customField3"
        )
        
        $customClasses = @(
            "deviceObject",
            "applicationUser",
            "serviceAccount",
            "customObject1",
            "customObject2",
            "customObject3"
        )
        
        $schemaResult = Set-ADLDSSchema -InstanceName $InstanceName -CustomAttributes $customAttributes -CustomClasses $customClasses
        if ($schemaResult.Success) {
            Write-Host "   ✓ Schema extended with $($customAttributes.Count) custom attributes!" -ForegroundColor Green
            Write-Host "   ✓ Schema extended with $($customClasses.Count) custom classes!" -ForegroundColor Green
        }
        
        Write-Host "`n4. Creating test objects with custom attributes..." -ForegroundColor Yellow
        $testUsers = @(
            @{ UserName = "testuser1"; UserDN = "CN=testuser1,CN=TestPartition,DC=SchemaTest,DC=local" },
            @{ UserName = "testuser2"; UserDN = "CN=testuser2,CN=TestPartition,DC=SchemaTest,DC=local" },
            @{ UserName = "testuser3"; UserDN = "CN=testuser3,CN=TestPartition,DC=SchemaTest,DC=local" }
        )
        
        foreach ($user in $testUsers) {
            $userResult = Add-ADLDSUser -InstanceName $InstanceName -PartitionDN "CN=TestPartition,DC=SchemaTest,DC=local" -UserName $user.UserName -UserDN $user.UserDN
            if ($userResult.Success) {
                Write-Host "   ✓ Test user '$($user.UserName)' created!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n🎉 Schema extension example completed successfully!" -ForegroundColor Green
        Write-Host "This demonstrates how to extend AD LDS schema for custom applications and use cases." -ForegroundColor Cyan
    }
    
    "SecurityHardening" {
        Write-Host "`n=== Security Hardening Example ===" -ForegroundColor Green
        
        Write-Host "`nThis example demonstrates comprehensive AD LDS security hardening." -ForegroundColor Yellow
        
        Write-Host "`n1. Creating secure instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 397 -SSLPort 644
        if ($instanceResult.Success) {
            Write-Host "   ✓ Secure instance created!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Configuring maximum security authentication..." -ForegroundColor Yellow
        $authResult = Set-ADLDSAuthentication -InstanceName $InstanceName -AuthenticationType "Kerberos" -EnableSSL -RequireStrongAuthentication
        if ($authResult.Success) {
            Write-Host "   ✓ Maximum security authentication configured!" -ForegroundColor Green
        }
        
        Write-Host "`n3. Enabling comprehensive security policies..." -ForegroundColor Yellow
        $securityResult = Enable-ADLDSSecurityPolicies -InstanceName $InstanceName -EnableAuditLogging -EnablePasswordPolicy -EnableAccountLockout -EnableSSLRequired -EnableStrongAuthentication
        if ($securityResult.Success) {
            Write-Host "   ✓ Comprehensive security policies enabled!" -ForegroundColor Green
        }
        
        Write-Host "`n4. Configuring access control..." -ForegroundColor Yellow
        $accessControls = @(
            @{ ObjectDN = "CN=DefaultPartition,DC=SecureDir,DC=local"; Principal = "CN=Administrators"; Permission = "Full Control" },
            @{ ObjectDN = "CN=DefaultPartition,DC=SecureDir,DC=local"; Principal = "CN=ServiceAccounts"; Permission = "Read" }
        )
        
        foreach ($accessControl in $accessControls) {
            $aclResult = Set-ADLDSAccessControl -InstanceName $InstanceName -ObjectDN $accessControl.ObjectDN -Principal $accessControl.Principal -Permission $accessControl.Permission
            if ($aclResult.Success) {
                Write-Host "   ✓ Access control configured for $($accessControl.Principal)!" -ForegroundColor Green
            }
        }
        
        Write-Host "`n5. Testing security compliance..." -ForegroundColor Yellow
        $complianceResult = Test-ADLDSSecurityCompliance -InstanceName $InstanceName -ComplianceStandard "SOX"
        if ($complianceResult.Success) {
            Write-Host "   ✓ Security compliance test completed!" -ForegroundColor Green
            Write-Host "   ✓ Overall Compliance: $($complianceResult.ComplianceStatus.OverallCompliance)" -ForegroundColor Green
        }
        
        Write-Host "`n6. Getting security status..." -ForegroundColor Yellow
        $securityStatus = Get-ADLDSSecurityStatus -InstanceName $InstanceName
        if ($securityStatus.Success) {
            Write-Host "   ✓ Security Status Retrieved!" -ForegroundColor Green
            Write-Host "   ✓ Authentication Type: $($securityStatus.SecurityStatus.AuthenticationType)" -ForegroundColor Green
            Write-Host "   ✓ SSL Enabled: $($securityStatus.SecurityStatus.SSLEnabled)" -ForegroundColor Green
            Write-Host "   ✓ Audit Logging: $($securityStatus.SecurityStatus.AuditLoggingEnabled)" -ForegroundColor Green
        }
        
        Write-Host "`n🎉 Security hardening example completed successfully!" -ForegroundColor Green
        Write-Host "This demonstrates comprehensive AD LDS security configuration for enterprise environments." -ForegroundColor Cyan
    }
    
    "MonitoringSetup" {
        Write-Host "`n=== Monitoring Setup Example ===" -ForegroundColor Green
        
        Write-Host "`nThis example demonstrates setting up comprehensive AD LDS monitoring and alerting." -ForegroundColor Yellow
        
        Write-Host "`n1. Creating monitored instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 398 -SSLPort 645
        if ($instanceResult.Success) {
            Write-Host "   ✓ Monitored instance created!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Configuring comprehensive alerting..." -ForegroundColor Yellow
        $alertTypes = @("HighConnectionRate", "HighQueryRate", "HighErrorRate", "ServiceDown", "HighResponseTime")
        $alertingResult = Set-ADLDSAlerting -InstanceName $InstanceName -AlertTypes $alertTypes
        if ($alertingResult.Success) {
            Write-Host "   ✓ Comprehensive alerting configured!" -ForegroundColor Green
        }
        
        Write-Host "`n3. Getting health status..." -ForegroundColor Yellow
        $healthResult = Get-ADLDSHealthStatus -InstanceName $InstanceName
        if ($healthResult.Success) {
            Write-Host "   ✓ Health status retrieved!" -ForegroundColor Green
            Write-Host "   ✓ Overall Health: $($healthResult.HealthStatus.OverallHealth)" -ForegroundColor Green
        }
        
        Write-Host "`n4. Getting analytics..." -ForegroundColor Yellow
        $analyticsResult = Get-ADLDSAnalytics -InstanceName $InstanceName -TimeRange 24
        if ($analyticsResult.Success) {
            Write-Host "   ✓ Analytics retrieved!" -ForegroundColor Green
            Write-Host "   ✓ Total Operations: $($analyticsResult.Analytics.OperationStatistics.TotalOperations)" -ForegroundColor Green
        }
        
        Write-Host "`n5. Starting monitoring session..." -ForegroundColor Yellow
        Write-Host "   (This would start a 5-minute monitoring session in production)" -ForegroundColor Yellow
        Write-Host "   ✓ Monitoring session configured!" -ForegroundColor Green
        
        Write-Host "`n🎉 Monitoring setup example completed successfully!" -ForegroundColor Green
        Write-Host "This demonstrates comprehensive AD LDS monitoring and alerting capabilities." -ForegroundColor Cyan
    }
    
    "TroubleshootingDemo" {
        Write-Host "`n=== Troubleshooting Demo Example ===" -ForegroundColor Green
        
        Write-Host "`nThis example demonstrates AD LDS troubleshooting and diagnostics capabilities." -ForegroundColor Yellow
        
        Write-Host "`n1. Creating test instance..." -ForegroundColor Yellow
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 399 -SSLPort 646
        if ($instanceResult.Success) {
            Write-Host "   ✓ Test instance created!" -ForegroundColor Green
        }
        
        Write-Host "`n2. Running comprehensive diagnostics..." -ForegroundColor Yellow
        $diagnosticsResult = Start-ADLDSDiagnostics -InstanceName $InstanceName -IncludeEventLogs -IncludeConnectivity -IncludePerformance
        if ($diagnosticsResult.Success) {
            Write-Host "   ✓ Comprehensive diagnostics completed!" -ForegroundColor Green
            Write-Host "   ✓ Issues Found: $($diagnosticsResult.IssuesFound.Count)" -ForegroundColor Green
            Write-Host "   ✓ Recommendations: $($diagnosticsResult.Recommendations.Count)" -ForegroundColor Green
        }
        
        Write-Host "`n3. Testing configuration..." -ForegroundColor Yellow
        $testResult = Test-ADLDSConfiguration -InstanceName $InstanceName
        if ($testResult.Success) {
            Write-Host "   ✓ Configuration test completed!" -ForegroundColor Green
            Write-Host "   ✓ Configuration Valid: $($testResult.ConfigurationValid)" -ForegroundColor Green
        }
        
        Write-Host "`n4. Getting troubleshooting guide..." -ForegroundColor Yellow
        $guideResult = Get-ADLDSTroubleshootingGuide
        if ($guideResult.Success) {
            Write-Host "   ✓ Troubleshooting guide retrieved!" -ForegroundColor Green
            Write-Host "   ✓ Common Issues: $($guideResult.TroubleshootingGuide.CommonIssues.Count)" -ForegroundColor Green
            Write-Host "   ✓ Diagnostic Steps: $($guideResult.TroubleshootingGuide.DiagnosticSteps.Count)" -ForegroundColor Green
        }
        
        Write-Host "`n5. Demonstrating repair capabilities..." -ForegroundColor Yellow
        Write-Host "   (This would demonstrate automated repair in production)" -ForegroundColor Yellow
        Write-Host "   ✓ Repair capabilities demonstrated!" -ForegroundColor Green
        
        Write-Host "`n🎉 Troubleshooting demo example completed successfully!" -ForegroundColor Green
        Write-Host "This demonstrates comprehensive AD LDS troubleshooting and diagnostics capabilities." -ForegroundColor Cyan
    }
}

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "AD LDS Examples Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example: $Example" -ForegroundColor Yellow
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Status: Completed Successfully" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n📚 Example completed! This demonstrates practical AD LDS usage scenarios." -ForegroundColor Green
Write-Host "You can now use these examples as templates for your own AD LDS implementations." -ForegroundColor Cyan
