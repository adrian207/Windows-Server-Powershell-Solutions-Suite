#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure Host Guardian Service (HGS)

.DESCRIPTION
    Comprehensive configuration management script for HGS including:
    - Attestation mode configuration
    - Certificate management
    - Host group management
    - Policy configuration
    - Security baseline application

.PARAMETER HgsServer
    HGS server name

.PARAMETER ConfigurationFile
    Path to JSON configuration file

.PARAMETER AttestationMode
    Attestation mode (TPM or Admin)

.PARAMETER SecurityLevel
    Security level (Low, Medium, High, Critical)

.PARAMETER CertificateThumbprint
    Certificate thumbprint for key protection

.PARAMETER HostGroups
    Array of host groups to configure

.PARAMETER Policies
    Array of policies to configure

.PARAMETER BackupPath
    Path to backup current configuration

.PARAMETER Force
    Force configuration without confirmation

.EXAMPLE
    .\Configure-HGS.ps1 -HgsServer "HGS01" -AttestationMode "TPM" -SecurityLevel "High"

.EXAMPLE
    .\Configure-HGS.ps1 -ConfigurationFile "C:\Config\HGS-Config.json" -Force

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HgsServer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet("TPM", "Admin")]
    [string]$AttestationMode,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$SecurityLevel = "High",

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [array]$HostGroups = @(),

    [Parameter(Mandatory = $false)]
    [array]$Policies = @(),

    [Parameter(Mandatory = $false)]
    [string]$BackupPath = "C:\HGS-Backup",

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Import required modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ModulePath\..\..\Modules\HGS-Core.psm1" -Force
Import-Module "$ModulePath\..\..\Modules\HGS-Security.psm1" -Force

# Global variables
$script:ConfigurationLog = @()
$script:ConfigurationStartTime = Get-Date
$script:ConfigurationData = @{}

function Write-ConfigurationLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
    
    $script:ConfigurationLog += $logEntry
    
    $color = switch ($Level) {
        "Info" { "White" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Backup-HGSConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    Write-ConfigurationLog "Creating configuration backup..." "Info"
    
    try {
        if (!(Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force
        }
        
        $backupFile = "$BackupPath\HGS-Config-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
        
        # Export HGS configuration
        Export-HgsServerConfiguration -Path $backupFile
        
        Write-ConfigurationLog "Configuration backed up to: $backupFile" "Success"
        return $backupFile
    }
    catch {
        Write-ConfigurationLog "Failed to create backup: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSBasicConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ConfigurationLog "Configuring basic HGS settings..." "Info"
    
    try {
        # Configure attestation mode
        if ($Config.AttestationMode) {
            Set-HGSAttestationMode -Mode $Config.AttestationMode -HgsServer $Config.HgsServer
            Write-ConfigurationLog "Attestation mode set to: $($Config.AttestationMode)" "Success"
        }
        
        # Configure certificate
        if ($Config.CertificateThumbprint) {
            Set-HgsKeyProtectionCertificate -Thumbprint $Config.CertificateThumbprint
            Write-ConfigurationLog "Certificate configured: $($Config.CertificateThumbprint)" "Success"
        }
        
        # Configure security level
        if ($Config.SecurityLevel) {
            Set-HGSSecurityBaseline -BaselineName "HGS-Configuration" -ComplianceStandard "Custom" -SecurityLevel $Config.SecurityLevel
            Write-ConfigurationLog "Security level set to: $($Config.SecurityLevel)" "Success"
        }
        
        return $true
    }
    catch {
        Write-ConfigurationLog "Failed to configure basic settings: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSHostGroups {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ConfigurationLog "Configuring HGS host groups..." "Info"
    
    try {
        if ($Config.HostGroups.Count -gt 0) {
            foreach ($hostGroup in $Config.HostGroups) {
                if ($hostGroup.Action -eq "Add") {
                    Add-HGSHost -HostName $hostGroup.Name -AttestationMode $hostGroup.AttestationMode -HgsServer $Config.HgsServer
                    Write-ConfigurationLog "Added host group: $($hostGroup.Name)" "Success"
                }
                elseif ($hostGroup.Action -eq "Remove") {
                    Remove-HGSHost -HostName $hostGroup.Name -HgsServer $Config.HgsServer
                    Write-ConfigurationLog "Removed host group: $($hostGroup.Name)" "Success"
                }
                elseif ($hostGroup.Action -eq "Update") {
                    Remove-HGSHost -HostName $hostGroup.Name -HgsServer $Config.HgsServer
                    Add-HGSHost -HostName $hostGroup.Name -AttestationMode $hostGroup.AttestationMode -HgsServer $Config.HgsServer
                    Write-ConfigurationLog "Updated host group: $($hostGroup.Name)" "Success"
                }
            }
        }
        
        return $true
    }
    catch {
        Write-ConfigurationLog "Failed to configure host groups: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSPolicies {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ConfigurationLog "Configuring HGS policies..." "Info"
    
    try {
        if ($Config.Policies.Count -gt 0) {
            foreach ($policy in $Config.Policies) {
                switch ($policy.Type) {
                    "Attestation" {
                        Set-HGSAttestationPolicy -PolicyName $policy.Name -PolicyType $policy.PolicyType -SecurityLevel $policy.SecurityLevel
                        Write-ConfigurationLog "Configured attestation policy: $($policy.Name)" "Success"
                    }
                    "TrustBoundary" {
                        Set-HGSTrustBoundary -BoundaryName $policy.Name -BoundaryType $policy.BoundaryType -IsolationLevel $policy.IsolationLevel
                        Write-ConfigurationLog "Configured trust boundary: $($policy.Name)" "Success"
                    }
                    "ZeroTrust" {
                        Set-HGSZeroTrust -TrustModel $policy.TrustModel -VerificationLevel $policy.VerificationLevel -PolicyEnforcement $policy.PolicyEnforcement
                        Write-ConfigurationLog "Configured Zero Trust policy" "Success"
                    }
                    "MultiTenant" {
                        Set-HGSMultiTenantSecurity -TenantName $policy.Name -IsolationLevel $policy.IsolationLevel -ResourceQuotas $policy.ResourceQuotas
                        Write-ConfigurationLog "Configured multi-tenant policy: $($policy.Name)" "Success"
                    }
                    "AirGapped" {
                        Set-HGSAirGappedSecurity -NetworkIsolation $policy.NetworkIsolation -OfflineMode:$policy.OfflineMode -LocalAttestation:$policy.LocalAttestation
                        Write-ConfigurationLog "Configured air-gapped policy" "Success"
                    }
                }
            }
        }
        
        return $true
    }
    catch {
        Write-ConfigurationLog "Failed to configure policies: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ConfigurationLog "Configuring HGS certificates..." "Info"
    
    try {
        if ($Config.Certificates.Count -gt 0) {
            foreach ($cert in $Config.Certificates) {
                Set-HGSCertificateManagement -CertificateType $cert.Type -Action $cert.Action -CertificatePath $cert.Path -Thumbprint $cert.Thumbprint
                Write-ConfigurationLog "Configured certificate: $($cert.Type)" "Success"
            }
        }
        
        return $true
    }
    catch {
        Write-ConfigurationLog "Failed to configure certificates: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSAdvancedConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ConfigurationLog "Configuring advanced HGS settings..." "Info"
    
    try {
        # Configure cluster attestation if enabled
        if ($Config.ClusterAttestation.Enabled) {
            Set-HGSClusterAttestation -ClusterName $Config.ClusterAttestation.ClusterName -ClusterNodes $Config.ClusterAttestation.Nodes -HgsServer $Config.HgsServer
            Write-ConfigurationLog "Cluster attestation configured" "Success"
        }
        
        # Configure disaster recovery if enabled
        if ($Config.DisasterRecovery.Enabled) {
            Set-HGSDisasterRecovery -PrimaryHgsServer $Config.HgsServer -SecondaryHgsServer $Config.DisasterRecovery.SecondaryServer -ReplicationMode $Config.DisasterRecovery.ReplicationMode
            Write-ConfigurationLog "Disaster recovery configured" "Success"
        }
        
        # Configure hybrid cloud if enabled
        if ($Config.HybridCloud.Enabled) {
            Set-HGSHybridCloud -AzureStackEndpoint $Config.HybridCloud.AzureStackEndpoint -OnPremisesHgsServer $Config.HgsServer -TrustMode $Config.HybridCloud.TrustMode
            Write-ConfigurationLog "Hybrid cloud configured" "Success"
        }
        
        # Configure offline deployment if enabled
        if ($Config.OfflineDeployment.Enabled) {
            Set-HGSOfflineDeployment -TemplatePath $Config.OfflineDeployment.TemplatePath -AttestationPolicy $Config.OfflineDeployment.AttestationPolicy -HgsServer $Config.HgsServer
            Write-ConfigurationLog "Offline deployment configured" "Success"
        }
        
        # Configure rogue host detection if enabled
        if ($Config.RogueHostDetection.Enabled) {
            Set-HGSRogueHostDetection -DetectionThreshold $Config.RogueHostDetection.Threshold -RevocationAction $Config.RogueHostDetection.Action -HgsServer $Config.HgsServer
            Write-ConfigurationLog "Rogue host detection configured" "Success"
        }
        
        # Configure forensic integrity if enabled
        if ($Config.ForensicIntegrity.Enabled) {
            Set-HGSForensicIntegrity -BaselinePath $Config.ForensicIntegrity.BaselinePath -VerificationInterval $Config.ForensicIntegrity.Interval -HgsServer $Config.HgsServer
            Write-ConfigurationLog "Forensic integrity configured" "Success"
        }
        
        # Configure PAW hosting if enabled
        if ($Config.PAWHosting.Enabled) {
            Set-HGSPAWHosting -PAWTemplatePath $Config.PAWHosting.TemplatePath -SecurityPolicy $Config.PAWHosting.SecurityPolicy -HgsServer $Config.HgsServer
            Write-ConfigurationLog "PAW hosting configured" "Success"
        }
        
        # Configure cross-forest if enabled
        if ($Config.CrossForest.Enabled) {
            Set-HGSCrossForest -ForestName $Config.CrossForest.ForestName -TrustCertificate $Config.CrossForest.TrustCertificate -HgsServer $Config.HgsServer
            Write-ConfigurationLog "Cross-forest configured" "Success"
        }
        
        # Configure secure build pipelines if enabled
        if ($Config.SecureBuildPipelines.Enabled) {
            Set-HGSSecureBuildPipelines -BuildServerName $Config.SecureBuildPipelines.BuildServerName -SigningKeyPath $Config.SecureBuildPipelines.SigningKeyPath -ContainerRegistry $Config.SecureBuildPipelines.ContainerRegistry
            Write-ConfigurationLog "Secure build pipelines configured" "Success"
        }
        
        # Configure government compliance if enabled
        if ($Config.GovernmentCompliance.Enabled) {
            Set-HGSGovernmentCompliance -ComplianceStandard $Config.GovernmentCompliance.Standard -SecurityLevel $Config.GovernmentCompliance.SecurityLevel -AuditLogging
            Write-ConfigurationLog "Government compliance configured" "Success"
        }
        
        # Configure edge deployment if enabled
        if ($Config.EdgeDeployment.Enabled) {
            Set-HGSEdgeDeployment -EdgeHostName $Config.EdgeDeployment.EdgeHostName -CentralHgsServer $Config.HgsServer -ConnectivityMode $Config.EdgeDeployment.ConnectivityMode
            Write-ConfigurationLog "Edge deployment configured" "Success"
        }
        
        # Configure TPM integration if enabled
        if ($Config.TPMIntegration.Enabled) {
            Set-HGSTPMIntegration -TPMVersion $Config.TPMIntegration.TPMVersion -BitLockerIntegration:$Config.TPMIntegration.BitLockerIntegration -PCRValues $Config.TPMIntegration.PCRValues
            Write-ConfigurationLog "TPM integration configured" "Success"
        }
        
        # Configure nested virtualization if enabled
        if ($Config.NestedVirtualization.Enabled) {
            Set-HGSNestedVirtualization -TestEnvironment $Config.NestedVirtualization.TestEnvironment -NestedHosts $Config.NestedVirtualization.NestedHosts
            Write-ConfigurationLog "Nested virtualization configured" "Success"
        }
        
        # Configure VBS synergy if enabled
        if ($Config.VBSSynergy.Enabled) {
            Set-HGSVBSSynergy -VBSEndpoint $Config.VBSSynergy.VBSEndpoint -CredentialGuardEnabled:$Config.VBSSynergy.CredentialGuardEnabled -SecurityLevel $Config.VBSSynergy.SecurityLevel
            Write-ConfigurationLog "VBS synergy configured" "Success"
        }
        
        # Configure SIEM integration if enabled
        if ($Config.SIEMIntegration.Enabled) {
            Set-HGSSIEMIntegration -SIEMEndpoint $Config.SIEMIntegration.SIEMEndpoint -LogLevel $Config.SIEMIntegration.LogLevel -ComplianceSystem $Config.SIEMIntegration.ComplianceSystem
            Write-ConfigurationLog "SIEM integration configured" "Success"
        }
        
        # Configure policy automation if enabled
        if ($Config.PolicyAutomation.Enabled) {
            Set-HGSPolicyAutomation -AutomationScript $Config.PolicyAutomation.AutomationScript -UpdateInterval $Config.PolicyAutomation.UpdateInterval -DynamicAllowListing:$Config.PolicyAutomation.DynamicAllowListing
            Write-ConfigurationLog "Policy automation configured" "Success"
        }
        
        # Configure third-party integration if enabled
        if ($Config.ThirdPartyIntegration.Enabled) {
            Set-HGSThirdPartyIntegration -ManagementTool $Config.ThirdPartyIntegration.ManagementTool -IntegrationEndpoint $Config.ThirdPartyIntegration.IntegrationEndpoint -DashboardIntegration:$Config.ThirdPartyIntegration.DashboardIntegration
            Write-ConfigurationLog "Third-party integration configured" "Success"
        }
        
        # Configure lifecycle management if enabled
        if ($Config.LifecycleManagement.Enabled) {
            Set-HGSLifecycleManagement -RetirementPolicy $Config.LifecycleManagement.RetirementPolicy -PatchValidation:$Config.LifecycleManagement.PatchValidation -ContinuousIntegrity:$Config.LifecycleManagement.ContinuousIntegrity
            Write-ConfigurationLog "Lifecycle management configured" "Success"
        }
        
        return $true
    }
    catch {
        Write-ConfigurationLog "Failed to configure advanced settings: $($_.Exception.Message)" "Error"
        throw
    }
}

function Test-HGSConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ConfigurationLog "Testing HGS configuration..." "Info"
    
    try {
        # Import troubleshooting module
        Import-Module "$ModulePath\..\..\Modules\HGS-Troubleshooting.psm1" -Force
        
        # Run configuration test
        $testResult = Test-HGSConfiguration -HgsServer $Config.HgsServer -TestType "All"
        
        if ($testResult.OverallResult -eq "Pass") {
            Write-ConfigurationLog "Configuration test passed" "Success"
            return $true
        } else {
            Write-ConfigurationLog "Configuration test failed" "Warning"
            foreach ($issue in $testResult.Issues) {
                Write-ConfigurationLog "Issue: $issue" "Warning"
            }
            return $false
        }
    }
    catch {
        Write-ConfigurationLog "Failed to test configuration: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Save-ConfigurationReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ConfigurationLog "Saving configuration report..." "Info"
    
    try {
        $reportPath = "C:\HGS-Configuration\Reports\HGS-Configuration-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        
        # Create report directory
        $reportDir = Split-Path $reportPath -Parent
        if (!(Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force
        }
        
        $configurationReport = @{
            ConfigurationInfo = @{
                HgsServer = $Config.HgsServer
                StartTime = $script:ConfigurationStartTime
                EndTime = Get-Date
                Duration = (Get-Date) - $script:ConfigurationStartTime
                Configuration = $Config
            }
            ConfigurationLog = $script:ConfigurationLog
            CurrentStatus = Get-HGSStatus -HgsServer $Config.HgsServer
            Recommendations = @(
                "Monitor HGS configuration changes",
                "Review security policies regularly",
                "Test configuration after changes",
                "Maintain configuration backups",
                "Document configuration changes"
            )
        }
        
        $configurationReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-ConfigurationLog "Configuration report saved to: $reportPath" "Success"
        return $reportPath
    }
    catch {
        Write-ConfigurationLog "Failed to save configuration report: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Main configuration logic
try {
    Write-ConfigurationLog "Starting HGS configuration..." "Info"
    Write-ConfigurationLog "Server: $HgsServer" "Info"
    
    # Load configuration from file if provided
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        Write-ConfigurationLog "Loading configuration from file: $ConfigurationFile" "Info"
        $script:ConfigurationData = Get-Content $ConfigurationFile | ConvertFrom-Json | ConvertTo-Hashtable
    } else {
        # Use parameter-based configuration
        $script:ConfigurationData = @{
            HgsServer = $HgsServer
            AttestationMode = $AttestationMode
            SecurityLevel = $SecurityLevel
            CertificateThumbprint = $CertificateThumbprint
            HostGroups = $HostGroups
            Policies = $Policies
            Certificates = @()
            ClusterAttestation = @{
                Enabled = $false
                ClusterName = ""
                Nodes = @()
            }
            DisasterRecovery = @{
                Enabled = $false
                SecondaryServer = ""
                ReplicationMode = "Active-Passive"
            }
            HybridCloud = @{
                Enabled = $false
                AzureStackEndpoint = ""
                TrustMode = "Federated"
            }
            OfflineDeployment = @{
                Enabled = $false
                TemplatePath = ""
                AttestationPolicy = ""
            }
            RogueHostDetection = @{
                Enabled = $true
                Threshold = 3
                Action = "Immediate"
            }
            ForensicIntegrity = @{
                Enabled = $false
                BaselinePath = "C:\Baselines"
                Interval = "Daily"
            }
            PAWHosting = @{
                Enabled = $false
                TemplatePath = ""
                SecurityPolicy = ""
            }
            CrossForest = @{
                Enabled = $false
                ForestName = ""
                TrustCertificate = ""
            }
            SecureBuildPipelines = @{
                Enabled = $false
                BuildServerName = ""
                SigningKeyPath = ""
                ContainerRegistry = ""
            }
            GovernmentCompliance = @{
                Enabled = $false
                Standard = "DoD"
                SecurityLevel = "High"
            }
            EdgeDeployment = @{
                Enabled = $false
                EdgeHostName = ""
                ConnectivityMode = "Intermittent"
            }
            TPMIntegration = @{
                Enabled = $true
                TPMVersion = "2.0"
                BitLockerIntegration = $false
                PCRValues = @(0,1,2,3,4,5,6,7)
            }
            NestedVirtualization = @{
                Enabled = $false
                TestEnvironment = ""
                NestedHosts = @()
            }
            VBSSynergy = @{
                Enabled = $false
                VBSEndpoint = ""
                CredentialGuardEnabled = $false
                SecurityLevel = "High"
            }
            SIEMIntegration = @{
                Enabled = $false
                SIEMEndpoint = ""
                LogLevel = "Detailed"
                ComplianceSystem = ""
            }
            PolicyAutomation = @{
                Enabled = $false
                AutomationScript = ""
                UpdateInterval = "Daily"
                DynamicAllowListing = $false
            }
            ThirdPartyIntegration = @{
                Enabled = $false
                ManagementTool = ""
                IntegrationEndpoint = ""
                DashboardIntegration = $false
            }
            LifecycleManagement = @{
                Enabled = $false
                RetirementPolicy = "Automatic"
                PatchValidation = $false
                ContinuousIntegrity = $false
            }
        }
    }
    
    # Confirm configuration
    if (!$Force) {
        Write-Host "`nHGS Configuration Settings:" -ForegroundColor Cyan
        Write-Host "Server Name: $($script:ConfigurationData.HgsServer)" -ForegroundColor White
        Write-Host "Attestation Mode: $($script:ConfigurationData.AttestationMode)" -ForegroundColor White
        Write-Host "Security Level: $($script:ConfigurationData.SecurityLevel)" -ForegroundColor White
        Write-Host "Host Groups: $($script:ConfigurationData.HostGroups.Count)" -ForegroundColor White
        Write-Host "Policies: $($script:ConfigurationData.Policies.Count)" -ForegroundColor White
        
        $confirmation = Read-Host "`nDo you want to proceed with HGS configuration? (Y/N)"
        if ($confirmation -notmatch "^[Yy]") {
            Write-ConfigurationLog "Configuration cancelled by user" "Warning"
            exit 0
        }
    }
    
    # Create backup
    $backupFile = Backup-HGSConfiguration -BackupPath $BackupPath
    
    # Execute configuration steps
    Set-HGSBasicConfiguration -Config $script:ConfigurationData
    Set-HGSHostGroups -Config $script:ConfigurationData
    Set-HGSPolicies -Config $script:ConfigurationData
    Set-HGSCertificates -Config $script:ConfigurationData
    Set-HGSAdvancedConfiguration -Config $script:ConfigurationData
    
    # Test configuration
    $testResult = Test-HGSConfiguration -Config $script:ConfigurationData
    
    # Save configuration report
    $reportPath = Save-ConfigurationReport -Config $script:ConfigurationData
    
    # Final status
    if ($testResult) {
        Write-ConfigurationLog "HGS configuration completed successfully!" "Success"
        Write-Host "`nConfiguration Summary:" -ForegroundColor Green
        Write-Host "✓ Basic HGS settings configured" -ForegroundColor Green
        Write-Host "✓ Host groups configured" -ForegroundColor Green
        Write-Host "✓ Policies configured" -ForegroundColor Green
        Write-Host "✓ Certificates configured" -ForegroundColor Green
        Write-Host "✓ Advanced settings configured" -ForegroundColor Green
        Write-Host "✓ Configuration tested successfully" -ForegroundColor Green
        Write-Host "`nConfiguration report saved to: $reportPath" -ForegroundColor Cyan
        Write-Host "Backup saved to: $backupFile" -ForegroundColor Cyan
    } else {
        Write-ConfigurationLog "HGS configuration completed with warnings" "Warning"
        Write-Host "`nConfiguration completed with warnings. Please review the configuration report." -ForegroundColor Yellow
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Review the configuration report" -ForegroundColor White
    Write-Host "2. Test HGS functionality" -ForegroundColor White
    Write-Host "3. Monitor HGS services" -ForegroundColor White
    Write-Host "4. Document configuration changes" -ForegroundColor White
    Write-Host "5. Schedule regular configuration reviews" -ForegroundColor White
    
}
catch {
    Write-ConfigurationLog "HGS configuration failed: $($_.Exception.Message)" "Error"
    Write-Host "`nConfiguration failed. Please check the error messages above and resolve the issues." -ForegroundColor Red
    exit 1
}
