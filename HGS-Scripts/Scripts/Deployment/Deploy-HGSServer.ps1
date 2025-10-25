#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Host Guardian Service (HGS) Server

.DESCRIPTION
    Comprehensive deployment script for Host Guardian Service including:
    - HGS role installation and configuration
    - Attestation service setup
    - Key protection service configuration
    - Security baseline implementation
    - Monitoring and alerting setup

.PARAMETER ServerName
    Name of the server to deploy HGS on

.PARAMETER AttestationMode
    Attestation mode (TPM or Admin)

.PARAMETER SecurityLevel
    Security level (Low, Medium, High, Critical)

.PARAMETER CertificateThumbprint
    Certificate thumbprint for HGS services

.PARAMETER ConfigurationFile
    Path to JSON configuration file

.PARAMETER SkipPrerequisites
    Skip prerequisite checks

.PARAMETER Force
    Force deployment without confirmation

.EXAMPLE
    .\Deploy-HGSServer.ps1 -ServerName "HGS01" -AttestationMode "TPM" -SecurityLevel "High"

.EXAMPLE
    .\Deploy-HGSServer.ps1 -ConfigurationFile "C:\Config\HGS-Config.json" -Force

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [ValidateSet("TPM", "Admin")]
    [string]$AttestationMode = "TPM",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$SecurityLevel = "High",

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPrerequisites,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Import required modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ModulePath\..\Modules\HGS-Core.psm1" -Force
Import-Module "$ModulePath\..\Modules\HGS-Security.psm1" -Force
Import-Module "$ModulePath\..\Modules\HGS-Monitoring.psm1" -Force
Import-Module "$ModulePath\..\Modules\HGS-Troubleshooting.psm1" -Force

# Global variables
$script:DeploymentLog = @()
$script:DeploymentStartTime = Get-Date
$script:DeploymentConfig = @{}

function Write-DeploymentLog {
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
    
    $script:DeploymentLog += $logEntry
    
    $color = switch ($Level) {
        "Info" { "White" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Test-Prerequisites {
    Write-DeploymentLog "Testing prerequisites..." "Info"
    
    $prerequisites = @{
        PowerShellVersion = $PSVersionTable.PSVersion.Major -ge 5
        AdministratorRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        WindowsVersion = (Get-CimInstance Win32_OperatingSystem).Version -ge "10.0.14393" # Windows Server 2016
        HyperVInstalled = (Get-WindowsFeature -Name Hyper-V).InstallState -eq "Installed"
        TPMAvailable = $null -ne (Get-Tpm -ErrorAction SilentlyContinue)
    }
    
    $failedPrerequisites = $prerequisites.GetEnumerator() | Where-Object { !$_.Value }
    
    if ($failedPrerequisites.Count -gt 0) {
        foreach ($prereq in $failedPrerequisites) {
            Write-DeploymentLog "Prerequisite failed: $($prereq.Key)" "Error"
        }
        throw "Prerequisites not met. Please resolve the issues above."
    }
    
    Write-DeploymentLog "All prerequisites met" "Success"
    return $true
}

function Install-HGSPrerequisites {
    Write-DeploymentLog "Installing HGS prerequisites..." "Info"
    
    try {
        # Install required Windows features
        $requiredFeatures = @(
            "HostGuardianServiceRole",
            "Hyper-V",
            "Hyper-V-PowerShell",
            "RSAT-Hyper-V-Tools"
        )
        
        foreach ($feature in $requiredFeatures) {
            $featureState = Get-WindowsFeature -Name $feature
            if ($featureState.InstallState -ne "Installed") {
                Write-DeploymentLog "Installing Windows feature: $feature" "Info"
                $installResult = Install-WindowsFeature -Name $feature -IncludeManagementTools
                if ($installResult.Success) {
                    Write-DeploymentLog "Successfully installed $feature" "Success"
                } else {
                    throw "Failed to install $feature"
                }
            } else {
                Write-DeploymentLog "$feature is already installed" "Info"
            }
        }
        
        # Enable TPM if available
        if ($null -ne (Get-Tpm -ErrorAction SilentlyContinue)) {
            $tpm = Get-Tpm
            if ($tpm.TpmPresent -and !$tpm.TpmReady) {
                Write-DeploymentLog "Initializing TPM..." "Info"
                Initialize-Tpm -AllowClear -AllowPhysicalPresence
                Write-DeploymentLog "TPM initialized successfully" "Success"
            }
        }
        
        return $true
    }
    catch {
        Write-DeploymentLog "Failed to install prerequisites: $($_.Exception.Message)" "Error"
        throw
    }
}

function Initialize-HGSServices {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-DeploymentLog "Initializing HGS services..." "Info"
    
    try {
        # Initialize HGS server
        if ($Config.AttestationService -and $Config.KeyProtectionService) {
            Initialize-HgsServer -HgsServiceName "HGS" -StartService
            Write-DeploymentLog "HGS initialized with both attestation and key protection services" "Success"
        } elseif ($Config.AttestationService) {
            Initialize-HgsServer -HgsServiceName "HGS" -Attestation -StartService
            Write-DeploymentLog "HGS initialized with attestation service only" "Success"
        } elseif ($Config.KeyProtectionService) {
            Initialize-HgsServer -HgsServiceName "HGS" -KeyProtection -StartService
            Write-DeploymentLog "HGS initialized with key protection service only" "Success"
        }
        
        # Configure attestation mode
        if ($Config.AttestationMode -eq "TPM") {
            Set-HgsServer -TrustTpm
            Write-DeploymentLog "TPM-Trusted attestation mode enabled" "Success"
        } else {
            Set-HgsServer -TrustActiveDirectory
            Write-DeploymentLog "Admin-Trusted attestation mode enabled" "Success"
        }
        
        # Configure certificate if provided
        if ($Config.CertificateThumbprint) {
            Set-HgsKeyProtectionCertificate -Thumbprint $Config.CertificateThumbprint
            Write-DeploymentLog "Certificate configured for key protection service" "Success"
        }
        
        return $true
    }
    catch {
        Write-DeploymentLog "Failed to initialize HGS services: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSSecurityBaseline {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-DeploymentLog "Configuring HGS security baseline..." "Info"
    
    try {
        # Configure security baseline
        Set-HGSSecurityBaseline -BaselineName "HGS-Deployment" -ComplianceStandard "Custom" -SecurityLevel $Config.SecurityLevel
        
        # Configure Zero Trust if enabled
        if ($Config.ZeroTrust) {
            Set-HGSZeroTrust -TrustModel "NeverTrust" -VerificationLevel "Continuous" -PolicyEnforcement "Strict"
            Write-DeploymentLog "Zero Trust configuration enabled" "Success"
        }
        
        # Configure multi-tenant security if enabled
        if ($Config.MultiTenant) {
            Set-HGSMultiTenantSecurity -TenantName "Default" -IsolationLevel $Config.SecurityLevel
            Write-DeploymentLog "Multi-tenant security configured" "Success"
        }
        
        # Configure air-gapped security if enabled
        if ($Config.AirGapped) {
            Set-HGSAirGappedSecurity -NetworkIsolation "Complete" -OfflineMode -LocalAttestation
            Write-DeploymentLog "Air-gapped security configured" "Success"
        }
        
        return $true
    }
    catch {
        Write-DeploymentLog "Failed to configure security baseline: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSMonitoring {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-DeploymentLog "Configuring HGS monitoring..." "Info"
    
    try {
        # Configure monitoring
        Set-HGSMonitoring -MonitoringLevel $Config.MonitoringLevel -LogRetention $Config.LogRetention
        
        # Configure alerting if enabled
        if ($Config.Alerting.Enabled) {
            Set-HGSAlerting -AlertMethods $Config.Alerting.Methods -Recipients $Config.Alerting.Recipients
            Write-DeploymentLog "Alerting configured" "Success"
        }
        
        # Configure logging
        Set-HGSLogging -LogLevel $Config.LogLevel -LogRetention $Config.LogRetention -LogLocation $Config.LogLocation
        
        # Configure dashboard
        Set-HGSDashboard -DashboardType $Config.DashboardType -RefreshInterval $Config.DashboardRefreshInterval
        
        return $true
    }
    catch {
        Write-DeploymentLog "Failed to configure monitoring: $($_.Exception.Message)" "Error"
        throw
    }
}

function Add-HGSHosts {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-DeploymentLog "Adding HGS hosts..." "Info"
    
    try {
        if ($Config.Hosts.Count -gt 0) {
            foreach ($hostItem in $Config.Hosts) {
                Add-HGSHost -HostName $hostItem.Name -AttestationMode $hostItem.AttestationMode -HgsServer $Config.ServerName
                Write-DeploymentLog "Added host: $($hostItem.Name)" "Success"
            }
        }
        
        return $true
    }
    catch {
        Write-DeploymentLog "Failed to add hosts: $($_.Exception.Message)" "Error"
        throw
    }
}

function Set-HGSEnterpriseScenarios {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-DeploymentLog "Configuring enterprise scenarios..." "Info"
    
    try {
        # Configure cluster attestation if enabled
        if ($Config.ClusterAttestation.Enabled) {
            Set-HGSClusterAttestation -ClusterName $Config.ClusterAttestation.ClusterName -ClusterNodes $Config.ClusterAttestation.Nodes
            Write-DeploymentLog "Cluster attestation configured" "Success"
        }
        
        # Configure disaster recovery if enabled
        if ($Config.DisasterRecovery.Enabled) {
            Set-HGSDisasterRecovery -PrimaryHgsServer $Config.ServerName -SecondaryHgsServer $Config.DisasterRecovery.SecondaryServer -ReplicationMode $Config.DisasterRecovery.ReplicationMode
            Write-DeploymentLog "Disaster recovery configured" "Success"
        }
        
        # Configure hybrid cloud if enabled
        if ($Config.HybridCloud.Enabled) {
            Set-HGSHybridCloud -AzureStackEndpoint $Config.HybridCloud.AzureStackEndpoint -OnPremisesHgsServer $Config.ServerName -TrustMode $Config.HybridCloud.TrustMode
            Write-DeploymentLog "Hybrid cloud configuration completed" "Success"
        }
        
        # Configure offline deployment if enabled
        if ($Config.OfflineDeployment.Enabled) {
            Set-HGSOfflineDeployment -TemplatePath $Config.OfflineDeployment.TemplatePath -AttestationPolicy $Config.OfflineDeployment.AttestationPolicy
            Write-DeploymentLog "Offline deployment configured" "Success"
        }
        
        # Configure rogue host detection if enabled
        if ($Config.RogueHostDetection.Enabled) {
            Set-HGSRogueHostDetection -DetectionThreshold $Config.RogueHostDetection.Threshold -RevocationAction $Config.RogueHostDetection.Action
            Write-DeploymentLog "Rogue host detection configured" "Success"
        }
        
        # Configure forensic integrity if enabled
        if ($Config.ForensicIntegrity.Enabled) {
            Set-HGSForensicIntegrity -BaselinePath $Config.ForensicIntegrity.BaselinePath -VerificationInterval $Config.ForensicIntegrity.Interval
            Write-DeploymentLog "Forensic integrity verification configured" "Success"
        }
        
        # Configure PAW hosting if enabled
        if ($Config.PAWHosting.Enabled) {
            Set-HGSPAWHosting -PAWTemplatePath $Config.PAWHosting.TemplatePath -SecurityPolicy $Config.PAWHosting.SecurityPolicy
            Write-DeploymentLog "PAW hosting configured" "Success"
        }
        
        # Configure cross-forest if enabled
        if ($Config.CrossForest.Enabled) {
            Set-HGSCrossForest -ForestName $Config.CrossForest.ForestName -TrustCertificate $Config.CrossForest.TrustCertificate
            Write-DeploymentLog "Cross-forest configuration completed" "Success"
        }
        
        # Configure secure build pipelines if enabled
        if ($Config.SecureBuildPipelines.Enabled) {
            Set-HGSSecureBuildPipelines -BuildServerName $Config.SecureBuildPipelines.BuildServerName -SigningKeyPath $Config.SecureBuildPipelines.SigningKeyPath -ContainerRegistry $Config.SecureBuildPipelines.ContainerRegistry
            Write-DeploymentLog "Secure build pipeline configuration completed" "Success"
        }
        
        # Configure government compliance if enabled
        if ($Config.GovernmentCompliance.Enabled) {
            Set-HGSGovernmentCompliance -ComplianceStandard $Config.GovernmentCompliance.Standard -SecurityLevel $Config.GovernmentCompliance.SecurityLevel -AuditLogging
            Write-DeploymentLog "Government compliance configuration completed" "Success"
        }
        
        # Configure edge deployment if enabled
        if ($Config.EdgeDeployment.Enabled) {
            Set-HGSEdgeDeployment -EdgeHostName $Config.EdgeDeployment.EdgeHostName -CentralHgsServer $Config.ServerName -ConnectivityMode $Config.EdgeDeployment.ConnectivityMode
            Write-DeploymentLog "Edge deployment configuration completed" "Success"
        }
        
        # Configure TPM integration if enabled
        if ($Config.TPMIntegration.Enabled) {
            Set-HGSTPMIntegration -TPMVersion $Config.TPMIntegration.TPMVersion -BitLockerIntegration:$Config.TPMIntegration.BitLockerIntegration -PCRValues $Config.TPMIntegration.PCRValues
            Write-DeploymentLog "TPM integration configuration completed" "Success"
        }
        
        # Configure nested virtualization if enabled
        if ($Config.NestedVirtualization.Enabled) {
            Set-HGSNestedVirtualization -TestEnvironment $Config.NestedVirtualization.TestEnvironment -NestedHosts $Config.NestedVirtualization.NestedHosts
            Write-DeploymentLog "Nested virtualization configuration completed" "Success"
        }
        
        # Configure VBS synergy if enabled
        if ($Config.VBSSynergy.Enabled) {
            Set-HGSVBSSynergy -VBSEndpoint $Config.VBSSynergy.VBSEndpoint -CredentialGuardEnabled:$Config.VBSSynergy.CredentialGuardEnabled -SecurityLevel $Config.VBSSynergy.SecurityLevel
            Write-DeploymentLog "VBS synergy configuration completed" "Success"
        }
        
        # Configure SIEM integration if enabled
        if ($Config.SIEMIntegration.Enabled) {
            Set-HGSSIEMIntegration -SIEMEndpoint $Config.SIEMIntegration.SIEMEndpoint -LogLevel $Config.SIEMIntegration.LogLevel -ComplianceSystem $Config.SIEMIntegration.ComplianceSystem
            Write-DeploymentLog "SIEM integration configuration completed" "Success"
        }
        
        # Configure policy automation if enabled
        if ($Config.PolicyAutomation.Enabled) {
            Set-HGSPolicyAutomation -AutomationScript $Config.PolicyAutomation.AutomationScript -UpdateInterval $Config.PolicyAutomation.UpdateInterval -DynamicAllowListing:$Config.PolicyAutomation.DynamicAllowListing
            Write-DeploymentLog "Policy automation configuration completed" "Success"
        }
        
        # Configure third-party integration if enabled
        if ($Config.ThirdPartyIntegration.Enabled) {
            Set-HGSThirdPartyIntegration -ManagementTool $Config.ThirdPartyIntegration.ManagementTool -IntegrationEndpoint $Config.ThirdPartyIntegration.IntegrationEndpoint -DashboardIntegration:$Config.ThirdPartyIntegration.DashboardIntegration
            Write-DeploymentLog "Third-party integration configuration completed" "Success"
        }
        
        # Configure lifecycle management if enabled
        if ($Config.LifecycleManagement.Enabled) {
            Set-HGSLifecycleManagement -RetirementPolicy $Config.LifecycleManagement.RetirementPolicy -PatchValidation:$Config.LifecycleManagement.PatchValidation -ContinuousIntegrity:$Config.LifecycleManagement.ContinuousIntegrity
            Write-DeploymentLog "Lifecycle management configuration completed" "Success"
        }
        
        return $true
    }
    catch {
        Write-DeploymentLog "Failed to configure enterprise scenarios: $($_.Exception.Message)" "Error"
        throw
    }
}

function Test-HGSDeployment {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-DeploymentLog "Testing HGS deployment..." "Info"
    
    try {
        # Run comprehensive diagnostics
        $diagnostics = Test-HGSDiagnostics -HgsServer $Config.ServerName -DiagnosticLevel "Comprehensive" -IncludePerformance
        
        if ($diagnostics.OverallHealth -eq "Healthy") {
            Write-DeploymentLog "HGS deployment test passed" "Success"
            return $true
        } else {
            Write-DeploymentLog "HGS deployment test failed. Health status: $($diagnostics.OverallHealth)" "Warning"
            foreach ($issue in $diagnostics.Issues) {
                Write-DeploymentLog "Issue: $issue" "Warning"
            }
            return $false
        }
    }
    catch {
        Write-DeploymentLog "Failed to test HGS deployment: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Save-DeploymentReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-DeploymentLog "Saving deployment report..." "Info"
    
    try {
        $reportPath = "C:\HGS-Deployment\Reports\HGS-Deployment-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        
        # Create report directory
        $reportDir = Split-Path $reportPath -Parent
        if (!(Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force
        }
        
        $deploymentReport = @{
            DeploymentInfo = @{
                ServerName = $Config.ServerName
                StartTime = $script:DeploymentStartTime
                EndTime = Get-Date
                Duration = (Get-Date) - $script:DeploymentStartTime
                Configuration = $Config
            }
            DeploymentLog = $script:DeploymentLog
            HealthStatus = Get-HGSStatus -HgsServer $Config.ServerName
            Recommendations = @(
                "Monitor HGS services regularly",
                "Review security policies quarterly",
                "Update certificates before expiration",
                "Test disaster recovery procedures",
                "Review attestation logs for anomalies"
            )
        }
        
        $deploymentReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-DeploymentLog "Deployment report saved to: $reportPath" "Success"
        return $reportPath
    }
    catch {
        Write-DeploymentLog "Failed to save deployment report: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Main deployment logic
try {
    Write-DeploymentLog "Starting HGS deployment..." "Info"
    Write-DeploymentLog "Server: $ServerName" "Info"
    Write-DeploymentLog "Attestation Mode: $AttestationMode" "Info"
    Write-DeploymentLog "Security Level: $SecurityLevel" "Info"
    
    # Load configuration from file if provided
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        Write-DeploymentLog "Loading configuration from file: $ConfigurationFile" "Info"
        $script:DeploymentConfig = Get-Content $ConfigurationFile | ConvertFrom-Json | ConvertTo-Hashtable
    } else {
        # Use default configuration
        $script:DeploymentConfig = @{
            ServerName = $ServerName
            AttestationMode = $AttestationMode
            SecurityLevel = $SecurityLevel
            CertificateThumbprint = $CertificateThumbprint
            AttestationService = $true
            KeyProtectionService = $true
            ZeroTrust = $false
            MultiTenant = $false
            AirGapped = $false
            MonitoringLevel = "Enhanced"
            LogRetention = 30
            LogLevel = "Detailed"
            LogLocation = "C:\Logs\HGS"
            DashboardType = "PowerShell"
            DashboardRefreshInterval = 30
            Alerting = @{
                Enabled = $false
                Methods = @()
                Recipients = @()
            }
            Hosts = @()
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
    
    # Confirm deployment
    if (!$Force) {
        Write-Host "`nHGS Deployment Configuration:" -ForegroundColor Cyan
        Write-Host "Server Name: $($script:DeploymentConfig.ServerName)" -ForegroundColor White
        Write-Host "Attestation Mode: $($script:DeploymentConfig.AttestationMode)" -ForegroundColor White
        Write-Host "Security Level: $($script:DeploymentConfig.SecurityLevel)" -ForegroundColor White
        Write-Host "Attestation Service: $($script:DeploymentConfig.AttestationService)" -ForegroundColor White
        Write-Host "Key Protection Service: $($script:DeploymentConfig.KeyProtectionService)" -ForegroundColor White
        
        $confirmation = Read-Host "`nDo you want to proceed with HGS deployment? (Y/N)"
        if ($confirmation -notmatch "^[Yy]") {
            Write-DeploymentLog "Deployment cancelled by user" "Warning"
            exit 0
        }
    }
    
    # Execute deployment steps
    if (!$SkipPrerequisites) {
        Test-Prerequisites
        Install-HGSPrerequisites
    }
    
    Initialize-HGSServices -Config $script:DeploymentConfig
    Set-HGSSecurityBaseline -Config $script:DeploymentConfig
    Set-HGSMonitoring -Config $script:DeploymentConfig
    Add-HGSHosts -Config $script:DeploymentConfig
    Set-HGSEnterpriseScenarios -Config $script:DeploymentConfig
    
    # Test deployment
    $testResult = Test-HGSDeployment -Config $script:DeploymentConfig
    
    # Save deployment report
    $reportPath = Save-DeploymentReport -Config $script:DeploymentConfig
    
    # Final status
    if ($testResult) {
        Write-DeploymentLog "HGS deployment completed successfully!" "Success"
        Write-Host "`nDeployment Summary:" -ForegroundColor Green
        Write-Host "✓ HGS services installed and configured" -ForegroundColor Green
        Write-Host "✓ Security baseline applied" -ForegroundColor Green
        Write-Host "✓ Monitoring and alerting configured" -ForegroundColor Green
        Write-Host "✓ Enterprise scenarios configured" -ForegroundColor Green
        Write-Host "✓ Deployment tested successfully" -ForegroundColor Green
        Write-Host "`nDeployment report saved to: $reportPath" -ForegroundColor Cyan
    } else {
        Write-DeploymentLog "HGS deployment completed with warnings" "Warning"
        Write-Host "`nDeployment completed with warnings. Please review the deployment report." -ForegroundColor Yellow
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Review the deployment report" -ForegroundColor White
    Write-Host "2. Configure additional hosts as needed" -ForegroundColor White
    Write-Host "3. Test attestation with sample hosts" -ForegroundColor White
    Write-Host "4. Set up regular monitoring and maintenance" -ForegroundColor White
    Write-Host "5. Document your HGS configuration" -ForegroundColor White
    
}
catch {
    Write-DeploymentLog "HGS deployment failed: $($_.Exception.Message)" "Error"
    Write-Host "`nDeployment failed. Please check the error messages above and resolve the issues." -ForegroundColor Red
    exit 1
}
