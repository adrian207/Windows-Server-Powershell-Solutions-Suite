#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy NPAS Server

.DESCRIPTION
    This script deploys and configures a Network Policy and Access Services (NPAS) server
    with comprehensive security, monitoring, and troubleshooting capabilities.

.PARAMETER ServerName
    Name of the server to deploy NPAS on

.PARAMETER ConfigurationFile
    Path to configuration file (optional)

.PARAMETER InstallFeatures
    Install required Windows features

.PARAMETER ConfigureSecurity
    Configure security settings

.PARAMETER ConfigureMonitoring
    Configure monitoring settings

.PARAMETER ConfigureTroubleshooting
    Configure troubleshooting settings

.EXAMPLE
    .\Deploy-NPASServer.ps1 -ServerName "NPAS-SERVER01"

.EXAMPLE
    .\Deploy-NPASServer.ps1 -ServerName "NPAS-SERVER01" -ConfigurationFile "C:\Config\NPAS-Config.json" -InstallFeatures -ConfigureSecurity
#>

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,

    [Parameter(Mandatory = $false)]
    [switch]$InstallFeatures,

    [Parameter(Mandatory = $false)]
    [switch]$ConfigureSecurity,

    [Parameter(Mandatory = $false)]
    [switch]$ConfigureMonitoring,

    [Parameter(Mandatory = $false)]
    [switch]$ConfigureTroubleshooting
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script configuration
$scriptConfig = @{
    ServerName = $ServerName
    ConfigurationFile = $ConfigurationFile
    InstallFeatures = $InstallFeatures
    ConfigureSecurity = $ConfigureSecurity
    ConfigureMonitoring = $ConfigureMonitoring
    ConfigureTroubleshooting = $ConfigureTroubleshooting
    LogPath = "C:\NPAS\Logs"
    BackupPath = "C:\NPAS\Backup"
    StartTime = Get-Date
}

# Create log directory
if (-not (Test-Path $scriptConfig.LogPath)) {
    New-Item -Path $scriptConfig.LogPath -ItemType Directory -Force
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Information"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage -ForegroundColor $(
        switch ($Level) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Success" { "Green" }
            default { "White" }
        }
    )
    
    $logMessage | Out-File -FilePath "$($scriptConfig.LogPath)\NPAS-Deployment.log" -Append -Encoding UTF8
}

try {
    Write-Log "Starting NPAS server deployment..." "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Configuration File: $ConfigurationFile" "Information"
    Write-Log "Install Features: $InstallFeatures" "Information"
    Write-Log "Configure Security: $ConfigureSecurity" "Information"
    Write-Log "Configure Monitoring: $ConfigureMonitoring" "Information"
    Write-Log "Configure Troubleshooting: $ConfigureTroubleshooting" "Information"

    # Import required modules
    Write-Log "Importing NPAS modules..." "Information"
    $modulePath = Join-Path $PSScriptRoot "Modules"
    
    if (Test-Path "$modulePath\NPAS-Core.psm1") {
        Import-Module "$modulePath\NPAS-Core.psm1" -Force
        Write-Log "NPAS-Core module imported successfully" "Success"
    } else {
        throw "NPAS-Core module not found at $modulePath\NPAS-Core.psm1"
    }

    if (Test-Path "$modulePath\NPAS-Security.psm1") {
        Import-Module "$modulePath\NPAS-Security.psm1" -Force
        Write-Log "NPAS-Security module imported successfully" "Success"
    } else {
        throw "NPAS-Security module not found at $modulePath\NPAS-Security.psm1"
    }

    if (Test-Path "$modulePath\NPAS-Monitoring.psm1") {
        Import-Module "$modulePath\NPAS-Monitoring.psm1" -Force
        Write-Log "NPAS-Monitoring module imported successfully" "Success"
    } else {
        throw "NPAS-Monitoring module not found at $modulePath\NPAS-Monitoring.psm1"
    }

    if (Test-Path "$modulePath\NPAS-Troubleshooting.psm1") {
        Import-Module "$modulePath\NPAS-Troubleshooting.psm1" -Force
        Write-Log "NPAS-Troubleshooting module imported successfully" "Success"
    } else {
        throw "NPAS-Troubleshooting module not found at $modulePath\NPAS-Troubleshooting.psm1"
    }

    # Load configuration if provided
    $configuration = @{}
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        Write-Log "Loading configuration from $ConfigurationFile..." "Information"
        $configuration = Get-Content $ConfigurationFile | ConvertFrom-Json
        Write-Log "Configuration loaded successfully" "Success"
    } else {
        Write-Log "Using default configuration" "Information"
        $configuration = @{
            Features = @("NPAS", "NPAS-Policy-Server", "NPAS-Health-Registration-Authority")
            SecuritySettings = @{
                AuthenticationMethods = @("EAP-TLS", "PEAP-MS-CHAPv2", "MS-CHAPv2")
                EncryptionLevel = "Strong"
                AuditLevel = "Comprehensive"
                MFAEnabled = $true
            }
            MonitoringSettings = @{
                MonitoringLevel = "Advanced"
                AlertingEnabled = $true
                LogLevel = "Information"
            }
            TroubleshootingSettings = @{
                DiagnosticsEnabled = $true
                HealthChecksEnabled = $true
                PerformanceMonitoring = $true
            }
        }
    }

    # Install NPAS features
    if ($InstallFeatures) {
        Write-Log "Installing NPAS features..." "Information"
        $installResult = Install-NPASRoles -ServerName $ServerName -Features $configuration.Features
        
        if ($installResult.Success) {
            Write-Log "NPAS features installed successfully" "Success"
            Write-Log "Features installed: $($installResult.FeaturesInstalled.Count)" "Information"
        } else {
            throw "Failed to install NPAS features: $($installResult.Error)"
        }
    }

    # Configure NPAS server
    Write-Log "Configuring NPAS server..." "Information"
    $configResult = Configure-NPASServer -ServerName $ServerName -LogPath $scriptConfig.LogPath -AccountingEnabled
    
    if ($configResult.Success) {
        Write-Log "NPAS server configured successfully" "Success"
    } else {
        throw "Failed to configure NPAS server: $($configResult.Error)"
    }

    # Configure security settings
    if ($ConfigureSecurity) {
        Write-Log "Configuring NPAS security settings..." "Information"
        
        # Configure authentication
        $authResult = Set-NPASAuthentication -ServerName $ServerName -AuthenticationMethods $configuration.SecuritySettings.AuthenticationMethods -CertificateValidation -SmartCardSupport
        
        if ($authResult.Success) {
            Write-Log "NPAS authentication configured successfully" "Success"
        } else {
            Write-Log "Failed to configure NPAS authentication: $($authResult.Error)" "Warning"
        }

        # Configure authorization
        $authzResult = Set-NPASAuthorization -ServerName $ServerName -AuthorizationMethod "RBAC" -GroupPolicies @("Network-Admins", "Wireless-Users", "VPN-Users") -TimeRestrictions
        
        if ($authzResult.Success) {
            Write-Log "NPAS authorization configured successfully" "Success"
        } else {
            Write-Log "Failed to configure NPAS authorization: $($authzResult.Error)" "Warning"
        }

        # Configure encryption
        $encryptResult = Set-NPASEncryption -ServerName $ServerName -EncryptionLevel $configuration.SecuritySettings.EncryptionLevel -EncryptionMethods @("AES-256", "TLS-1.2", "TLS-1.3") -KeyManagement
        
        if ($encryptResult.Success) {
            Write-Log "NPAS encryption configured successfully" "Success"
        } else {
            Write-Log "Failed to configure NPAS encryption: $($encryptResult.Error)" "Warning"
        }

        # Configure auditing
        $auditResult = Set-NPASAuditing -ServerName $ServerName -AuditLevel $configuration.SecuritySettings.AuditLevel -LogFormat "Database" -RetentionPeriod 90
        
        if ($auditResult.Success) {
            Write-Log "NPAS auditing configured successfully" "Success"
        } else {
            Write-Log "Failed to configure NPAS auditing: $($auditResult.Error)" "Warning"
        }

        # Configure MFA if enabled
        if ($configuration.SecuritySettings.MFAEnabled) {
            $mfaResult = Set-NPASMFASettings -ServerName $ServerName -MFAProvider "Azure-MFA" -MFAMethods @("SMS", "Phone", "Authenticator-App") -ConditionalAccess
            
            if ($mfaResult.Success) {
                Write-Log "NPAS MFA configured successfully" "Success"
            } else {
                Write-Log "Failed to configure NPAS MFA: $($mfaResult.Error)" "Warning"
            }
        }
    }

    # Configure monitoring settings
    if ($ConfigureMonitoring) {
        Write-Log "Configuring NPAS monitoring settings..." "Information"
        
        $monitorResult = Set-NPASMonitoring -ServerName $ServerName -MonitoringLevel $configuration.MonitoringSettings.MonitoringLevel -AlertingEnabled:$configuration.MonitoringSettings.AlertingEnabled
        
        if ($monitorResult.Success) {
            Write-Log "NPAS monitoring configured successfully" "Success"
        } else {
            Write-Log "Failed to configure NPAS monitoring: $($monitorResult.Error)" "Warning"
        }

        # Configure alerting
        $alertResult = Set-NPASAlerting -ServerName $ServerName -AlertTypes @("Authentication-Failure", "Performance-Warning", "Security-Violation") -NotificationMethods @("Email", "Webhook")
        
        if ($alertResult.Success) {
            Write-Log "NPAS alerting configured successfully" "Success"
        } else {
            Write-Log "Failed to configure NPAS alerting: $($alertResult.Error)" "Warning"
        }

        # Configure logging
        $logResult = Set-NPASLogging -ServerName $ServerName -LogPath $scriptConfig.LogPath -LogLevel $configuration.MonitoringSettings.LogLevel
        
        if ($logResult.Success) {
            Write-Log "NPAS logging configured successfully" "Success"
        } else {
            Write-Log "Failed to configure NPAS logging: $($logResult.Error)" "Warning"
        }
    }

    # Configure troubleshooting settings
    if ($ConfigureTroubleshooting) {
        Write-Log "Configuring NPAS troubleshooting settings..." "Information"
        
        # Run initial diagnostics
        $diagResult = Test-NPASDiagnostics -ServerName $ServerName -DiagnosticType "All"
        
        if ($diagResult.Success) {
            Write-Log "NPAS diagnostics completed successfully" "Success"
            Write-Log "Issues found: $($diagResult.IssuesFound.Count)" "Information"
            Write-Log "Recommendations: $($diagResult.Recommendations.Count)" "Information"
        } else {
            Write-Log "NPAS diagnostics completed with issues: $($diagResult.Error)" "Warning"
        }

        # Perform health check
        $healthResult = Get-NPASHealthCheck -ServerName $ServerName -HealthCheckType "Comprehensive"
        
        if ($healthResult.Success) {
            Write-Log "NPAS health check completed successfully" "Success"
            Write-Log "Health Score: $($healthResult.HealthScore)%" "Information"
        } else {
            Write-Log "NPAS health check completed with issues: $($healthResult.Error)" "Warning"
        }

        # Validate configuration
        $validateResult = Validate-NPASConfiguration -ServerName $ServerName -ValidationType "All"
        
        if ($validateResult.Success) {
            Write-Log "NPAS configuration validation completed successfully" "Success"
        } else {
            Write-Log "NPAS configuration validation completed with issues: $($validateResult.Error)" "Warning"
        }
    }

    # Create sample policies
    Write-Log "Creating sample NPAS policies..." "Information"
    
    $policies = @(
        @{
            Name = "Wireless Access Policy"
            Type = "Access"
            Conditions = @("User-Groups", "Wireless-Users")
            Settings = @{
                AccessPermission = "Grant"
                AuthenticationType = "EAP-TLS"
                VLANAssignment = "Wireless-VLAN"
            }
        },
        @{
            Name = "VPN Access Policy"
            Type = "Access"
            Conditions = @("User-Groups", "VPN-Users")
            Settings = @{
                AccessPermission = "Grant"
                AuthenticationType = "MS-CHAPv2"
                SessionTimeout = 480
            }
        },
        @{
            Name = "Guest Access Policy"
            Type = "Access"
            Conditions = @("User-Groups", "Guest-Users")
            Settings = @{
                AccessPermission = "Grant"
                AuthenticationType = "PAP"
                VLANAssignment = "Guest-VLAN"
                TimeRestrictions = $true
            }
        }
    )

    foreach ($policy in $policies) {
        $policyResult = New-NPASPolicy -PolicyName $policy.Name -PolicyType $policy.Type -Conditions $policy.Conditions -Settings $policy.Settings
        
        if ($policyResult.Success) {
            Write-Log "Policy '$($policy.Name)' created successfully" "Success"
        } else {
            Write-Log "Failed to create policy '$($policy.Name)': $($policyResult.Error)" "Warning"
        }
    }

    # Test connectivity
    Write-Log "Testing NPAS connectivity..." "Information"
    $connectivityResult = Test-NPASConnectivity -ServerName $ServerName
    
    if ($connectivityResult.Success) {
        Write-Log "NPAS connectivity test passed" "Success"
    } else {
        Write-Log "NPAS connectivity test failed: $($connectivityResult.Error)" "Warning"
    }

    # Get final status
    Write-Log "Getting NPAS server status..." "Information"
    $statusResult = Get-NPASStatus -ServerName $ServerName
    
    if ($statusResult.Success) {
        Write-Log "NPAS server status retrieved successfully" "Success"
        Write-Log "Service Status: $($statusResult.Status.ServiceStatus)" "Information"
        Write-Log "Policy Count: $($statusResult.Status.PolicyCount)" "Information"
        Write-Log "Total Requests: $($statusResult.Status.Statistics.TotalRequests)" "Information"
    } else {
        Write-Log "Failed to get NPAS server status: $($statusResult.Error)" "Warning"
    }

    # Calculate deployment duration
    $deploymentDuration = (Get-Date) - $scriptConfig.StartTime
    Write-Log "NPAS server deployment completed successfully!" "Success"
    Write-Log "Deployment Duration: $($deploymentDuration.TotalMinutes) minutes" "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Log Path: $($scriptConfig.LogPath)" "Information"
    Write-Log "Backup Path: $($scriptConfig.BackupPath)" "Information"

    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "=== NPAS SERVER DEPLOYMENT SUMMARY ===" -ForegroundColor Green
    Write-Host "Server Name: $ServerName" -ForegroundColor Cyan
    Write-Host "Deployment Duration: $($deploymentDuration.TotalMinutes) minutes" -ForegroundColor Cyan
    Write-Host "Features Installed: $InstallFeatures" -ForegroundColor Cyan
    Write-Host "Security Configured: $ConfigureSecurity" -ForegroundColor Cyan
    Write-Host "Monitoring Configured: $ConfigureMonitoring" -ForegroundColor Cyan
    Write-Host "Troubleshooting Configured: $ConfigureTroubleshooting" -ForegroundColor Cyan
    Write-Host "Log Path: $($scriptConfig.LogPath)" -ForegroundColor Cyan
    Write-Host "Backup Path: $($scriptConfig.BackupPath)" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Green

} catch {
    Write-Log "NPAS server deployment failed: $($_.Exception.Message)" "Error"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
