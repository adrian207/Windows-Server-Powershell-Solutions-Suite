#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy NPAS Enterprise Scenarios

.DESCRIPTION
    This script provides comprehensive deployment of all 30 Network Policy and Access Services (NPAS) enterprise scenarios
    including authentication, authorization, monitoring, troubleshooting, security features, and advanced configurations.

.PARAMETER ServerName
    Name of the NPAS server to deploy scenarios on

.PARAMETER ScenarioFile
    Path to scenario configuration file (optional)

.PARAMETER Scenarios
    Array of specific scenarios to deploy (optional)

.PARAMETER DeployAll
    Deploy all 30 enterprise scenarios

.PARAMETER SecurityLevel
    Security level for scenarios (Basic, Standard, High, Enterprise)

.PARAMETER ComplianceStandards
    Array of compliance standards to implement

.EXAMPLE
    .\Deploy-NPASEnterpriseScenarios.ps1 -ServerName "NPAS-SERVER01" -DeployAll -SecurityLevel "Enterprise" -ComplianceStandards @("NIST", "ISO-27001")

.EXAMPLE
    .\Deploy-NPASEnterpriseScenarios.ps1 -ServerName "NPAS-SERVER01" -Scenarios @("RADIUS", "802.1X", "VPN") -SecurityLevel "High"
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
    [string]$ScenarioFile,

    [Parameter(Mandatory = $false)]
    [string[]]$Scenarios,

    [Parameter(Mandatory = $false)]
    [switch]$DeployAll,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "High", "Enterprise")]
    [string]$SecurityLevel = "Standard",

    [Parameter(Mandatory = $false)]
    [string[]]$ComplianceStandards = @("NIST")
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script configuration
$scriptConfig = @{
    ServerName = $ServerName
    ScenarioFile = $ScenarioFile
    Scenarios = $Scenarios
    DeployAll = $DeployAll
    SecurityLevel = $SecurityLevel
    ComplianceStandards = $ComplianceStandards
    LogPath = "C:\NPAS\Logs\Enterprise-Scenarios"
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
    
    $logMessage | Out-File -FilePath "$($scriptConfig.LogPath)\NPAS-Enterprise-Scenarios.log" -Append -Encoding UTF8
}

try {
    Write-Log "Starting NPAS enterprise scenarios deployment..." "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Scenario File: $ScenarioFile" "Information"
    Write-Log "Scenarios: $($Scenarios -join ', ')" "Information"
    Write-Log "Deploy All: $DeployAll" "Information"
    Write-Log "Security Level: $SecurityLevel" "Information"
    Write-Log "Compliance Standards: $($ComplianceStandards -join ', ')" "Information"

    # Import required modules
    Write-Log "Importing NPAS modules..." "Information"
    $modulePath = Join-Path $PSScriptRoot "..\..\Modules"
    
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

    # Define all 30 enterprise scenarios
    $allScenarios = @{
        "RADIUS" = @{
            Name = "RADIUS Authentication for Network Devices"
            Description = "Centralized authentication for switches, wireless controllers, VPN concentrators, and firewalls"
            Function = "Set-NPASRadius"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "802.1X" = @{
            Name = "802.1X Wired and Wireless Authentication"
            Description = "Enterprise network security baseline with certificate-based authentication"
            Function = "Set-NPAS8021X"
            Dependencies = @("Certificate")
            SecurityLevel = "High"
        }
        "VPN" = @{
            Name = "VPN Authentication and Authorization"
            Description = "Policy-based remote access control with group-based policies"
            Function = "Set-NPASVPN"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "Certificate" = @{
            Name = "Certificate-Based Network Authentication"
            Description = "Passwordless, phishing-resistant access using certificates"
            Function = "Set-NPASCertificate"
            Dependencies = @()
            SecurityLevel = "High"
        }
        "CrossForest" = @{
            Name = "Cross-Forest Authentication"
            Description = "Multi-domain authentication for complex enterprise environments"
            Function = "Set-NPASCrossForest"
            Dependencies = @()
            SecurityLevel = "Enterprise"
        }
        "AzureAD" = @{
            Name = "Wi-Fi with Microsoft Entra ID"
            Description = "Cloud-connected enterprise authentication with Azure AD integration"
            Function = "Set-NPASFederation"
            Dependencies = @("Wireless")
            SecurityLevel = "Enterprise"
        }
        "Guest" = @{
            Name = "Guest or Contractor VLAN Assignment"
            Description = "Time-limited, internet-only access for visitors and contractors"
            Function = "Set-NPASGuest"
            Dependencies = @()
            SecurityLevel = "Basic"
        }
        "Conditional" = @{
            Name = "Conditional Network Access"
            Description = "Risk-based access control with device compliance and location awareness"
            Function = "Set-NPASConditional"
            Dependencies = @()
            SecurityLevel = "Enterprise"
        }
        "DynamicVLAN" = @{
            Name = "Wireless Authentication with Dynamic VLANs"
            Description = "Identity-based network segmentation with automatic VLAN assignment"
            Function = "Set-NPASVLAN"
            Dependencies = @("Wireless")
            SecurityLevel = "High"
        }
        "DHCP" = @{
            Name = "Integration with DHCP Enforcement"
            Description = "Network access control through DHCP lease management"
            Function = "Set-NPASDHCP"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "NAP" = @{
            Name = "Network Access Protection (NAP)"
            Description = "Health-based network access control with remediation"
            Function = "Set-NPASHealth"
            Dependencies = @()
            SecurityLevel = "High"
        }
        "DeviceHealth" = @{
            Name = "Integration with Device Health Attestation"
            Description = "Hardware-based security validation for trusted devices"
            Function = "Set-NPASDeviceHealth"
            Dependencies = @()
            SecurityLevel = "Enterprise"
        }
        "MFA" = @{
            Name = "Multi-Factor Authentication for VPNs"
            Description = "Enhanced security for remote access with second-factor authentication"
            Function = "Set-NPASMFA"
            Dependencies = @("VPN")
            SecurityLevel = "High"
        }
        "BYOD" = @{
            Name = "Wi-Fi Authentication for BYOD"
            Description = "Secure onboarding and management of personal devices"
            Function = "Set-NPASBYOD"
            Dependencies = @("Wireless")
            SecurityLevel = "Standard"
        }
        "Compliance" = @{
            Name = "Compliance-Driven Access Control"
            Description = "Regulatory compliance enforcement with audit trails"
            Function = "Set-NPASCompliance"
            Dependencies = @()
            SecurityLevel = "Enterprise"
        }
        "Proxy" = @{
            Name = "RADIUS Proxy and Multi-Site Redundancy"
            Description = "Distributed authentication with failover and load balancing"
            Function = "Set-NPASProxy"
            Dependencies = @("RADIUS")
            SecurityLevel = "Enterprise"
        }
        "LoadBalancing" = @{
            Name = "Load-Balanced RADIUS Infrastructure"
            Description = "High-availability authentication with traffic distribution"
            Function = "Set-NPASLoadBalancing"
            Dependencies = @("RADIUS")
            SecurityLevel = "Enterprise"
        }
        "Branch" = @{
            Name = "Wired Port Authentication in Branch Offices"
            Description = "Centralized policy enforcement for remote locations"
            Function = "Set-NPASBranch"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "Automation" = @{
            Name = "PowerShell Policy Automation"
            Description = "Infrastructure as Code for policy management and deployment"
            Function = "Set-NPASAutomation"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "RoleBased" = @{
            Name = "Role-Based Access for IT Staff"
            Description = "Granular permissions for administrative access"
            Function = "Set-NPASRoleBased"
            Dependencies = @()
            SecurityLevel = "High"
        }
        "GroupFilter" = @{
            Name = "Integration with AD Groups and OU Filters"
            Description = "Directory-based access control with organizational unit filtering"
            Function = "Set-NPASGroupFilter"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "Education" = @{
            Name = "Wireless Access in Educational Campuses"
            Description = "Student and faculty network access with educational policies"
            Function = "Set-NPASEducation"
            Dependencies = @("Wireless")
            SecurityLevel = "Standard"
        }
        "RDGateway" = @{
            Name = "Remote Desktop Gateway Integration"
            Description = "Secure remote desktop access with NPAS authentication"
            Function = "Set-NPASRDGateway"
            Dependencies = @()
            SecurityLevel = "High"
        }
        "IoT" = @{
            Name = "IoT Device Onboarding"
            Description = "Automated device registration and network access for IoT devices"
            Function = "Set-NPASIoT"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "SplitTunnel" = @{
            Name = "VPN Split-Tunnel Enforcement"
            Description = "Traffic routing control based on user identity and policies"
            Function = "Set-NPASSplitTunnel"
            Dependencies = @("VPN")
            SecurityLevel = "High"
        }
        "Federation" = @{
            Name = "Federated Authentication via ADFS or Azure AD"
            Description = "Single sign-on integration with identity providers"
            Function = "Set-NPASFederation"
            Dependencies = @()
            SecurityLevel = "Enterprise"
        }
        "GuestPortal" = @{
            Name = "Secure Guest Portal Integration"
            Description = "Self-service guest access with sponsor approval workflows"
            Function = "Set-NPASGuestPortal"
            Dependencies = @("Guest")
            SecurityLevel = "Standard"
        }
        "Firewall" = @{
            Name = "Integration with Firewalls or NAC Appliances"
            Description = "Network security appliance integration with policy enforcement"
            Function = "Set-NPASFirewall"
            Dependencies = @()
            SecurityLevel = "High"
        }
        "TACACS" = @{
            Name = "TACACS+ Alternative for Windows Environments"
            Description = "Cisco TACACS+ replacement with Windows-native authentication"
            Function = "Set-NPASTACACS"
            Dependencies = @()
            SecurityLevel = "Standard"
        }
        "Accounting" = @{
            Name = "RADIUS Logging and Accounting"
            Description = "Comprehensive audit trails and session tracking"
            Function = "Set-NPASAccounting"
            Dependencies = @("RADIUS")
            SecurityLevel = "Standard"
        }
    }

    # Determine which scenarios to deploy
    $scenariosToDeploy = @()
    
    if ($DeployAll) {
        $scenariosToDeploy = $allScenarios.Keys
        Write-Log "Deploying all 30 enterprise scenarios" "Information"
    } elseif ($Scenarios) {
        $scenariosToDeploy = $Scenarios
        Write-Log "Deploying specified scenarios: $($Scenarios -join ', ')" "Information"
    } else {
        # Default scenarios for basic deployment
        $scenariosToDeploy = @("RADIUS", "802.1X", "VPN", "Certificate", "Guest")
        Write-Log "Deploying default scenarios: $($scenariosToDeploy -join ', ')" "Information"
    }

    # Load scenario configuration if provided
    if ($ScenarioFile -and (Test-Path $ScenarioFile)) {
        Write-Log "Loading scenario configuration from $ScenarioFile..." "Information"
        Get-Content $ScenarioFile | ConvertFrom-Json | Out-Null
        Write-Log "Scenario configuration loaded successfully" "Success"
    } else {
        Write-Log "Using default scenario configuration" "Information"
    }

    # Track deployment results
    $deploymentResults = @{
        Successful = @()
        Failed = @()
        Skipped = @()
        Dependencies = @()
    }

    # Deploy scenarios
    foreach ($scenarioKey in $scenariosToDeploy) {
        if ($allScenarios.ContainsKey($scenarioKey)) {
            $scenario = $allScenarios[$scenarioKey]
            Write-Log "Deploying scenario: $($scenario.Name)" "Information"
            Write-Log "Description: $($scenario.Description)" "Information"
            Write-Log "Security Level: $($scenario.SecurityLevel)" "Information"
            
            # Check dependencies
            $dependenciesMet = $true
            foreach ($dependency in $scenario.Dependencies) {
                if (-not $deploymentResults.Successful.Contains($dependency)) {
                    Write-Log "Dependency $dependency not met for scenario $scenarioKey" "Warning"
                    $dependenciesMet = $false
                    $deploymentResults.Dependencies += $scenarioKey
                    break
                }
            }
            
            if (-not $dependenciesMet) {
                Write-Log "Skipping scenario $scenarioKey due to unmet dependencies" "Warning"
                $deploymentResults.Skipped += $scenarioKey
                continue
            }
            
            # Deploy scenario
            try {
                $deploymentResult = & $scenario.Function -ServerName $ServerName
                
                if ($deploymentResult.Success) {
                    Write-Log "Scenario $scenarioKey deployed successfully" "Success"
                    $deploymentResults.Successful += $scenarioKey
                } else {
                    Write-Log "Scenario $scenarioKey deployment failed: $($deploymentResult.Error)" "Warning"
                    $deploymentResults.Failed += $scenarioKey
                }
            } catch {
                Write-Log "Scenario $scenarioKey deployment failed with exception: $($_.Exception.Message)" "Error"
                $deploymentResults.Failed += $scenarioKey
            }
        } else {
            Write-Log "Unknown scenario: $scenarioKey" "Warning"
            $deploymentResults.Failed += $scenarioKey
        }
    }

    # Deploy additional scenarios for dependencies
    if ($deploymentResults.Dependencies.Count -gt 0) {
        Write-Log "Deploying additional scenarios for dependencies..." "Information"
        
        foreach ($scenarioKey in $deploymentResults.Dependencies) {
            if ($allScenarios.ContainsKey($scenarioKey)) {
                $scenario = $allScenarios[$scenarioKey]
                Write-Log "Deploying dependency scenario: $($scenario.Name)" "Information"
                
                try {
                    $deploymentResult = & $scenario.Function -ServerName $ServerName
                    
                    if ($deploymentResult.Success) {
                        Write-Log "Dependency scenario $scenarioKey deployed successfully" "Success"
                        $deploymentResults.Successful += $scenarioKey
                    } else {
                        Write-Log "Dependency scenario $scenarioKey deployment failed: $($deploymentResult.Error)" "Warning"
                        $deploymentResults.Failed += $scenarioKey
                    }
                } catch {
                    Write-Log "Dependency scenario $scenarioKey deployment failed with exception: $($_.Exception.Message)" "Error"
                    $deploymentResults.Failed += $scenarioKey
                }
            }
        }
    }

    # Configure security for deployed scenarios
    Write-Log "Configuring security for deployed scenarios..." "Information"
    $securityResult = Set-NPASAuthentication -ServerName $ServerName -AuthenticationMethods @("EAP-TLS", "PEAP-MS-CHAPv2", "MS-CHAPv2") -CertificateValidation -SmartCardSupport
    
    if ($securityResult.Success) {
        Write-Log "Security configuration completed successfully" "Success"
    } else {
        Write-Log "Security configuration failed: $($securityResult.Error)" "Warning"
    }

    # Configure compliance for deployed scenarios
    Write-Log "Configuring compliance for deployed scenarios..." "Information"
    $complianceResult = Set-NPASCompliance -ServerName $ServerName -ComplianceStandards $ComplianceStandards -PolicyEnforcement -RiskAssessment
    
    if ($complianceResult.Success) {
        Write-Log "Compliance configuration completed successfully" "Success"
    } else {
        Write-Log "Compliance configuration failed: $($complianceResult.Error)" "Warning"
    }

    # Test connectivity for deployed scenarios
    Write-Log "Testing connectivity for deployed scenarios..." "Information"
    $connectivityResult = Test-NPASConnectivity -ServerName $ServerName
    
    if ($connectivityResult.Success) {
        Write-Log "Connectivity test passed for deployed scenarios" "Success"
    } else {
        Write-Log "Connectivity test failed for deployed scenarios: $($connectivityResult.Error)" "Warning"
    }

    # Get final status
    Write-Log "Getting final NPAS status..." "Information"
    $statusResult = Get-NPASStatus -ServerName $ServerName
    
    if ($statusResult.Success) {
        Write-Log "Final status retrieved successfully" "Success"
        Write-Log "Service Status: $($statusResult.Status.ServiceStatus)" "Information"
        Write-Log "Policy Count: $($statusResult.Status.PolicyCount)" "Information"
        Write-Log "Total Requests: $($statusResult.Status.Statistics.TotalRequests)" "Information"
        Write-Log "Successful Requests: $($statusResult.Status.Statistics.SuccessfulRequests)" "Information"
        Write-Log "Failed Requests: $($statusResult.Status.Statistics.FailedRequests)" "Information"
        Write-Log "Active Connections: $($statusResult.Status.Statistics.ActiveConnections)" "Information"
    } else {
        Write-Log "Failed to get final status: $($statusResult.Error)" "Warning"
    }

    # Calculate deployment duration
    $deploymentDuration = (Get-Date) - $scriptConfig.StartTime
    Write-Log "NPAS enterprise scenarios deployment completed!" "Success"
    Write-Log "Deployment Duration: $($deploymentDuration.TotalMinutes) minutes" "Information"
    Write-Log "Scenarios Deployed: $($deploymentResults.Successful.Count)" "Information"
    Write-Log "Scenarios Failed: $($deploymentResults.Failed.Count)" "Information"
    Write-Log "Scenarios Skipped: $($deploymentResults.Skipped.Count)" "Information"
    Write-Log "Security Level: $SecurityLevel" "Information"
    Write-Log "Compliance Standards: $($ComplianceStandards -join ', ')" "Information"

    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "=== NPAS ENTERPRISE SCENARIOS DEPLOYMENT SUMMARY ===" -ForegroundColor Green
    Write-Host "Server Name: $ServerName" -ForegroundColor Cyan
    Write-Host "Deployment Duration: $($deploymentDuration.TotalMinutes) minutes" -ForegroundColor Cyan
    Write-Host "Scenarios Deployed: $($deploymentResults.Successful.Count)" -ForegroundColor Cyan
    Write-Host "Scenarios Failed: $($deploymentResults.Failed.Count)" -ForegroundColor Cyan
    Write-Host "Scenarios Skipped: $($deploymentResults.Skipped.Count)" -ForegroundColor Cyan
    Write-Host "Security Level: $SecurityLevel" -ForegroundColor Cyan
    Write-Host "Compliance Standards: $($ComplianceStandards -join ', ')" -ForegroundColor Cyan
    Write-Host "Log Path: $($scriptConfig.LogPath)" -ForegroundColor Cyan
    
    if ($deploymentResults.Successful.Count -gt 0) {
        Write-Host "`nSuccessfully Deployed Scenarios:" -ForegroundColor Green
        foreach ($scenario in $deploymentResults.Successful) {
            Write-Host "  ✓ $scenario" -ForegroundColor Green
        }
    }
    
    if ($deploymentResults.Failed.Count -gt 0) {
        Write-Host "`nFailed Scenarios:" -ForegroundColor Red
        foreach ($scenario in $deploymentResults.Failed) {
            Write-Host "  ✗ $scenario" -ForegroundColor Red
        }
    }
    
    if ($deploymentResults.Skipped.Count -gt 0) {
        Write-Host "`nSkipped Scenarios:" -ForegroundColor Yellow
        foreach ($scenario in $deploymentResults.Skipped) {
            Write-Host "  - $scenario" -ForegroundColor Yellow
        }
    }
    
    Write-Host "=================================================" -ForegroundColor Green

} catch {
    Write-Log "NPAS enterprise scenarios deployment failed: $($_.Exception.Message)" "Error"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
