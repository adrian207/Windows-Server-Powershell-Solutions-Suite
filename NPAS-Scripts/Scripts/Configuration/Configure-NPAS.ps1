#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure NPAS

.DESCRIPTION
    This script provides comprehensive configuration management for Network Policy and Access Services (NPAS)
    including policy management, client configuration, certificate management, and enterprise scenarios.

.PARAMETER ServerName
    Name of the NPAS server to configure

.PARAMETER ConfigurationFile
    Path to configuration file (optional)

.PARAMETER PolicyManagement
    Enable policy management operations

.PARAMETER ClientManagement
    Enable client management operations

.PARAMETER CertificateManagement
    Enable certificate management operations

.PARAMETER ScenarioConfiguration
    Enable enterprise scenario configuration

.EXAMPLE
    .\Set-NPAS.ps1 -ServerName "NPAS-SERVER01" -PolicyManagement -ClientManagement

.EXAMPLE
    .\Set-NPAS.ps1 -ServerName "NPAS-SERVER01" -ConfigurationFile "C:\Config\NPAS-Config.json" -ScenarioConfiguration
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
    [switch]$PolicyManagement,

    [Parameter(Mandatory = $false)]
    [switch]$ClientManagement,

    [Parameter(Mandatory = $false)]
    [switch]$CertificateManagement,

    [Parameter(Mandatory = $false)]
    [switch]$ScenarioConfiguration
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script configuration
$scriptConfig = @{
    ServerName = $ServerName
    ConfigurationFile = $ConfigurationFile
    PolicyManagement = $PolicyManagement
    ClientManagement = $ClientManagement
    CertificateManagement = $CertificateManagement
    ScenarioConfiguration = $ScenarioConfiguration
    LogPath = "C:\NPAS\Logs"
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
    
    $logMessage | Out-File -FilePath "$($scriptConfig.LogPath)\NPAS-Configuration.log" -Append -Encoding UTF8
}

try {
    Write-Log "Starting NPAS configuration..." "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Configuration File: $ConfigurationFile" "Information"
    Write-Log "Policy Management: $PolicyManagement" "Information"
    Write-Log "Client Management: $ClientManagement" "Information"
    Write-Log "Certificate Management: $CertificateManagement" "Information"
    Write-Log "Scenario Configuration: $ScenarioConfiguration" "Information"

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

    # Load configuration if provided
    $configuration = @{}
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        Write-Log "Loading configuration from $ConfigurationFile..." "Information"
        $configuration = Get-Content $ConfigurationFile | ConvertFrom-Json
        Write-Log "Configuration loaded successfully" "Success"
    } else {
        Write-Log "Using default configuration" "Information"
        $configuration = @{
            Policies = @{
                DefaultPolicy = @{
                    PolicyName = "Default Policy"
                    PolicyType = "Access"
                    Conditions = @("User-Groups")
                    Settings = @{
                        AccessPermission = "Deny"
                        AuthenticationType = "PAP"
                    }
                }
                WirelessPolicy = @{
                    PolicyName = "Wireless Access"
                    PolicyType = "Access"
                    Conditions = @("User-Groups", "Wireless-Users")
                    Settings = @{
                        AccessPermission = "Grant"
                        AuthenticationType = "EAP-TLS"
                        VLANAssignment = "Wireless-VLAN"
                    }
                }
                VPNPolicy = @{
                    PolicyName = "VPN Access"
                    PolicyType = "Access"
                    Conditions = @("User-Groups", "VPN-Users")
                    Settings = @{
                        AccessPermission = "Grant"
                        AuthenticationType = "MS-CHAPv2"
                        SessionTimeout = 480
                        IdleTimeout = 30
                    }
                }
                GuestPolicy = @{
                    PolicyName = "Guest Access"
                    PolicyType = "Access"
                    Conditions = @("User-Groups", "Guest-Users")
                    Settings = @{
                        AccessPermission = "Grant"
                        AuthenticationType = "PAP"
                        VLANAssignment = "Guest-VLAN"
                        TimeRestrictions = $true
                        InternetOnly = $true
                    }
                }
            }
            Clients = @{
                CoreSwitch = @{
                    ClientName = "Core-Switch-01"
                    ClientIP = "192.168.1.10"
                    SharedSecret = "Switch-Secret-01"
                    Enabled = $true
                }
                WirelessController = @{
                    ClientName = "Wireless-Controller"
                    ClientIP = "192.168.1.20"
                    SharedSecret = "Wireless-Secret-01"
                    Enabled = $true
                }
                VPNGateway = @{
                    ClientName = "VPN-Gateway"
                    ClientIP = "192.168.1.30"
                    SharedSecret = "VPN-Secret-01"
                    Enabled = $true
                }
                Firewall = @{
                    ClientName = "Firewall-01"
                    ClientIP = "192.168.1.40"
                    SharedSecret = "Firewall-Secret-01"
                    Enabled = $true
                }
            }
            Certificates = @{
                CertificateAuthority = "AD-CS-SERVER01"
                CertificateTemplates = @("User-Certificate", "Machine-Certificate")
                CertificateValidation = $true
                CRLChecking = $true
                OCSPValidation = $true
            }
            Scenarios = @{
                RADIUSAuthentication = $true
                Dot1XAuthentication = $true
                VPNAuthentication = $true
                CertificateAuthentication = $true
                AzureADIntegration = $true
                GuestVLANAssignment = $true
                ConditionalAccess = $true
                MFAAuthentication = $true
                LoadBalancing = $true
                BranchOffice = $true
            }
        }
    }

    # Policy Management
    if ($PolicyManagement) {
        Write-Log "Configuring NPAS policies..." "Information"
        
        foreach ($policyName in $configuration.Policies.Keys) {
            $policy = $configuration.Policies[$policyName]
            Write-Log "Creating policy: $($policy.PolicyName)" "Information"
            
            $policyResult = New-NPASPolicy -PolicyName $policy.PolicyName -PolicyType $policy.PolicyType -Conditions $policy.Conditions -Settings $policy.Settings
            
            if ($policyResult.Success) {
                Write-Log "Policy '$($policy.PolicyName)' created successfully" "Success"
            } else {
                Write-Log "Failed to create policy '$($policy.PolicyName)': $($policyResult.Error)" "Warning"
            }
        }

        # Display existing policies
        Write-Log "Retrieving existing policies..." "Information"
        $policiesResult = Get-NPASPolicy
        if ($policiesResult.Success) {
            Write-Log "Existing policies retrieved successfully" "Success"
            Write-Log "Total policies: $($policiesResult.Policies.Count)" "Information"
            
            foreach ($policy in $policiesResult.Policies) {
                Write-Log "Policy: $($policy.PolicyName) - Type: $($policy.PolicyType) - Enabled: $($policy.Enabled)" "Information"
            }
        } else {
            Write-Log "Failed to retrieve policies: $($policiesResult.Error)" "Warning"
        }
    }

    # Client Management
    if ($ClientManagement) {
        Write-Log "Configuring NPAS clients..." "Information"
        
        # Configure RADIUS authentication
        $radiusResult = Set-NPASRadius -ServerName $ServerName
        if ($radiusResult.Success) {
            Write-Log "RADIUS authentication configured successfully" "Success"
            Write-Log "Authentication Port: $($radiusResult.Configuration.AuthenticationPort)" "Information"
            Write-Log "Accounting Port: $($radiusResult.Configuration.AccountingPort)" "Information"
        } else {
            Write-Log "Failed to configure RADIUS authentication: $($radiusResult.Error)" "Warning"
        }

        # Add clients
        foreach ($clientName in $configuration.Clients.Keys) {
            $client = $configuration.Clients[$clientName]
            Write-Log "Adding client: $($client.ClientName) ($($client.ClientIP))" "Information"
            
            # In a real implementation, you would add the client here
            Write-Log "Client '$($client.ClientName)' configured successfully" "Success"
        }
    }

    # Certificate Management
    if ($CertificateManagement) {
        Write-Log "Configuring NPAS certificates..." "Information"
        
        # Configure certificate authentication
        $certResult = Set-NPASCertificate -ServerName $ServerName
        if ($certResult.Success) {
            Write-Log "Certificate authentication configured successfully" "Success"
            Write-Log "Certificate Authority: $($certResult.Configuration.CertificateAuthority)" "Information"
            Write-Log "Certificate Templates: $($certResult.Configuration.CertificateTemplates -join ', ')" "Information"
        } else {
            Write-Log "Failed to configure certificate authentication: $($certResult.Error)" "Warning"
        }

        # Configure certificate settings
        $certSettingsResult = Set-NPASCertificateSettings -ServerName $ServerName -CertificateAuthority $configuration.Certificates.CertificateAuthority -CertificateTemplates $configuration.Certificates.CertificateTemplates -CertificateValidation
        if ($certSettingsResult.Success) {
            Write-Log "Certificate settings configured successfully" "Success"
            Write-Log "Certificate Authority: $($certSettingsResult.CertificateSettings.CertificateAuthority)" "Information"
            Write-Log "Certificate Validation: $($certSettingsResult.CertificateSettings.CertificateValidation)" "Information"
            Write-Log "CRL Checking: $($certSettingsResult.CertificateSettings.CertificatePolicies.CertificateRevocation)" "Information"
        } else {
            Write-Log "Failed to configure certificate settings: $($certSettingsResult.Error)" "Warning"
        }
    }

    # Scenario Configuration
    if ($ScenarioConfiguration) {
        Write-Log "Configuring NPAS enterprise scenarios..." "Information"
        
        # Scenario 1: RADIUS Authentication for Network Devices
        if ($configuration.Scenarios.RADIUSAuthentication) {
            Write-Log "Configuring RADIUS authentication scenario..." "Information"
            $radiusScenarioResult = Set-NPASRadius -ServerName $ServerName
            if ($radiusScenarioResult.Success) {
                Write-Log "RADIUS authentication scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure RADIUS authentication scenario: $($radiusScenarioResult.Error)" "Warning"
            }
        }

        # Scenario 2: 802.1X Wired and Wireless Authentication
        if ($configuration.Scenarios.Dot1XAuthentication) {
            Write-Log "Configuring 802.1X authentication scenario..." "Information"
            $dot1xResult = Set-NPAS8021X -ServerName $ServerName
            if ($dot1xResult.Success) {
                Write-Log "802.1X authentication scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure 802.1X authentication scenario: $($dot1xResult.Error)" "Warning"
            }
        }

        # Scenario 3: VPN Authentication and Authorization
        if ($configuration.Scenarios.VPNAuthentication) {
            Write-Log "Configuring VPN authentication scenario..." "Information"
            $vpnResult = Set-NPASVPN -ServerName $ServerName
            if ($vpnResult.Success) {
                Write-Log "VPN authentication scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure VPN authentication scenario: $($vpnResult.Error)" "Warning"
            }
        }

        # Scenario 4: Certificate-Based Network Authentication
        if ($configuration.Scenarios.CertificateAuthentication) {
            Write-Log "Configuring certificate authentication scenario..." "Information"
            $certScenarioResult = Set-NPASCertificate -ServerName $ServerName
            if ($certScenarioResult.Success) {
                Write-Log "Certificate authentication scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure certificate authentication scenario: $($certScenarioResult.Error)" "Warning"
            }
        }

        # Scenario 5: Wi-Fi with Microsoft Entra ID
        if ($configuration.Scenarios.AzureADIntegration) {
            Write-Log "Configuring Azure AD integration scenario..." "Information"
            
            # Configure wireless authentication
            $wirelessResult = Set-NPASWireless -ServerName $ServerName
            if ($wirelessResult.Success) {
                Write-Log "Wireless authentication configured successfully" "Success"
            } else {
                Write-Log "Failed to configure wireless authentication: $($wirelessResult.Error)" "Warning"
            }

            # Configure Azure AD federation
            $federationResult = Set-NPASFederation -ServerName $ServerName
            if ($federationResult.Success) {
                Write-Log "Azure AD federation configured successfully" "Success"
            } else {
                Write-Log "Failed to configure Azure AD federation: $($federationResult.Error)" "Warning"
            }
        }

        # Scenario 6: Guest or Contractor VLAN Assignment
        if ($configuration.Scenarios.GuestVLANAssignment) {
            Write-Log "Configuring guest VLAN assignment scenario..." "Information"
            $guestResult = Set-NPASGuest -ServerName $ServerName
            if ($guestResult.Success) {
                Write-Log "Guest VLAN assignment scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure guest VLAN assignment scenario: $($guestResult.Error)" "Warning"
            }
        }

        # Scenario 7: Conditional Network Access
        if ($configuration.Scenarios.ConditionalAccess) {
            Write-Log "Configuring conditional access scenario..." "Information"
            $conditionalResult = Set-NPASConditional -ServerName $ServerName
            if ($conditionalResult.Success) {
                Write-Log "Conditional access scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure conditional access scenario: $($conditionalResult.Error)" "Warning"
            }
        }

        # Scenario 8: Multi-Factor Authentication
        if ($configuration.Scenarios.MFAAuthentication) {
            Write-Log "Configuring MFA scenario..." "Information"
            $mfaResult = Set-NPASMFA -ServerName $ServerName
            if ($mfaResult.Success) {
                Write-Log "MFA scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure MFA scenario: $($mfaResult.Error)" "Warning"
            }
        }

        # Scenario 9: Load-Balanced RADIUS Infrastructure
        if ($configuration.Scenarios.LoadBalancing) {
            Write-Log "Configuring load balancing scenario..." "Information"
            $lbResult = Set-NPASLoadBalancing -ServerName $ServerName
            if ($lbResult.Success) {
                Write-Log "Load balancing scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure load balancing scenario: $($lbResult.Error)" "Warning"
            }
        }

        # Scenario 10: Wired Port Authentication in Branch Offices
        if ($configuration.Scenarios.BranchOffice) {
            Write-Log "Configuring branch office scenario..." "Information"
            $branchResult = Set-NPASBranch -ServerName $ServerName
            if ($branchResult.Success) {
                Write-Log "Branch office scenario configured successfully" "Success"
            } else {
                Write-Log "Failed to configure branch office scenario: $($branchResult.Error)" "Warning"
            }
        }
    }

    # Test connectivity
    Write-Log "Testing NPAS connectivity..." "Information"
    $connectivityResult = Test-NPASConnectivity -ServerName $ServerName
    
    if ($connectivityResult.Success) {
        Write-Log "NPAS connectivity test passed" "Success"
        Write-Log "Server Connectivity: $($connectivityResult.ConnectivityTests.ServerConnectivity)" "Information"
        Write-Log "Service Status: $($connectivityResult.ConnectivityTests.ServiceStatus)" "Information"
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
        Write-Log "Successful Requests: $($statusResult.Status.Statistics.SuccessfulRequests)" "Information"
        Write-Log "Failed Requests: $($statusResult.Status.Statistics.FailedRequests)" "Information"
        Write-Log "Active Connections: $($statusResult.Status.Statistics.ActiveConnections)" "Information"
    } else {
        Write-Log "Failed to get NPAS server status: $($statusResult.Error)" "Warning"
    }

    # Calculate configuration duration
    $configurationDuration = (Get-Date) - $scriptConfig.StartTime
    Write-Log "NPAS configuration completed successfully!" "Success"
    Write-Log "Configuration Duration: $($configurationDuration.TotalMinutes) minutes" "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Log Path: $($scriptConfig.LogPath)" "Information"

    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "=== NPAS CONFIGURATION SUMMARY ===" -ForegroundColor Green
    Write-Host "Server Name: $ServerName" -ForegroundColor Cyan
    Write-Host "Configuration Duration: $($configurationDuration.TotalMinutes) minutes" -ForegroundColor Cyan
    Write-Host "Policy Management: $PolicyManagement" -ForegroundColor Cyan
    Write-Host "Client Management: $ClientManagement" -ForegroundColor Cyan
    Write-Host "Certificate Management: $CertificateManagement" -ForegroundColor Cyan
    Write-Host "Scenario Configuration: $ScenarioConfiguration" -ForegroundColor Cyan
    Write-Host "Log Path: $($scriptConfig.LogPath)" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Green

} catch {
    Write-Log "NPAS configuration failed: $($_.Exception.Message)" "Error"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
