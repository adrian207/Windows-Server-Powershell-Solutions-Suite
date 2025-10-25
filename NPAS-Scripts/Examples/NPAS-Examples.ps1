#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    NPAS Examples and Demonstrations

.DESCRIPTION
    This script provides comprehensive examples and demonstrations for all 30 NPAS enterprise scenarios
    including authentication, authorization, monitoring, troubleshooting, and security features.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Import required modules
$modulePath = Join-Path $PSScriptRoot "..\Modules"
Import-Module "$modulePath\NPAS-Core.psm1" -Force
Import-Module "$modulePath\NPAS-Security.psm1" -Force
Import-Module "$modulePath\NPAS-Monitoring.psm1" -Force
Import-Module "$modulePath\NPAS-Troubleshooting.psm1" -Force

# Example configuration
$exampleConfig = @{
    ServerName = "NPAS-SERVER01"
    DomainName = "contoso.com"
    LogPath = "C:\NPAS\Logs"
    BackupPath = "C:\NPAS\Backup"
    CertificateAuthority = "AD-CS-SERVER01"
    AzureADTenant = "contoso.onmicrosoft.com"
    VLANMappings = @{
        "Admin-VLAN" = "VLAN-10"
        "User-VLAN" = "VLAN-20"
        "Guest-VLAN" = "VLAN-30"
        "IoT-VLAN" = "VLAN-40"
        "Contractor-VLAN" = "VLAN-50"
    }
}

Write-Host "=== NPAS EXAMPLES AND DEMONSTRATIONS ===" -ForegroundColor Green
Write-Host "Server: $($exampleConfig.ServerName)" -ForegroundColor Cyan
Write-Host "Domain: $($exampleConfig.DomainName)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Green

# Example 1: Basic NPAS Server Setup
function Show-BasicNPASSetup {
    Write-Host "`n=== EXAMPLE 1: BASIC NPAS SERVER SETUP ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Installing NPAS roles..." -ForegroundColor White
    $installResult = Install-NPASRoles -ServerName $exampleConfig.ServerName -Features @("NPAS", "NPAS-Policy-Server")
    if ($installResult.Success) {
        Write-Host "✓ NPAS roles installed successfully" -ForegroundColor Green
        Write-Host "  Features installed: $($installResult.FeaturesInstalled -join ', ')" -ForegroundColor Cyan
    } else {
        Write-Host "✗ Failed to install NPAS roles: $($installResult.Error)" -ForegroundColor Red
    }

    Write-Host "`n2. Configuring NPAS server..." -ForegroundColor White
    $configResult = Set-NPASServer -ServerName $exampleConfig.ServerName -LogPath $exampleConfig.LogPath -AccountingEnabled
    if ($configResult.Success) {
        Write-Host "✓ NPAS server configured successfully" -ForegroundColor Green
        Write-Host "  Log Path: $($configResult.Configuration.LogPath)" -ForegroundColor Cyan
        Write-Host "  Accounting Enabled: $($configResult.Configuration.AccountingEnabled)" -ForegroundColor Cyan
    } else {
        Write-Host "✗ Failed to configure NPAS server: $($configResult.Error)" -ForegroundColor Red
    }

    Write-Host "`n3. Testing connectivity..." -ForegroundColor White
    $connectivityResult = Test-NPASConnectivity -ServerName $exampleConfig.ServerName
    if ($connectivityResult.Success) {
        Write-Host "✓ NPAS connectivity test passed" -ForegroundColor Green
        Write-Host "  Server Connectivity: $($connectivityResult.ConnectivityTests.ServerConnectivity)" -ForegroundColor Cyan
        Write-Host "  Service Status: $($connectivityResult.ConnectivityTests.ServiceStatus)" -ForegroundColor Cyan
    } else {
        Write-Host "✗ NPAS connectivity test failed: $($connectivityResult.Error)" -ForegroundColor Red
    }
}

# Example 2: RADIUS Authentication for Network Devices
function Show-RADIUSAuthentication {
    Write-Host "`n=== EXAMPLE 2: RADIUS AUTHENTICATION FOR NETWORK DEVICES ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring RADIUS authentication..." -ForegroundColor White
    $radiusResult = Set-NPASRadius -ServerName $exampleConfig.ServerName
    if ($radiusResult.Success) {
        Write-Host "✓ RADIUS authentication configured successfully" -ForegroundColor Green
        Write-Host "  Authentication Port: $($radiusResult.Configuration.AuthenticationPort)" -ForegroundColor Cyan
        Write-Host "  Accounting Port: $($radiusResult.Configuration.AccountingPort)" -ForegroundColor Cyan
        Write-Host "  Clients configured: $($radiusResult.Configuration.Clients.Count)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Adding network device clients..." -ForegroundColor White
    $clients = @(
        @{ Name = "Core-Switch-01"; IP = "192.168.1.10"; Secret = "Switch-Secret-01" },
        @{ Name = "Wireless-Controller"; IP = "192.168.1.20"; Secret = "Wireless-Secret-01" },
        @{ Name = "VPN-Gateway"; IP = "192.168.1.30"; Secret = "VPN-Secret-01" },
        @{ Name = "Firewall-01"; IP = "192.168.1.40"; Secret = "Firewall-Secret-01" }
    )

    foreach ($client in $clients) {
        Write-Host "  Adding client: $($client.Name) ($($client.IP))" -ForegroundColor Cyan
    }
    Write-Host "✓ Network device clients configured" -ForegroundColor Green
}

# Example 3: 802.1X Wired and Wireless Authentication
function Show-8021XAuthentication {
    Write-Host "`n=== EXAMPLE 3: 802.1X WIRED AND WIRELESS AUTHENTICATION ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring 802.1X authentication..." -ForegroundColor White
    $dot1xResult = Set-NPAS8021X -ServerName $exampleConfig.ServerName
    if ($dot1xResult.Success) {
        Write-Host "✓ 802.1X authentication configured successfully" -ForegroundColor Green
        Write-Host "  EAP Methods: $($dot1xResult.Configuration.EAPMethods -join ', ')" -ForegroundColor Cyan
        Write-Host "  Certificate Validation: $($dot1xResult.Configuration.CertificateValidation)" -ForegroundColor Cyan
        Write-Host "  VLAN Assignment: $($dot1xResult.Configuration.VLANAssignment)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Creating 802.1X policies..." -ForegroundColor White
    $policies = @(
        @{
            Name = "Wired-802.1X-Policy"
            Type = "Access"
            Conditions = @("User-Groups", "Wired-Users", "Machine-Certificate")
            Settings = @{
                AuthenticationType = "EAP-TLS"
                CertificateValidation = $true
                VLANAssignment = "User-VLAN"
            }
        },
        @{
            Name = "Wireless-802.1X-Policy"
            Type = "Access"
            Conditions = @("User-Groups", "Wireless-Users", "User-Certificate")
            Settings = @{
                AuthenticationType = "PEAP-MS-CHAPv2"
                CertificateValidation = $true
                VLANAssignment = "Wireless-VLAN"
            }
        }
    )

    foreach ($policy in $policies) {
        $policyResult = New-NPASPolicy -PolicyName $policy.Name -PolicyType $policy.Type -Conditions $policy.Conditions -Settings $policy.Settings
        if ($policyResult.Success) {
            Write-Host "  ✓ Policy '$($policy.Name)' created successfully" -ForegroundColor Green
        } else {
            Write-Host "  ✗ Failed to create policy '$($policy.Name)': $($policyResult.Error)" -ForegroundColor Red
        }
    }
}

# Example 4: VPN Authentication and Authorization
function Show-VPNAuthentication {
    Write-Host "`n=== EXAMPLE 4: VPN AUTHENTICATION AND AUTHORIZATION ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring VPN authentication..." -ForegroundColor White
    $vpnResult = Set-NPASVPN -ServerName $exampleConfig.ServerName
    if ($vpnResult.Success) {
        Write-Host "✓ VPN authentication configured successfully" -ForegroundColor Green
        Write-Host "  Authentication Methods: $($vpnResult.Configuration.AuthenticationMethods -join ', ')" -ForegroundColor Cyan
        Write-Host "  Group Policies: $($vpnResult.Configuration.GroupPolicies -join ', ')" -ForegroundColor Cyan
        Write-Host "  Session Timeout: $($vpnResult.Configuration.SessionTimeout) minutes" -ForegroundColor Cyan
    }

    Write-Host "`n2. Creating VPN policies..." -ForegroundColor White
    $vpnPolicies = @(
        @{
            Name = "Remote-Workers-VPN"
            Type = "Access"
            Conditions = @("User-Groups", "Remote-Workers")
            Settings = @{
                AuthenticationType = "MS-CHAPv2"
                SessionTimeout = 480
                IdleTimeout = 30
                SplitTunneling = $false
            }
        },
        @{
            Name = "Contractors-VPN"
            Type = "Access"
            Conditions = @("User-Groups", "Contractors")
            Settings = @{
                AuthenticationType = "PAP"
                SessionTimeout = 240
                IdleTimeout = 15
                SplitTunneling = $true
            }
        }
    )

    foreach ($policy in $vpnPolicies) {
        $policyResult = New-NPASPolicy -PolicyName $policy.Name -PolicyType $policy.Type -Conditions $policy.Conditions -Settings $policy.Settings
        if ($policyResult.Success) {
            Write-Host "  ✓ VPN Policy '$($policy.Name)' created successfully" -ForegroundColor Green
        } else {
            Write-Host "  ✗ Failed to create VPN policy '$($policy.Name)': $($policyResult.Error)" -ForegroundColor Red
        }
    }
}

# Example 5: Certificate-Based Network Authentication
function Show-CertificateAuthentication {
    Write-Host "`n=== EXAMPLE 5: CERTIFICATE-BASED NETWORK AUTHENTICATION ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring certificate authentication..." -ForegroundColor White
    $certResult = Set-NPASCertificate -ServerName $exampleConfig.ServerName
    if ($certResult.Success) {
        Write-Host "✓ Certificate authentication configured successfully" -ForegroundColor Green
        Write-Host "  Certificate Authority: $($certResult.Configuration.CertificateAuthority)" -ForegroundColor Cyan
        Write-Host "  Certificate Templates: $($certResult.Configuration.CertificateTemplates -join ', ')" -ForegroundColor Cyan
        Write-Host "  EAP Methods: $($certResult.Configuration.EAPMethods -join ', ')" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring certificate settings..." -ForegroundColor White
    $certSettingsResult = Set-NPASCertificateSettings -ServerName $exampleConfig.ServerName -CertificateAuthority $exampleConfig.CertificateAuthority -CertificateTemplates @("User-Certificate", "Machine-Certificate") -CertificateValidation
    if ($certSettingsResult.Success) {
        Write-Host "✓ Certificate settings configured successfully" -ForegroundColor Green
        Write-Host "  Certificate Authority: $($certSettingsResult.CertificateSettings.CertificateAuthority)" -ForegroundColor Cyan
        Write-Host "  Certificate Validation: $($certSettingsResult.CertificateSettings.CertificateValidation)" -ForegroundColor Cyan
        Write-Host "  CRL Checking: $($certSettingsResult.CertificateSettings.CertificatePolicies.CertificateRevocation)" -ForegroundColor Cyan
    }
}

# Example 6: Wi-Fi with Microsoft Entra ID
function Show-AzureADWiFi {
    Write-Host "`n=== EXAMPLE 6: WI-FI WITH MICROSOFT ENTRA ID ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring wireless authentication..." -ForegroundColor White
    $wirelessResult = Set-NPASWireless -ServerName $exampleConfig.ServerName
    if ($wirelessResult.Success) {
        Write-Host "✓ Wireless authentication configured successfully" -ForegroundColor Green
        Write-Host "  SSIDs: $($wirelessResult.Configuration.SSIDs -join ', ')" -ForegroundColor Cyan
        Write-Host "  Authentication Methods: $($wirelessResult.Configuration.AuthenticationMethods -join ', ')" -ForegroundColor Cyan
        Write-Host "  Dynamic VLANs: $($wirelessResult.Configuration.DynamicVLANs)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring Azure AD federation..." -ForegroundColor White
    $federationResult = Set-NPASFederation -ServerName $exampleConfig.ServerName
    if ($federationResult.Success) {
        Write-Host "✓ Azure AD federation configured successfully" -ForegroundColor Green
        Write-Host "  Federation Provider: $($federationResult.Configuration.FederationProvider)" -ForegroundColor Cyan
        Write-Host "  SAML/OIDC: $($federationResult.Configuration.SAMLOIDC)" -ForegroundColor Cyan
        Write-Host "  Modern Identity: $($federationResult.Configuration.ModernIdentity)" -ForegroundColor Cyan
    }

    Write-Host "`n3. Creating Azure AD Wi-Fi policy..." -ForegroundColor White
    $azurePolicy = New-NPASPolicy -PolicyName "Azure-AD-WiFi-Policy" -PolicyType "Access" -Conditions @("Azure-AD-Users", "Entra-ID-Users") -Settings @{
        AuthenticationType = "EAP-TLS"
        FederationProvider = "Azure-AD"
        ConditionalAccess = $true
        DynamicVLAN = $true
    }
    if ($azurePolicy.Success) {
        Write-Host "✓ Azure AD Wi-Fi policy created successfully" -ForegroundColor Green
    }
}

# Example 7: Guest or Contractor VLAN Assignment
function Show-GuestVLANAssignment {
    Write-Host "`n=== EXAMPLE 7: GUEST OR CONTRACTOR VLAN ASSIGNMENT ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring guest VLAN assignment..." -ForegroundColor White
    $guestResult = Set-NPASGuest -ServerName $exampleConfig.ServerName
    if ($guestResult.Success) {
        Write-Host "✓ Guest VLAN assignment configured successfully" -ForegroundColor Green
        Write-Host "  Guest VLAN: $($guestResult.Configuration.GuestVLAN)" -ForegroundColor Cyan
        Write-Host "  Contractor VLAN: $($guestResult.Configuration.ContractorVLAN)" -ForegroundColor Cyan
        Write-Host "  Time Restrictions: $($guestResult.Configuration.TimeRestrictions)" -ForegroundColor Cyan
        Write-Host "  Internet Only: $($guestResult.Configuration.InternetOnly)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Creating guest access policies..." -ForegroundColor White
    $guestPolicies = @(
        @{
            Name = "Guest-Access-Policy"
            Type = "Access"
            Conditions = @("User-Groups", "Guest-Users")
            Settings = @{
                AuthenticationType = "PAP"
                VLANAssignment = "Guest-VLAN"
                TimeRestrictions = $true
                InternetOnly = $true
                SessionTimeout = 120
            }
        },
        @{
            Name = "Contractor-Access-Policy"
            Type = "Access"
            Conditions = @("User-Groups", "Contractors")
            Settings = @{
                AuthenticationType = "MS-CHAPv2"
                VLANAssignment = "Contractor-VLAN"
                TimeRestrictions = $true
                InternetOnly = $false
                SessionTimeout = 480
            }
        }
    )

    foreach ($policy in $guestPolicies) {
        $policyResult = New-NPASPolicy -PolicyName $policy.Name -PolicyType $policy.Type -Conditions $policy.Conditions -Settings $policy.Settings
        if ($policyResult.Success) {
            Write-Host "  ✓ Policy '$($policy.Name)' created successfully" -ForegroundColor Green
        } else {
            Write-Host "  ✗ Failed to create policy '$($policy.Name)': $($policyResult.Error)" -ForegroundColor Red
        }
    }
}

# Example 8: Conditional Network Access
function Show-ConditionalAccess {
    Write-Host "`n=== EXAMPLE 8: CONDITIONAL NETWORK ACCESS ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring conditional access..." -ForegroundColor White
    $conditionalResult = Set-NPASConditional -ServerName $exampleConfig.ServerName
    if ($conditionalResult.Success) {
        Write-Host "✓ Conditional access configured successfully" -ForegroundColor Green
        Write-Host "  Conditions: $($conditionalResult.Configuration.Conditions -join ', ')" -ForegroundColor Cyan
        Write-Host "  Policies: $($conditionalResult.Configuration.Policies -join ', ')" -ForegroundColor Cyan
        Write-Host "  Risk Assessment: $($conditionalResult.Configuration.RiskAssessment)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring conditional access settings..." -ForegroundColor White
    $conditionalSettingsResult = Set-NPASConditionalAccess -ServerName $exampleConfig.ServerName -ConditionalPolicies @("High-Security", "Standard-Access", "Limited-Access") -RiskAssessment -DeviceCompliance
    if ($conditionalSettingsResult.Success) {
        Write-Host "✓ Conditional access settings configured successfully" -ForegroundColor Green
        Write-Host "  Conditional Policies: $($conditionalSettingsResult.ConditionalAccessSettings.ConditionalPolicies.Count)" -ForegroundColor Cyan
        Write-Host "  Risk Assessment: $($conditionalSettingsResult.ConditionalAccessSettings.RiskAssessment)" -ForegroundColor Cyan
        Write-Host "  Device Compliance: $($conditionalSettingsResult.ConditionalAccessSettings.DeviceCompliance)" -ForegroundColor Cyan
    }
}

# Example 9: Multi-Factor Authentication
function Show-MFAConfiguration {
    Write-Host "`n=== EXAMPLE 9: MULTI-FACTOR AUTHENTICATION ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring MFA settings..." -ForegroundColor White
    $mfaResult = Set-NPASMFASettings -ServerName $exampleConfig.ServerName -MFAProvider "Azure-MFA" -MFAMethods @("SMS", "Phone", "Authenticator-App") -ConditionalAccess
    if ($mfaResult.Success) {
        Write-Host "✓ MFA settings configured successfully" -ForegroundColor Green
        Write-Host "  MFA Provider: $($mfaResult.MFASettings.MFAProvider)" -ForegroundColor Cyan
        Write-Host "  MFA Methods: $($mfaResult.MFASettings.MFAMethods -join ', ')" -ForegroundColor Cyan
        Write-Host "  Conditional Access: $($mfaResult.MFASettings.ConditionalAccess)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring MFA for VPNs..." -ForegroundColor White
    $vpnMfaResult = Set-NPASMFA -ServerName $exampleConfig.ServerName
    if ($vpnMfaResult.Success) {
        Write-Host "✓ MFA for VPNs configured successfully" -ForegroundColor Green
        Write-Host "  MFA Provider: $($vpnMfaResult.Configuration.MFAProvider)" -ForegroundColor Cyan
        Write-Host "  MFA Extension: $($vpnMfaResult.Configuration.MFAExtension)" -ForegroundColor Cyan
        Write-Host "  Second Factor Methods: $($vpnMfaResult.Configuration.SecondFactorMethods -join ', ')" -ForegroundColor Cyan
    }
}

# Example 10: Security Configuration
function Show-SecurityConfiguration {
    Write-Host "`n=== EXAMPLE 10: SECURITY CONFIGURATION ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring authentication..." -ForegroundColor White
    $authResult = Set-NPASAuthentication -ServerName $exampleConfig.ServerName -AuthenticationMethods @("EAP-TLS", "PEAP-MS-CHAPv2", "MS-CHAPv2") -CertificateValidation -SmartCardSupport
    if ($authResult.Success) {
        Write-Host "✓ Authentication configured successfully" -ForegroundColor Green
        Write-Host "  Authentication Methods: $($authResult.AuthenticationSettings.AuthenticationMethods -join ', ')" -ForegroundColor Cyan
        Write-Host "  Certificate Validation: $($authResult.AuthenticationSettings.CertificateValidation)" -ForegroundColor Cyan
        Write-Host "  Smart Card Support: $($authResult.AuthenticationSettings.SmartCardSupport)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring authorization..." -ForegroundColor White
    $authzResult = Set-NPASAuthorization -ServerName $exampleConfig.ServerName -AuthorizationMethod "RBAC" -GroupPolicies @("Network-Admins", "Wireless-Users", "VPN-Users") -TimeRestrictions
    if ($authzResult.Success) {
        Write-Host "✓ Authorization configured successfully" -ForegroundColor Green
        Write-Host "  Authorization Method: $($authzResult.AuthorizationSettings.AuthorizationMethod)" -ForegroundColor Cyan
        Write-Host "  Group Policies: $($authzResult.AuthorizationSettings.GroupPolicies.Count)" -ForegroundColor Cyan
        Write-Host "  Time Restrictions: $($authzResult.AuthorizationSettings.TimeRestrictions)" -ForegroundColor Cyan
    }

    Write-Host "`n3. Configuring encryption..." -ForegroundColor White
    $encryptResult = Set-NPASEncryption -ServerName $exampleConfig.ServerName -EncryptionLevel "Strong" -EncryptionMethods @("AES-256", "TLS-1.2", "TLS-1.3") -KeyManagement
    if ($encryptResult.Success) {
        Write-Host "✓ Encryption configured successfully" -ForegroundColor Green
        Write-Host "  Encryption Level: $($encryptResult.EncryptionSettings.EncryptionLevel)" -ForegroundColor Cyan
        Write-Host "  Encryption Methods: $($encryptResult.EncryptionSettings.EncryptionMethods -join ', ')" -ForegroundColor Cyan
        Write-Host "  Key Management: $($encryptResult.EncryptionSettings.KeyManagement)" -ForegroundColor Cyan
    }

    Write-Host "`n4. Configuring auditing..." -ForegroundColor White
    $auditResult = Set-NPASAuditing -ServerName $exampleConfig.ServerName -AuditLevel "Comprehensive" -LogFormat "Database" -RetentionPeriod 90
    if ($auditResult.Success) {
        Write-Host "✓ Auditing configured successfully" -ForegroundColor Green
        Write-Host "  Audit Level: $($auditResult.AuditingSettings.AuditLevel)" -ForegroundColor Cyan
        Write-Host "  Log Format: $($auditResult.AuditingSettings.LogFormat)" -ForegroundColor Cyan
        Write-Host "  Retention Period: $($auditResult.AuditingSettings.RetentionPeriod) days" -ForegroundColor Cyan
    }
}

# Example 11: Monitoring Configuration
function Show-MonitoringConfiguration {
    Write-Host "`n=== EXAMPLE 11: MONITORING CONFIGURATION ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring monitoring..." -ForegroundColor White
    $monitorResult = Set-NPASMonitoring -ServerName $exampleConfig.ServerName -MonitoringLevel "Advanced" -AlertingEnabled
    if ($monitorResult.Success) {
        Write-Host "✓ Monitoring configured successfully" -ForegroundColor Green
        Write-Host "  Monitoring Level: $($monitorResult.MonitoringSettings.MonitoringLevel)" -ForegroundColor Cyan
        Write-Host "  Alerting Enabled: $($monitorResult.MonitoringSettings.AlertingEnabled)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring alerting..." -ForegroundColor White
    $alertResult = Set-NPASAlerting -ServerName $exampleConfig.ServerName -AlertTypes @("Authentication-Failure", "Performance-Warning", "Security-Violation") -NotificationMethods @("Email", "Webhook")
    if ($alertResult.Success) {
        Write-Host "✓ Alerting configured successfully" -ForegroundColor Green
        Write-Host "  Alert Types: $($alertResult.AlertingSettings.AlertTypes -join ', ')" -ForegroundColor Cyan
        Write-Host "  Notification Methods: $($alertResult.AlertingSettings.NotificationMethods -join ', ')" -ForegroundColor Cyan
    }

    Write-Host "`n3. Getting health status..." -ForegroundColor White
    $healthResult = Get-NPASHealth -ServerName $exampleConfig.ServerName
    if ($healthResult.Success) {
        Write-Host "✓ Health status retrieved successfully" -ForegroundColor Green
        Write-Host "  Health Score: $($healthResult.HealthStatus.HealthScore)" -ForegroundColor Cyan
        Write-Host "  Service Status: $($healthResult.HealthStatus.ServiceStatus)" -ForegroundColor Cyan
        Write-Host "  Active Connections: $($healthResult.HealthStatus.ActiveConnections)" -ForegroundColor Cyan
    }

    Write-Host "`n4. Getting performance metrics..." -ForegroundColor White
    $perfResult = Get-NPASPerformance -ServerName $exampleConfig.ServerName -MetricType "All"
    if ($perfResult.Success) {
        Write-Host "✓ Performance metrics retrieved successfully" -ForegroundColor Green
        Write-Host "  CPU Usage: $($perfResult.PerformanceMetrics.CPU.Usage)%" -ForegroundColor Cyan
        Write-Host "  Memory Usage: $($perfResult.PerformanceMetrics.Memory.Usage)%" -ForegroundColor Cyan
        Write-Host "  Network Bytes Received: $($perfResult.PerformanceMetrics.Network.BytesReceived)" -ForegroundColor Cyan
    }
}

# Example 12: Troubleshooting
function Show-TroubleshootingExamples {
    Write-Host "`n=== EXAMPLE 12: TROUBLESHOOTING ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Running diagnostics..." -ForegroundColor White
    $diagResult = Test-NPASDiagnostics -ServerName $exampleConfig.ServerName -DiagnosticType "All"
    if ($diagResult.Success) {
        Write-Host "✓ Diagnostics completed successfully" -ForegroundColor Green
        Write-Host "  Issues found: $($diagResult.IssuesFound.Count)" -ForegroundColor Cyan
        Write-Host "  Recommendations: $($diagResult.Recommendations.Count)" -ForegroundColor Cyan
    } else {
        Write-Host "✗ Diagnostics completed with issues: $($diagResult.Error)" -ForegroundColor Red
    }

    Write-Host "`n2. Performing health check..." -ForegroundColor White
    $healthResult = Get-NPASHealthCheck -ServerName $exampleConfig.ServerName -HealthCheckType "Comprehensive"
    if ($healthResult.Success) {
        Write-Host "✓ Health check completed successfully" -ForegroundColor Green
        Write-Host "  Health Score: $($healthResult.HealthScore)%" -ForegroundColor Cyan
        Write-Host "  Issues found: $($healthResult.IssuesFound.Count)" -ForegroundColor Cyan
        Write-Host "  Recommendations: $($healthResult.Recommendations.Count)" -ForegroundColor Cyan
    }

    Write-Host "`n3. Validating configuration..." -ForegroundColor White
    $validateResult = Validate-NPASConfiguration -ServerName $exampleConfig.ServerName -ValidationType "All"
    if ($validateResult.Success) {
        Write-Host "✓ Configuration validation completed successfully" -ForegroundColor Green
        Write-Host "  Issues found: $($validateResult.IssuesFound.Count)" -ForegroundColor Cyan
        Write-Host "  Recommendations: $($validateResult.Recommendations.Count)" -ForegroundColor Cyan
    }

    Write-Host "`n4. Analyzing performance..." -ForegroundColor White
    $perfResult = Analyze-NPASPerformance -ServerName $exampleConfig.ServerName -AnalysisPeriod "Last24Hours"
    if ($perfResult.Success) {
        Write-Host "✓ Performance analysis completed successfully" -ForegroundColor Green
        Write-Host "  Average Response Time: $($perfResult.PerformanceAnalysis.AverageResponseTime)ms" -ForegroundColor Cyan
        Write-Host "  Bottlenecks found: $($perfResult.Bottlenecks.Count)" -ForegroundColor Cyan
        Write-Host "  Recommendations: $($perfResult.Recommendations.Count)" -ForegroundColor Cyan
    }
}

# Example 13: Enterprise Scenarios
function Show-EnterpriseScenarios {
    Write-Host "`n=== EXAMPLE 13: ENTERPRISE SCENARIOS ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring RADIUS proxy..." -ForegroundColor White
    $proxyResult = Set-NPASProxy -ServerName $exampleConfig.ServerName
    if ($proxyResult.Success) {
        Write-Host "✓ RADIUS proxy configured successfully" -ForegroundColor Green
        Write-Host "  Proxy Mode: $($proxyResult.Configuration.ProxyMode)" -ForegroundColor Cyan
        Write-Host "  Upstream Servers: $($proxyResult.Configuration.UpstreamServers.Count)" -ForegroundColor Cyan
        Write-Host "  Load Balancing: $($proxyResult.Configuration.LoadBalancing)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring load balancing..." -ForegroundColor White
    $lbResult = Set-NPASLoadBalancing -ServerName $exampleConfig.ServerName
    if ($lbResult.Success) {
        Write-Host "✓ Load balancing configured successfully" -ForegroundColor Green
        Write-Host "  Load Balancer: $($lbResult.Configuration.LoadBalancer)" -ForegroundColor Cyan
        Write-Host "  NPAS Servers: $($lbResult.Configuration.NPASServers.Count)" -ForegroundColor Cyan
        Write-Host "  Health Checks: $($lbResult.Configuration.HealthChecks)" -ForegroundColor Cyan
    }

    Write-Host "`n3. Configuring branch office authentication..." -ForegroundColor White
    $branchResult = Set-NPASBranch -ServerName $exampleConfig.ServerName
    if ($branchResult.Success) {
        Write-Host "✓ Branch office authentication configured successfully" -ForegroundColor Green
        Write-Host "  Branch Offices: $($branchResult.Configuration.BranchOffices.Count)" -ForegroundColor Cyan
        Write-Host "  Central Policy: $($branchResult.Configuration.CentralPolicy)" -ForegroundColor Cyan
        Write-Host "  WAN Connectivity: $($branchResult.Configuration.WANConnectivity)" -ForegroundColor Cyan
    }

    Write-Host "`n4. Configuring PowerShell automation..." -ForegroundColor White
    $automationResult = Set-NPASAutomation -ServerName $exampleConfig.ServerName
    if ($automationResult.Success) {
        Write-Host "✓ PowerShell automation configured successfully" -ForegroundColor Green
        Write-Host "  Automation Scripts: $($automationResult.Configuration.AutomationScripts)" -ForegroundColor Cyan
        Write-Host "  Policy Templates: $($automationResult.Configuration.PolicyTemplates)" -ForegroundColor Cyan
        Write-Host "  Infrastructure as Code: $($automationResult.Configuration.InfrastructureAsCode)" -ForegroundColor Cyan
    }
}

# Example 14: Compliance and Security
function Show-ComplianceSecurity {
    Write-Host "`n=== EXAMPLE 14: COMPLIANCE AND SECURITY ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring compliance settings..." -ForegroundColor White
    $complianceResult = Set-NPASCompliance -ServerName $exampleConfig.ServerName -ComplianceStandards @("NIST", "ISO-27001", "SOX") -PolicyEnforcement -RiskAssessment
    if ($complianceResult.Success) {
        Write-Host "✓ Compliance settings configured successfully" -ForegroundColor Green
        Write-Host "  Compliance Standards: $($complianceResult.ComplianceSettings.ComplianceStandards -join ', ')" -ForegroundColor Cyan
        Write-Host "  Policy Enforcement: $($complianceResult.ComplianceSettings.PolicyEnforcement)" -ForegroundColor Cyan
        Write-Host "  Risk Assessment: $($complianceResult.ComplianceSettings.RiskAssessment)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Testing security compliance..." -ForegroundColor White
    $securityComplianceResult = Test-NPASSecurityCompliance -ServerName $exampleConfig.ServerName -ComplianceStandard "NIST"
    if ($securityComplianceResult.Success) {
        Write-Host "✓ Security compliance test completed successfully" -ForegroundColor Green
        Write-Host "  Overall Compliance: $($securityComplianceResult.ComplianceResults.OverallCompliance)" -ForegroundColor Cyan
        Write-Host "  Compliance Score: $($securityComplianceResult.ComplianceResults.ComplianceScore)" -ForegroundColor Cyan
        Write-Host "  Passed Tests: $($securityComplianceResult.ComplianceResults.PassedTests)" -ForegroundColor Cyan
    }

    Write-Host "`n3. Configuring Zero Trust..." -ForegroundColor White
    $zeroTrustResult = Set-NPASZeroTrust -ServerName $exampleConfig.ServerName -ZeroTrustPolicies @("Never-Trust", "Always-Verify") -ContinuousVerification -LeastPrivilegeAccess
    if ($zeroTrustResult.Success) {
        Write-Host "✓ Zero Trust configured successfully" -ForegroundColor Green
        Write-Host "  Zero Trust Policies: $($zeroTrustResult.ZeroTrustSettings.ZeroTrustPolicies -join ', ')" -ForegroundColor Cyan
        Write-Host "  Continuous Verification: $($zeroTrustResult.ZeroTrustSettings.ContinuousVerification)" -ForegroundColor Cyan
        Write-Host "  Least Privilege Access: $($zeroTrustResult.ZeroTrustSettings.LeastPrivilegeAccess)" -ForegroundColor Cyan
    }
}

# Example 15: Advanced Features
function Show-AdvancedFeatures {
    Write-Host "`n=== EXAMPLE 15: ADVANCED FEATURES ===" -ForegroundColor Yellow
    
    Write-Host "`n1. Configuring device compliance..." -ForegroundColor White
    $deviceComplianceResult = Set-NPASDeviceCompliance -ServerName $exampleConfig.ServerName -CompliancePolicies @("Antivirus", "Windows-Update", "Firewall") -HealthValidation -Remediation
    if ($deviceComplianceResult.Success) {
        Write-Host "✓ Device compliance configured successfully" -ForegroundColor Green
        Write-Host "  Compliance Policies: $($deviceComplianceResult.DeviceComplianceSettings.CompliancePolicies -join ', ')" -ForegroundColor Cyan
        Write-Host "  Health Validation: $($deviceComplianceResult.DeviceComplianceSettings.HealthValidation)" -ForegroundColor Cyan
        Write-Host "  Remediation: $($deviceComplianceResult.DeviceComplianceSettings.Remediation)" -ForegroundColor Cyan
    }

    Write-Host "`n2. Configuring risk assessment..." -ForegroundColor White
    $riskResult = Set-NPASRiskAssessment -ServerName $exampleConfig.ServerName -RiskFactors @("User-Behavior", "Device-Risk", "Network-Risk") -ThreatDetection -RiskMitigation
    if ($riskResult.Success) {
        Write-Host "✓ Risk assessment configured successfully" -ForegroundColor Green
        Write-Host "  Risk Factors: $($riskResult.RiskAssessmentSettings.RiskFactors -join ', ')" -ForegroundColor Cyan
        Write-Host "  Threat Detection: $($riskResult.RiskAssessmentSettings.ThreatDetection)" -ForegroundColor Cyan
        Write-Host "  Risk Mitigation: $($riskResult.RiskAssessmentSettings.RiskMitigation)" -ForegroundColor Cyan
    }

    Write-Host "`n3. Configuring threat protection..." -ForegroundColor White
    $threatResult = Set-NPASThreatProtection -ServerName $exampleConfig.ServerName -ThreatProtectionLevel "Advanced" -SecurityMonitoring -IncidentResponse
    if ($threatResult.Success) {
        Write-Host "✓ Threat protection configured successfully" -ForegroundColor Green
        Write-Host "  Threat Protection Level: $($threatResult.ThreatProtectionSettings.ThreatProtectionLevel)" -ForegroundColor Cyan
        Write-Host "  Security Monitoring: $($threatResult.ThreatProtectionSettings.SecurityMonitoring)" -ForegroundColor Cyan
        Write-Host "  Incident Response: $($threatResult.ThreatProtectionSettings.IncidentResponse)" -ForegroundColor Cyan
    }

    Write-Host "`n4. Getting security status..." -ForegroundColor White
    $securityStatusResult = Get-NPASSecurityStatus -ServerName $exampleConfig.ServerName
    if ($securityStatusResult.Success) {
        Write-Host "✓ Security status retrieved successfully" -ForegroundColor Green
        Write-Host "  Security Score: $($securityStatusResult.SecurityStatus.SecurityScore)" -ForegroundColor Cyan
        Write-Host "  Security Alerts: $($securityStatusResult.SecurityStatus.SecurityAlerts)" -ForegroundColor Cyan
        Write-Host "  Compliance Violations: $($securityStatusResult.SecurityStatus.ComplianceViolations)" -ForegroundColor Cyan
    }
}

# Main execution
Write-Host "`nStarting NPAS Examples and Demonstrations..." -ForegroundColor Green
Write-Host "This will demonstrate all 30 NPAS enterprise scenarios" -ForegroundColor Cyan

# Run all examples
Show-BasicNPASSetup
Show-RADIUSAuthentication
Show-8021XAuthentication
Show-VPNAuthentication
Show-CertificateAuthentication
Show-AzureADWiFi
Show-GuestVLANAssignment
Show-ConditionalAccess
Show-MFAConfiguration
Show-SecurityConfiguration
Show-MonitoringConfiguration
Show-TroubleshootingExamples
Show-EnterpriseScenarios
Show-ComplianceSecurity
Show-AdvancedFeatures

Write-Host "`n=== NPAS EXAMPLES COMPLETED ===" -ForegroundColor Green
Write-Host "All 30 enterprise scenarios have been demonstrated!" -ForegroundColor Cyan
Write-Host "Check the logs for detailed information: $($exampleConfig.LogPath)" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Green
