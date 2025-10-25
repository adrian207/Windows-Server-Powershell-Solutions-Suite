# Remote Access Services PowerShell Examples

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Basic Installation Examples

### Install Remote Access Services
```powershell
# Install DirectAccess and VPN
Install-DirectAccess -IncludeVPN -IncludeManagementTools

# Install Web Application Proxy
Install-WebApplicationProxy -IncludeManagementTools

# Install Network Policy Server
Install-NPSServer -IncludeManagementTools
```

### Verify Installation
```powershell
# Check Remote Access installation status
Get-RemoteAccessServiceStatus

# Test Remote Access health
Test-RemoteAccessHealth

# Get Remote Access prerequisites
Test-RemoteAccessPrerequisites
```

## DirectAccess Examples

### Configure DirectAccess
```powershell
# Configure DirectAccess with basic settings
New-DirectAccessConfiguration -GpoName "DirectAccess-Client" -InternalInterface "LAN" -ExternalInterface "WAN"

# Configure DirectAccess with certificates
Set-DirectAccessSettings -CertificateThumbprint "1234567890ABCDEF" -EnableIPv6

# Test DirectAccess connectivity
Test-DirectAccessConnectivity -ClientComputer "CLIENT01"
```

### DirectAccess Management
```powershell
# Start DirectAccess monitoring
Start-DirectAccessMonitoring -LogFile "C:\Logs\DirectAccess-Monitor.log"

# Get DirectAccess status
Get-DirectAccessStatus

# Configure DirectAccess policies
Set-DirectAccessSettings -EnableClientTunneling -EnableServerTunneling
```

## VPN Examples

### Configure VPN Server
```powershell
# Configure VPN server with SSTP
New-VPNConfiguration -VPNType "SSTP" -AuthenticationMethod "MS-CHAPv2" -EncryptionLevel "Strong"

# Configure VPN with certificates
Set-VPNSettings -CertificateThumbprint "1234567890ABCDEF" -EnableCertificateAuthentication

# Configure VPN IP address range
Set-VPNSettings -IPAddressRange "192.168.100.1-192.168.100.100"
```

### VPN Management
```powershell
# Start VPN monitoring
Start-VPNMonitoring -LogFile "C:\Logs\VPN-Monitor.log"

# Get VPN status
Get-VPNStatus

# Test VPN connectivity
Test-VPNConnectivity -ClientIP "192.168.1.100"
```

## Web Application Proxy Examples

### Configure Web Application Proxy
```powershell
# Configure Web Application Proxy
New-WebApplicationProxyConfiguration -FederationServiceName "sts.contoso.com" -CertificateThumbprint "1234567890ABCDEF"

# Configure Web Application Proxy with ADFS
Set-WebApplicationProxySettings -ADFSServerName "adfs.contoso.com" -ExternalURL "https://wap.contoso.com"

# Configure Web Application Proxy policies
Set-WebApplicationProxySettings -EnablePreauthentication -EnableOAuth2
```

### Web Application Proxy Management
```powershell
# Start Web Application Proxy monitoring
Start-WebApplicationProxyMonitoring -LogFile "C:\Logs\WAP-Monitor.log"

# Get Web Application Proxy status
Get-WebApplicationProxyStatus

# Test Web Application Proxy connectivity
Test-WebApplicationProxyConnectivity -ExternalURL "https://wap.contoso.com"
```

## Network Policy Server (NPS) Examples

### Configure NPS
```powershell
# Configure NPS server
New-NPSConfiguration -ServerName "NPS01" -AuthenticationMethod "MS-CHAPv2" -AccountingMethod "RADIUS"

# Configure NPS policies
Set-NPSSettings -PolicyName "Wireless-Access" -ClientName "Wireless-Controller" -SharedSecret "SecurePassword123"

# Configure NPS for 802.1X
Set-NPSSettings -Enable8021X -AuthenticationMethod "EAP-TLS"
```

### NPS Management
```powershell
# Start NPS monitoring
Start-NPSMonitoring -LogFile "C:\Logs\NPS-Monitor.log"

# Get NPS status
Get-NPSStatus

# Test NPS connectivity
Test-NPSConnectivity -ClientIP "192.168.1.100"
```

## Monitoring Examples

### Performance Monitoring
```powershell
# Start comprehensive monitoring
Start-RemoteAccessMonitoring -MonitoringType "All" -LogFile "C:\Logs\RemoteAccess-Monitor.log"

# Get performance counters
Get-RemoteAccessPerformanceCounters -CounterType "All"

# Get specific performance metrics
Get-RemoteAccessPerformanceCounters -CounterType "Connections" -Component "VPN"
```

### Event Log Analysis
```powershell
# Get Remote Access event logs
Get-RemoteAccessEventLogs -LogType "Application" -MaxEntries 100

# Get error events
Get-RemoteAccessEventLogs -LogType "System" -Level "Error" -MaxEntries 50

# Get warning events
Get-RemoteAccessEventLogs -LogType "Application" -Level "Warning" -MaxEntries 25
```

### Log File Analysis
```powershell
# Get Remote Access log files
Get-RemoteAccessLogFiles -LogType "Accounting" -MaxEntries 1000

# Get error log files
Get-RemoteAccessLogFiles -LogType "Error" -MaxEntries 500

# Get log file statistics
Get-RemoteAccessLogFileStatistics -LogType "Accounting" -TimeRange "Last24Hours"
```

## Security Examples

### Security Configuration
```powershell
# Configure security policy
Set-RemoteAccessSecurityPolicy -EnableSSL -RequireClientCertificates -EnableFirewallRules

# Test security compliance
Test-RemoteAccessCompliance -Component "All"

# Start security monitoring
Start-RemoteAccessSecurityMonitoring -LogFile "C:\Logs\Security-Monitor.log"
```

### Certificate Management
```powershell
# Set SSL certificate
Set-RemoteAccessCertificate -CertificateThumbprint "1234567890ABCDEF" -Component "DirectAccess"

# Get certificate information
Get-RemoteAccessCertificate -Component "VPN"

# Test certificate
Test-RemoteAccessCertificate -CertificateThumbprint "1234567890ABCDEF"
```

## Backup and Recovery Examples

### Configuration Backup
```powershell
# Create configuration backup
New-RemoteAccessConfigurationBackup -BackupPath "C:\Backups\RemoteAccess" -IncludeDirectAccess -IncludeVPN -IncludeNPS

# Create full backup
New-RemoteAccessConfigurationBackup -BackupPath "C:\Backups\RemoteAccess" -IncludeDirectAccess -IncludeVPN -IncludeWebApplicationProxy -IncludeNPS -IncludeCertificates -IncludePolicies -CompressBackup

# Get backup status
Get-RemoteAccessBackupStatus -BackupPath "C:\Backups\RemoteAccess"
```

### Log Backup
```powershell
# Create log backup
New-RemoteAccessLogBackup -BackupPath "C:\Backups\RemoteAccess" -IncludeEventLogs -IncludeAccountingLogs -LogRetentionDays 30

# Create comprehensive log backup
New-RemoteAccessLogBackup -BackupPath "C:\Backups\RemoteAccess" -IncludeEventLogs -IncludeAccountingLogs -IncludeDiagnosticLogs -CompressBackup
```

### Restore Operations
```powershell
# Restore configuration
Restore-RemoteAccessConfiguration -BackupPath "C:\Backups\RemoteAccess\RemoteAccessConfig_20231201.zip" -RestoreDirectAccess -RestoreVPN -ConfirmRestore

# Restore certificates
Restore-RemoteAccessConfiguration -BackupPath "C:\Backups\RemoteAccess\RemoteAccessConfig_20231201.zip" -RestoreCertificates -ConfirmRestore

# Restore all components
Restore-RemoteAccessConfiguration -BackupPath "C:\Backups\RemoteAccess\RemoteAccessConfig_20231201.zip" -RestoreDirectAccess -RestoreVPN -RestoreWebApplicationProxy -RestoreNPS -RestoreCertificates -RestorePolicies -ConfirmRestore
```

### Automated Backup Scheduling
```powershell
# Start daily backup schedule
Start-RemoteAccessBackupSchedule -BackupPath "C:\Backups\RemoteAccess" -ScheduleInterval "Daily" -BackupType "Both" -RetentionDays 30

# Start weekly backup schedule
Start-RemoteAccessBackupSchedule -BackupPath "C:\Backups\RemoteAccess" -ScheduleInterval "Weekly" -BackupType "Configuration" -RetentionDays 90

# Start monthly backup schedule
Start-RemoteAccessBackupSchedule -BackupPath "C:\Backups\RemoteAccess" -ScheduleInterval "Monthly" -BackupType "Both" -RetentionDays 365
```

## Troubleshooting Examples

### Comprehensive Diagnostics
```powershell
# Start quick diagnostics
Start-RemoteAccessDiagnostics -DiagnosticType "Quick"

# Start full diagnostics
Start-RemoteAccessDiagnostics -DiagnosticType "Full" -IncludeLogAnalysis -IncludePerformanceAnalysis

# Start NPS diagnostics
Start-RemoteAccessDiagnostics -DiagnosticType "NPS" -IncludeLogAnalysis

# Start DirectAccess diagnostics
Start-RemoteAccessDiagnostics -DiagnosticType "DirectAccess" -IncludePerformanceAnalysis
```

### Troubleshooting Recommendations
```powershell
# Get all recommendations
Get-RemoteAccessTroubleshootingRecommendations

# Get NPS recommendations
Get-RemoteAccessTroubleshootingRecommendations -IssueType "NPS" -Severity "High"

# Get connectivity recommendations
Get-RemoteAccessTroubleshootingRecommendations -IssueType "Connectivity" -Severity "Medium"

# Get security recommendations
Get-RemoteAccessTroubleshootingRecommendations -IssueType "Security" -Severity "Critical"
```

### Connectivity Testing
```powershell
# Test DirectAccess connectivity
Test-DirectAccessConnectivity -ClientComputer "CLIENT01"

# Test VPN connectivity
Test-VPNConnectivity -ClientIP "192.168.1.100"

# Test Web Application Proxy connectivity
Test-WebApplicationProxyConnectivity -ExternalURL "https://wap.contoso.com"

# Test NPS connectivity
Test-NPSConnectivity -ClientIP "192.168.1.100"
```

### Repair Operations
```powershell
# Repair DirectAccess
Repair-RemoteAccessConfiguration -RepairType "DirectAccess" -ConfirmRepair

# Repair VPN
Repair-RemoteAccessConfiguration -RepairType "VPN" -ConfirmRepair

# Repair NPS
Repair-RemoteAccessConfiguration -RepairType "NPS" -ConfirmRepair

# Repair all components
Repair-RemoteAccessConfiguration -RepairType "All" -ConfirmRepair
```

## Deployment Examples

### Full Deployment
```powershell
# Deploy all Remote Access Services
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "Full"

# Deploy with custom log file
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "Full" -LogFile "C:\Logs\RemoteAccess-Deploy.log"
```

### Component-specific Deployment
```powershell
# Deploy DirectAccess only
.\Scripts\DirectAccess\Implement-DirectAccess.ps1 -Action "Install"

# Deploy VPN only
.\Scripts\VPN\Implement-VPN.ps1 -Action "Install"

# Deploy Web Application Proxy only
.\Scripts\WebApplicationProxy\Implement-WebApplicationProxy.ps1 -Action "Install"

# Deploy NPS only
.\Scripts\NPS\Implement-NPS.ps1 -Action "Install"
```

### Custom Deployment
```powershell
# Deploy with custom configuration
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "Custom" -ConfigurationFile "C:\Config\RemoteAccess-Deploy.json"

# Deploy specific components
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "Custom" -SkipDirectAccess -SkipVPN
```

## Advanced Examples

### Multi-Site Management
```powershell
# Configure multiple DirectAccess servers
$servers = @("DA-Server1", "DA-Server2", "DA-Server3")
foreach ($server in $servers) {
    New-DirectAccessConfiguration -ServerName $server -GpoName "DirectAccess-$server"
}

# Configure multiple VPN servers
$vpnServers = @("VPN-Server1", "VPN-Server2")
foreach ($server in $vpnServers) {
    New-VPNConfiguration -ServerName $server -VPNType "SSTP"
}
```

### Automated Monitoring
```powershell
# Start continuous monitoring
Start-RemoteAccessMonitoring -MonitoringType "All" -LogFile "C:\Logs\RemoteAccess-Continuous.log" -ContinuousMonitoring

# Monitor specific components
Start-RemoteAccessMonitoring -MonitoringType "Performance" -Components @("DirectAccess", "VPN") -LogFile "C:\Logs\RemoteAccess-Specific.log"
```

### Batch Operations
```powershell
# Backup multiple components
$components = @("DirectAccess", "VPN", "NPS")
foreach ($component in $components) {
    New-RemoteAccessConfigurationBackup -BackupPath "C:\Backups\RemoteAccess" -Component $component -CompressBackup
}

# Test connectivity for multiple clients
$clients = @("CLIENT01", "CLIENT02", "CLIENT03")
foreach ($client in $clients) {
    Test-DirectAccessConnectivity -ClientComputer $client
}
```

## Error Handling Examples

### Try-Catch Blocks
```powershell
try {
    New-DirectAccessConfiguration -GpoName "DirectAccess-Client"
    Write-Host "DirectAccess configuration created successfully"
} catch {
    Write-Error "Failed to create DirectAccess configuration: $($_.Exception.Message)"
}
```

### Error Handling with Retry
```powershell
$maxRetries = 3
$retryCount = 0

do {
    try {
        Install-DirectAccess -IncludeVPN
        Write-Host "DirectAccess installation successful"
        break
    } catch {
        $retryCount++
        Write-Warning "Installation attempt $retryCount failed: $($_.Exception.Message)"
        if ($retryCount -ge $maxRetries) {
            throw "DirectAccess installation failed after $maxRetries attempts"
        }
        Start-Sleep -Seconds 30
    }
} while ($retryCount -lt $maxRetries)
```

## Best Practices

### Configuration Management
```powershell
# Use configuration files for consistent deployments
$config = Get-Content "C:\Config\RemoteAccess-Config.json" | ConvertFrom-Json
foreach ($component in $config.Components) {
    switch ($component.Type) {
        "DirectAccess" {
            New-DirectAccessConfiguration -GpoName $component.GpoName -InternalInterface $component.InternalInterface
        }
        "VPN" {
            New-VPNConfiguration -VPNType $component.VPNType -AuthenticationMethod $component.AuthenticationMethod
        }
        "NPS" {
            New-NPSConfiguration -ServerName $component.ServerName -AuthenticationMethod $component.AuthenticationMethod
        }
    }
}
```

### Logging and Monitoring
```powershell
# Enable comprehensive logging
Start-RemoteAccessMonitoring -MonitoringType "All" -LogFile "C:\Logs\RemoteAccess-$(Get-Date -Format 'yyyyMMdd').log"

# Regular health checks
$healthCheck = Test-RemoteAccessHealth
if ($healthCheck.OverallHealth -ne "Healthy") {
    Write-Warning "Remote Access health check failed: $($healthCheck.Issues -join ', ')"
}
```

### Backup Strategy
```powershell
# Implement regular backup strategy
Start-RemoteAccessBackupSchedule -BackupPath "C:\Backups\RemoteAccess" -ScheduleInterval "Daily" -BackupType "Both" -RetentionDays 30

# Test restore procedures
Restore-RemoteAccessConfiguration -BackupPath "C:\Backups\RemoteAccess\Test-Restore" -RestoreDirectAccess -ConfirmRestore
```

## Enterprise Scenarios

### 802.1X Wireless Authentication
```powershell
# Configure NPS for 802.1X wireless authentication
Set-NPSSettings -PolicyName "Wireless-8021X" -AuthenticationMethod "EAP-TLS" -Enable8021X

# Configure certificate-based authentication
Set-NPSSettings -CertificateThumbprint "1234567890ABCDEF" -EnableCertificateAuthentication

# Configure dynamic VLAN assignment
Set-NPSSettings -VLANAssignment "Dynamic" -VLANMapping @{
    "Finance" = "VLAN-10"
    "HR" = "VLAN-20"
    "IT" = "VLAN-30"
    "Guest" = "VLAN-99"
}
```

### Multi-Factor Authentication
```powershell
# Configure Azure MFA NPS Extension
Install-AzureMFANPSExtension -AzureMFAEndpoint "https://mfa.contoso.com" -CertificateThumbprint "1234567890ABCDEF"

# Configure certificate + password authentication
Set-NPSSettings -AuthenticationMethod "EAP-TLS" -SecondaryAuthentication "MS-CHAPv2"

# Configure hardware token support
Set-NPSSettings -HardwareTokenProvider "RSA" -TokenServer "token.contoso.com"
```

### RADIUS Proxy Configuration
```powershell
# Configure RADIUS proxy for multi-tenant
Set-NPSSettings -ProxyMode $true -UpstreamServers @{
    "tenant1.contoso.com" = "192.168.1.10"
    "tenant2.contoso.com" = "192.168.1.20"
}

# Configure load balancing
Set-NPSSettings -LoadBalancing $true -PrimaryServer "192.168.1.10" -SecondaryServer "192.168.1.20"

# Configure failover
Set-NPSSettings -FailoverTimeout 30 -RetryAttempts 3
```

### Compliance and Auditing
```powershell
# Configure detailed accounting logging
Set-NPSSettings -AccountingLogging "Detailed" -LogFormat "CSV" -LogPath "C:\Logs\NPS-Accounting"

# Configure compliance reporting
Start-RemoteAccessComplianceReporting -ReportType "Audit" -OutputPath "C:\Reports\Compliance"

# Configure real-time session monitoring
Start-RemoteAccessSessionMonitoring -LogFile "C:\Logs\Session-Monitor.log" -RealTimeMonitoring
```