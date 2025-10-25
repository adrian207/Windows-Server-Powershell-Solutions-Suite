# IIS Web Server PowerShell Examples

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Basic Installation Examples

### Install IIS with Basic Features
```powershell
# Install IIS with minimal features
Install-IISWebServer -IncludeBasicFeatures

# Install IIS with all features
Install-IISWebServer -IncludeAllFeatures -EnableLogging -EnableCompression

# Install IIS with custom features
Install-IISWebServer -IncludeFeatures @("IIS-WebServer", "IIS-CommonHttpFeatures") -EnableLogging
```

### Verify Installation
```powershell
# Check IIS installation status
Get-IISFeatureStatus

# Test IIS health
Test-IISHealth

# Get IIS service status
Get-IISServiceStatus
```

## Website Management Examples

### Create Websites
```powershell
# Create a basic website
New-IISWebsite -Name "MyWebsite" -Port 80 -PhysicalPath "C:\inetpub\wwwroot\MySite"

# Create website with specific binding
New-IISWebsite -Name "MyWebsite" -Port 443 -PhysicalPath "C:\inetpub\wwwroot\MySite" -Protocol "HTTPS"

# Create website with host header
New-IISWebsite -Name "MyWebsite" -Port 80 -PhysicalPath "C:\inetpub\wwwroot\MySite" -HostHeader "www.example.com"
```

### Manage Application Pools
```powershell
# Create application pool
New-IISApplicationPool -Name "MyAppPool" -ManagedRuntimeVersion "v4.0" -ManagedPipelineMode "Integrated"

# Configure application pool
Set-IISApplicationPool -Name "MyAppPool" -IdleTimeout "00:20:00" -RecyclingPeriodicRestart "00:00:00"

# Get application pool status
Get-IISApplicationPool -Name "MyAppPool"
```

### Virtual Directories
```powershell
# Create virtual directory
New-IISVirtualDirectory -Name "MyVDir" -PhysicalPath "C:\MyContent" -WebsiteName "MyWebsite"

# Create application
New-IISApplication -Name "MyApp" -PhysicalPath "C:\MyApp" -WebsiteName "MyWebsite" -ApplicationPoolName "MyAppPool"
```

## Security Configuration Examples

### SSL Certificate Management
```powershell
# Set SSL certificate for website
Set-IISSSLCertificate -WebsiteName "MyWebsite" -CertificateThumbprint "1234567890ABCDEF"

# Get SSL certificate information
Get-IISSSLCertificate -WebsiteName "MyWebsite"

# Test SSL certificate
Test-IISSSLCertificate -WebsiteName "MyWebsite"
```

### Security Policies
```powershell
# Configure security policy
Set-IISSecurityPolicy -WebsiteName "MyWebsite" -EnableSSL -RequireClientCertificates

# Test security compliance
Test-IISSecurityCompliance -WebsiteName "MyWebsite"

# Start security monitoring
Start-IISSecurityMonitoring -WebsiteName "MyWebsite" -LogFile "C:\Logs\Security.log"
```

## Monitoring Examples

### Performance Monitoring
```powershell
# Start performance monitoring
Start-IISMonitoring -MonitoringType "Performance" -LogFile "C:\Logs\IIS-Performance.log"

# Get performance counters
Get-IISPerformanceCounters -CounterType "All"

# Get specific performance metrics
Get-IISPerformanceCounters -CounterType "Connections" -WebsiteName "MyWebsite"
```

### Event Log Analysis
```powershell
# Get IIS event logs
Get-IISEventLogs -LogType "Application" -MaxEntries 100

# Get error events
Get-IISEventLogs -LogType "System" -Level "Error" -MaxEntries 50

# Get warning events
Get-IISEventLogs -LogType "Application" -Level "Warning" -MaxEntries 25
```

### Log File Analysis
```powershell
# Get IIS log files
Get-IISLogFiles -LogType "Access" -MaxEntries 1000

# Get error log files
Get-IISLogFiles -LogType "Error" -MaxEntries 500

# Get log file statistics
Get-IISLogFileStatistics -LogType "Access" -TimeRange "Last24Hours"
```

## Backup and Recovery Examples

### Configuration Backup
```powershell
# Create configuration backup
New-IISConfigurationBackup -BackupPath "C:\Backups\IIS" -IncludeWebsites -IncludeApplicationPools

# Create full backup
New-IISConfigurationBackup -BackupPath "C:\Backups\IIS" -IncludeWebsites -IncludeApplicationPools -IncludeSystemSettings -IncludeCertificates -CompressBackup

# Get backup status
Get-IISBackupStatus -BackupPath "C:\Backups\IIS"
```

### Content Backup
```powershell
# Create content backup
New-IISContentBackup -BackupPath "C:\Backups\IIS" -WebsiteNames @("MyWebsite") -CompressBackup

# Create backup for all websites
New-IISContentBackup -BackupPath "C:\Backups\IIS" -CompressBackup

# Create backup with exclusions
New-IISContentBackup -BackupPath "C:\Backups\IIS" -ExcludePatterns @("*.log", "*.tmp", "*.cache")
```

### Restore Operations
```powershell
# Restore configuration
Restore-IISConfiguration -BackupPath "C:\Backups\IIS\IISConfig_20231201.zip" -RestoreWebsites -RestoreApplicationPools -ConfirmRestore

# Restore certificates
Restore-IISConfiguration -BackupPath "C:\Backups\IIS\IISConfig_20231201.zip" -RestoreCertificates -ConfirmRestore

# Restore all components
Restore-IISConfiguration -BackupPath "C:\Backups\IIS\IISConfig_20231201.zip" -RestoreWebsites -RestoreApplicationPools -RestoreSystemSettings -RestoreCertificates -ConfirmRepair
```

### Automated Backup Scheduling
```powershell
# Start daily backup schedule
Start-IISBackupSchedule -BackupPath "C:\Backups\IIS" -ScheduleInterval "Daily" -BackupType "Both" -RetentionDays 30

# Start weekly backup schedule
Start-IISBackupSchedule -BackupPath "C:\Backups\IIS" -ScheduleInterval "Weekly" -BackupType "Configuration" -RetentionDays 90

# Start monthly backup schedule
Start-IISBackupSchedule -BackupPath "C:\Backups\IIS" -ScheduleInterval "Monthly" -BackupType "Both" -RetentionDays 365
```

## Troubleshooting Examples

### Comprehensive Diagnostics
```powershell
# Start quick diagnostics
Start-IISDiagnostics -DiagnosticType "Quick"

# Start full diagnostics
Start-IISDiagnostics -DiagnosticType "Full" -IncludeLogAnalysis -IncludePerformanceAnalysis

# Start performance diagnostics
Start-IISDiagnostics -DiagnosticType "Performance" -IncludePerformanceAnalysis

# Start configuration diagnostics
Start-IISDiagnostics -DiagnosticType "Configuration"
```

### Troubleshooting Recommendations
```powershell
# Get all recommendations
Get-IISTroubleshootingRecommendations

# Get performance recommendations
Get-IISTroubleshootingRecommendations -IssueType "Performance" -Severity "High"

# Get connectivity recommendations
Get-IISTroubleshootingRecommendations -IssueType "Connectivity" -Severity "Medium"

# Get security recommendations
Get-IISTroubleshootingRecommendations -IssueType "Security" -Severity "Critical"
```

### Connectivity Testing
```powershell
# Test basic connectivity
Test-IISConnectivity -WebsiteName "MyWebsite" -Port 80

# Test HTTPS connectivity
Test-IISConnectivity -WebsiteName "MyWebsite" -Port 443 -Protocol "HTTPS"

# Test with extended duration
Test-IISConnectivity -WebsiteName "MyWebsite" -Port 80 -TestDuration 60
```

### Repair Operations
```powershell
# Repair services
Repair-IISConfiguration -RepairType "Services" -ConfirmRepair

# Repair configuration
Repair-IISConfiguration -RepairType "Configuration" -ConfirmRepair

# Repair permissions
Repair-IISConfiguration -RepairType "Permissions" -ConfirmRepair

# Repair all components
Repair-IISConfiguration -RepairType "All" -ConfirmRepair
```

## Deployment Examples

### Full Deployment
```powershell
# Deploy IIS with all features
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Full"

# Deploy with custom log file
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Full" -LogFile "C:\Logs\IIS-Deploy.log"
```

### Basic Deployment
```powershell
# Deploy IIS with basic features
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Basic"

# Deploy with minimal configuration
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Basic" -SkipSecurity -SkipMonitoring -SkipBackup
```

### Custom Deployment
```powershell
# Deploy with custom configuration
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Custom" -ConfigurationFile "C:\Config\IIS-Deploy.json"

# Deploy with specific components
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Custom" -SkipSecurity -SkipMonitoring
```

### Upgrade Deployment
```powershell
# Upgrade existing IIS installation
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Upgrade"

# Upgrade with custom configuration
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Upgrade" -ConfigurationFile "C:\Config\IIS-Upgrade.json"
```

### Migration Deployment
```powershell
# Migrate IIS configuration
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Migration"

# Migrate with custom configuration
.\Scripts\Deploy-IISWebServer.ps1 -DeploymentType "Migration" -ConfigurationFile "C:\Config\IIS-Migration.json"
```

## Advanced Examples

### Multi-Site Management
```powershell
# Create multiple websites
$websites = @("Site1", "Site2", "Site3")
foreach ($site in $websites) {
    New-IISWebsite -Name $site -Port 80 -PhysicalPath "C:\inetpub\wwwroot\$site"
}

# Configure multiple application pools
$appPools = @("AppPool1", "AppPool2", "AppPool3")
foreach ($pool in $appPools) {
    New-IISApplicationPool -Name $pool -ManagedRuntimeVersion "v4.0"
}
```

### Automated Monitoring
```powershell
# Start continuous monitoring
Start-IISMonitoring -MonitoringType "All" -LogFile "C:\Logs\IIS-Continuous.log" -ContinuousMonitoring

# Monitor specific websites
Start-IISMonitoring -MonitoringType "Performance" -WebsiteNames @("MyWebsite1", "MyWebsite2") -LogFile "C:\Logs\IIS-Specific.log"
```

### Batch Operations
```powershell
# Backup multiple websites
$websites = @("Website1", "Website2", "Website3")
foreach ($website in $websites) {
    New-IISContentBackup -BackupPath "C:\Backups\IIS" -WebsiteNames @($website) -CompressBackup
}

# Test connectivity for multiple websites
$websites = @("Website1", "Website2", "Website3")
foreach ($website in $websites) {
    Test-IISConnectivity -WebsiteName $website -Port 80
}
```

## Error Handling Examples

### Try-Catch Blocks
```powershell
try {
    New-IISWebsite -Name "MyWebsite" -Port 80 -PhysicalPath "C:\inetpub\wwwroot\MySite"
    Write-Host "Website created successfully"
} catch {
    Write-Error "Failed to create website: $($_.Exception.Message)"
}
```

### Error Handling with Retry
```powershell
$maxRetries = 3
$retryCount = 0

do {
    try {
        Install-IISWebServer -IncludeAllFeatures
        Write-Host "IIS installation successful"
        break
    } catch {
        $retryCount++
        Write-Warning "Installation attempt $retryCount failed: $($_.Exception.Message)"
        if ($retryCount -ge $maxRetries) {
            throw "IIS installation failed after $maxRetries attempts"
        }
        Start-Sleep -Seconds 30
    }
} while ($retryCount -lt $maxRetries)
```

## Best Practices

### Configuration Management
```powershell
# Use configuration files for consistent deployments
$config = Get-Content "C:\Config\IIS-Config.json" | ConvertFrom-Json
foreach ($website in $config.Websites) {
    New-IISWebsite -Name $website.Name -Port $website.Port -PhysicalPath $website.PhysicalPath
}
```

### Logging and Monitoring
```powershell
# Enable comprehensive logging
Start-IISMonitoring -MonitoringType "All" -LogFile "C:\Logs\IIS-$(Get-Date -Format 'yyyyMMdd').log"

# Regular health checks
$healthCheck = Test-IISHealth
if ($healthCheck.OverallHealth -ne "Healthy") {
    Write-Warning "IIS health check failed: $($healthCheck.Issues -join ', ')"
}
```

### Backup Strategy
```powershell
# Implement regular backup strategy
Start-IISBackupSchedule -BackupPath "C:\Backups\IIS" -ScheduleInterval "Daily" -BackupType "Both" -RetentionDays 30

# Test restore procedures
Restore-IISConfiguration -BackupPath "C:\Backups\IIS\Test-Restore" -RestoreWebsites -ConfirmRestore
```
