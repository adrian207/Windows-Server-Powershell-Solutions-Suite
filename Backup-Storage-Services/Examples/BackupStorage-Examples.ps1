#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Backup Storage Examples and Demonstrations

.DESCRIPTION
    This script provides comprehensive examples and demonstrations of backup and storage
    management capabilities including common scenarios and best practices.

.PARAMETER ExampleType
    Type of example to demonstrate (BasicSetup, AdvancedConfiguration, Troubleshooting, Monitoring)

.PARAMETER Scenario
    Specific scenario to demonstrate

.PARAMETER LogPath
    Path for example logs

.EXAMPLE
    .\BackupStorage-Examples.ps1 -ExampleType "BasicSetup" -Scenario "FileServer"

.EXAMPLE
    .\BackupStorage-Examples.ps1 -ExampleType "AdvancedConfiguration" -Scenario "HighAvailability"

.NOTES
    Author: Backup Storage PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("BasicSetup", "AdvancedConfiguration", "Troubleshooting", "Monitoring", "All")]
    [string]$ExampleType,

    [Parameter(Mandatory = $false)]
    [ValidateSet("FileServer", "BackupServer", "StorageServer", "HighAvailability", "DisasterRecovery", "PerformanceOptimization")]
    [string]$Scenario = "FileServer",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\BackupStorage\Examples",

    [Parameter(Mandatory = $false)]
    [switch]$Interactive,

    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Script configuration
$scriptConfig = @{
    ExampleType = $ExampleType
    Scenario = $Scenario
    LogPath = $LogPath
    Interactive = $Interactive
    Verbose = $Verbose
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Backup Storage Examples and Demonstrations" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example Type: $ExampleType" -ForegroundColor Yellow
Write-Host "Scenario: $Scenario" -ForegroundColor Yellow
Write-Host "Interactive: $Interactive" -ForegroundColor Yellow
Write-Host "Verbose: $Verbose" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\BackupStorage-Core.psm1" -Force
    Write-Host "Backup Storage modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Backup Storage modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

# Function to display example header
function Show-ExampleHeader {
    param(
        [string]$Title,
        [string]$Description
    )
    
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host $Title -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host $Description -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Green
}

# Function to demonstrate basic setup
function Show-BasicSetupExamples {
    Write-Host "`n🎯 BASIC SETUP EXAMPLES" -ForegroundColor Cyan
    
    Show-ExampleHeader "Example 1: File Server Setup" "Setting up a basic file server with backup capabilities"
    
    Write-Host "`nStep 1: Install File Server Role" -ForegroundColor Yellow
    Write-Host "Command: Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools" -ForegroundColor White
    
    Write-Host "`nStep 2: Create Shared Folders" -ForegroundColor Yellow
    Write-Host "Command: New-Item -Path 'C:\Shares\Data' -ItemType Directory -Force" -ForegroundColor White
    Write-Host "Command: New-SmbShare -Name 'Data' -Path 'C:\Shares\Data' -FullAccess 'Everyone'" -ForegroundColor White
    
    Write-Host "`nStep 3: Configure Backup" -ForegroundColor Yellow
    Write-Host "Command: Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools" -ForegroundColor White
    
    Show-ExampleHeader "Example 2: Storage Server Setup" "Setting up a dedicated storage server"
    
    Write-Host "`nStep 1: Install Storage Features" -ForegroundColor Yellow
    Write-Host "Command: Install-WindowsFeature -Name Storage-Services -IncludeManagementTools" -ForegroundColor White
    Write-Host "Command: Install-WindowsFeature -Name FS-Data-Deduplication -IncludeManagementTools" -ForegroundColor White
    
    Write-Host "`nStep 2: Configure Storage Spaces" -ForegroundColor Yellow
    Write-Host "Command: New-StoragePool -FriendlyName 'DataPool' -StorageSubsystemFriendlyName 'Windows Storage*'" -ForegroundColor White
    
    Show-ExampleHeader "Example 3: Backup Server Setup" "Setting up a dedicated backup server"
    
    Write-Host "`nStep 1: Install Backup Features" -ForegroundColor Yellow
    Write-Host "Command: Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools" -ForegroundColor White
    Write-Host "Command: Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools" -ForegroundColor White
    
    Write-Host "`nStep 2: Configure Backup Storage" -ForegroundColor Yellow
    Write-Host "Command: New-Item -Path 'D:\Backups' -ItemType Directory -Force" -ForegroundColor White
    Write-Host "Command: New-Item -Path 'D:\Backups\Daily' -ItemType Directory -Force" -ForegroundColor White
}

# Function to demonstrate advanced configuration
function Show-AdvancedConfigurationExamples {
    Write-Host "`n🚀 ADVANCED CONFIGURATION EXAMPLES" -ForegroundColor Cyan
    
    Show-ExampleHeader "Example 1: High Availability Setup" "Configuring high availability for storage systems"
    
    Write-Host "`nStep 1: Configure Failover Clustering" -ForegroundColor Yellow
    Write-Host "Command: Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools" -ForegroundColor White
    
    Write-Host "`nStep 2: Configure Storage Replica" -ForegroundColor Yellow
    Write-Host "Command: Install-WindowsFeature -Name Storage-Replica -IncludeManagementTools" -ForegroundColor White
    
    Show-ExampleHeader "Example 2: Performance Optimization" "Optimizing storage performance"
    
    Write-Host "`nStep 1: Configure Storage Spaces Direct" -ForegroundColor Yellow
    Write-Host "Command: Enable-ClusterS2D -Confirm:`$false" -ForegroundColor White
    
    Write-Host "`nStep 2: Configure Deduplication" -ForegroundColor Yellow
    Write-Host "Command: Enable-DedupVolume -Volume D: -DataAccess" -ForegroundColor White
    
    Show-ExampleHeader "Example 3: Disaster Recovery Setup" "Configuring disaster recovery"
    
    Write-Host "`nStep 1: Configure Azure Backup" -ForegroundColor Yellow
    Write-Host "Command: Install-Module -Name Az.RecoveryServices -Force" -ForegroundColor White
    
    Write-Host "`nStep 2: Configure Offsite Backup" -ForegroundColor Yellow
    Write-Host "Command: Set-WBBackupTarget -BackupTarget @{TargetPath='\\OffsiteServer\Backups'}" -ForegroundColor White
}

# Function to demonstrate troubleshooting
function Show-TroubleshootingExamples {
    Write-Host "`n🔧 TROUBLESHOOTING EXAMPLES" -ForegroundColor Cyan
    
    Show-ExampleHeader "Example 1: Performance Issues" "Troubleshooting storage performance problems"
    
    Write-Host "`nStep 1: Check Disk Performance" -ForegroundColor Yellow
    Write-Host "Command: Get-Counter '\PhysicalDisk(*)\% Disk Time' -SampleInterval 1 -MaxSamples 10" -ForegroundColor White
    
    Write-Host "`nStep 2: Check Memory Usage" -ForegroundColor Yellow
    Write-Host "Command: Get-Counter '\Memory\Available MBytes' -SampleInterval 1 -MaxSamples 10" -ForegroundColor White
    
    Show-ExampleHeader "Example 2: Backup Issues" "Troubleshooting backup problems"
    
    Write-Host "`nStep 1: Check Backup Service Status" -ForegroundColor Yellow
    Write-Host "Command: Get-Service -Name 'VSS' | Select-Object Name, Status, StartType" -ForegroundColor White
    Write-Host "Command: Get-Service -Name 'SDRSVC' | Select-Object Name, Status, StartType" -ForegroundColor White
    
    Write-Host "`nStep 2: Check Backup Logs" -ForegroundColor Yellow
    Write-Host "Command: Get-WinEvent -LogName 'Microsoft-Windows-Backup' -MaxEvents 10" -ForegroundColor White
    
    Show-ExampleHeader "Example 3: Storage Issues" "Troubleshooting storage problems"
    
    Write-Host "`nStep 1: Check Disk Health" -ForegroundColor Yellow
    Write-Host "Command: Get-PhysicalDisk | Select-Object DeviceID, HealthStatus, OperationalStatus" -ForegroundColor White
    
    Write-Host "`nStep 2: Check Volume Status" -ForegroundColor Yellow
    Write-Host "Command: Get-Volume | Select-Object DriveLetter, HealthStatus, OperationalStatus" -ForegroundColor White
}

# Function to demonstrate monitoring
function Show-MonitoringExamples {
    Write-Host "`n📊 MONITORING EXAMPLES" -ForegroundColor Cyan
    
    Show-ExampleHeader "Example 1: Performance Monitoring" "Setting up performance monitoring"
    
    Write-Host "`nStep 1: Create Performance Counters" -ForegroundColor Yellow
    Write-Host "Command: Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 10" -ForegroundColor White
    Write-Host "Command: Get-Counter '\Memory\Available MBytes' -SampleInterval 1 -MaxSamples 10" -ForegroundColor White
    
    Write-Host "`nStep 2: Create Monitoring Script" -ForegroundColor Yellow
    Write-Host "Command: while (`$true) { Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1 }" -ForegroundColor White
    
    Show-ExampleHeader "Example 2: Alert Configuration" "Setting up alerts and notifications"
    
    Write-Host "`nStep 1: Create Alert Thresholds" -ForegroundColor Yellow
    Write-Host "Command: `$thresholds = @{ CPUUsage = 80; MemoryUsage = 85; DiskUsage = 90 }" -ForegroundColor White
    
    Write-Host "`nStep 2: Create Alert Function" -ForegroundColor Yellow
    Write-Host "Command: function Send-Alert { param([string]`$Message) Write-EventLog -LogName Application -Source 'BackupStorage' -EventId 1001 -Message `$Message }" -ForegroundColor White
    
    Show-ExampleHeader "Example 3: Report Generation" "Generating monitoring reports"
    
    Write-Host "`nStep 1: Create Report Function" -ForegroundColor Yellow
    Write-Host "Command: function Generate-PerformanceReport { `$report = @{ Timestamp = Get-Date; CPUUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue } }" -ForegroundColor White
}

# Function to demonstrate all examples
function Show-AllExamples {
    Show-BasicSetupExamples
    Show-AdvancedConfigurationExamples
    Show-TroubleshootingExamples
    Show-MonitoringExamples
}

# Main execution
switch ($ExampleType) {
    "BasicSetup" {
        Show-BasicSetupExamples
    }
    "AdvancedConfiguration" {
        Show-AdvancedConfigurationExamples
    }
    "Troubleshooting" {
        Show-TroubleshootingExamples
    }
    "Monitoring" {
        Show-MonitoringExamples
    }
    "All" {
        Show-AllExamples
    }
}

# Generate example report
Write-Host "`nGenerating example report..." -ForegroundColor Green

$exampleReport = @{
    ExampleType = $ExampleType
    Scenario = $Scenario
    ExamplesShown = @()
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

# Add examples based on type
switch ($ExampleType) {
    "BasicSetup" {
        $exampleReport.ExamplesShown = @(
            "File Server Setup",
            "Storage Server Setup",
            "Backup Server Setup"
        )
    }
    "AdvancedConfiguration" {
        $exampleReport.ExamplesShown = @(
            "High Availability Setup",
            "Performance Optimization",
            "Disaster Recovery Setup"
        )
    }
    "Troubleshooting" {
        $exampleReport.ExamplesShown = @(
            "Performance Issues",
            "Backup Issues",
            "Storage Issues"
        )
    }
    "Monitoring" {
        $exampleReport.ExamplesShown = @(
            "Performance Monitoring",
            "Alert Configuration",
            "Report Generation"
        )
    }
    "All" {
        $exampleReport.ExamplesShown = @(
            "File Server Setup",
            "Storage Server Setup",
            "Backup Server Setup",
            "High Availability Setup",
            "Performance Optimization",
            "Disaster Recovery Setup",
            "Performance Issues",
            "Backup Issues",
            "Storage Issues",
            "Performance Monitoring",
            "Alert Configuration",
            "Report Generation"
        )
    }
}

# Save example report
$reportFile = Join-Path $LogPath "BackupStorageExamples-$ExampleType-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$exampleReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Example report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "Backup Storage Examples Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example Type: $ExampleType" -ForegroundColor Yellow
Write-Host "Scenario: $Scenario" -ForegroundColor Yellow
Write-Host "Examples Shown: $($exampleReport.ExamplesShown.Count)" -ForegroundColor Yellow
Write-Host "Interactive: $Interactive" -ForegroundColor Yellow
Write-Host "Verbose: $Verbose" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 Backup storage examples demonstration completed successfully!" -ForegroundColor Green
Write-Host "The examples have been shown and documented for reference." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the example report" -ForegroundColor White
Write-Host "2. Try the examples in your environment" -ForegroundColor White
Write-Host "3. Customize examples for your needs" -ForegroundColor White
Write-Host "4. Document your own examples" -ForegroundColor White
Write-Host "5. Share examples with your team" -ForegroundColor White
Write-Host "6. Create additional examples" -ForegroundColor White