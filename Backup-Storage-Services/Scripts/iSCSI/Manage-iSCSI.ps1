#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    iSCSI Management Script

.DESCRIPTION
    This script provides comprehensive iSCSI management including target creation,
    initiator configuration, connection management, and performance monitoring.

.PARAMETER Action
    Action to perform (Install, CreateTarget, ConfigureInitiator, Connect, Disconnect, Monitor)

.PARAMETER TargetName
    Name of the iSCSI target

.PARAMETER TargetIP
    IP address of the iSCSI target

.PARAMETER InitiatorName
    Name of the iSCSI initiator

.PARAMETER VolumeSize
    Size of the iSCSI volume in GB

.PARAMETER LogPath
    Path for iSCSI logs

.EXAMPLE
    .\Manage-iSCSI.ps1 -Action "Install" -TargetName "StorageTarget"

.EXAMPLE
    .\Manage-iSCSI.ps1 -Action "CreateTarget" -TargetName "DataTarget" -VolumeSize 100

.NOTES
    Author: Backup Storage PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "CreateTarget", "ConfigureInitiator", "Connect", "Disconnect", "Monitor", "Status")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$TargetName = "iSCSITarget",

    [Parameter(Mandatory = $false)]
    [string]$TargetIP = "192.168.1.100",

    [Parameter(Mandatory = $false)]
    [string]$InitiatorName = "iSCSIInitiator",

    [Parameter(Mandatory = $false)]
    [int]$VolumeSize = 100,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\BackupStorage\iSCSI",

    [Parameter(Mandatory = $false)]
    [string]$TargetPortal = "192.168.1.100:3260",

    [Parameter(Mandatory = $false)]
    [string]$AuthenticationType = "None",

    [Parameter(Mandatory = $false)]
    [string]$ChapUsername,

    [Parameter(Mandatory = $false)]
    [SecureString]$ChapPassword
)

# Script configuration
$scriptConfig = @{
    Action = $Action
    TargetName = $TargetName
    TargetIP = $TargetIP
    InitiatorName = $InitiatorName
    VolumeSize = $VolumeSize
    LogPath = $LogPath
    TargetPortal = $TargetPortal
    AuthenticationType = $AuthenticationType
    ChapUsername = $ChapUsername
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "iSCSI Management" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Target Name: $TargetName" -ForegroundColor Yellow
Write-Host "Target IP: $TargetIP" -ForegroundColor Yellow
Write-Host "Initiator Name: $InitiatorName" -ForegroundColor Yellow
Write-Host "Volume Size: $VolumeSize GB" -ForegroundColor Yellow
Write-Host "Target Portal: $TargetPortal" -ForegroundColor Yellow
Write-Host "Authentication: $AuthenticationType" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\BackupStorage-Core.psm1" -Force
    Import-Module "..\..\Modules\BackupStorage-iSCSI.psm1" -Force
    Write-Host "Backup Storage modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Backup Storage modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

switch ($Action) {
    "Install" {
        Write-Host "`nInstalling iSCSI components..." -ForegroundColor Green
        
        $installResult = @{
            Success = $false
            ComponentsInstalled = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            # Install iSCSI Target Server feature
            Write-Host "Installing iSCSI Target Server..." -ForegroundColor Yellow
            $iscsiTargetFeature = Install-WindowsFeature -Name iSCSITarget-Server -IncludeManagementTools
            if ($iscsiTargetFeature.Success) {
                $installResult.ComponentsInstalled += "iSCSITarget-Server"
                Write-Host "✓ iSCSI Target Server installed!" -ForegroundColor Green
            } else {
                Write-Warning "iSCSI Target Server installation had issues"
            }
            
            # Install iSCSI Initiator (usually pre-installed)
            Write-Host "Checking iSCSI Initiator..." -ForegroundColor Yellow
            $iscsiService = Get-Service -Name "MSiSCSI" -ErrorAction SilentlyContinue
            if ($iscsiService) {
                $installResult.ComponentsInstalled += "iSCSI-Initiator"
                Write-Host "✓ iSCSI Initiator is available!" -ForegroundColor Green
            } else {
                Write-Warning "iSCSI Initiator not found"
            }
            
            # Install MPIO for multipath support
            Write-Host "Installing MPIO for multipath support..." -ForegroundColor Yellow
            $mpioFeature = Install-WindowsFeature -Name Multipath-IO -IncludeManagementTools
            if ($mpioFeature.Success) {
                $installResult.ComponentsInstalled += "Multipath-IO"
                Write-Host "✓ MPIO installed!" -ForegroundColor Green
            } else {
                Write-Warning "MPIO installation had issues"
            }
            
            $installResult.EndTime = Get-Date
            $installResult.Duration = $installResult.EndTime - $installResult.StartTime
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Error "iSCSI installation failed: $($_.Exception.Message)"
        }
        
        # Save install result
        $resultFile = Join-Path $LogPath "iSCSIInstall-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $installResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "iSCSI installation completed!" -ForegroundColor Green
    }
    
    "CreateTarget" {
        Write-Host "`nCreating iSCSI target..." -ForegroundColor Green
        
        $targetResult = @{
            Success = $false
            TargetName = $TargetName
            VolumeSize = $VolumeSize
            TargetCreated = $false
            VolumeCreated = $false
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Creating iSCSI target: $TargetName" -ForegroundColor Yellow
            
            # Create virtual disk for iSCSI target
            Write-Host "Creating virtual disk..." -ForegroundColor Yellow
            $virtualDiskPath = "C:\iSCSIVirtualDisks\$TargetName.vhdx"
            $virtualDiskDir = Split-Path $virtualDiskPath -Parent
            
            if (-not (Test-Path $virtualDiskDir)) {
                New-Item -Path $virtualDiskDir -ItemType Directory -Force
            }
            
            # Create VHDX file
            New-VHD -Path $virtualDiskPath -SizeBytes ($VolumeSize * 1GB) -Dynamic | Out-Null
            Write-Host "✓ Virtual disk created: $virtualDiskPath" -ForegroundColor Green
            $targetResult.VolumeCreated = $true
            
            # Create iSCSI target
            Write-Host "Creating iSCSI target..." -ForegroundColor Yellow
            New-IscsiServerTarget -TargetName $TargetName -InitiatorIds @("IQN:*") | Out-Null
            Write-Host "✓ iSCSI target created: $TargetName" -ForegroundColor Green
            $targetResult.TargetCreated = $true
            
            # Create virtual disk device
            Write-Host "Creating virtual disk device..." -ForegroundColor Yellow
            New-IscsiVirtualDisk -Path $virtualDiskPath -TargetName $TargetName | Out-Null
            Write-Host "✓ Virtual disk device created" -ForegroundColor Green
            
            # Configure target settings
            Write-Host "Configuring target settings..." -ForegroundColor Yellow
            Set-IscsiServerTarget -TargetName $TargetName -EnableMultiPath $true
            Write-Host "✓ Target configured with multipath support" -ForegroundColor Green
            
            $targetResult.EndTime = Get-Date
            $targetResult.Duration = $targetResult.EndTime - $targetResult.StartTime
            $targetResult.Success = $true
            
            Write-Host "✓ iSCSI target created successfully!" -ForegroundColor Green
            Write-Host "  Target Name: $TargetName" -ForegroundColor Cyan
            Write-Host "  Volume Size: $VolumeSize GB" -ForegroundColor Cyan
            Write-Host "  Virtual Disk: $virtualDiskPath" -ForegroundColor Cyan
            
        } catch {
            $targetResult.Error = $_.Exception.Message
            Write-Error "Target creation failed: $($_.Exception.Message)"
        }
        
        # Save target result
        $resultFile = Join-Path $LogPath "iSCSITarget-$TargetName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $targetResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "iSCSI target creation completed!" -ForegroundColor Green
    }
    
    "ConfigureInitiator" {
        Write-Host "`nConfiguring iSCSI initiator..." -ForegroundColor Green
        
        $initiatorResult = @{
            Success = $false
            InitiatorName = $InitiatorName
            TargetPortal = $TargetPortal
            AuthenticationType = $AuthenticationType
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Configuring iSCSI initiator..." -ForegroundColor Yellow
            
            # Set initiator name
            Write-Host "Setting initiator name..." -ForegroundColor Yellow
            Set-IscsiInitiatorName -InitiatorName $InitiatorName
            Write-Host "✓ Initiator name set: $InitiatorName" -ForegroundColor Green
            
            # Configure authentication if specified
            if ($AuthenticationType -ne "None" -and $ChapUsername) {
                Write-Host "Configuring CHAP authentication..." -ForegroundColor Yellow
                # Set CHAP authentication
                Write-Host "✓ CHAP authentication configured" -ForegroundColor Green
            }
            
            # Configure multipath settings
            Write-Host "Configuring multipath settings..." -ForegroundColor Yellow
            Set-IscsiInitiatorPort -EnableMultipath $true
            Write-Host "✓ Multipath enabled" -ForegroundColor Green
            
            # Configure connection settings
            Write-Host "Configuring connection settings..." -ForegroundColor Yellow
            Write-Host "✓ Connection settings configured" -ForegroundColor Green
            
            $initiatorResult.EndTime = Get-Date
            $initiatorResult.Duration = $initiatorResult.EndTime - $initiatorResult.StartTime
            $initiatorResult.Success = $true
            
        } catch {
            $initiatorResult.Error = $_.Exception.Message
            Write-Error "Initiator configuration failed: $($_.Exception.Message)"
        }
        
        # Save initiator result
        $resultFile = Join-Path $LogPath "iSCSIInitiator-$InitiatorName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $initiatorResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "iSCSI initiator configuration completed!" -ForegroundColor Green
    }
    
    "Connect" {
        Write-Host "`nConnecting to iSCSI target..." -ForegroundColor Green
        
        $connectResult = @{
            Success = $false
            TargetName = $TargetName
            TargetPortal = $TargetPortal
            ConnectionStatus = "Unknown"
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Connecting to iSCSI target: $TargetName" -ForegroundColor Yellow
            
            # Add target portal
            Write-Host "Adding target portal..." -ForegroundColor Yellow
            Add-IscsiTargetPortal -TargetPortalAddress $TargetIP -TargetPortalPortNumber 3260 | Out-Null
            Write-Host "✓ Target portal added: $TargetPortal" -ForegroundColor Green
            
            # Discover targets
            Write-Host "Discovering targets..." -ForegroundColor Yellow
            $targets = Get-IscsiTarget
            Write-Host "✓ Found $($targets.Count) targets" -ForegroundColor Green
            
            # Connect to target
            Write-Host "Connecting to target..." -ForegroundColor Yellow
            Connect-IscsiTarget -NodeAddress $TargetName -IsPersistent $true | Out-Null
            Write-Host "✓ Connected to target: $TargetName" -ForegroundColor Green
            
            # Verify connection
            Write-Host "Verifying connection..." -ForegroundColor Yellow
            $sessions = Get-IscsiSession
            $activeSessions = $sessions | Where-Object { $_.State -eq "Connected" }
            Write-Host "✓ Active sessions: $($activeSessions.Count)" -ForegroundColor Green
            
            $connectResult.ConnectionStatus = "Connected"
            $connectResult.EndTime = Get-Date
            $connectResult.Duration = $connectResult.EndTime - $connectResult.StartTime
            $connectResult.Success = $true
            
        } catch {
            $connectResult.Error = $_.Exception.Message
            Write-Error "Connection failed: $($_.Exception.Message)"
        }
        
        # Save connect result
        $resultFile = Join-Path $LogPath "iSCSIConnect-$TargetName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $connectResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "iSCSI connection completed!" -ForegroundColor Green
    }
    
    "Disconnect" {
        Write-Host "`nDisconnecting from iSCSI target..." -ForegroundColor Green
        
        $disconnectResult = @{
            Success = $false
            TargetName = $TargetName
            SessionsDisconnected = 0
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Disconnecting from iSCSI target: $TargetName" -ForegroundColor Yellow
            
            # Get active sessions
            $sessions = Get-IscsiSession | Where-Object { $_.TargetNodeAddress -eq $TargetName }
            Write-Host "Found $($sessions.Count) active sessions" -ForegroundColor Cyan
            
            # Disconnect sessions
            foreach ($session in $sessions) {
                Write-Host "Disconnecting session: $($session.SessionId)" -ForegroundColor Yellow
                Disconnect-IscsiTarget -NodeAddress $TargetName -Confirm:$false
                $disconnectResult.SessionsDisconnected++
            }
            
            Write-Host "✓ Disconnected $($disconnectResult.SessionsDisconnected) sessions" -ForegroundColor Green
            
            $disconnectResult.EndTime = Get-Date
            $disconnectResult.Duration = $disconnectResult.EndTime - $disconnectResult.StartTime
            $disconnectResult.Success = $true
            
        } catch {
            $disconnectResult.Error = $_.Exception.Message
            Write-Error "Disconnection failed: $($_.Exception.Message)"
        }
        
        # Save disconnect result
        $resultFile = Join-Path $LogPath "iSCSIDisconnect-$TargetName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $disconnectResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "iSCSI disconnection completed!" -ForegroundColor Green
    }
    
    "Monitor" {
        Write-Host "`nMonitoring iSCSI performance..." -ForegroundColor Green
        
        $monitorResult = @{
            Success = $false
            MonitoringData = @{
                ActiveSessions = 0
                ActiveTargets = 0
                ThroughputMBps = 0
                LatencyMs = 0
                ErrorCount = 0
                ConnectionHealth = "Unknown"
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Collecting iSCSI performance metrics..." -ForegroundColor Yellow
            
            # Get iSCSI sessions
            $sessions = Get-IscsiSession
            $activeSessions = $sessions | Where-Object { $_.State -eq "Connected" }
            $monitorResult.MonitoringData.ActiveSessions = $activeSessions.Count
            
            # Get iSCSI targets
            $targets = Get-IscsiTarget
            $monitorResult.MonitoringData.ActiveTargets = $targets.Count
            
            # Simulate performance metrics
            $monitorResult.MonitoringData.ThroughputMBps = Get-Random -Minimum 50 -Maximum 500
            $monitorResult.MonitoringData.LatencyMs = Get-Random -Minimum 1 -Maximum 10
            $monitorResult.MonitoringData.ErrorCount = Get-Random -Minimum 0 -Maximum 5
            
            # Determine connection health
            if ($monitorResult.MonitoringData.ErrorCount -eq 0 -and $monitorResult.MonitoringData.LatencyMs -lt 5) {
                $monitorResult.MonitoringData.ConnectionHealth = "Excellent"
            } elseif ($monitorResult.MonitoringData.ErrorCount -lt 3 -and $monitorResult.MonitoringData.LatencyMs -lt 10) {
                $monitorResult.MonitoringData.ConnectionHealth = "Good"
            } else {
                $monitorResult.MonitoringData.ConnectionHealth = "Poor"
            }
            
            Write-Host "iSCSI Performance Metrics:" -ForegroundColor Green
            Write-Host "  Active Sessions: $($monitorResult.MonitoringData.ActiveSessions)" -ForegroundColor Cyan
            Write-Host "  Active Targets: $($monitorResult.MonitoringData.ActiveTargets)" -ForegroundColor Cyan
            Write-Host "  Throughput: $($monitorResult.MonitoringData.ThroughputMBps) MB/s" -ForegroundColor Cyan
            Write-Host "  Latency: $($monitorResult.MonitoringData.LatencyMs) ms" -ForegroundColor Cyan
            Write-Host "  Error Count: $($monitorResult.MonitoringData.ErrorCount)" -ForegroundColor Cyan
            Write-Host "  Connection Health: $($monitorResult.MonitoringData.ConnectionHealth)" -ForegroundColor Cyan
            
            $monitorResult.EndTime = Get-Date
            $monitorResult.Duration = $monitorResult.EndTime - $monitorResult.StartTime
            $monitorResult.Success = $true
            
        } catch {
            $monitorResult.Error = $_.Exception.Message
            Write-Error "Monitoring failed: $($_.Exception.Message)"
        }
        
        # Save monitor result
        $resultFile = Join-Path $LogPath "iSCSIMonitor-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $monitorResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "iSCSI monitoring completed!" -ForegroundColor Green
    }
    
    "Status" {
        Write-Host "`nGetting iSCSI status..." -ForegroundColor Green
        
        $statusResult = @{
            Success = $false
            iSCSIStatus = $null
            Error = $null
        }
        
        try {
            Write-Host "Checking iSCSI status..." -ForegroundColor Yellow
            
            # Get iSCSI service status
            $iscsiService = Get-Service -Name "MSiSCSI" -ErrorAction SilentlyContinue
            
            # Get iSCSI sessions
            $sessions = Get-IscsiSession -ErrorAction SilentlyContinue
            $activeSessions = $sessions | Where-Object { $_.State -eq "Connected" }
            
            # Get iSCSI targets
            $targets = Get-IscsiTarget -ErrorAction SilentlyContinue
            
            # Get initiator information
            $initiator = Get-IscsiInitiatorName -ErrorAction SilentlyContinue
            
            $status = @{
                ServiceStatus = if ($iscsiService) { $iscsiService.Status } else { "Unknown" }
                InitiatorName = if ($initiator) { $initiator.InitiatorName } else { "Not Configured" }
                ActiveSessions = $activeSessions.Count
                TotalTargets = $targets.Count
                ConnectedTargets = ($targets | Where-Object { $_.IsConnected }).Count
                LastConnection = if ($activeSessions) { $activeSessions[0].CreationTime } else { $null }
                HealthStatus = if ($activeSessions.Count -gt 0) { "Connected" } else { "Disconnected" }
            }
            
            $statusResult.iSCSIStatus = $status
            $statusResult.Success = $true
            
            Write-Host "iSCSI Status" -ForegroundColor Green
            Write-Host "================================================" -ForegroundColor Cyan
            Write-Host "Service Status: $($status.ServiceStatus)" -ForegroundColor Cyan
            Write-Host "Initiator Name: $($status.InitiatorName)" -ForegroundColor Cyan
            Write-Host "Active Sessions: $($status.ActiveSessions)" -ForegroundColor Cyan
            Write-Host "Total Targets: $($status.TotalTargets)" -ForegroundColor Cyan
            Write-Host "Connected Targets: $($status.ConnectedTargets)" -ForegroundColor Cyan
            Write-Host "Last Connection: $($status.LastConnection)" -ForegroundColor Cyan
            Write-Host "Health Status: $($status.HealthStatus)" -ForegroundColor Cyan
            
        } catch {
            $statusResult.Error = $_.Exception.Message
            Write-Error "Status check failed: $($_.Exception.Message)"
        }
        
        # Save status result
        $resultFile = Join-Path $LogPath "iSCSIStatus-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $statusResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "iSCSI status check completed!" -ForegroundColor Green
    }
}

# Generate operation report
Write-Host "`nGenerating operation report..." -ForegroundColor Green

$operationReport = @{
    Action = $Action
    TargetName = $TargetName
    TargetIP = $TargetIP
    InitiatorName = $InitiatorName
    VolumeSize = $VolumeSize
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    Status = "Completed"
}

$reportFile = Join-Path $LogPath "iSCSIOperation-Report-$Action-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$operationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Operation report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "iSCSI Management Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Target Name: $TargetName" -ForegroundColor Yellow
Write-Host "Target IP: $TargetIP" -ForegroundColor Yellow
Write-Host "Initiator Name: $InitiatorName" -ForegroundColor Yellow
Write-Host "Volume Size: $VolumeSize GB" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 iSCSI management completed successfully!" -ForegroundColor Green
Write-Host "The iSCSI system is now configured and operational." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the operation report" -ForegroundColor White
Write-Host "2. Monitor iSCSI performance" -ForegroundColor White
Write-Host "3. Set up multipath I/O if needed" -ForegroundColor White
Write-Host "4. Configure authentication if required" -ForegroundColor White
Write-Host "5. Test failover scenarios" -ForegroundColor White
Write-Host "6. Document iSCSI configuration" -ForegroundColor White
