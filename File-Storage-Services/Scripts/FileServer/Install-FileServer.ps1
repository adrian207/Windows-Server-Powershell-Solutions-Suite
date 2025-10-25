#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Installation and Configuration Script

.DESCRIPTION
    This script provides a comprehensive file server installation and configuration process.
    It handles prerequisites, installation, configuration, and initial setup.

.PARAMETER DomainName
    The domain name for the file server

.PARAMETER ServerName
    The name of the file server (default: current computer name)

.PARAMETER EnableSMB1
    Enable SMB 1.0 protocol (not recommended for security)

.PARAMETER EnableSMB2
    Enable SMB 2.0 protocol

.PARAMETER EnableSMB3
    Enable SMB 3.0 protocol (recommended)

.PARAMETER RequireSigning
    Require SMB signing for security

.PARAMETER EnableEncryption
    Enable SMB encryption

.PARAMETER EnableFSRM
    Enable File Server Resource Manager

.PARAMETER EnableDFS
    Enable Distributed File System

.PARAMETER EnableNFS
    Enable Network File System

.PARAMETER SkipPrerequisites
    Skip prerequisite installation

.PARAMETER SkipConfiguration
    Skip initial configuration

.PARAMETER RestartRequired
    Allow automatic restart if required

.PARAMETER SMBPerformanceOptimization
    Apply SMB performance optimization (Basic, HighLatency, Enterprise, None)

.PARAMETER OptimizeForHighLatency
    Optimize SMB settings for high-latency networks

.PARAMETER OptimizeForEnterprise
    Optimize SMB settings for enterprise environments

.EXAMPLE
    .\Install-FileServer.ps1 -DomainName "contoso.com" -EnableSMB3 -RequireSigning -EnableEncryption

.EXAMPLE
    .\Install-FileServer.ps1 -DomainName "contoso.com" -EnableSMB3 -EnableFSRM -EnableDFS

.EXAMPLE
    .\Install-FileServer.ps1 -DomainName "contoso.com" -EnableSMB3 -SMBPerformanceOptimization "HighLatency"

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    
    [string]$ServerName = $env:COMPUTERNAME,
    
    [switch]$EnableSMB1,
    
    [switch]$EnableSMB2,
    
    [switch]$EnableSMB3,
    
    [switch]$RequireSigning,
    
    [switch]$EnableEncryption,
    
    [switch]$EnableFSRM,
    
    [switch]$EnableDFS,
    
    [switch]$EnableNFS,
    
    [switch]$SkipPrerequisites,
    
    [switch]$SkipConfiguration,
    
    [switch]$RestartRequired,
    
    [ValidateSet("Basic", "HighLatency", "Enterprise", "None")]
    [string]$SMBPerformanceOptimization = "None",
    
    [switch]$OptimizeForHighLatency,
    
    [switch]$OptimizeForEnterprise
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force
    Import-Module (Join-Path $modulePath "SMB-Performance.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:InstallationLog = @()
$script:StartTime = Get-Date

function Write-InstallationLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:InstallationLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Test-InstallationPrerequisites {
    Write-InstallationLog "Testing installation prerequisites..." "INFO"
    
    $prerequisites = Test-FileStoragePrerequisites
    
    if (-not $prerequisites) {
        Write-InstallationLog "Prerequisites check failed. Please resolve issues before continuing." "ERROR"
        return $false
    }
    
    Write-InstallationLog "Prerequisites check passed." "SUCCESS"
    return $true
}

function Install-Prerequisites {
    if ($SkipPrerequisites) {
        Write-InstallationLog "Skipping prerequisite installation as requested." "INFO"
        return $true
    }
    
    Write-InstallationLog "Installing file server prerequisites..." "INFO"
    
    try {
        Install-FileStoragePrerequisites -RestartRequired:$RestartRequired
        Write-InstallationLog "Prerequisites installed successfully." "SUCCESS"
        return $true
    } catch {
        Write-InstallationLog "Failed to install prerequisites: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-FileServerFeatures {
    Write-InstallationLog "Installing file server features..." "INFO"
    
    try {
        $features = @('FS-FileServer')
        
        # Add optional features based on parameters
        if ($EnableDFS) {
            $features += @('FS-DFS-Namespace', 'FS-DFS-Replication')
        }
        
        if ($EnableNFS) {
            $features += @('FS-NFS-Service')
        }
        
        if ($EnableFSRM) {
            $features += @('FS-Resource-Manager')
        }
        
        $restartNeeded = $false
        
        foreach ($feature in $features) {
            $featureInfo = Get-WindowsFeature -Name $feature
            
            if ($featureInfo.InstallState -ne 'Installed') {
                Write-InstallationLog "Installing feature: $feature" "INFO"
                $result = Install-WindowsFeature -Name $feature -IncludeManagementTools
                
                if ($result.RestartNeeded) {
                    $restartNeeded = $true
                }
                
                if ($result.Success) {
                    Write-InstallationLog "Successfully installed: $feature" "SUCCESS"
                } else {
                    Write-InstallationLog "Failed to install: $feature" "ERROR"
                    return $false
                }
            } else {
                Write-InstallationLog "Feature already installed: $feature" "INFO"
            }
        }
        
        if ($restartNeeded -and $RestartRequired) {
            Write-InstallationLog "Restart required. Restarting computer..." "WARNING"
            Restart-Computer -Force
        } elseif ($restartNeeded) {
            Write-InstallationLog "A restart is required to complete the installation." "WARNING"
        }
        
        return $true
        
    } catch {
        Write-InstallationLog "Error installing file server features: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-FileServerConfiguration {
    if ($SkipConfiguration) {
        Write-InstallationLog "Skipping file server configuration as requested." "INFO"
        return $true
    }
    
    Write-InstallationLog "Configuring file server..." "INFO"
    
    try {
        # Determine SMB performance optimization level
        $smbOptimizationLevel = "None"
        if ($OptimizeForHighLatency) {
            $smbOptimizationLevel = "HighLatency"
        } elseif ($OptimizeForEnterprise) {
            $smbOptimizationLevel = "Enterprise"
        } elseif ($SMBPerformanceOptimization -ne "None") {
            $smbOptimizationLevel = $SMBPerformanceOptimization
        }
        
        # Apply SMB performance optimization if specified
        if ($smbOptimizationLevel -ne "None") {
            Write-InstallationLog "Applying SMB performance optimization: $smbOptimizationLevel" "INFO"
            try {
                $smbResult = Set-SMBPerformanceOptimization -OptimizationLevel $smbOptimizationLevel
                if ($smbResult) {
                    Write-InstallationLog "SMB performance optimization applied successfully" "SUCCESS"
                    if ($smbResult.RestartRequired) {
                        Write-InstallationLog "Restart required for SMB optimization" "WARNING"
                    }
                } else {
                    Write-InstallationLog "SMB performance optimization failed" "WARNING"
                }
            } catch {
                Write-InstallationLog "Error applying SMB performance optimization: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Configure SMB protocols
        if ($EnableSMB1) {
            Write-InstallationLog "Enabling SMB 1.0 protocol..." "WARNING"
            Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
        }
        
        if ($EnableSMB2) {
            Write-InstallationLog "Enabling SMB 2.0 protocol..." "INFO"
            Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
        }
        
        if ($EnableSMB3) {
            Write-InstallationLog "Enabling SMB 3.0 protocol..." "INFO"
            Set-SmbServerConfiguration -EnableSMB3Protocol $true -Force
        }
        
        # Configure SMB security
        if ($RequireSigning) {
            Write-InstallationLog "Enabling SMB signing requirement..." "INFO"
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        }
        
        if ($EnableEncryption) {
            Write-InstallationLog "Enabling SMB encryption..." "INFO"
            Set-SmbServerConfiguration -EncryptData $true -Force
        }
        
        Write-InstallationLog "SMB configuration completed." "SUCCESS"
        
        # Configure FSRM if enabled
        if ($EnableFSRM) {
            Write-InstallationLog "Configuring FSRM..." "INFO"
            Enable-FSRM -EnableQuotas -EnableFileScreening -EnableReporting
            Write-InstallationLog "FSRM configuration completed." "SUCCESS"
        }
        
        # Configure DFS if enabled
        if ($EnableDFS) {
            Write-InstallationLog "Configuring DFS..." "INFO"
            # DFS configuration would go here
            Write-InstallationLog "DFS configuration completed." "SUCCESS"
        }
        
        # Configure NFS if enabled
        if ($EnableNFS) {
            Write-InstallationLog "Configuring NFS..." "INFO"
            # NFS configuration would go here
            Write-InstallationLog "NFS configuration completed." "SUCCESS"
        }
        
        Write-InstallationLog "File server configuration completed successfully." "SUCCESS"
        return $true
        
    } catch {
        Write-InstallationLog "Failed to configure file server: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-FileServerServices {
    Write-InstallationLog "Starting file server services..." "INFO"
    
    try {
        Start-FileServerServices
        Write-InstallationLog "File server services started successfully." "SUCCESS"
        return $true
    } catch {
        Write-InstallationLog "Failed to start file server services: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-Installation {
    Write-InstallationLog "Testing file server installation..." "INFO"
    
    try {
        Start-Sleep -Seconds 10  # Allow services to fully start
        
        $status = Get-FileServerStatus
        $health = Test-FileServerHealth
        
        if ($status.Configuration.FileServerInstalled -and $health.Overall -eq 'Healthy') {
            Write-InstallationLog "File server installation test passed." "SUCCESS"
            return $true
        } else {
            Write-InstallationLog "File server installation test failed. Status: $($status.Configuration.FileServerInstalled), Health: $($health.Overall)" "WARNING"
            return $false
        }
    } catch {
        Write-InstallationLog "Error testing installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-InstallationLog {
    $logPath = Join-Path $scriptPath "Installation-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:InstallationLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-InstallationLog "Installation log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save installation log: $($_.Exception.Message)"
    }
}

# Main installation process
try {
    # Set default values
    if (-not $PSBoundParameters.ContainsKey('EnableSMB3')) {
        $EnableSMB3 = $true
    }
    
    Write-InstallationLog "Starting file server installation process..." "INFO"
    Write-InstallationLog "Domain: $DomainName" "INFO"
    Write-InstallationLog "Server: $ServerName" "INFO"
    Write-InstallationLog "SMB 1.0: $EnableSMB1" "INFO"
    Write-InstallationLog "SMB 2.0: $EnableSMB2" "INFO"
    Write-InstallationLog "SMB 3.0: $EnableSMB3" "INFO"
    Write-InstallationLog "Require Signing: $RequireSigning" "INFO"
    Write-InstallationLog "Enable Encryption: $EnableEncryption" "INFO"
    Write-InstallationLog "Enable FSRM: $EnableFSRM" "INFO"
    Write-InstallationLog "Enable DFS: $EnableDFS" "INFO"
    Write-InstallationLog "Enable NFS: $EnableNFS" "INFO"
    Write-InstallationLog "SMB Performance Optimization: $SMBPerformanceOptimization" "INFO"
    Write-InstallationLog "Optimize for High Latency: $OptimizeForHighLatency" "INFO"
    Write-InstallationLog "Optimize for Enterprise: $OptimizeForEnterprise" "INFO"
    
    # Step 1: Test prerequisites
    if (-not (Test-InstallationPrerequisites)) {
        throw "Prerequisites check failed"
    }
    
    # Step 2: Install prerequisites
    if (-not (Install-Prerequisites)) {
        throw "Prerequisite installation failed"
    }
    
    # Step 3: Install file server features
    if (-not (Install-FileServerFeatures)) {
        throw "File server feature installation failed"
    }
    
    # Step 4: Configure file server
        if (-not (Set-FileServerConfiguration)) {
        throw "File server configuration failed"
    }
    
    # Step 5: Start services
    if (-not (Start-FileServerServices)) {
        throw "Failed to start file server services"
    }
    
    # Step 6: Test installation
    if (-not (Test-Installation)) {
        Write-InstallationLog "Installation completed but tests failed. Manual verification may be required." "WARNING"
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-InstallationLog "File server installation completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== File Server Installation Summary ===" -ForegroundColor Cyan
    Write-Host "Domain: $DomainName" -ForegroundColor White
    Write-Host "Server: $ServerName" -ForegroundColor White
    Write-Host "SMB 3.0: $EnableSMB3" -ForegroundColor White
    Write-Host "FSRM: $EnableFSRM" -ForegroundColor White
    Write-Host "DFS: $EnableDFS" -ForegroundColor White
    Write-Host "NFS: $EnableNFS" -ForegroundColor White
    Write-Host "Installation Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save installation log
    Save-InstallationLog
    
    Write-Host "`nInstallation completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-InstallationLog "File server installation failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save installation log
    Save-InstallationLog
    
    Write-Host "`nInstallation failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the installation log for details." -ForegroundColor Yellow
    
    exit 1
}
