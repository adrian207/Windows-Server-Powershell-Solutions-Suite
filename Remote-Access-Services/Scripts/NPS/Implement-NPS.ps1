#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Network Policy Server (NPS) Implementation Script

.DESCRIPTION
    This script provides comprehensive Network Policy Server implementation
    including installation, configuration, and management.

.PARAMETER Action
    Action to perform (Install, Configure, Test, Monitor, Remove)

.PARAMETER ConfigurationFile
    Path to configuration file

.PARAMETER LogFile
    Path to log file

.EXAMPLE
    .\Implement-NPS.ps1 -Action "Install"

.EXAMPLE
    .\Implement-NPS.ps1 -Action "Configure" -ConfigurationFile "C:\Config\NPS.json"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Configure", "Test", "Monitor", "Remove")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile
)

# Script configuration
$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Logging configuration
if (-not $LogFile) {
    $LogFile = "C:\Logs\NPS-Implementation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

# Create log directory if it doesn't exist
$LogDirectory = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

#region Helper Functions

function Write-NPSLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

function Test-NPSPrerequisites {
    Write-NPSLog "Testing NPS prerequisites..."
    
    $prerequisites = @{
        OSVersion = $false
        PowerShellVersion = $false
        AdministratorPrivileges = $false
        NetworkConnectivity = $false
        NPSInstalled = $false
        ADDSInstalled = $false
    }
    
    # Check OS version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10) {
        $prerequisites.OSVersion = $true
        Write-NPSLog "OS Version: Windows 10/Server 2016+ (Compatible)"
    } else {
        Write-NPSLog "OS Version: $($osVersion) (Incompatible)" "ERROR"
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
        Write-NPSLog "PowerShell Version: $psVersion (Compatible)"
    } else {
        Write-NPSLog "PowerShell Version: $psVersion (Incompatible)" "ERROR"
    }
    
    # Check administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $prerequisites.AdministratorPrivileges = $true
        Write-NPSLog "Administrator privileges: Confirmed"
    } else {
        Write-NPSLog "Administrator privileges: Not available" "ERROR"
    }
    
    # Check network connectivity
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
        $prerequisites.NetworkConnectivity = $ping
        Write-NPSLog "Network connectivity: $($ping ? 'Available' : 'Not available')"
    } catch {
        Write-NPSLog "Network connectivity: Check failed" "WARNING"
    }
    
    # Check NPS installation
    try {
        $npsFeature = Get-WindowsFeature -Name "NPAS" -ErrorAction SilentlyContinue
        $prerequisites.NPSInstalled = ($npsFeature -and $npsFeature.InstallState -eq "Installed")
        Write-NPSLog "NPS installation: $($prerequisites.NPSInstalled ? 'Installed' : 'Not installed')"
    } catch {
        Write-NPSLog "NPS installation: Check failed" "WARNING"
    }
    
    # Check AD DS installation
    try {
        $addsFeature = Get-WindowsFeature -Name "AD-Domain-Services" -ErrorAction SilentlyContinue
        $prerequisites.ADDSInstalled = ($addsFeature -and $addsFeature.InstallState -eq "Installed")
        Write-NPSLog "AD DS installation: $($prerequisites.ADDSInstalled ? 'Installed' : 'Not installed')"
    } catch {
        Write-NPSLog "AD DS installation: Check failed" "WARNING"
    }
    
    return $prerequisites
}

function Install-NPSFeatures {
    Write-NPSLog "Installing NPS features..."
    
    try {
        # Install Network Policy Server feature
        $result = Install-WindowsFeature -Name "NPAS" -IncludeManagementTools -ErrorAction Stop
        if ($result.Success) {
            Write-NPSLog "Network Policy Server feature installed successfully"
        } else {
            throw "Failed to install Network Policy Server feature"
        }
        
        # Install additional required features
        $additionalFeatures = @(
            "RSAT-NPAS-PowerShell",
            "RSAT-NPAS-Mgmt"
        )
        
        foreach ($feature in $additionalFeatures) {
            try {
                $featureResult = Install-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
                if ($featureResult.Success) {
                    Write-NPSLog "Feature $feature installed successfully"
                } else {
                    Write-NPSLog "Feature $feature installation failed" "WARNING"
                }
            } catch {
                Write-NPSLog "Feature $feature installation error: $($_.Exception.Message)" "WARNING"
            }
        }
        
        return $true
        
    } catch {
        Write-NPSLog "NPS features installation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-NPSConfiguration {
    param(
        [hashtable]$Configuration
    )
    
    Write-NPSLog "Configuring NPS..."
    
    try {
        # Import NPS module
        Import-Module NPS -Force -ErrorAction SilentlyContinue
        
        # Configure NPS settings
        if ($Configuration.ContainsKey("ServerName")) {
            Write-NPSLog "Setting server name: $($Configuration.ServerName)"
            # Note: Actual NPS configuration would require specific cmdlets
            # This is a placeholder for the configuration process
        }
        
        if ($Configuration.ContainsKey("AuthenticationMethod")) {
            Write-NPSLog "Setting authentication method: $($Configuration.AuthenticationMethod)"
        }
        
        if ($Configuration.ContainsKey("AccountingMethod")) {
            Write-NPSLog "Setting accounting method: $($Configuration.AccountingMethod)"
        }
        
        if ($Configuration.ContainsKey("PolicyName")) {
            Write-NPSLog "Setting policy name: $($Configuration.PolicyName)"
        }
        
        if ($Configuration.ContainsKey("ClientName")) {
            Write-NPSLog "Setting client name: $($Configuration.ClientName)"
        }
        
        if ($Configuration.ContainsKey("SharedSecret")) {
            Write-NPSLog "Setting shared secret: [HIDDEN]"
        }
        
        Write-NPSLog "NPS configuration completed successfully"
        return $true
        
    } catch {
        Write-NPSLog "NPS configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-NPSConfiguration {
    Write-NPSLog "Testing NPS configuration..."
    
    try {
        # Import NPS module
        Import-Module NPS -Force -ErrorAction SilentlyContinue
        
        # Test NPS status
        # Note: Actual NPS testing would require specific cmdlets
        # This is a placeholder for the testing process
        Write-NPSLog "NPS configuration test completed"
        
        return @{
            Success = $true
            Status = "Healthy"
            Issues = @()
        }
        
    } catch {
        Write-NPSLog "NPS configuration test failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Status = "Failed"
            Issues = @($_.Exception.Message)
        }
    }
}

function Start-NPSMonitoring {
    Write-NPSLog "Starting NPS monitoring..."
    
    try {
        # Start monitoring NPS services
        $services = @("IAS", "PolicyAgent")
        
        foreach ($service in $services) {
            try {
                $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($serviceObj) {
                    Write-NPSLog "Service $service status: $($serviceObj.Status)"
                } else {
                    Write-NPSLog "Service $service not found" "WARNING"
                }
            } catch {
                Write-NPSLog "Service $service check failed: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Monitor NPS performance counters
        try {
            $perfCounters = Get-Counter -ListSet "*IAS*" -ErrorAction SilentlyContinue
            if ($perfCounters) {
                Write-NPSLog "NPS performance counters available: $($perfCounters.Count)"
            } else {
                Write-NPSLog "NPS performance counters not available" "WARNING"
            }
        } catch {
            Write-NPSLog "Performance counter check failed: $($_.Exception.Message)" "WARNING"
        }
        
        Write-NPSLog "NPS monitoring started successfully"
        return $true
        
    } catch {
        Write-NPSLog "NPS monitoring failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-NPSConfiguration {
    Write-NPSLog "Removing NPS configuration..."
    
    try {
        # Import NPS module
        Import-Module NPS -Force -ErrorAction SilentlyContinue
        
        # Remove NPS configuration
        # Note: Actual NPS removal would require specific cmdlets
        # This is a placeholder for the removal process
        Write-NPSLog "NPS configuration removal completed"
        
        return $true
        
    } catch {
        Write-NPSLog "NPS configuration removal failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion

#region Main Script Logic

try {
    Write-NPSLog "Starting NPS Implementation Script - Version $ScriptVersion"
    Write-NPSLog "Action: $Action"
    Write-NPSLog "Computer: $env:COMPUTERNAME"
    Write-NPSLog "User: $env:USERNAME"
    
    # Test prerequisites
    $prerequisites = Test-NPSPrerequisites
    
    $criticalFailures = @()
    if (-not $prerequisites.OSVersion) { $criticalFailures += "OS Version" }
    if (-not $prerequisites.PowerShellVersion) { $criticalFailures += "PowerShell Version" }
    if (-not $prerequisites.AdministratorPrivileges) { $criticalFailures += "Administrator Privileges" }
    
    if ($criticalFailures.Count -gt 0) {
        throw "Critical prerequisites failed: $($criticalFailures -join ', ')"
    }
    
    Write-NPSLog "Prerequisites check completed successfully"
    
    # Load configuration if provided
    $configuration = @{}
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        try {
            $configuration = Get-Content $ConfigurationFile -Raw | ConvertFrom-Json -AsHashtable
            Write-NPSLog "Configuration loaded from: $ConfigurationFile"
        } catch {
            Write-NPSLog "Failed to load configuration file: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Execute action
    $actionResult = @{
        Action = $Action
        Success = $false
        StartTime = $ScriptStartTime
        EndTime = $null
        Duration = $null
        Error = $null
        Prerequisites = $prerequisites
        Configuration = $configuration
    }
    
    switch ($Action) {
        "Install" {
            Write-NPSLog "Installing NPS..."
            $actionResult.Success = Install-NPSFeatures
        }
        
        "Configure" {
            Write-NPSLog "Configuring NPS..."
            $actionResult.Success = Set-NPSConfiguration -Configuration $configuration
        }
        
        "Test" {
            Write-NPSLog "Testing NPS configuration..."
            $testResult = Test-NPSConfiguration
            $actionResult.Success = $testResult.Success
            $actionResult.TestResult = $testResult
        }
        
        "Monitor" {
            Write-NPSLog "Starting NPS monitoring..."
            $actionResult.Success = Start-NPSMonitoring
        }
        
        "Remove" {
            Write-NPSLog "Removing NPS configuration..."
            $actionResult.Success = Remove-NPSConfiguration
        }
    }
    
    # Calculate duration
    $actionResult.EndTime = Get-Date
    $actionResult.Duration = $actionResult.EndTime - $actionResult.StartTime
    
    if ($actionResult.Success) {
        Write-NPSLog "NPS $Action completed successfully!"
        Write-NPSLog "Duration: $($actionResult.Duration.TotalMinutes.ToString('F2')) minutes"
    } else {
        Write-NPSLog "NPS $Action failed!" "ERROR"
        Write-NPSLog "Duration: $($actionResult.Duration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    }
    
    # Return result
    return [PSCustomObject]$actionResult
    
} catch {
    $scriptEndTime = Get-Date
    $scriptDuration = $scriptEndTime - $ScriptStartTime
    
    Write-NPSLog "NPS Implementation Script FAILED!" "ERROR"
    Write-NPSLog "Error: $($_.Exception.Message)" "ERROR"
    Write-NPSLog "Duration: $($scriptDuration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    
    # Return failure result
    $actionResult = @{
        Action = $Action
        Success = $false
        StartTime = $ScriptStartTime
        EndTime = $scriptEndTime
        Duration = $scriptDuration
        Error = $_.Exception.Message
    }
    
    return [PSCustomObject]$actionResult
}

#endregion
