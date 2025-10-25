#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Comprehensive RDS Deployment and Management Script

.DESCRIPTION
    This script provides comprehensive RDS deployment and management capabilities
    including installation, configuration, monitoring, and troubleshooting.

.PARAMETER Action
    Action to perform (Install, Configure, Monitor, Troubleshoot, All)

.PARAMETER DeploymentType
    Type of RDS deployment (SessionHost, ConnectionBroker, Gateway, WebAccess, Licensing, All)

.PARAMETER ConfigurationFile
    Path to configuration file

.PARAMETER LogFile
    Log file path

.PARAMETER Verbose
    Enable verbose logging

.EXAMPLE
    .\Deploy-RDSServices.ps1 -Action "Install" -DeploymentType "All"

.EXAMPLE
    .\Deploy-RDSServices.ps1 -Action "Configure" -ConfigurationFile "C:\Config\RDSConfig.json" -LogFile "C:\Logs\RDSDeploy.log"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Configure", "Monitor", "Troubleshoot", "All")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("SessionHost", "ConnectionBroker", "Gateway", "WebAccess", "Licensing", "All")]
    [string]$DeploymentType = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Script metadata
$ScriptVersion = "1.0.0"

#region Script Functions

function Write-ScriptLog {
    <#
    .SYNOPSIS
        Writes log messages to console and optionally to file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info" { Write-Host $logMessage -ForegroundColor White }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }
    
    if ($LogFile) {
        try {
            Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

function Test-ScriptPrerequisites {
    <#
    .SYNOPSIS
        Tests script prerequisites
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        PowerShellVersion = $false
        AdministratorPrivileges = $false
        WindowsVersion = $false
        RequiredModules = $false
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
    } else {
        Write-ScriptLog "PowerShell version 5.0 or higher is required" "Error"
    }
    
    # Check administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $prerequisites.AdministratorPrivileges = $true
    } else {
        Write-ScriptLog "Administrator privileges are required" "Error"
    }
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10) {
        $prerequisites.WindowsVersion = $true
    } else {
        Write-ScriptLog "Windows Server 2016 or higher is required" "Error"
    }
    
    # Check required modules
    $requiredModules = @("RemoteDesktop", "GroupPolicy")
    $availableModules = 0
    foreach ($moduleName in $requiredModules) {
        $module = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
        if ($module) {
            $availableModules++
        }
    }
    
    if ($availableModules -eq $requiredModules.Count) {
        $prerequisites.RequiredModules = $true
    } else {
        Write-ScriptLog "Required PowerShell modules are not available" "Warning"
    }
    
    return $prerequisites
}

function Install-RDSServices {
    <#
    .SYNOPSIS
        Installs RDS services based on deployment type
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeploymentType
    )
    
    try {
        Write-ScriptLog "Starting RDS services installation..." "Info"
        
        # Import RDS modules
        $modulePaths = @(
            ".\Modules\RDS-Core.psm1",
            ".\Modules\RDS-SessionHost.psm1",
            ".\Modules\RDS-ConnectionBroker.psm1",
            ".\Modules\RDS-Gateway.psm1",
            ".\Modules\RDS-WebAccess.psm1",
            ".\Modules\RDS-Licensing.psm1"
        )
        
        foreach ($modulePath in $modulePaths) {
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -ErrorAction SilentlyContinue
                Write-ScriptLog "Imported module: $modulePath" "Info"
            }
        }
        
        $installResults = @{}
        
        # Install based on deployment type
        switch ($DeploymentType) {
            "SessionHost" {
                Write-ScriptLog "Installing RDS Session Host..." "Info"
                $result = Install-RDSSessionHost -StartService -SetAutoStart -IncludeManagementTools
                $installResults["SessionHost"] = $result
            }
            "ConnectionBroker" {
                Write-ScriptLog "Installing RDS Connection Broker..." "Info"
                $result = Install-RDSConnectionBroker -StartService -SetAutoStart -IncludeManagementTools
                $installResults["ConnectionBroker"] = $result
            }
            "Gateway" {
                Write-ScriptLog "Installing RDS Gateway..." "Info"
                $result = Install-RDSGateway -StartService -SetAutoStart -IncludeManagementTools
                $installResults["Gateway"] = $result
            }
            "WebAccess" {
                Write-ScriptLog "Installing RDS Web Access..." "Info"
                $result = Install-RDSWebAccess -StartService -SetAutoStart -IncludeManagementTools
                $installResults["WebAccess"] = $result
            }
            "Licensing" {
                Write-ScriptLog "Installing RDS Licensing..." "Info"
                $result = Install-RDSLicensing -StartService -SetAutoStart -IncludeManagementTools
                $installResults["Licensing"] = $result
            }
            "All" {
                Write-ScriptLog "Installing all RDS services..." "Info"
                $installResults["SessionHost"] = Install-RDSSessionHost -StartService -SetAutoStart -IncludeManagementTools
                $installResults["ConnectionBroker"] = Install-RDSConnectionBroker -StartService -SetAutoStart -IncludeManagementTools
                $installResults["Gateway"] = Install-RDSGateway -StartService -SetAutoStart -IncludeManagementTools
                $installResults["WebAccess"] = Install-RDSWebAccess -StartService -SetAutoStart -IncludeManagementTools
                $installResults["Licensing"] = Install-RDSLicensing -StartService -SetAutoStart -IncludeManagementTools
            }
        }
        
        # Check installation results
        $successCount = 0
        $totalCount = $installResults.Count
        
        foreach ($service in $installResults.Keys) {
            if ($installResults[$service].Success) {
                $successCount++
                Write-ScriptLog "$service installation completed successfully" "Success"
            } else {
                Write-ScriptLog "$service installation failed: $($installResults[$service].Error)" "Error"
            }
        }
        
        if ($successCount -eq $totalCount) {
            Write-ScriptLog "All RDS services installed successfully" "Success"
        } else {
            Write-ScriptLog "Some RDS services failed to install. Success: $successCount/$totalCount" "Warning"
        }
        
        return $installResults
        
    } catch {
        Write-ScriptLog "Error installing RDS services: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Set-RDSServicesConfiguration {
    <#
    .SYNOPSIS
        Configures RDS services
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigurationFile
    )
    
    try {
        Write-ScriptLog "Starting RDS services configuration..." "Info"
        
        # Import RDS modules
        $modulePaths = @(
            ".\Modules\RDS-Core.psm1",
            ".\Modules\RDS-SessionHost.psm1",
            ".\Modules\RDS-ConnectionBroker.psm1",
            ".\Modules\RDS-Gateway.psm1",
            ".\Modules\RDS-WebAccess.psm1",
            ".\Modules\RDS-Licensing.psm1",
            ".\Modules\RDS-Security.psm1"
        )
        
        foreach ($modulePath in $modulePaths) {
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -ErrorAction SilentlyContinue
                Write-ScriptLog "Imported module: $modulePath" "Info"
            }
        }
        
        $configResults = @{}
        
        # Configure Session Host
        Write-ScriptLog "Configuring RDS Session Host..." "Info"
        $sessionHostConfig = New-RDSSessionHostConfiguration -MaxConnections 100 -IdleTimeout 30 -DisconnectTimeout 60
        $configResults["SessionHost"] = $sessionHostConfig
        
        # Configure Connection Broker
        Write-ScriptLog "Configuring RDS Connection Broker..." "Info"
        $connectionBrokerConfig = New-RDSHighAvailabilityConfiguration -PrimaryServer $env:COMPUTERNAME -SecondaryServer $null
        $configResults["ConnectionBroker"] = $connectionBrokerConfig
        
        # Configure Gateway
        Write-ScriptLog "Configuring RDS Gateway..." "Info"
        $gatewayConfig = New-RDSGatewayConfiguration -GatewayName "RDS-Gateway" -CertificateThumbprint $null
        $configResults["Gateway"] = $gatewayConfig
        
        # Configure Web Access
        Write-ScriptLog "Configuring RDS Web Access..." "Info"
        $webAccessConfig = New-RDSWebAccessConfiguration -WebAccessName "RDS-WebAccess" -CertificateThumbprint $null
        $configResults["WebAccess"] = $webAccessConfig
        
        # Configure Licensing
        Write-ScriptLog "Configuring RDS Licensing..." "Info"
        $licensingConfig = New-RDSLicensingConfiguration -LicenseMode "PerUser" -ActivationMethod "Automatic"
        $configResults["Licensing"] = $licensingConfig
        
        # Configure Security
        Write-ScriptLog "Configuring RDS Security..." "Info"
        $securityConfig = Set-RDSSecurityPolicy -AuthenticationLevel "Packet" -EncryptionLevel "High" -RequireNLA
        $configResults["Security"] = $securityConfig
        
        # Check configuration results
        $successCount = 0
        $totalCount = $configResults.Count
        
        foreach ($service in $configResults.Keys) {
            if ($configResults[$service].Success) {
                $successCount++
                Write-ScriptLog "$service configuration completed successfully" "Success"
            } else {
                Write-ScriptLog "$service configuration failed: $($configResults[$service].Error)" "Error"
            }
        }
        
        if ($successCount -eq $totalCount) {
            Write-ScriptLog "All RDS services configured successfully" "Success"
        } else {
            Write-ScriptLog "Some RDS services failed to configure. Success: $successCount/$totalCount" "Warning"
        }
        
        return $configResults
        
    } catch {
        Write-ScriptLog "Error configuring RDS services: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Start-RDSMonitoring {
    <#
    .SYNOPSIS
        Starts RDS monitoring
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-ScriptLog "Starting RDS monitoring..." "Info"
        
        # Import RDS modules
        $modulePaths = @(
            ".\Modules\RDS-Core.psm1",
            ".\Modules\RDS-Monitoring.psm1",
            ".\Modules\RDS-Security.psm1"
        )
        
        foreach ($modulePath in $modulePaths) {
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -ErrorAction SilentlyContinue
                Write-ScriptLog "Imported module: $modulePath" "Info"
            }
        }
        
        # Get monitoring status
        Write-ScriptLog "Getting RDS monitoring status..." "Info"
        $monitoringStatus = Get-RDSMonitoringStatus -IncludePerformanceCounters -IncludeEventLogs -MaxEvents 50
        
        if ($monitoringStatus) {
            Write-ScriptLog "RDS monitoring status retrieved successfully" "Success"
            Write-ScriptLog "Health Status: $($monitoringStatus.HealthStatus)" "Info"
            Write-ScriptLog "Running Services: $($monitoringStatus.Summary.RunningServices)/$($monitoringStatus.Summary.TotalServices)" "Info"
        } else {
            Write-ScriptLog "Failed to get RDS monitoring status" "Error"
        }
        
        # Test RDS health
        Write-ScriptLog "Testing RDS health..." "Info"
        $healthTest = Test-RDSHealth -TestType "Full"
        
        if ($healthTest) {
            Write-ScriptLog "RDS health test completed" "Success"
            Write-ScriptLog "Overall Health: $($healthTest.OverallHealth)" "Info"
        } else {
            Write-ScriptLog "Failed to test RDS health" "Error"
        }
        
        # Test RDS compliance
        Write-ScriptLog "Testing RDS compliance..." "Info"
        $complianceTest = Test-RDSCompliance -IncludeAuditLogs -MaxAuditEvents 50
        
        if ($complianceTest) {
            Write-ScriptLog "RDS compliance test completed" "Success"
            Write-ScriptLog "Overall Compliance: $($complianceTest.OverallCompliance)" "Info"
        } else {
            Write-ScriptLog "Failed to test RDS compliance" "Error"
        }
        
        return @{
            MonitoringStatus = $monitoringStatus
            HealthTest = $healthTest
            ComplianceTest = $complianceTest
        }
        
    } catch {
        Write-ScriptLog "Error starting RDS monitoring: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Start-RDSTroubleshooting {
    <#
    .SYNOPSIS
        Starts RDS troubleshooting
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-ScriptLog "Starting RDS troubleshooting..." "Info"
        
        # Import RDS modules
        $modulePaths = @(
            ".\Modules\RDS-Core.psm1",
            ".\Modules\RDS-Monitoring.psm1",
            ".\Modules\RDS-Security.psm1"
        )
        
        foreach ($modulePath in $modulePaths) {
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -ErrorAction SilentlyContinue
                Write-ScriptLog "Imported module: $modulePath" "Info"
            }
        }
        
        $troubleshootingResults = @{}
        
        # Test RDS prerequisites
        Write-ScriptLog "Testing RDS prerequisites..." "Info"
        $prerequisites = Test-RDSPrerequisites
        $troubleshootingResults["Prerequisites"] = $prerequisites
        
        # Test RDS health
        Write-ScriptLog "Testing RDS health..." "Info"
        $healthTest = Test-RDSHealth -TestType "Full"
        $troubleshootingResults["HealthTest"] = $healthTest
        
        # Test RDS compliance
        Write-ScriptLog "Testing RDS compliance..." "Info"
        $complianceTest = Test-RDSCompliance -IncludeAuditLogs -MaxAuditEvents 100
        $troubleshootingResults["ComplianceTest"] = $complianceTest
        
        # Test RDS connectivity
        Write-ScriptLog "Testing RDS connectivity..." "Info"
        $connectivityTest = Test-RDSSessionHostConnectivity
        $troubleshootingResults["ConnectivityTest"] = $connectivityTest
        
        # Generate troubleshooting report
        Write-ScriptLog "Generating troubleshooting report..." "Info"
        $troubleshootingReport = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            HealthTest = $healthTest
            ComplianceTest = $complianceTest
            ConnectivityTest = $connectivityTest
            Recommendations = @()
        }
        
        # Generate recommendations based on test results
        if ($healthTest -and $healthTest.OverallHealth -ne "Healthy") {
            $troubleshootingReport.Recommendations += "RDS health issues detected. Check service status and configuration."
        }
        
        if ($complianceTest -and $complianceTest.OverallCompliance -ne "Compliant") {
            $troubleshootingReport.Recommendations += "RDS compliance issues detected. Review security policies and configuration."
        }
        
        if ($connectivityTest -and -not $connectivityTest.Success) {
            $troubleshootingReport.Recommendations += "RDS connectivity issues detected. Check network configuration and firewall settings."
        }
        
        Write-ScriptLog "RDS troubleshooting completed" "Success"
        Write-ScriptLog "Total recommendations: $($troubleshootingReport.Recommendations.Count)" "Info"
        
        return $troubleshootingReport
        
    } catch {
        Write-ScriptLog "Error starting RDS troubleshooting: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Main Script Execution

try {
    Write-ScriptLog "RDS Deployment Script Started" "Info"
    Write-ScriptLog "Script Version: $ScriptVersion" "Info"
    Write-ScriptLog "Action: $Action" "Info"
    Write-ScriptLog "Deployment Type: $DeploymentType" "Info"
    
    # Test prerequisites
    Write-ScriptLog "Testing script prerequisites..." "Info"
    $prerequisites = Test-ScriptPrerequisites
    
    if (-not $prerequisites.AdministratorPrivileges) {
        Write-ScriptLog "Administrator privileges are required to run this script" "Error"
        exit 1
    }
    
    if (-not $prerequisites.PowerShellVersion) {
        Write-ScriptLog "PowerShell version 5.0 or higher is required" "Error"
        exit 1
    }
    
    if (-not $prerequisites.WindowsVersion) {
        Write-ScriptLog "Windows Server 2016 or higher is required" "Error"
        exit 1
    }
    
    Write-ScriptLog "All prerequisites met" "Success"
    
    # Execute based on action
    switch ($Action) {
        "Install" {
            Write-ScriptLog "Executing RDS installation..." "Info"
            $installResults = Install-RDSServices -DeploymentType $DeploymentType
            if ($installResults) {
                Write-ScriptLog "RDS installation completed" "Success"
            } else {
                Write-ScriptLog "RDS installation failed" "Error"
                exit 1
            }
        }
        "Configure" {
            Write-ScriptLog "Executing RDS configuration..." "Info"
            $configResults = Set-RDSServicesConfiguration -ConfigurationFile $ConfigurationFile
            if ($configResults) {
                Write-ScriptLog "RDS configuration completed" "Success"
            } else {
                Write-ScriptLog "RDS configuration failed" "Error"
                exit 1
            }
        }
        "Monitor" {
            Write-ScriptLog "Executing RDS monitoring..." "Info"
            $monitoringResults = Start-RDSMonitoring
            if ($monitoringResults) {
                Write-ScriptLog "RDS monitoring completed" "Success"
            } else {
                Write-ScriptLog "RDS monitoring failed" "Error"
                exit 1
            }
        }
        "Troubleshoot" {
            Write-ScriptLog "Executing RDS troubleshooting..." "Info"
            $troubleshootingResults = Start-RDSTroubleshooting
            if ($troubleshootingResults) {
                Write-ScriptLog "RDS troubleshooting completed" "Success"
            } else {
                Write-ScriptLog "RDS troubleshooting failed" "Error"
                exit 1
            }
        }
        "All" {
            Write-ScriptLog "Executing complete RDS deployment..." "Info"
            
            # Install
            Write-ScriptLog "Step 1: Installing RDS services..." "Info"
            $installResults = Install-RDSServices -DeploymentType $DeploymentType
            if (-not $installResults) {
                Write-ScriptLog "RDS installation failed" "Error"
                exit 1
            }
            
            # Configure
            Write-ScriptLog "Step 2: Configuring RDS services..." "Info"
            $configResults = Set-RDSServicesConfiguration -ConfigurationFile $ConfigurationFile
            if (-not $configResults) {
                Write-ScriptLog "RDS configuration failed" "Error"
                exit 1
            }
            
            # Monitor
            Write-ScriptLog "Step 3: Monitoring RDS services..." "Info"
            $monitoringResults = Start-RDSMonitoring
            if (-not $monitoringResults) {
                Write-ScriptLog "RDS monitoring failed" "Error"
                exit 1
            }
            
            # Troubleshoot
            Write-ScriptLog "Step 4: Troubleshooting RDS services..." "Info"
            $troubleshootingResults = Start-RDSTroubleshooting
            if (-not $troubleshootingResults) {
                Write-ScriptLog "RDS troubleshooting failed" "Error"
                exit 1
            }
            
            Write-ScriptLog "Complete RDS deployment completed successfully" "Success"
        }
    }
    
    Write-ScriptLog "RDS Deployment Script Completed Successfully" "Success"
    
} catch {
    Write-ScriptLog "Script execution failed: $($_.Exception.Message)" "Error"
    exit 1
}

#endregion
