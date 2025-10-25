#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Centralized Application Delivery RDS Environment

.DESCRIPTION
    This script deploys a complete RDS environment for centralized application delivery,
    including Session Host, Connection Broker, Web Access, and Gateway components.

.PARAMETER DeploymentName
    Name for the RDS deployment

.PARAMETER SessionHostCount
    Number of Session Host servers to deploy

.PARAMETER Applications
    Array of applications to publish

.PARAMETER UserGroups
    Array of user groups to grant access

.PARAMETER EnableGateway
    Enable Remote Desktop Gateway

.PARAMETER EnableWebAccess
    Enable RD Web Access

.PARAMETER LogFile
    Log file path for deployment

.EXAMPLE
    .\Deploy-CentralizedApplicationDelivery.ps1 -DeploymentName "AppDelivery-RDS" -SessionHostCount 3 -Applications @("Office365", "SAP", "CustomApp")

.EXAMPLE
    .\Deploy-CentralizedApplicationDelivery.ps1 -DeploymentName "LOB-Apps" -UserGroups @("LOB-Users", "Finance-Users") -EnableGateway -EnableWebAccess
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [int]$SessionHostCount = 2,
    
    [Parameter(Mandatory = $false)]
    [string[]]$Applications = @("Office365", "Notepad", "Calculator"),
    
    [Parameter(Mandatory = $false)]
    [string[]]$UserGroups = @("Domain Users"),
    
    [switch]$EnableGateway,
    
    [switch]$EnableWebAccess,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = "C:\Logs\RDS-Deployment.log"
)

# Set up logging
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-DeploymentLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

try {
    Write-DeploymentLog "Starting Centralized Application Delivery RDS Deployment: $DeploymentName"
    
    # Import RDS modules
    $modulePaths = @(
        ".\Modules\RDS-Core.psm1",
        ".\Modules\RDS-SessionHost.psm1",
        ".\Modules\RDS-ConnectionBroker.psm1",
        ".\Modules\RDS-Gateway.psm1",
        ".\Modules\RDS-WebAccess.psm1",
        ".\Modules\RDS-Licensing.psm1",
        ".\Modules\RDS-Monitoring.psm1",
        ".\Modules\RDS-Security.psm1"
    )
    
    foreach ($modulePath in $modulePaths) {
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force
            Write-DeploymentLog "Imported module: $modulePath"
        } else {
            Write-DeploymentLog "Module not found: $modulePath" "WARNING"
        }
    }
    
    # Test prerequisites
    Write-DeploymentLog "Testing prerequisites..."
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites.AdministratorPrivileges) {
        throw "Administrator privileges are required for RDS deployment"
    }
    
    # Step 1: Install RDS Session Host
    Write-DeploymentLog "Installing RDS Session Host..."
    $sessionHostResult = Install-RDSSessionHost -IncludeManagementTools -RestartRequired
    if ($sessionHostResult.Success) {
        Write-DeploymentLog "RDS Session Host installed successfully"
    } else {
        throw "Failed to install RDS Session Host: $($sessionHostResult.Error)"
    }
    
    # Step 2: Install Connection Broker
    Write-DeploymentLog "Installing RDS Connection Broker..."
    $brokerResult = Install-RDSConnectionBroker -IncludeManagementTools -RestartRequired
    if ($brokerResult.Success) {
        Write-DeploymentLog "RDS Connection Broker installed successfully"
    } else {
        throw "Failed to install RDS Connection Broker: $($brokerResult.Error)"
    }
    
    # Step 3: Configure RDS deployment
    Write-DeploymentLog "Configuring RDS deployment..."
    $deploymentResult = New-RDSDeployment -DeploymentName $DeploymentName -SessionHostCount $SessionHostCount
    if ($deploymentResult.Success) {
        Write-DeploymentLog "RDS deployment configured successfully"
    } else {
        throw "Failed to configure RDS deployment: $($deploymentResult.Error)"
    }
    
    # Step 4: Install and configure Gateway (if enabled)
    if ($EnableGateway) {
        Write-DeploymentLog "Installing and configuring RD Gateway..."
        $gatewayResult = Install-RDSGateway -IncludeManagementTools -RestartRequired
        if ($gatewayResult.Success) {
            Write-DeploymentLog "RD Gateway installed successfully"
            
            # Configure Gateway settings
            $gatewayConfig = Set-RDSGatewaySettings -EnableSSL -RequireClientCertificates
            if ($gatewayConfig.Success) {
                Write-DeploymentLog "RD Gateway configured successfully"
            }
        } else {
            Write-DeploymentLog "Failed to install RD Gateway: $($gatewayResult.Error)" "WARNING"
        }
    }
    
    # Step 5: Install and configure Web Access (if enabled)
    if ($EnableWebAccess) {
        Write-DeploymentLog "Installing and configuring RD Web Access..."
        $webAccessResult = Install-RDSWebAccess -IncludeManagementTools -RestartRequired
        if ($webAccessResult.Success) {
            Write-DeploymentLog "RD Web Access installed successfully"
            
            # Configure Web Access settings
            $webAccessConfig = Set-RDSWebAccessSettings -EnableSSO -CustomizePortal
            if ($webAccessConfig.Success) {
                Write-DeploymentLog "RD Web Access configured successfully"
            }
        } else {
            Write-DeploymentLog "Failed to install RD Web Access: $($webAccessResult.Error)" "WARNING"
        }
    }
    
    # Step 6: Install and configure Licensing
    Write-DeploymentLog "Installing and configuring RDS Licensing..."
    $licensingResult = Install-RDSLicensing -IncludeManagementTools -RestartRequired
    if ($licensingResult.Success) {
        Write-DeploymentLog "RDS Licensing installed successfully"
        
        # Configure licensing settings
        $licensingConfig = Set-RDSLicensingSettings -LicenseMode "PerUser" -LicenseServer "localhost"
        if ($licensingConfig.Success) {
            Write-DeploymentLog "RDS Licensing configured successfully"
        }
    } else {
        Write-DeploymentLog "Failed to install RDS Licensing: $($licensingResult.Error)" "WARNING"
    }
    
    # Step 7: Publish applications
    Write-DeploymentLog "Publishing applications..."
    foreach ($app in $Applications) {
        try {
            $publishResult = Publish-RDSApplication -ApplicationName $app -UserGroups $UserGroups
            if ($publishResult.Success) {
                Write-DeploymentLog "Published application: $app"
            } else {
                Write-DeploymentLog "Failed to publish application $app : $($publishResult.Error)" "WARNING"
            }
        } catch {
            Write-DeploymentLog "Error publishing application $app : $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Step 8: Configure user access
    Write-DeploymentLog "Configuring user access..."
    foreach ($group in $UserGroups) {
        try {
            $accessResult = Set-RDSUserAccess -UserGroup $group -AccessLevel "Full"
            if ($accessResult.Success) {
                Write-DeploymentLog "Configured access for group: $group"
            } else {
                Write-DeploymentLog "Failed to configure access for group $group : $($accessResult.Error)" "WARNING"
            }
        } catch {
            Write-DeploymentLog "Error configuring access for group $group : $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Step 9: Start monitoring
    Write-DeploymentLog "Starting RDS monitoring..."
    $monitoringResult = Start-RDSMonitoring -MonitoringType "All" -LogFile "C:\Logs\RDS-Monitor.log"
    if ($monitoringResult.Success) {
        Write-DeploymentLog "RDS monitoring started successfully"
    } else {
        Write-DeploymentLog "Failed to start RDS monitoring: $($monitoringResult.Error)" "WARNING"
    }
    
    # Step 10: Verify deployment
    Write-DeploymentLog "Verifying deployment..."
    $verificationResult = Test-RDSDeployment -DeploymentName $DeploymentName
    if ($verificationResult.Success) {
        Write-DeploymentLog "Deployment verification successful"
        Write-DeploymentLog "Deployment Summary:" "INFO"
        Write-DeploymentLog "  - Deployment Name: $DeploymentName" "INFO"
        Write-DeploymentLog "  - Session Hosts: $SessionHostCount" "INFO"
        Write-DeploymentLog "  - Applications: $($Applications -join ', ')" "INFO"
        Write-DeploymentLog "  - User Groups: $($UserGroups -join ', ')" "INFO"
        Write-DeploymentLog "  - Gateway Enabled: $EnableGateway" "INFO"
        Write-DeploymentLog "  - Web Access Enabled: $EnableWebAccess" "INFO"
    } else {
        Write-DeploymentLog "Deployment verification failed: $($verificationResult.Error)" "ERROR"
    }
    
    Write-DeploymentLog "Centralized Application Delivery RDS Deployment completed successfully!" "SUCCESS"
    
} catch {
    Write-DeploymentLog "Deployment failed: $($_.Exception.Message)" "ERROR"
    Write-Error "Centralized Application Delivery RDS Deployment failed: $($_.Exception.Message)"
    exit 1
}
