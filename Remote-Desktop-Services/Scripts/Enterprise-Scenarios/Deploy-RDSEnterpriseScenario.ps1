#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Master RDS Enterprise Scenario Deployment Script

.DESCRIPTION
    This script provides a unified interface for deploying any of the 30 enterprise RDS scenarios,
    from centralized application delivery to cloud bursting and advanced virtualization.

.PARAMETER Scenario
    Enterprise scenario to deploy

.PARAMETER DeploymentName
    Name for the RDS deployment

.PARAMETER ConfigurationFile
    JSON configuration file for the deployment

.PARAMETER LogFile
    Log file path for deployment

.PARAMETER DryRun
    Perform a dry run without making changes

.EXAMPLE
    .\Deploy-RDSEnterpriseScenario.ps1 -Scenario "CentralizedApplicationDelivery" -DeploymentName "AppDelivery-RDS"

.EXAMPLE
    .\Deploy-RDSEnterpriseScenario.ps1 -Scenario "VDI" -DeploymentName "VDI-Production" -ConfigurationFile "C:\Config\VDI-Config.json"

.EXAMPLE
    .\Deploy-RDSEnterpriseScenario.ps1 -Scenario "GraphicsAccelerated" -DeploymentName "CAD-RDS" -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "CentralizedApplicationDelivery",
        "FullDesktopVirtualization", 
        "RemoteAppPublishing",
        "RemoteDesktopGateway",
        "RDSWithAzureMFA",
        "VDI",
        "HybridRDSAzure",
        "ContractorAccess",
        "KioskThinClient",
        "EducationComputerLab",
        "DisasterRecovery",
        "PrivilegedAccessWorkstations",
        "GraphicsAccelerated",
        "ApplicationCompatibilitySandbox",
        "FSLogixProfileContainers",
        "LoadBalancingHA",
        "RDSWebAccessPortal",
        "GovernmentRegulated",
        "RemoteSupportHelpdesk",
        "MultiForestFederated",
        "TimeLimitedAccess",
        "IntuneIntegration",
        "FileServicesIntegration",
        "PowerShellAutomation",
        "HighLatencyOptimization",
        "LicensingAuditing",
        "RDSJumpHost",
        "SharedComputeEnvironments",
        "RemoteDevelopmentEnvironments",
        "CloudBurstingScaling"
    )]
    [string]$Scenario,
    
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = "C:\Logs\RDS-Enterprise-Deployment.log",
    
    [switch]$DryRun
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

function Get-ScenarioScript {
    param([string]$ScenarioName)
    
    $scenarioScripts = @{
        "CentralizedApplicationDelivery" = "Deploy-CentralizedApplicationDelivery.ps1"
        "FullDesktopVirtualization" = "Deploy-FullDesktopVirtualization.ps1"
        "RemoteAppPublishing" = "Deploy-RemoteAppPublishing.ps1"
        "RemoteDesktopGateway" = "Deploy-RemoteDesktopGateway.ps1"
        "RDSWithAzureMFA" = "Deploy-RDSWithAzureMFA.ps1"
        "VDI" = "Deploy-VDIEnvironment.ps1"
        "HybridRDSAzure" = "Deploy-HybridRDSAzure.ps1"
        "ContractorAccess" = "Deploy-ContractorAccess.ps1"
        "KioskThinClient" = "Deploy-KioskThinClient.ps1"
        "EducationComputerLab" = "Deploy-EducationComputerLab.ps1"
        "DisasterRecovery" = "Deploy-DisasterRecovery.ps1"
        "PrivilegedAccessWorkstations" = "Deploy-PrivilegedAccessWorkstations.ps1"
        "GraphicsAccelerated" = "Deploy-GraphicsAcceleratedRDS.ps1"
        "ApplicationCompatibilitySandbox" = "Deploy-ApplicationCompatibilitySandbox.ps1"
        "FSLogixProfileContainers" = "Deploy-FSLogixProfileContainers.ps1"
        "LoadBalancingHA" = "Deploy-LoadBalancingHA.ps1"
        "RDSWebAccessPortal" = "Deploy-RDSWebAccessPortal.ps1"
        "GovernmentRegulated" = "Deploy-GovernmentRegulated.ps1"
        "RemoteSupportHelpdesk" = "Deploy-RemoteSupportHelpdesk.ps1"
        "MultiForestFederated" = "Deploy-MultiForestFederated.ps1"
        "TimeLimitedAccess" = "Deploy-TimeLimitedAccess.ps1"
        "IntuneIntegration" = "Deploy-IntuneIntegration.ps1"
        "FileServicesIntegration" = "Deploy-FileServicesIntegration.ps1"
        "PowerShellAutomation" = "Deploy-PowerShellAutomation.ps1"
        "HighLatencyOptimization" = "Deploy-HighLatencyOptimization.ps1"
        "LicensingAuditing" = "Deploy-LicensingAuditing.ps1"
        "RDSJumpHost" = "Deploy-RDSJumpHost.ps1"
        "SharedComputeEnvironments" = "Deploy-SharedComputeEnvironments.ps1"
        "RemoteDevelopmentEnvironments" = "Deploy-RemoteDevelopmentEnvironments.ps1"
        "CloudBurstingScaling" = "Deploy-CloudBurstingScaling.ps1"
    }
    
    return $scenarioScripts[$ScenarioName]
}

function Get-ScenarioDescription {
    param([string]$ScenarioName)
    
    $scenarioDescriptions = @{
        "CentralizedApplicationDelivery" = "Deploy centralized application delivery environment with Session Host, Connection Broker, and application publishing"
        "FullDesktopVirtualization" = "Deploy full desktop virtualization with multi-user sessions and profile management"
        "RemoteAppPublishing" = "Deploy RemoteApp publishing for seamless application integration"
        "RemoteDesktopGateway" = "Deploy RD Gateway for secure internet access with SSL and certificate authentication"
        "RDSWithAzureMFA" = "Deploy RDS with Azure MFA integration via NPS Extension"
        "VDI" = "Deploy Virtual Desktop Infrastructure with VM pools and user assignments"
        "HybridRDSAzure" = "Deploy hybrid RDS environment integrated with Azure Virtual Desktop"
        "ContractorAccess" = "Deploy controlled access environment for contractors and partners"
        "KioskThinClient" = "Deploy kiosk and thin client environment with locked-down access"
        "EducationComputerLab" = "Deploy education environment with virtual classrooms and exam systems"
        "DisasterRecovery" = "Deploy disaster recovery environment for business continuity"
        "PrivilegedAccessWorkstations" = "Deploy secure PAW environment with enhanced security and auditing"
        "GraphicsAccelerated" = "Deploy graphics-accelerated environment for CAD, GIS, and 3D rendering"
        "ApplicationCompatibilitySandbox" = "Deploy compatibility sandbox for legacy applications"
        "FSLogixProfileContainers" = "Deploy FSLogix profile containers for advanced profile management"
        "LoadBalancingHA" = "Deploy load balancing and high availability configuration"
        "RDSWebAccessPortal" = "Deploy unified web access portal with customization"
        "GovernmentRegulated" = "Deploy government/regulated environment with compliance features"
        "RemoteSupportHelpdesk" = "Deploy remote support and helpdesk environment"
        "MultiForestFederated" = "Deploy multi-forest federated access environment"
        "TimeLimitedAccess" = "Deploy time-limited access for temporary users"
        "IntuneIntegration" = "Deploy RDS with Intune integration for device compliance"
        "FileServicesIntegration" = "Deploy RDS with file services integration and OneDrive"
        "PowerShellAutomation" = "Deploy PowerShell automation for infrastructure management"
        "HighLatencyOptimization" = "Deploy high-latency optimization for remote connections"
        "LicensingAuditing" = "Deploy licensing and auditing system for CAL management"
        "RDSJumpHost" = "Deploy RDS as secure jump host for administrative access"
        "SharedComputeEnvironments" = "Deploy shared compute environment for research and simulation"
        "RemoteDevelopmentEnvironments" = "Deploy remote development environment with IDE isolation"
        "CloudBurstingScaling" = "Deploy cloud bursting and on-demand scaling configuration"
    }
    
    return $scenarioDescriptions[$ScenarioName]
}

try {
    Write-DeploymentLog "Starting RDS Enterprise Scenario Deployment: $Scenario"
    Write-DeploymentLog "Deployment Name: $DeploymentName"
    Write-DeploymentLog "Dry Run: $DryRun"
    
    # Get scenario information
    $scenarioScript = Get-ScenarioScript -ScenarioName $Scenario
    $scenarioDescription = Get-ScenarioDescription -ScenarioName $Scenario
    
    Write-DeploymentLog "Scenario: $Scenario"
    Write-DeploymentLog "Description: $scenarioDescription"
    Write-DeploymentLog "Script: $scenarioScript"
    
    # Check if scenario script exists
    $scriptPath = Join-Path ".\Scripts\Enterprise-Scenarios" $scenarioScript
    if (-not (Test-Path $scriptPath)) {
        Write-DeploymentLog "Scenario script not found: $scriptPath" "ERROR"
        throw "Scenario script not found: $scriptPath"
    }
    
    # Load configuration if provided
    $configuration = @{}
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        try {
            $configuration = Get-Content $ConfigurationFile | ConvertFrom-Json | ConvertTo-Hashtable
            Write-DeploymentLog "Loaded configuration from: $ConfigurationFile"
        } catch {
            Write-DeploymentLog "Failed to load configuration file: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Perform dry run if requested
    if ($DryRun) {
        Write-DeploymentLog "DRY RUN MODE - No changes will be made" "INFO"
        Write-DeploymentLog "Would execute: $scriptPath" "INFO"
        Write-DeploymentLog "With parameters:" "INFO"
        Write-DeploymentLog "  - DeploymentName: $DeploymentName" "INFO"
        
        foreach ($key in $configuration.Keys) {
            Write-DeploymentLog "  - $key : $($configuration[$key])" "INFO"
        }
        
        Write-DeploymentLog "Dry run completed successfully" "SUCCESS"
        return
    }
    
    # Execute scenario script
    Write-DeploymentLog "Executing scenario script: $scenarioScript"
    
    # Build parameter hashtable
    $scriptParams = @{
        DeploymentName = $DeploymentName
        LogFile = $LogFile
    }
    
    # Add configuration parameters
    foreach ($key in $configuration.Keys) {
        $scriptParams[$key] = $configuration[$key]
    }
    
    # Execute the script
    try {
        & $scriptPath @scriptParams
        
        if ($LASTEXITCODE -eq 0) {
            Write-DeploymentLog "Scenario deployment completed successfully!" "SUCCESS"
            Write-DeploymentLog "Scenario: $Scenario" "SUCCESS"
            Write-DeploymentLog "Deployment Name: $DeploymentName" "SUCCESS"
        } else {
            Write-DeploymentLog "Scenario deployment failed with exit code: $LASTEXITCODE" "ERROR"
            throw "Scenario deployment failed"
        }
    } catch {
        Write-DeploymentLog "Error executing scenario script: $($_.Exception.Message)" "ERROR"
        throw
    }
    
} catch {
    Write-DeploymentLog "Master deployment failed: $($_.Exception.Message)" "ERROR"
    Write-Error "RDS Enterprise Scenario Deployment failed: $($_.Exception.Message)"
    exit 1
}
