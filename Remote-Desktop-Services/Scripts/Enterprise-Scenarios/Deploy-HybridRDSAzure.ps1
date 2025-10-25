#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Hybrid RDS + Azure Virtual Desktop Environment

.DESCRIPTION
    This script deploys a hybrid RDS environment that integrates with Azure Virtual Desktop (AVD)
    for seamless cloud and on-premises resource management.

.PARAMETER DeploymentName
    Name for the hybrid RDS deployment

.PARAMETER AzureSubscriptionId
    Azure subscription ID

.PARAMETER ResourceGroupName
    Azure resource group name

.PARAMETER WorkspaceName
    AVD workspace name

.PARAMETER HostPoolName
    AVD host pool name

.PARAMETER AzureRegion
    Azure region for resources

.PARAMETER EnableCloudBursting
    Enable cloud bursting capabilities

.PARAMETER BurstingPolicy
    Cloud bursting policy (CPU, Memory, Sessions)

.PARAMETER MaxInstances
    Maximum instances for cloud bursting

.PARAMETER UserAssignments
    Array of hybrid user assignments

.PARAMETER LogFile
    Log file path for deployment

.EXAMPLE
    .\Deploy-HybridRDSAzure.ps1 -DeploymentName "Hybrid-RDS" -AzureSubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "RDS-Hybrid-RG"

.EXAMPLE
    .\Deploy-HybridRDSAzure.ps1 -DeploymentName "Hybrid-RDS" -AzureSubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "RDS-Hybrid-RG" -EnableCloudBursting -BurstingPolicy "CPU" -MaxInstances 20
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $true)]
    [string]$AzureSubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$WorkspaceName,
    
    [Parameter(Mandatory = $false)]
    [string]$HostPoolName,
    
    [Parameter(Mandatory = $false)]
    [string]$AzureRegion = "East US",
    
    [switch]$EnableCloudBursting,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CPU", "Memory", "Sessions", "Custom")]
    [string]$BurstingPolicy = "CPU",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxInstances = 10,
    
    [Parameter(Mandatory = $false)]
    [hashtable[]]$UserAssignments = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = "C:\Logs\Hybrid-RDS-Deployment.log"
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
    Write-DeploymentLog "Starting Hybrid RDS + Azure Virtual Desktop Deployment: $DeploymentName"
    
    # Import RDS modules
    $modulePaths = @(
        ".\Modules\RDS-Core.psm1",
        ".\Modules\RDS-SessionHost.psm1",
        ".\Modules\RDS-ConnectionBroker.psm1",
        ".\Modules\RDS-HybridCloud.psm1",
        ".\Modules\RDS-Performance.psm1",
        ".\Modules\RDS-Monitoring.psm1"
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
    $prerequisites = Test-RDSHybridPrerequisites
    if (-not $prerequisites.AdministratorPrivileges) {
        throw "Administrator privileges are required for hybrid RDS deployment"
    }
    
    if (-not $prerequisites.AzureConnectivity) {
        Write-DeploymentLog "Azure connectivity not available. Please check network connectivity." "WARNING"
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
    
    # Step 3: Connect to Azure Virtual Desktop
    Write-DeploymentLog "Connecting to Azure Virtual Desktop..."
    $connectionResult = Connect-RDSAzureVirtualDesktop -AzureSubscriptionId $AzureSubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -HostPoolName $HostPoolName -AzureRegion $AzureRegion -AuthenticationMethod "Interactive"
    if ($connectionResult.Success) {
        Write-DeploymentLog "Connected to Azure Virtual Desktop successfully"
        Write-DeploymentLog "Connection ID: $($connectionResult.ConnectionId)"
    } else {
        throw "Failed to connect to Azure Virtual Desktop: $($connectionResult.Error)"
    }
    
    # Step 4: Configure cloud bursting (if enabled)
    if ($EnableCloudBursting) {
        Write-DeploymentLog "Configuring cloud bursting..."
        $burstingResult = New-RDSCloudBurstingConfiguration -BurstingPolicy $BurstingPolicy -AzureResourceGroup $ResourceGroupName -EnableAutoScaling -MaxInstances $MaxInstances -MinInstances 1
        if ($burstingResult.Success) {
            Write-DeploymentLog "Cloud bursting configured successfully"
            Write-DeploymentLog "Configuration ID: $($burstingResult.ConfigurationId)"
        } else {
            Write-DeploymentLog "Failed to configure cloud bursting: $($burstingResult.Error)" "WARNING"
        }
    }
    
    # Step 5: Configure hybrid user assignments
    Write-DeploymentLog "Configuring hybrid user assignments..."
    foreach ($assignment in $UserAssignments) {
        try {
            $assignmentResult = Set-RDSHybridUserAssignment -UserName $assignment.UserName -ResourceType $assignment.ResourceType -AssignmentPolicy $assignment.AssignmentPolicy -AzureWorkspace $WorkspaceName -OnPremisesPool $assignment.OnPremisesPool
            if ($assignmentResult.Success) {
                Write-DeploymentLog "Configured hybrid assignment for user: $($assignment.UserName)"
            } else {
                Write-DeploymentLog "Failed to configure hybrid assignment for user $($assignment.UserName) : $($assignmentResult.Error)" "WARNING"
            }
        } catch {
            Write-DeploymentLog "Error configuring hybrid assignment for user $($assignment.UserName) : $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Step 6: Configure performance optimization for hybrid environment
    Write-DeploymentLog "Configuring performance optimization for hybrid environment..."
    $perfResult = Set-RDSBandwidthOptimization -EnableCompression -EnableCaching -EnableAdaptiveGraphics -EnableUDPTransport -CompressionLevel 6 -CacheSize 150
    if ($perfResult.Success) {
        Write-DeploymentLog "Performance optimization configured successfully"
    } else {
        Write-DeploymentLog "Failed to configure performance optimization: $($perfResult.Error)" "WARNING"
    }
    
    # Step 7: Configure hybrid-specific registry settings
    Write-DeploymentLog "Configuring hybrid-specific settings..."
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Hybrid"
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $registryPath -Name "DeploymentName" -Value $DeploymentName -Type String
        Set-ItemProperty -Path $registryPath -Name "AzureSubscriptionId" -Value $AzureSubscriptionId -Type String
        Set-ItemProperty -Path $registryPath -Name "ResourceGroupName" -Value $ResourceGroupName -Type String
        Set-ItemProperty -Path $registryPath -Name "WorkspaceName" -Value $WorkspaceName -Type String
        Set-ItemProperty -Path $registryPath -Name "HostPoolName" -Value $HostPoolName -Type String
        Set-ItemProperty -Path $registryPath -Name "AzureRegion" -Value $AzureRegion -Type String
        Set-ItemProperty -Path $registryPath -Name "EnableCloudBursting" -Value ([int]$EnableCloudBursting) -Type DWord
        Set-ItemProperty -Path $registryPath -Name "BurstingPolicy" -Value $BurstingPolicy -Type String
        Set-ItemProperty -Path $registryPath -Name "MaxInstances" -Value $MaxInstances -Type DWord
        
        Write-DeploymentLog "Hybrid-specific registry settings configured"
    } catch {
        Write-DeploymentLog "Failed to configure hybrid-specific registry settings: $($_.Exception.Message)" "WARNING"
    }
    
    # Step 8: Start hybrid monitoring
    Write-DeploymentLog "Starting hybrid monitoring..."
    $monitoringResult = Start-RDSMonitoring -MonitoringType "All" -LogFile "C:\Logs\Hybrid-Monitor.log" -ContinuousMonitoring
    if ($monitoringResult.Success) {
        Write-DeploymentLog "Hybrid monitoring started successfully"
    } else {
        Write-DeploymentLog "Failed to start hybrid monitoring: $($monitoringResult.Error)" "WARNING"
    }
    
    # Step 9: Verify hybrid deployment
    Write-DeploymentLog "Verifying hybrid deployment..."
    $statusResult = Get-RDSHybridStatus -IncludeAzureResources -IncludeOnPremisesResources -IncludeUserAssignments
    if ($statusResult.Summary.TotalAzureResources -gt 0 -or $statusResult.Summary.TotalOnPremisesResources -gt 0) {
        Write-DeploymentLog "Hybrid deployment verification successful"
        Write-DeploymentLog "Azure Resources: $($statusResult.Summary.TotalAzureResources)" "INFO"
        Write-DeploymentLog "On-Premises Resources: $($statusResult.Summary.TotalOnPremisesResources)" "INFO"
        Write-DeploymentLog "User Assignments: $($statusResult.Summary.TotalUserAssignments)" "INFO"
    } else {
        Write-DeploymentLog "Hybrid deployment verification failed" "WARNING"
    }
    
    # Step 10: Verify deployment
    Write-DeploymentLog "Deployment Summary:" "INFO"
    Write-DeploymentLog "  - Deployment Name: $DeploymentName" "INFO"
    Write-DeploymentLog "  - Azure Subscription: $AzureSubscriptionId" "INFO"
    Write-DeploymentLog "  - Resource Group: $ResourceGroupName" "INFO"
    Write-DeploymentLog "  - Workspace: $WorkspaceName" "INFO"
    Write-DeploymentLog "  - Host Pool: $HostPoolName" "INFO"
    Write-DeploymentLog "  - Azure Region: $AzureRegion" "INFO"
    Write-DeploymentLog "  - Cloud Bursting: $EnableCloudBursting" "INFO"
    Write-DeploymentLog "  - Bursting Policy: $BurstingPolicy" "INFO"
    Write-DeploymentLog "  - Max Instances: $MaxInstances" "INFO"
    Write-DeploymentLog "  - User Assignments: $($UserAssignments.Count)" "INFO"
    
    Write-DeploymentLog "Hybrid RDS + Azure Virtual Desktop Deployment completed successfully!" "SUCCESS"
    
} catch {
    Write-DeploymentLog "Deployment failed: $($_.Exception.Message)" "ERROR"
    Write-Error "Hybrid RDS + Azure Virtual Desktop Deployment failed: $($_.Exception.Message)"
    exit 1
}
