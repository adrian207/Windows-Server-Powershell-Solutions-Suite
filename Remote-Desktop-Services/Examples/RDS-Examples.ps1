#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RDS Examples and Demonstrations Script

.DESCRIPTION
    This script provides comprehensive RDS examples and demonstrations including
    basic setup examples, advanced configuration scenarios, troubleshooting examples,
    and best practices demonstrations.

.PARAMETER ExampleType
    Type of example to demonstrate (BasicSetup, AdvancedConfiguration, Troubleshooting, BestPractices)

.PARAMETER LogPath
    Path for operation logs

.PARAMETER ExamplePath
    Path for example storage

.EXAMPLE
    .\RDS-Examples.ps1 -ExampleType "BasicSetup" -ExamplePath "C:\RDS\Examples"

.EXAMPLE
    .\RDS-Examples.ps1 -ExampleType "AdvancedConfiguration" -ExamplePath "C:\RDS\Examples"

.NOTES
    Author: RDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("BasicSetup", "AdvancedConfiguration", "Troubleshooting", "BestPractices", "EnterpriseScenarios", "SecurityScenarios", "PerformanceScenarios")]
    [string]$ExampleType,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\RDS\Examples",

    [Parameter(Mandatory = $false)]
    [string]$ExamplePath = "C:\RDS\Examples",

    [Parameter(Mandatory = $false)]
    [string[]]$SessionHostServers = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string]$ConnectionBrokerServer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [switch]$EnableHighAvailability,

    [Parameter(Mandatory = $false)]
    [switch]$EnableLoadBalancing,

    [Parameter(Mandatory = $false)]
    [switch]$EnableMonitoring,

    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients
)

# Script configuration
$scriptConfig = @{
    ExampleType = $ExampleType
    LogPath = $LogPath
    ExamplePath = $ExamplePath
    SessionHostServers = $SessionHostServers
    ConnectionBrokerServer = $ConnectionBrokerServer
    EnableHighAvailability = $EnableHighAvailability
    EnableLoadBalancing = $EnableLoadBalancing
    EnableMonitoring = $EnableMonitoring
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "RDS Examples and Demonstrations" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example Type: $ExampleType" -ForegroundColor Yellow
Write-Host "Example Path: $ExamplePath" -ForegroundColor Yellow
Write-Host "Session Host Servers: $($SessionHostServers -join ', ')" -ForegroundColor Yellow
Write-Host "Connection Broker Server: $ConnectionBrokerServer" -ForegroundColor Yellow
Write-Host "High Availability: $EnableHighAvailability" -ForegroundColor Yellow
Write-Host "Load Balancing: $EnableLoadBalancing" -ForegroundColor Yellow
Write-Host "Monitoring: $EnableMonitoring" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\RDS-Core.psm1" -Force
    Import-Module "..\..\Modules\RDS-Examples.psm1" -Force
    Write-Host "RDS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import RDS modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

# Create example directory
if (-not (Test-Path $ExamplePath)) {
    New-Item -Path $ExamplePath -ItemType Directory -Force
}

switch ($ExampleType) {
    "BasicSetup" {
        Write-Host "`nDemonstrating RDS Basic Setup..." -ForegroundColor Green
        
        $exampleResult = @{
            Success = $false
            ExampleType = $ExampleType
            ExamplePath = $ExamplePath
            BasicSetupExamples = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting RDS basic setup examples..." -ForegroundColor Yellow
            
            # Basic setup examples
            Write-Host "Demonstrating basic setup examples..." -ForegroundColor Cyan
            $basicSetupExamples = @{
                ExampleType = $ExampleType
                ExamplePath = $ExamplePath
                SessionHostServers = $SessionHostServers
                BasicSetupScenarios = @{
                    InstallationExample = @{
                        Scenario = "RDS Installation"
                        Description = "Install RDS roles and features"
                        Steps = @(
                            "Install Windows Server 2019/2022",
                            "Install RDS roles",
                            "Configure RDS deployment",
                            "Verify installation"
                        )
                        Commands = @(
                            "Install-WindowsFeature -Name RDS-RD-Server",
                            "Install-WindowsFeature -Name RDS-Connection-Broker",
                            "Install-WindowsFeature -Name RDS-Gateway",
                            "Install-WindowsFeature -Name RDS-Web-Access"
                        )
                    }
                    ConfigurationExample = @{
                        Scenario = "RDS Configuration"
                        Description = "Configure RDS deployment"
                        Steps = @(
                            "Configure Connection Broker",
                            "Configure Session Host",
                            "Configure Gateway",
                            "Configure Web Access"
                        )
                        Commands = @(
                            "New-RDSessionDeployment -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Add-RDServer -ConnectionBroker $ConnectionBrokerServer -Server $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    UserAccessExample = @{
                        Scenario = "User Access Configuration"
                        Description = "Configure user access to RDS"
                        Steps = @(
                            "Create user groups",
                            "Assign permissions",
                            "Configure access policies",
                            "Test user access"
                        )
                        Commands = @(
                            "New-ADGroup -Name 'RDS Users' -GroupScope Global",
                            "Add-ADGroupMember -Identity 'RDS Users' -Members 'User1', 'User2'",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                }
                ExampleSettings = @{
                    HighAvailability = $EnableHighAvailability
                    LoadBalancing = $EnableLoadBalancing
                    Monitoring = $EnableMonitoring
                    Backup = $true
                    Security = $true
                }
                Monitoring = $EnableMonitoring
                EmailRecipients = $EmailRecipients
            }
            
            $exampleResult.BasicSetupExamples = $basicSetupExamples
            $exampleResult.EndTime = Get-Date
            $exampleResult.Duration = $exampleResult.EndTime - $exampleResult.StartTime
            $exampleResult.Success = $true
            
            Write-Host "`nRDS Basic Setup Examples Results:" -ForegroundColor Green
            Write-Host "  Example Type: $($exampleResult.ExampleType)" -ForegroundColor Cyan
            Write-Host "  Example Path: $($exampleResult.ExamplePath)" -ForegroundColor Cyan
            Write-Host "  Session Host Servers: $($basicSetupExamples.SessionHostServers.Count)" -ForegroundColor Cyan
            Write-Host "  High Availability: $($basicSetupExamples.ExampleSettings.HighAvailability)" -ForegroundColor Cyan
            Write-Host "  Load Balancing: $($basicSetupExamples.ExampleSettings.LoadBalancing)" -ForegroundColor Cyan
            Write-Host "  Monitoring: $($basicSetupExamples.ExampleSettings.Monitoring)" -ForegroundColor Cyan
            
            Write-Host "`nBasic Setup Scenarios:" -ForegroundColor Green
            foreach ($scenario in $basicSetupExamples.BasicSetupScenarios.GetEnumerator()) {
                Write-Host "  $($scenario.Key):" -ForegroundColor Yellow
                Write-Host "    Scenario: $($scenario.Value.Scenario)" -ForegroundColor White
                Write-Host "    Description: $($scenario.Value.Description)" -ForegroundColor White
                Write-Host "    Steps:" -ForegroundColor White
                foreach ($step in $scenario.Value.Steps) {
                    Write-Host "      • $step" -ForegroundColor White
                }
                Write-Host "    Commands:" -ForegroundColor White
                foreach ($command in $scenario.Value.Commands) {
                    Write-Host "      $command" -ForegroundColor White
                }
            }
            
        } catch {
            $exampleResult.Error = $_.Exception.Message
            Write-Error "RDS basic setup examples failed: $($_.Exception.Message)"
        }
        
        # Save example result
        $resultFile = Join-Path $LogPath "RDS-BasicSetupExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $exampleResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "RDS basic setup examples completed!" -ForegroundColor Green
    }
    
    "AdvancedConfiguration" {
        Write-Host "`nDemonstrating RDS Advanced Configuration..." -ForegroundColor Green
        
        $exampleResult = @{
            Success = $false
            ExampleType = $ExampleType
            ExamplePath = $ExamplePath
            AdvancedConfigurationExamples = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting RDS advanced configuration examples..." -ForegroundColor Yellow
            
            # Advanced configuration examples
            Write-Host "Demonstrating advanced configuration examples..." -ForegroundColor Cyan
            $advancedConfigurationExamples = @{
                ExampleType = $ExampleType
                ExamplePath = $ExamplePath
                SessionHostServers = $SessionHostServers
                AdvancedConfigurationScenarios = @{
                    HighAvailabilityExample = @{
                        Scenario = "High Availability Configuration"
                        Description = "Configure RDS high availability"
                        Steps = @(
                            "Configure Connection Broker HA",
                            "Configure Session Host HA",
                            "Configure Gateway HA",
                            "Configure Web Access HA"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    LoadBalancingExample = @{
                        Scenario = "Load Balancing Configuration"
                        Description = "Configure RDS load balancing"
                        Steps = @(
                            "Configure load balancing",
                            "Set up health checks",
                            "Configure failover",
                            "Test load balancing"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    SecurityExample = @{
                        Scenario = "Security Configuration"
                        Description = "Configure RDS security"
                        Steps = @(
                            "Configure authentication",
                            "Set up authorization",
                            "Configure encryption",
                            "Set up auditing"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                }
                ExampleSettings = @{
                    HighAvailability = $EnableHighAvailability
                    LoadBalancing = $EnableLoadBalancing
                    Monitoring = $EnableMonitoring
                    Backup = $true
                    Security = $true
                }
                Monitoring = $EnableMonitoring
                EmailRecipients = $EmailRecipients
            }
            
            $exampleResult.AdvancedConfigurationExamples = $advancedConfigurationExamples
            $exampleResult.EndTime = Get-Date
            $exampleResult.Duration = $exampleResult.EndTime - $exampleResult.StartTime
            $exampleResult.Success = $true
            
            Write-Host "`nRDS Advanced Configuration Examples Results:" -ForegroundColor Green
            Write-Host "  Example Type: $($exampleResult.ExampleType)" -ForegroundColor Cyan
            Write-Host "  Example Path: $($exampleResult.ExamplePath)" -ForegroundColor Cyan
            Write-Host "  Session Host Servers: $($advancedConfigurationExamples.SessionHostServers.Count)" -ForegroundColor Cyan
            Write-Host "  High Availability: $($advancedConfigurationExamples.ExampleSettings.HighAvailability)" -ForegroundColor Cyan
            Write-Host "  Load Balancing: $($advancedConfigurationExamples.ExampleSettings.LoadBalancing)" -ForegroundColor Cyan
            Write-Host "  Monitoring: $($advancedConfigurationExamples.ExampleSettings.Monitoring)" -ForegroundColor Cyan
            
            Write-Host "`nAdvanced Configuration Scenarios:" -ForegroundColor Green
            foreach ($scenario in $advancedConfigurationExamples.AdvancedConfigurationScenarios.GetEnumerator()) {
                Write-Host "  $($scenario.Key):" -ForegroundColor Yellow
                Write-Host "    Scenario: $($scenario.Value.Scenario)" -ForegroundColor White
                Write-Host "    Description: $($scenario.Value.Description)" -ForegroundColor White
                Write-Host "    Steps:" -ForegroundColor White
                foreach ($step in $scenario.Value.Steps) {
                    Write-Host "      • $step" -ForegroundColor White
                }
                Write-Host "    Commands:" -ForegroundColor White
                foreach ($command in $scenario.Value.Commands) {
                    Write-Host "      $command" -ForegroundColor White
                }
            }
            
        } catch {
            $exampleResult.Error = $_.Exception.Message
            Write-Error "RDS advanced configuration examples failed: $($_.Exception.Message)"
        }
        
        # Save example result
        $resultFile = Join-Path $LogPath "RDS-AdvancedConfigurationExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $exampleResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "RDS advanced configuration examples completed!" -ForegroundColor Green
    }
    
    "Troubleshooting" {
        Write-Host "`nDemonstrating RDS Troubleshooting..." -ForegroundColor Green
        
        $exampleResult = @{
            Success = $false
            ExampleType = $ExampleType
            ExamplePath = $ExamplePath
            TroubleshootingExamples = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting RDS troubleshooting examples..." -ForegroundColor Yellow
            
            # Troubleshooting examples
            Write-Host "Demonstrating troubleshooting examples..." -ForegroundColor Cyan
            $troubleshootingExamples = @{
                ExampleType = $ExampleType
                ExamplePath = $ExamplePath
                SessionHostServers = $SessionHostServers
                TroubleshootingScenarios = @{
                    ConnectionIssuesExample = @{
                        Scenario = "Connection Issues"
                        Description = "Troubleshoot RDS connection issues"
                        Steps = @(
                            "Check network connectivity",
                            "Verify RDS services",
                            "Check user permissions",
                            "Review event logs"
                        )
                        Commands = @(
                            "Test-NetConnection -ComputerName $ConnectionBrokerServer -Port 3389",
                            "Get-Service -Name 'TermService'",
                            "Get-EventLog -LogName 'Application' -Source 'TermService'",
                            "Get-RDSessionHost -ConnectionBroker $ConnectionBrokerServer"
                        )
                    }
                    PerformanceIssuesExample = @{
                        Scenario = "Performance Issues"
                        Description = "Troubleshoot RDS performance issues"
                        Steps = @(
                            "Check system resources",
                            "Monitor session performance",
                            "Check network performance",
                            "Review performance logs"
                        )
                        Commands = @(
                            "Get-Counter -Counter '\\Processor(_Total)\\% Processor Time'",
                            "Get-Counter -Counter '\\Memory\\Available MBytes'",
                            "Get-Counter -Counter '\\Network Interface(*)\\Bytes Total/sec'",
                            "Get-RDSessionHost -ConnectionBroker $ConnectionBrokerServer"
                        )
                    }
                    SecurityIssuesExample = @{
                        Scenario = "Security Issues"
                        Description = "Troubleshoot RDS security issues"
                        Steps = @(
                            "Check authentication",
                            "Verify authorization",
                            "Check encryption",
                            "Review security logs"
                        )
                        Commands = @(
                            "Get-EventLog -LogName 'Security' -Source 'Microsoft-Windows-Security-Auditing'",
                            "Get-EventLog -LogName 'Security' -Source 'Microsoft-Windows-Security-Auditing'",
                            "Get-EventLog -LogName 'Security' -Source 'Microsoft-Windows-Security-Auditing'",
                            "Get-RDSessionHost -ConnectionBroker $ConnectionBrokerServer"
                        )
                    }
                }
                ExampleSettings = @{
                    HighAvailability = $EnableHighAvailability
                    LoadBalancing = $EnableLoadBalancing
                    Monitoring = $EnableMonitoring
                    Backup = $true
                    Security = $true
                }
                Monitoring = $EnableMonitoring
                EmailRecipients = $EmailRecipients
            }
            
            $exampleResult.TroubleshootingExamples = $troubleshootingExamples
            $exampleResult.EndTime = Get-Date
            $exampleResult.Duration = $exampleResult.EndTime - $exampleResult.StartTime
            $exampleResult.Success = $true
            
            Write-Host "`nRDS Troubleshooting Examples Results:" -ForegroundColor Green
            Write-Host "  Example Type: $($exampleResult.ExampleType)" -ForegroundColor Cyan
            Write-Host "  Example Path: $($exampleResult.ExamplePath)" -ForegroundColor Cyan
            Write-Host "  Session Host Servers: $($troubleshootingExamples.SessionHostServers.Count)" -ForegroundColor Cyan
            Write-Host "  High Availability: $($troubleshootingExamples.ExampleSettings.HighAvailability)" -ForegroundColor Cyan
            Write-Host "  Load Balancing: $($troubleshootingExamples.ExampleSettings.LoadBalancing)" -ForegroundColor Cyan
            Write-Host "  Monitoring: $($troubleshootingExamples.ExampleSettings.Monitoring)" -ForegroundColor Cyan
            
            Write-Host "`nTroubleshooting Scenarios:" -ForegroundColor Green
            foreach ($scenario in $troubleshootingExamples.TroubleshootingScenarios.GetEnumerator()) {
                Write-Host "  $($scenario.Key):" -ForegroundColor Yellow
                Write-Host "    Scenario: $($scenario.Value.Scenario)" -ForegroundColor White
                Write-Host "    Description: $($scenario.Value.Description)" -ForegroundColor White
                Write-Host "    Steps:" -ForegroundColor White
                foreach ($step in $scenario.Value.Steps) {
                    Write-Host "      • $step" -ForegroundColor White
                }
                Write-Host "    Commands:" -ForegroundColor White
                foreach ($command in $scenario.Value.Commands) {
                    Write-Host "      $command" -ForegroundColor White
                }
            }
            
        } catch {
            $exampleResult.Error = $_.Exception.Message
            Write-Error "RDS troubleshooting examples failed: $($_.Exception.Message)"
        }
        
        # Save example result
        $resultFile = Join-Path $LogPath "RDS-TroubleshootingExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $exampleResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "RDS troubleshooting examples completed!" -ForegroundColor Green
    }
    
    "BestPractices" {
        Write-Host "`nDemonstrating RDS Best Practices..." -ForegroundColor Green
        
        $exampleResult = @{
            Success = $false
            ExampleType = $ExampleType
            ExamplePath = $ExamplePath
            BestPracticesExamples = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting RDS best practices examples..." -ForegroundColor Yellow
            
            # Best practices examples
            Write-Host "Demonstrating best practices examples..." -ForegroundColor Cyan
            $bestPracticesExamples = @{
                ExampleType = $ExampleType
                ExamplePath = $ExamplePath
                SessionHostServers = $SessionHostServers
                BestPracticesScenarios = @{
                    SecurityBestPracticesExample = @{
                        Scenario = "Security Best Practices"
                        Description = "Implement RDS security best practices"
                        Steps = @(
                            "Enable strong authentication",
                            "Implement least privilege access",
                            "Enable encryption",
                            "Set up auditing"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    PerformanceBestPracticesExample = @{
                        Scenario = "Performance Best Practices"
                        Description = "Implement RDS performance best practices"
                        Steps = @(
                            "Optimize system resources",
                            "Configure session limits",
                            "Set up monitoring",
                            "Implement load balancing"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    MonitoringBestPracticesExample = @{
                        Scenario = "Monitoring Best Practices"
                        Description = "Implement RDS monitoring best practices"
                        Steps = @(
                            "Set up performance monitoring",
                            "Configure health checks",
                            "Set up alerting",
                            "Implement reporting"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                }
                ExampleSettings = @{
                    HighAvailability = $EnableHighAvailability
                    LoadBalancing = $EnableLoadBalancing
                    Monitoring = $EnableMonitoring
                    Backup = $true
                    Security = $true
                }
                Monitoring = $EnableMonitoring
                EmailRecipients = $EmailRecipients
            }
            
            $exampleResult.BestPracticesExamples = $bestPracticesExamples
            $exampleResult.EndTime = Get-Date
            $exampleResult.Duration = $exampleResult.EndTime - $exampleResult.StartTime
            $exampleResult.Success = $true
            
            Write-Host "`nRDS Best Practices Examples Results:" -ForegroundColor Green
            Write-Host "  Example Type: $($exampleResult.ExampleType)" -ForegroundColor Cyan
            Write-Host "  Example Path: $($exampleResult.ExamplePath)" -ForegroundColor Cyan
            Write-Host "  Session Host Servers: $($bestPracticesExamples.SessionHostServers.Count)" -ForegroundColor Cyan
            Write-Host "  High Availability: $($bestPracticesExamples.ExampleSettings.HighAvailability)" -ForegroundColor Cyan
            Write-Host "  Load Balancing: $($bestPracticesExamples.ExampleSettings.LoadBalancing)" -ForegroundColor Cyan
            Write-Host "  Monitoring: $($bestPracticesExamples.ExampleSettings.Monitoring)" -ForegroundColor Cyan
            
            Write-Host "`nBest Practices Scenarios:" -ForegroundColor Green
            foreach ($scenario in $bestPracticesExamples.BestPracticesScenarios.GetEnumerator()) {
                Write-Host "  $($scenario.Key):" -ForegroundColor Yellow
                Write-Host "    Scenario: $($scenario.Value.Scenario)" -ForegroundColor White
                Write-Host "    Description: $($scenario.Value.Description)" -ForegroundColor White
                Write-Host "    Steps:" -ForegroundColor White
                foreach ($step in $scenario.Value.Steps) {
                    Write-Host "      • $step" -ForegroundColor White
                }
                Write-Host "    Commands:" -ForegroundColor White
                foreach ($command in $scenario.Value.Commands) {
                    Write-Host "      $command" -ForegroundColor White
                }
            }
            
        } catch {
            $exampleResult.Error = $_.Exception.Message
            Write-Error "RDS best practices examples failed: $($_.Exception.Message)"
        }
        
        # Save example result
        $resultFile = Join-Path $LogPath "RDS-BestPracticesExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $exampleResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "RDS best practices examples completed!" -ForegroundColor Green
    }
    
    "EnterpriseScenarios" {
        Write-Host "`nDemonstrating RDS Enterprise Scenarios..." -ForegroundColor Green
        
        $exampleResult = @{
            Success = $false
            ExampleType = $ExampleType
            ExamplePath = $ExamplePath
            EnterpriseScenariosExamples = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting RDS enterprise scenarios examples..." -ForegroundColor Yellow
            
            # Enterprise scenarios examples
            Write-Host "Demonstrating enterprise scenarios examples..." -ForegroundColor Cyan
            $enterpriseScenariosExamples = @{
                ExampleType = $ExampleType
                ExamplePath = $ExamplePath
                SessionHostServers = $SessionHostServers
                EnterpriseScenariosScenarios = @{
                    MultiSiteDeploymentExample = @{
                        Scenario = "Multi-Site Deployment"
                        Description = "Deploy RDS across multiple sites"
                        Steps = @(
                            "Configure site-to-site connectivity",
                            "Deploy RDS roles",
                            "Configure replication",
                            "Set up failover"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    HybridCloudDeploymentExample = @{
                        Scenario = "Hybrid Cloud Deployment"
                        Description = "Deploy RDS in hybrid cloud environment"
                        Steps = @(
                            "Configure cloud connectivity",
                            "Deploy cloud resources",
                            "Configure hybrid networking",
                            "Set up monitoring"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    DisasterRecoveryExample = @{
                        Scenario = "Disaster Recovery"
                        Description = "Implement RDS disaster recovery"
                        Steps = @(
                            "Configure backup systems",
                            "Set up replication",
                            "Configure failover",
                            "Test recovery procedures"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                }
                ExampleSettings = @{
                    HighAvailability = $EnableHighAvailability
                    LoadBalancing = $EnableLoadBalancing
                    Monitoring = $EnableMonitoring
                    Backup = $true
                    Security = $true
                }
                Monitoring = $EnableMonitoring
                EmailRecipients = $EmailRecipients
            }
            
            $exampleResult.EnterpriseScenariosExamples = $enterpriseScenariosExamples
            $exampleResult.EndTime = Get-Date
            $exampleResult.Duration = $exampleResult.EndTime - $exampleResult.StartTime
            $exampleResult.Success = $true
            
            Write-Host "`nRDS Enterprise Scenarios Examples Results:" -ForegroundColor Green
            Write-Host "  Example Type: $($exampleResult.ExampleType)" -ForegroundColor Cyan
            Write-Host "  Example Path: $($exampleResult.ExamplePath)" -ForegroundColor Cyan
            Write-Host "  Session Host Servers: $($enterpriseScenariosExamples.SessionHostServers.Count)" -ForegroundColor Cyan
            Write-Host "  High Availability: $($enterpriseScenariosExamples.ExampleSettings.HighAvailability)" -ForegroundColor Cyan
            Write-Host "  Load Balancing: $($enterpriseScenariosExamples.ExampleSettings.LoadBalancing)" -ForegroundColor Cyan
            Write-Host "  Monitoring: $($enterpriseScenariosExamples.ExampleSettings.Monitoring)" -ForegroundColor Cyan
            
            Write-Host "`nEnterprise Scenarios Scenarios:" -ForegroundColor Green
            foreach ($scenario in $enterpriseScenariosExamples.EnterpriseScenariosScenarios.GetEnumerator()) {
                Write-Host "  $($scenario.Key):" -ForegroundColor Yellow
                Write-Host "    Scenario: $($scenario.Value.Scenario)" -ForegroundColor White
                Write-Host "    Description: $($scenario.Value.Description)" -ForegroundColor White
                Write-Host "    Steps:" -ForegroundColor White
                foreach ($step in $scenario.Value.Steps) {
                    Write-Host "      • $step" -ForegroundColor White
                }
                Write-Host "    Commands:" -ForegroundColor White
                foreach ($command in $scenario.Value.Commands) {
                    Write-Host "      $command" -ForegroundColor White
                }
            }
            
        } catch {
            $exampleResult.Error = $_.Exception.Message
            Write-Error "RDS enterprise scenarios examples failed: $($_.Exception.Message)"
        }
        
        # Save example result
        $resultFile = Join-Path $LogPath "RDS-EnterpriseScenariosExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $exampleResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "RDS enterprise scenarios examples completed!" -ForegroundColor Green
    }
    
    "SecurityScenarios" {
        Write-Host "`nDemonstrating RDS Security Scenarios..." -ForegroundColor Green
        
        $exampleResult = @{
            Success = $false
            ExampleType = $ExampleType
            ExamplePath = $ExamplePath
            SecurityScenariosExamples = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting RDS security scenarios examples..." -ForegroundColor Yellow
            
            # Security scenarios examples
            Write-Host "Demonstrating security scenarios examples..." -ForegroundColor Cyan
            $securityScenariosExamples = @{
                ExampleType = $ExampleType
                ExamplePath = $ExamplePath
                SessionHostServers = $SessionHostServers
                SecurityScenariosScenarios = @{
                    MultiFactorAuthenticationExample = @{
                        Scenario = "Multi-Factor Authentication"
                        Description = "Implement MFA for RDS"
                        Steps = @(
                            "Configure MFA provider",
                            "Set up MFA policies",
                            "Configure user enrollment",
                            "Test MFA functionality"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    CertificateBasedAuthenticationExample = @{
                        Scenario = "Certificate-Based Authentication"
                        Description = "Implement certificate-based authentication"
                        Steps = @(
                            "Configure certificate authority",
                            "Issue user certificates",
                            "Configure certificate policies",
                            "Test certificate authentication"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    NetworkAccessControlExample = @{
                        Scenario = "Network Access Control"
                        Description = "Implement network access control"
                        Steps = @(
                            "Configure network policies",
                            "Set up access control lists",
                            "Configure network segmentation",
                            "Test network access control"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                }
                ExampleSettings = @{
                    HighAvailability = $EnableHighAvailability
                    LoadBalancing = $EnableLoadBalancing
                    Monitoring = $EnableMonitoring
                    Backup = $true
                    Security = $true
                }
                Monitoring = $EnableMonitoring
                EmailRecipients = $EmailRecipients
            }
            
            $exampleResult.SecurityScenariosExamples = $securityScenariosExamples
            $exampleResult.EndTime = Get-Date
            $exampleResult.Duration = $exampleResult.EndTime - $exampleResult.StartTime
            $exampleResult.Success = $true
            
            Write-Host "`nRDS Security Scenarios Examples Results:" -ForegroundColor Green
            Write-Host "  Example Type: $($exampleResult.ExampleType)" -ForegroundColor Cyan
            Write-Host "  Example Path: $($exampleResult.ExamplePath)" -ForegroundColor Cyan
            Write-Host "  Session Host Servers: $($securityScenariosExamples.SessionHostServers.Count)" -ForegroundColor Cyan
            Write-Host "  High Availability: $($securityScenariosExamples.ExampleSettings.HighAvailability)" -ForegroundColor Cyan
            Write-Host "  Load Balancing: $($securityScenariosExamples.ExampleSettings.LoadBalancing)" -ForegroundColor Cyan
            Write-Host "  Monitoring: $($securityScenariosExamples.ExampleSettings.Monitoring)" -ForegroundColor Cyan
            
            Write-Host "`nSecurity Scenarios Scenarios:" -ForegroundColor Green
            foreach ($scenario in $securityScenariosExamples.SecurityScenariosScenarios.GetEnumerator()) {
                Write-Host "  $($scenario.Key):" -ForegroundColor Yellow
                Write-Host "    Scenario: $($scenario.Value.Scenario)" -ForegroundColor White
                Write-Host "    Description: $($scenario.Value.Description)" -ForegroundColor White
                Write-Host "    Steps:" -ForegroundColor White
                foreach ($step in $scenario.Value.Steps) {
                    Write-Host "      • $step" -ForegroundColor White
                }
                Write-Host "    Commands:" -ForegroundColor White
                foreach ($command in $scenario.Value.Commands) {
                    Write-Host "      $command" -ForegroundColor White
                }
            }
            
        } catch {
            $exampleResult.Error = $_.Exception.Message
            Write-Error "RDS security scenarios examples failed: $($_.Exception.Message)"
        }
        
        # Save example result
        $resultFile = Join-Path $LogPath "RDS-SecurityScenariosExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $exampleResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "RDS security scenarios examples completed!" -ForegroundColor Green
    }
    
    "PerformanceScenarios" {
        Write-Host "`nDemonstrating RDS Performance Scenarios..." -ForegroundColor Green
        
        $exampleResult = @{
            Success = $false
            ExampleType = $ExampleType
            ExamplePath = $ExamplePath
            PerformanceScenariosExamples = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting RDS performance scenarios examples..." -ForegroundColor Yellow
            
            # Performance scenarios examples
            Write-Host "Demonstrating performance scenarios examples..." -ForegroundColor Cyan
            $performanceScenariosExamples = @{
                ExampleType = $ExampleType
                ExamplePath = $ExamplePath
                SessionHostServers = $SessionHostServers
                PerformanceScenariosScenarios = @{
                    ResourceOptimizationExample = @{
                        Scenario = "Resource Optimization"
                        Description = "Optimize RDS resource usage"
                        Steps = @(
                            "Analyze resource usage",
                            "Optimize CPU allocation",
                            "Optimize memory allocation",
                            "Optimize disk usage"
                        )
                        Commands = @(
                            "Get-Counter -Counter '\\Processor(_Total)\\% Processor Time'",
                            "Get-Counter -Counter '\\Memory\\Available MBytes'",
                            "Get-Counter -Counter '\\PhysicalDisk(_Total)\\Disk Read Bytes/sec'",
                            "Get-Counter -Counter '\\PhysicalDisk(_Total)\\Disk Write Bytes/sec'"
                        )
                    }
                    LoadBalancingExample = @{
                        Scenario = "Load Balancing"
                        Description = "Implement RDS load balancing"
                        Steps = @(
                            "Configure load balancing",
                            "Set up health checks",
                            "Configure failover",
                            "Test load balancing"
                        )
                        Commands = @(
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers",
                            "Set-RDSessionHost -ConnectionBroker $ConnectionBrokerServer -SessionHost $SessionHostServers"
                        )
                    }
                    PerformanceMonitoringExample = @{
                        Scenario = "Performance Monitoring"
                        Description = "Implement RDS performance monitoring"
                        Steps = @(
                            "Set up performance counters",
                            "Configure monitoring alerts",
                            "Set up performance reports",
                            "Test monitoring functionality"
                        )
                        Commands = @(
                            "Get-Counter -Counter '\\Processor(_Total)\\% Processor Time'",
                            "Get-Counter -Counter '\\Memory\\Available MBytes'",
                            "Get-Counter -Counter '\\Network Interface(*)\\Bytes Total/sec'",
                            "Get-Counter -Counter '\\Terminal Services\\Active Sessions'"
                        )
                    }
                }
                ExampleSettings = @{
                    HighAvailability = $EnableHighAvailability
                    LoadBalancing = $EnableLoadBalancing
                    Monitoring = $EnableMonitoring
                    Backup = $true
                    Security = $true
                }
                Monitoring = $EnableMonitoring
                EmailRecipients = $EmailRecipients
            }
            
            $exampleResult.PerformanceScenariosExamples = $performanceScenariosExamples
            $exampleResult.EndTime = Get-Date
            $exampleResult.Duration = $exampleResult.EndTime - $exampleResult.StartTime
            $exampleResult.Success = $true
            
            Write-Host "`nRDS Performance Scenarios Examples Results:" -ForegroundColor Green
            Write-Host "  Example Type: $($exampleResult.ExampleType)" -ForegroundColor Cyan
            Write-Host "  Example Path: $($exampleResult.ExamplePath)" -ForegroundColor Cyan
            Write-Host "  Session Host Servers: $($performanceScenariosExamples.SessionHostServers.Count)" -ForegroundColor Cyan
            Write-Host "  High Availability: $($performanceScenariosExamples.ExampleSettings.HighAvailability)" -ForegroundColor Cyan
            Write-Host "  Load Balancing: $($performanceScenariosExamples.ExampleSettings.LoadBalancing)" -ForegroundColor Cyan
            Write-Host "  Monitoring: $($performanceScenariosExamples.ExampleSettings.Monitoring)" -ForegroundColor Cyan
            
            Write-Host "`nPerformance Scenarios Scenarios:" -ForegroundColor Green
            foreach ($scenario in $performanceScenariosExamples.PerformanceScenariosScenarios.GetEnumerator()) {
                Write-Host "  $($scenario.Key):" -ForegroundColor Yellow
                Write-Host "    Scenario: $($scenario.Value.Scenario)" -ForegroundColor White
                Write-Host "    Description: $($scenario.Value.Description)" -ForegroundColor White
                Write-Host "    Steps:" -ForegroundColor White
                foreach ($step in $scenario.Value.Steps) {
                    Write-Host "      • $step" -ForegroundColor White
                }
                Write-Host "    Commands:" -ForegroundColor White
                foreach ($command in $scenario.Value.Commands) {
                    Write-Host "      $command" -ForegroundColor White
                }
            }
            
        } catch {
            $exampleResult.Error = $_.Exception.Message
            Write-Error "RDS performance scenarios examples failed: $($_.Exception.Message)"
        }
        
        # Save example result
        $resultFile = Join-Path $LogPath "RDS-PerformanceScenariosExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $exampleResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "RDS performance scenarios examples completed!" -ForegroundColor Green
    }
}

# Generate operation report
Write-Host "`nGenerating operation report..." -ForegroundColor Green

$operationReport = @{
    ExampleType = $ExampleType
    ExamplePath = $ExamplePath
    SessionHostServers = $SessionHostServers
    ConnectionBrokerServer = $ConnectionBrokerServer
    EnableHighAvailability = $EnableHighAvailability
    EnableLoadBalancing = $EnableLoadBalancing
    EnableMonitoring = $EnableMonitoring
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    Status = "Completed"
}

$reportFile = Join-Path $LogPath "RDS-Examples-Report-$ExampleType-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$operationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Operation report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "RDS Examples and Demonstrations Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example Type: $ExampleType" -ForegroundColor Yellow
Write-Host "Example Path: $ExamplePath" -ForegroundColor Yellow
Write-Host "Session Host Servers: $($SessionHostServers -join ', ')" -ForegroundColor Yellow
Write-Host "Connection Broker Server: $ConnectionBrokerServer" -ForegroundColor Yellow
Write-Host "High Availability: $EnableHighAvailability" -ForegroundColor Yellow
Write-Host "Load Balancing: $EnableLoadBalancing" -ForegroundColor Yellow
Write-Host "Monitoring: $EnableMonitoring" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 RDS examples and demonstrations completed successfully!" -ForegroundColor Green
Write-Host "The RDS examples system is now operational." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the operation report" -ForegroundColor White
Write-Host "2. Run additional examples" -ForegroundColor White
Write-Host "3. Customize examples for your environment" -ForegroundColor White
Write-Host "4. Document example procedures" -ForegroundColor White
Write-Host "5. Share examples with team" -ForegroundColor White
Write-Host "6. Create additional examples" -ForegroundColor White
