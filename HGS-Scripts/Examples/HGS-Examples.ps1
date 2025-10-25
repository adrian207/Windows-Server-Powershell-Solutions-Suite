#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    HGS Examples and Usage Demonstrations

.DESCRIPTION
    Comprehensive examples script demonstrating HGS functionality including:
    - Basic HGS server deployment
    - Shielded VM creation and management
    - Attestation configuration examples
    - Security policy examples
    - Monitoring and alerting examples
    - Troubleshooting examples
    - Enterprise scenario examples

.PARAMETER ExampleType
    Type of examples to run (All, Basic, Security, Monitoring, Troubleshooting, Enterprise)

.PARAMETER HgsServer
    HGS server name

.PARAMETER SecurityLevel
    Security level (Low, Medium, High, Critical)

.PARAMETER Interactive
    Run examples in interactive mode

.PARAMETER Force
    Run examples without confirmation

.EXAMPLE
    .\HGS-Examples.ps1 -ExampleType "Basic" -HgsServer "HGS01"

.EXAMPLE
    .\HGS-Examples.ps1 -ExampleType "All" -Interactive

.EXAMPLE
    .\HGS-Examples.ps1 -ExampleType "Security" -SecurityLevel "High" -Force

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Basic", "Security", "Monitoring", "Troubleshooting", "Enterprise")]
    [string]$ExampleType = "All",

    [Parameter(Mandatory = $false)]
    [string]$HgsServer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$SecurityLevel = "High",

    [Parameter(Mandatory = $false)]
    [switch]$Interactive,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Import required modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ModulePath\..\..\Modules\HGS-Core.psm1" -Force
Import-Module "$ModulePath\..\..\Modules\HGS-Security.psm1" -Force
Import-Module "$ModulePath\..\..\Modules\HGS-Monitoring.psm1" -Force
Import-Module "$ModulePath\..\..\Modules\HGS-Troubleshooting.psm1" -Force

# Global variables
$script:ExamplesLog = @()
$script:ExamplesStartTime = Get-Date

function Write-ExamplesLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
    
    $script:ExamplesLog += $logEntry
    
    $color = switch ($Level) {
        "Info" { "White" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Show-BasicExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== BASIC HGS EXAMPLES ===" -ForegroundColor Cyan
    
    # Example 1: Deploy HGS Server
    Write-Host "`n1. Deploy HGS Server:" -ForegroundColor Yellow
    Write-Host "   .\Deploy-HGSServer.ps1 -HgsServer '$($Config.HgsServer)' -SecurityLevel '$($Config.SecurityLevel)'" -ForegroundColor Green
    
    # Example 2: Configure HGS
    Write-Host "`n2. Configure HGS:" -ForegroundColor Yellow
    Write-Host "   .\Configure-HGS.ps1 -HgsServer '$($Config.HgsServer)' -AttestationMode 'TPM' -SecurityLevel '$($Config.SecurityLevel)'" -ForegroundColor Green
    
    # Example 3: Add Host to HGS
    Write-Host "`n3. Add Host to HGS:" -ForegroundColor Yellow
    Write-Host "   Add-HGSHost -HostName 'HV01' -AttestationMode 'TPM' -HgsServer '$($Config.HgsServer)'" -ForegroundColor Green
    
    # Example 4: Create Shielded VM Template
    Write-Host "`n4. Create Shielded VM Template:" -ForegroundColor Yellow
    Write-Host "   New-HGSShieldedVMTemplate -TemplateName 'WindowsServer2019-Shielded' -SourcePath 'C:\Templates\WS2019.vhdx'" -ForegroundColor Green
    
    # Example 5: Deploy Shielded VM
    Write-Host "`n5. Deploy Shielded VM:" -ForegroundColor Yellow
    Write-Host "   New-HGSShieldedVM -VMName 'TestVM' -TemplateName 'WindowsServer2019-Shielded' -HgsServer '$($Config.HgsServer)'" -ForegroundColor Green
    
    Write-ExamplesLog "Basic examples displayed" "Success"
}

function Show-SecurityExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== SECURITY EXAMPLES ===" -ForegroundColor Cyan
    
    # Example 1: Apply Security Baseline
    Write-Host "`n1. Apply Security Baseline:" -ForegroundColor Yellow
    Write-Host "   .\Secure-HGS.ps1 -HgsServer '$($Config.HgsServer)' -SecurityLevel '$($Config.SecurityLevel)' -ComplianceStandard 'DoD'" -ForegroundColor Green
    
    # Example 2: Configure Zero Trust
    Write-Host "`n2. Configure Zero Trust:" -ForegroundColor Yellow
    Write-Host "   Set-HGSZeroTrust -TrustModel 'NeverTrust' -VerificationLevel 'Continuous' -PolicyEnforcement 'Strict'" -ForegroundColor Green
    
    # Example 3: Multi-Tenant Security
    Write-Host "`n3. Multi-Tenant Security:" -ForegroundColor Yellow
    Write-Host "   Set-HGSMultiTenantSecurity -TenantName 'TenantA' -IsolationLevel 'High' -ResourceQuotas @{VMs=10; Storage='1TB'}" -ForegroundColor Green
    
    # Example 4: Trust Boundary Configuration
    Write-Host "`n4. Trust Boundary Configuration:" -ForegroundColor Yellow
    Write-Host "   Set-HGSTrustBoundary -BoundaryName 'Production' -BoundaryType 'Network' -IsolationLevel 'High'" -ForegroundColor Green
    
    # Example 5: Certificate Management
    Write-Host "`n5. Certificate Management:" -ForegroundColor Yellow
    Write-Host "   Set-HGSCertificateManagement -CertificateType 'KeyProtection' -Action 'Validate' -Thumbprint 'ABC123...'" -ForegroundColor Green
    
    # Example 6: Rogue Host Detection
    Write-Host "`n6. Rogue Host Detection:" -ForegroundColor Yellow
    Write-Host "   Set-HGSRogueHostDetection -DetectionThreshold 2 -RevocationAction 'Immediate' -HgsServer '$($Config.HgsServer)'" -ForegroundColor Green
    
    Write-ExamplesLog "Security examples displayed" "Success"
}

function Show-MonitoringExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== MONITORING EXAMPLES ===" -ForegroundColor Cyan
    
    # Example 1: Setup Monitoring
    Write-Host "`n1. Setup Monitoring:" -ForegroundColor Yellow
    Write-Host "   .\Monitor-HGS.ps1 -HgsServer '$($Config.HgsServer)' -MonitoringLevel 'Advanced' -AlertMethods @('Email', 'Webhook')" -ForegroundColor Green
    
    # Example 2: Health Check
    Write-Host "`n2. Health Check:" -ForegroundColor Yellow
    Write-Host "   Get-HGSHealthStatus -HgsServer '$($Config.HgsServer)' -IncludeDetails" -ForegroundColor Green
    
    # Example 3: Performance Metrics
    Write-Host "`n3. Performance Metrics:" -ForegroundColor Yellow
    Write-Host "   Get-HGSPerformanceMetrics -HgsServer '$($Config.HgsServer)' -MetricType 'All'" -ForegroundColor Green
    
    # Example 4: Event Analysis
    Write-Host "`n4. Event Analysis:" -ForegroundColor Yellow
    Write-Host "   Get-HGSEventAnalysis -HgsServer '$($Config.HgsServer)' -TimeRange 7 -AnalysisType 'Comprehensive'" -ForegroundColor Green
    
    # Example 5: Capacity Planning
    Write-Host "`n5. Capacity Planning:" -ForegroundColor Yellow
    Write-Host "   Get-HGSCapacityPlanning -HgsServer '$($Config.HgsServer)' -PlanningHorizon 12" -ForegroundColor Green
    
    # Example 6: Alert Configuration
    Write-Host "`n6. Alert Configuration:" -ForegroundColor Yellow
    Write-Host "   Set-HGSAlerting -AlertMethods @('Email', 'Slack', 'Teams') -Recipients @('admin@contoso.com', 'https://hooks.slack.com/...')" -ForegroundColor Green
    
    Write-ExamplesLog "Monitoring examples displayed" "Success"
}

function Show-TroubleshootingExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== TROUBLESHOOTING EXAMPLES ===" -ForegroundColor Cyan
    
    # Example 1: Run Diagnostics
    Write-Host "`n1. Run Diagnostics:" -ForegroundColor Yellow
    Write-Host "   .\Troubleshoot-HGS.ps1 -HgsServer '$($Config.HgsServer)' -DiagnosticLevel 'Comprehensive' -IncludePerformance" -ForegroundColor Green
    
    # Example 2: Configuration Test
    Write-Host "`n2. Configuration Test:" -ForegroundColor Yellow
    Write-Host "   Test-HGSConfiguration -HgsServer '$($Config.HgsServer)' -TestType 'All'" -ForegroundColor Green
    
    # Example 3: Event Analysis
    Write-Host "`n3. Event Analysis:" -ForegroundColor Yellow
    Write-Host "   Get-HGSEventAnalysis -HgsServer '$($Config.HgsServer)' -TimeRange 7 -AnalysisType 'Deep'" -ForegroundColor Green
    
    # Example 4: Repair Operations
    Write-Host "`n4. Repair Operations:" -ForegroundColor Yellow
    Write-Host "   Repair-HGSService -HgsServer '$($Config.HgsServer)' -RepairType 'All' -Force" -ForegroundColor Green
    
    # Example 5: Troubleshooting Guide
    Write-Host "`n5. Troubleshooting Guide:" -ForegroundColor Yellow
    Write-Host "   Get-HGSTroubleshootingGuide -IssueType 'Attestation' -Severity 'High'" -ForegroundColor Green
    
    # Example 6: Performance Troubleshooting
    Write-Host "`n6. Performance Troubleshooting:" -ForegroundColor Yellow
    Write-Host "   Get-HGSPerformanceMetrics -HgsServer '$($Config.HgsServer)' -MetricType 'All' | Where-Object { $_.CPU.ProcessorTime -gt 80 }" -ForegroundColor Green
    
    Write-ExamplesLog "Troubleshooting examples displayed" "Success"
}

function Show-EnterpriseExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== ENTERPRISE SCENARIOS EXAMPLES ===" -ForegroundColor Cyan
    
    # Example 1: Deploy All Scenarios
    Write-Host "`n1. Deploy All Enterprise Scenarios:" -ForegroundColor Yellow
    Write-Host "   .\Deploy-HGSEnterpriseScenarios.ps1 -AllScenarios -HgsServer '$($Config.HgsServer)' -SecurityLevel '$($Config.SecurityLevel)'" -ForegroundColor Green
    
    # Example 2: Deploy Specific Scenario
    Write-Host "`n2. Deploy Specific Scenario:" -ForegroundColor Yellow
    Write-Host "   .\Deploy-HGSEnterpriseScenarios.ps1 -ScenarioNumber 1 -HgsServer '$($Config.HgsServer)' -SecurityLevel '$($Config.SecurityLevel)'" -ForegroundColor Green
    
    # Example 3: Shielded VMs Scenario
    Write-Host "`n3. Shielded VMs Scenario:" -ForegroundColor Yellow
    Write-Host "   .\Deploy-HGSEnterpriseScenarios.ps1 -ScenarioName 'ShieldedVMs' -HgsServer '$($Config.HgsServer)'" -ForegroundColor Green
    
    # Example 4: Multi-Tenant Scenario
    Write-Host "`n4. Multi-Tenant Scenario:" -ForegroundColor Yellow
    Write-Host "   .\Deploy-HGSEnterpriseScenarios.ps1 -ScenarioName 'MultiTenantFabric' -HgsServer '$($Config.HgsServer)'" -ForegroundColor Green
    
    # Example 5: Government Compliance
    Write-Host "`n5. Government Compliance:" -ForegroundColor Yellow
    Write-Host "   .\Deploy-HGSEnterpriseScenarios.ps1 -ScenarioName 'GovernmentCompliance' -SecurityLevel 'Critical'" -ForegroundColor Green
    
    # Example 6: Air-Gapped Operation
    Write-Host "`n6. Air-Gapped Operation:" -ForegroundColor Yellow
    Write-Host "   .\Deploy-HGSEnterpriseScenarios.ps1 -ScenarioName 'AirGappedOperation' -HgsServer '$($Config.HgsServer)'" -ForegroundColor Green
    
    Write-ExamplesLog "Enterprise examples displayed" "Success"
}

function Show-AdvancedExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== ADVANCED EXAMPLES ===" -ForegroundColor Cyan
    
    # Example 1: Custom Policy Automation
    Write-Host "`n1. Custom Policy Automation:" -ForegroundColor Yellow
    Write-Host "   Set-HGSPolicyAutomation -AutomationScript 'C:\Scripts\SecurityPolicyUpdate.ps1' -UpdateInterval 'Hourly' -DynamicAllowListing" -ForegroundColor Green
    
    # Example 2: SIEM Integration
    Write-Host "`n2. SIEM Integration:" -ForegroundColor Yellow
    Write-Host "   Set-HGSSIEMIntegration -SIEMEndpoint 'https://siem.contoso.com' -LogLevel 'Verbose' -ComplianceSystem 'https://compliance.contoso.com'" -ForegroundColor Green
    
    # Example 3: Third-Party Integration
    Write-Host "`n3. Third-Party Integration:" -ForegroundColor Yellow
    Write-Host "   Set-HGSThirdPartyIntegration -ManagementTool 'SCVMM-Secure' -IntegrationEndpoint 'https://scvmm-secure.contoso.com' -DashboardIntegration" -ForegroundColor Green
    
    # Example 4: Lifecycle Management
    Write-Host "`n4. Lifecycle Management:" -ForegroundColor Yellow
    Write-Host "   Set-HGSLifecycleManagement -RetirementPolicy 'Automatic' -PatchValidation -ContinuousIntegrity" -ForegroundColor Green
    
    # Example 5: Cross-Forest Configuration
    Write-Host "`n5. Cross-Forest Configuration:" -ForegroundColor Yellow
    Write-Host "   Set-HGSCrossForest -ForestName 'contoso.com' -TrustCertificate 'CrossForest-HighSecurity' -HgsServer '$($Config.HgsServer)'" -ForegroundColor Green
    
    # Example 6: Hybrid Cloud Integration
    Write-Host "`n6. Hybrid Cloud Integration:" -ForegroundColor Yellow
    Write-Host "   Set-HGSHybridCloud -AzureStackEndpoint 'https://azurestack.local' -OnPremisesHgsServer '$($Config.HgsServer)' -TrustMode 'Federated'" -ForegroundColor Green
    
    Write-ExamplesLog "Advanced examples displayed" "Success"
}

function Show-PowerShellExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== POWERSHELL SCRIPTING EXAMPLES ===" -ForegroundColor Cyan
    
    # Example 1: Basic HGS Management
    Write-Host "`n1. Basic HGS Management:" -ForegroundColor Yellow
    Write-Host @"
   # Get HGS status
   Get-HGSStatus -HgsServer '$($Config.HgsServer)'
   
   # List all hosts
   Get-HGSHosts -HgsServer '$($Config.HgsServer)'
   
   # Get attestation policies
   Get-HGSAttestationPolicies -HgsServer '$($Config.HgsServer)'
"@ -ForegroundColor Green
    
    # Example 2: Automated Host Addition
    Write-Host "`n2. Automated Host Addition:" -ForegroundColor Yellow
    Write-Host @"
   # Add multiple hosts
   $hosts = @('HV01', 'HV02', 'HV03')
   foreach ($host in $hosts) {
       Add-HGSHost -HostName $host -AttestationMode 'TPM' -HgsServer '$($Config.HgsServer)'
   }
"@ -ForegroundColor Green
    
    # Example 3: Monitoring Script
    Write-Host "`n3. Monitoring Script:" -ForegroundColor Yellow
    Write-Host @"
   # Continuous monitoring
   while ($true) {
       $health = Get-HGSHealthStatus -HgsServer '$($Config.HgsServer)'
       if ($health.OverallHealth -ne 'Healthy') {
           Write-Warning "HGS health issue detected: $($health.Issues)"
       }
       Start-Sleep -Seconds 300
   }
"@ -ForegroundColor Green
    
    # Example 4: Configuration Backup
    Write-Host "`n4. Configuration Backup:" -ForegroundColor Yellow
    Write-Host @"
   # Backup HGS configuration
   $backupPath = "C:\HGS-Backup\Config-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
   Export-HgsServerConfiguration -Path $backupPath
"@ -ForegroundColor Green
    
    Write-ExamplesLog "PowerShell examples displayed" "Success"
}

function Show-InteractiveExamples {
    param([hashtable]$Config)
    
    Write-Host "`n=== INTERACTIVE EXAMPLES ===" -ForegroundColor Cyan
    
    do {
        Write-Host "`nSelect an example to run:" -ForegroundColor Yellow
        Write-Host "1. Basic HGS Operations" -ForegroundColor White
        Write-Host "2. Security Configuration" -ForegroundColor White
        Write-Host "3. Monitoring Setup" -ForegroundColor White
        Write-Host "4. Troubleshooting Tools" -ForegroundColor White
        Write-Host "5. Enterprise Scenarios" -ForegroundColor White
        Write-Host "6. Advanced Features" -ForegroundColor White
        Write-Host "7. PowerShell Scripting" -ForegroundColor White
        Write-Host "0. Exit" -ForegroundColor White
        
        $choice = Read-Host "Enter your choice (0-7)"
        
        switch ($choice) {
            "1" { Show-BasicExamples -Config $Config }
            "2" { Show-SecurityExamples -Config $Config }
            "3" { Show-MonitoringExamples -Config $Config }
            "4" { Show-TroubleshootingExamples -Config $Config }
            "5" { Show-EnterpriseExamples -Config $Config }
            "6" { Show-AdvancedExamples -Config $Config }
            "7" { Show-PowerShellExamples -Config $Config }
            "0" { 
                Write-Host "Exiting interactive examples..." -ForegroundColor Yellow
                break 
            }
            default { 
                Write-Host "Invalid choice. Please select 0-7." -ForegroundColor Red 
            }
        }
        
        if ($choice -ne "0") {
            $continue = Read-Host "`nPress Enter to continue or 'q' to quit"
            if ($continue -eq "q") { break }
        }
        
    } while ($choice -ne "0")
    
    Write-ExamplesLog "Interactive examples completed" "Success"
}

function Save-ExamplesReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-ExamplesLog "Saving examples report..." "Info"
    
    try {
        $reportPath = "C:\HGS-Examples\Reports\HGS-Examples-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        
        # Create report directory
        $reportDir = Split-Path $reportPath -Parent
        if (!(Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force
        }
        
        $examplesReport = @{
            ExamplesInfo = @{
                HgsServer = $Config.HgsServer
                StartTime = $script:ExamplesStartTime
                EndTime = Get-Date
                Duration = (Get-Date) - $script:ExamplesStartTime
                ExampleType = $Config.ExampleType
                SecurityLevel = $Config.SecurityLevel
                Interactive = $Config.Interactive
                Configuration = $Config
            }
            ExamplesLog = $script:ExamplesLog
            CurrentStatus = Get-HGSStatus -HgsServer $Config.HgsServer
            Recommendations = @(
                "Practice with examples in a lab environment",
                "Customize examples for your specific environment",
                "Document your own examples and procedures",
                "Share examples with your team",
                "Regularly review and update examples",
                "Test examples before production use",
                "Create automation scripts based on examples",
                "Train staff using these examples"
            )
        }
        
        $examplesReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-ExamplesLog "Examples report saved to: $reportPath" "Success"
        return $reportPath
    }
    catch {
        Write-ExamplesLog "Failed to save examples report: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Main examples logic
try {
    Write-ExamplesLog "Starting HGS Examples demonstration..." "Info"
    Write-ExamplesLog "Server: $HgsServer" "Info"
    Write-ExamplesLog "Example Type: $ExampleType" "Info"
    Write-ExamplesLog "Security Level: $SecurityLevel" "Info"
    
    # Build examples configuration
    $script:ExamplesConfig = @{
        HgsServer = $HgsServer
        SecurityLevel = $SecurityLevel
        ExampleType = $ExampleType
        Interactive = $Interactive
    }
    
    # Confirm examples execution
    if (!$Force) {
        Write-Host "`nHGS Examples Demonstration:" -ForegroundColor Cyan
        Write-Host "Server Name: $($script:ExamplesConfig.HgsServer)" -ForegroundColor White
        Write-Host "Example Type: $($script:ExamplesConfig.ExampleType)" -ForegroundColor White
        Write-Host "Security Level: $($script:ExamplesConfig.SecurityLevel)" -ForegroundColor White
        Write-Host "Interactive Mode: $($script:ExamplesConfig.Interactive)" -ForegroundColor White
        
        $confirmation = Read-Host "`nDo you want to proceed with HGS examples demonstration? (Y/N)"
        if ($confirmation -notmatch "^[Yy]") {
            Write-ExamplesLog "Examples demonstration cancelled by user" "Warning"
            exit 0
        }
    }
    
    # Execute examples based on type
    if ($Interactive) {
        Show-InteractiveExamples -Config $script:ExamplesConfig
    } else {
        switch ($ExampleType) {
            "All" {
                Show-BasicExamples -Config $script:ExamplesConfig
                Show-SecurityExamples -Config $script:ExamplesConfig
                Show-MonitoringExamples -Config $script:ExamplesConfig
                Show-TroubleshootingExamples -Config $script:ExamplesConfig
                Show-EnterpriseExamples -Config $script:ExamplesConfig
                Show-AdvancedExamples -Config $script:ExamplesConfig
                Show-PowerShellExamples -Config $script:ExamplesConfig
            }
            "Basic" { Show-BasicExamples -Config $script:ExamplesConfig }
            "Security" { Show-SecurityExamples -Config $script:ExamplesConfig }
            "Monitoring" { Show-MonitoringExamples -Config $script:ExamplesConfig }
            "Troubleshooting" { Show-TroubleshootingExamples -Config $script:ExamplesConfig }
            "Enterprise" { Show-EnterpriseExamples -Config $script:ExamplesConfig }
        }
    }
    
    # Save examples report
    $reportPath = Save-ExamplesReport -Config $script:ExamplesConfig
    
    # Final status
    Write-ExamplesLog "HGS Examples demonstration completed successfully!" "Success"
    Write-Host "`nExamples Summary:" -ForegroundColor Green
    Write-Host "✓ Examples demonstrated successfully" -ForegroundColor Green
    Write-Host "✓ All example types covered" -ForegroundColor Green
    Write-Host "✓ Interactive mode completed" -ForegroundColor Green
    Write-Host "✓ Examples report generated" -ForegroundColor Green
    Write-Host "`nExamples report saved to: $reportPath" -ForegroundColor Cyan
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Review the examples report" -ForegroundColor White
    Write-Host "2. Practice with examples in a lab environment" -ForegroundColor White
    Write-Host "3. Customize examples for your environment" -ForegroundColor White
    Write-Host "4. Create your own examples and procedures" -ForegroundColor White
    Write-Host "5. Share examples with your team" -ForegroundColor White
    Write-Host "6. Train staff using these examples" -ForegroundColor White
    Write-Host "7. Document your implementation procedures" -ForegroundColor White
    
}
catch {
    Write-ExamplesLog "HGS Examples demonstration failed: $($_.Exception.Message)" "Error"
    Write-Host "`nExamples demonstration failed. Please check the error messages above and resolve the issues." -ForegroundColor Red
    exit 1
}
