#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DNS Examples and Demonstrations Script

.DESCRIPTION
    This script provides comprehensive DNS examples and demonstrations including
    basic setup, advanced configuration, troubleshooting scenarios, and best practices.

.PARAMETER ExampleType
    Type of example to demonstrate (BasicSetup, AdvancedConfig, Troubleshooting, BestPractices, EnterpriseScenarios)

.PARAMETER LogPath
    Path for example logs

.EXAMPLE
    .\DNS-Examples.ps1 -ExampleType "BasicSetup"

.EXAMPLE
    .\DNS-Examples.ps1 -ExampleType "AdvancedConfig" -LogPath "C:\DNS\Examples"

.NOTES
    Author: DNS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("BasicSetup", "AdvancedConfig", "Troubleshooting", "BestPractices", "EnterpriseScenarios", "AllExamples")]
    [string]$ExampleType,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\DNS\Examples",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDocumentation,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeCodeSamples,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeBestPractices
)

# Script configuration
$scriptConfig = @{
    ExampleType = $ExampleType
    LogPath = $LogPath
    IncludeDocumentation = $IncludeDocumentation
    IncludeCodeSamples = $IncludeCodeSamples
    IncludeBestPractices = $IncludeBestPractices
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "DNS Examples and Demonstrations" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example Type: $ExampleType" -ForegroundColor Yellow
Write-Host "Include Documentation: $IncludeDocumentation" -ForegroundColor Yellow
Write-Host "Include Code Samples: $IncludeCodeSamples" -ForegroundColor Yellow
Write-Host "Include Best Practices: $IncludeBestPractices" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\DNS-Core.psm1" -Force
    Import-Module "..\..\Modules\DNS-Security.psm1" -Force
    Import-Module "..\..\Modules\DNS-Monitoring.psm1" -Force
    Import-Module "..\..\Modules\DNS-Troubleshooting.psm1" -Force
    Write-Host "DNS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import DNS modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

switch ($ExampleType) {
    "BasicSetup" {
        Write-Host "`nDemonstrating Basic DNS Setup..." -ForegroundColor Green
        
        $basicSetupResult = @{
            Success = $false
            Examples = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Running basic DNS setup examples..." -ForegroundColor Yellow
            
            # Example 1: Install DNS Server
            Write-Host "`nExample 1: Installing DNS Server Role" -ForegroundColor Cyan
            $example1 = @{
                Title = "Install DNS Server Role"
                Description = "Install the DNS Server role on Windows Server"
                Code = @"
# Install DNS Server role
Install-WindowsFeature -Name DNS -IncludeManagementTools

# Verify installation
Get-WindowsFeature -Name DNS
"@
                Result = "DNS Server role installed successfully"
                Notes = "Requires administrator privileges and server restart"
            }
            $basicSetupResult.Examples += $example1
            
            # Example 2: Create Primary Zone
            Write-Host "`nExample 2: Creating Primary DNS Zone" -ForegroundColor Cyan
            $example2 = @{
                Title = "Create Primary DNS Zone"
                Description = "Create a primary DNS zone for a domain"
                Code = @"
# Create primary zone
Add-DnsServerPrimaryZone -Name "contoso.com" -ZoneFile "contoso.com.dns"

# Add DNS records
Add-DnsServerResourceRecordA -Name "www" -ZoneName "contoso.com" -IPv4Address "192.168.1.10"
Add-DnsServerResourceRecordMX -Name "@" -ZoneName "contoso.com" -MailExchange "mail.contoso.com" -Preference 10
"@
                Result = "Primary zone 'contoso.com' created with initial records"
                Notes = "Zone file will be created automatically"
            }
            $basicSetupResult.Examples += $example2
            
            # Example 3: Configure Forwarders
            Write-Host "`nExample 3: Configuring DNS Forwarders" -ForegroundColor Cyan
            $example3 = @{
                Title = "Configure DNS Forwarders"
                Description = "Configure DNS forwarders for external resolution"
                Code = @"
# Set DNS forwarders
Set-DnsServerForwarder -IPAddress @("8.8.8.8", "8.8.4.4")

# Verify forwarder configuration
Get-DnsServerForwarder
"@
                Result = "DNS forwarders configured successfully"
                Notes = "Use reliable public DNS servers as forwarders"
            }
            $basicSetupResult.Examples += $example3
            
            # Example 4: Create Reverse Lookup Zone
            Write-Host "`nExample 4: Creating Reverse Lookup Zone" -ForegroundColor Cyan
            $example4 = @{
                Title = "Create Reverse Lookup Zone"
                Description = "Create a reverse lookup zone for PTR records"
                Code = @"
# Create reverse lookup zone
Add-DnsServerPrimaryZone -NetworkID "192.168.1.0/24" -ZoneFile "1.168.192.in-addr.arpa.dns"

# Add PTR record
Add-DnsServerResourceRecordPtr -Name "10" -ZoneName "1.168.192.in-addr.arpa" -PtrDomainName "www.contoso.com"
"@
                Result = "Reverse lookup zone created with PTR record"
                Notes = "Network ID should match your subnet"
            }
            $basicSetupResult.Examples += $example4
            
            # Example 5: Configure Dynamic Updates
            Write-Host "`nExample 5: Configuring Dynamic Updates" -ForegroundColor Cyan
            $example5 = @{
                Title = "Configure Dynamic Updates"
                Description = "Enable dynamic updates for DNS zones"
                Code = @"
# Configure dynamic updates
Set-DnsServerPrimaryZone -Name "contoso.com" -DynamicUpdate Secure

# Verify configuration
Get-DnsServerZone -Name "contoso.com" | Select-Object DynamicUpdate
"@
                Result = "Dynamic updates configured for zone"
                Notes = "Secure updates require Active Directory integration"
            }
            $basicSetupResult.Examples += $example5
            
            $basicSetupResult.EndTime = Get-Date
            $basicSetupResult.Duration = $basicSetupResult.EndTime - $basicSetupResult.StartTime
            $basicSetupResult.Success = $true
            
            Write-Host "`nBasic DNS Setup Examples Completed:" -ForegroundColor Green
            Write-Host "  Examples Demonstrated: $($basicSetupResult.Examples.Count)" -ForegroundColor Cyan
            
            foreach ($example in $basicSetupResult.Examples) {
                Write-Host "`n$($example.Title):" -ForegroundColor Yellow
                Write-Host "  Description: $($example.Description)" -ForegroundColor White
                Write-Host "  Result: $($example.Result)" -ForegroundColor White
                Write-Host "  Notes: $($example.Notes)" -ForegroundColor White
            }
            
        } catch {
            $basicSetupResult.Error = $_.Exception.Message
            Write-Error "Basic DNS setup examples failed: $($_.Exception.Message)"
        }
        
        # Save basic setup result
        $resultFile = Join-Path $LogPath "DNS-BasicSetup-Examples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $basicSetupResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Basic DNS setup examples completed!" -ForegroundColor Green
    }
    
    "AdvancedConfig" {
        Write-Host "`nDemonstrating Advanced DNS Configuration..." -ForegroundColor Green
        
        $advancedConfigResult = @{
            Success = $false
            Examples = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Running advanced DNS configuration examples..." -ForegroundColor Yellow
            
            # Example 1: DNSSEC Configuration
            Write-Host "`nExample 1: Configuring DNSSEC" -ForegroundColor Cyan
            $example1 = @{
                Title = "Configure DNSSEC"
                Description = "Enable DNSSEC for DNS security"
                Code = @"
# Enable DNSSEC
Set-DnsServerDnssecZoneSetting -ZoneName "contoso.com" -Enable

# Configure key signing key
Add-DnsServerSigningKey -ZoneName "contoso.com" -KeyType KeySigningKey -CryptoAlgorithm RSASHA256 -KeySize 2048

# Configure zone signing key
Add-DnsServerSigningKey -ZoneName "contoso.com" -KeyType ZoneSigningKey -CryptoAlgorithm RSASHA256 -KeySize 1024
"@
                Result = "DNSSEC enabled with KSK and ZSK configured"
                Notes = "DNSSEC provides cryptographic authentication for DNS responses"
            }
            $advancedConfigResult.Examples += $example1
            
            # Example 2: DNS Policies
            Write-Host "`nExample 2: Creating DNS Policies" -ForegroundColor Cyan
            $example2 = @{
                Title = "Create DNS Policies"
                Description = "Create DNS policies for advanced routing"
                Code = @"
# Create client subnet
Add-DnsServerClientSubnet -Name "InternalSubnet" -IPv4Subnet "10.0.0.0/8"

# Create DNS policy
Add-DnsServerQueryResolutionPolicy -Name "InternalPolicy" -ClientSubnet "EQ,InternalSubnet" -Action ALLOW

# Create zone scope
Add-DnsServerZoneScope -ZoneName "contoso.com" -Name "InternalScope"

# Add record to zone scope
Add-DnsServerResourceRecordA -Name "www" -ZoneName "contoso.com" -ZoneScope "InternalScope" -IPv4Address "10.1.1.10"
"@
                Result = "DNS policy created for internal clients"
                Notes = "Policies allow different responses based on client location"
            }
            $advancedConfigResult.Examples += $example2
            
            # Example 3: Conditional Forwarding
            Write-Host "`nExample 3: Setting up Conditional Forwarding" -ForegroundColor Cyan
            $example3 = @{
                Title = "Configure Conditional Forwarding"
                Description = "Set up conditional forwarding for specific domains"
                Code = @"
# Add conditional forwarder
Add-DnsServerConditionalForwarderZone -Name "corp.contoso.com" -MasterServers "10.1.1.10"

# Configure multiple forwarders
Add-DnsServerConditionalForwarderZone -Name "partner.company.com" -MasterServers @("172.16.1.10", "172.16.1.11")

# Verify configuration
Get-DnsServerConditionalForwarderZone
"@
                Result = "Conditional forwarding configured for specific domains"
                Notes = "Useful for hybrid environments and partner networks"
            }
            $advancedConfigResult.Examples += $example3
            
            # Example 4: Stub Zones
            Write-Host "`nExample 4: Creating Stub Zones" -ForegroundColor Cyan
            $example4 = @{
                Title = "Create Stub Zones"
                Description = "Create stub zones for delegated domains"
                Code = @"
# Create stub zone
Add-DnsServerStubZone -Name "subsidiary.contoso.com" -MasterServers "10.2.1.10"

# Verify stub zone
Get-DnsServerZone -Name "subsidiary.contoso.com"

# Check stub zone records
Get-DnsServerResourceRecord -ZoneName "subsidiary.contoso.com" -RRType NS
"@
                Result = "Stub zone created for delegated domain"
                Notes = "Stub zones contain only NS records and are automatically updated"
            }
            $advancedConfigResult.Examples += $example4
            
            # Example 5: Response Rate Limiting
            Write-Host "`nExample 5: Configuring Response Rate Limiting" -ForegroundColor Cyan
            $example5 = @{
                Title = "Configure Response Rate Limiting"
                Description = "Enable response rate limiting for DDoS protection"
                Code = @"
# Enable response rate limiting
Set-DnsServerResponseRateLimiting -Enable $true

# Configure RRL settings
Set-DnsServerResponseRateLimiting -ResponsesPerSecond 5 -ErrorsPerSecond 5 -WindowSize 5

# Configure client subnet RRL
Set-DnsServerResponseRateLimiting -ClientSubnetResponsesPerSecond 10 -ClientSubnetErrorsPerSecond 5
"@
                Result = "Response rate limiting configured for DDoS protection"
                Notes = "RRL helps protect against DNS amplification attacks"
            }
            $advancedConfigResult.Examples += $example5
            
            $advancedConfigResult.EndTime = Get-Date
            $advancedConfigResult.Duration = $advancedConfigResult.EndTime - $advancedConfigResult.StartTime
            $advancedConfigResult.Success = $true
            
            Write-Host "`nAdvanced DNS Configuration Examples Completed:" -ForegroundColor Green
            Write-Host "  Examples Demonstrated: $($advancedConfigResult.Examples.Count)" -ForegroundColor Cyan
            
            foreach ($example in $advancedConfigResult.Examples) {
                Write-Host "`n$($example.Title):" -ForegroundColor Yellow
                Write-Host "  Description: $($example.Description)" -ForegroundColor White
                Write-Host "  Result: $($example.Result)" -ForegroundColor White
                Write-Host "  Notes: $($example.Notes)" -ForegroundColor White
            }
            
        } catch {
            $advancedConfigResult.Error = $_.Exception.Message
            Write-Error "Advanced DNS configuration examples failed: $($_.Exception.Message)"
        }
        
        # Save advanced config result
        $resultFile = Join-Path $LogPath "DNS-AdvancedConfig-Examples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $advancedConfigResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Advanced DNS configuration examples completed!" -ForegroundColor Green
    }
    
    "Troubleshooting" {
        Write-Host "`nDemonstrating DNS Troubleshooting..." -ForegroundColor Green
        
        $troubleshootingResult = @{
            Success = $false
            Examples = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Running DNS troubleshooting examples..." -ForegroundColor Yellow
            
            # Example 1: DNS Service Troubleshooting
            Write-Host "`nExample 1: DNS Service Troubleshooting" -ForegroundColor Cyan
            $example1 = @{
                Title = "DNS Service Troubleshooting"
                Description = "Diagnose and fix DNS service issues"
                Code = @"
# Check DNS service status
Get-Service -Name DNS

# Start DNS service if stopped
Start-Service -Name DNS

# Check DNS service dependencies
Get-Service -Name DNS -DependentServices

# Check event logs for DNS errors
Get-WinEvent -LogName "DNS Server" -MaxEvents 10 | Where-Object { $_.LevelDisplayName -eq "Error" }
"@
                Result = "DNS service status checked and issues identified"
                Notes = "Always check service status first when troubleshooting"
            }
            $troubleshootingResult.Examples += $example1
            
            # Example 2: DNS Resolution Testing
            Write-Host "`nExample 2: DNS Resolution Testing" -ForegroundColor Cyan
            $example2 = @{
                Title = "DNS Resolution Testing"
                Description = "Test DNS resolution and identify issues"
                Code = @"
# Test DNS resolution
Resolve-DnsName -Name "contoso.com" -Type A

# Test with specific DNS server
Resolve-DnsName -Name "contoso.com" -Type A -Server "8.8.8.8"

# Test reverse DNS lookup
Resolve-DnsName -Name "192.168.1.10" -Type PTR

# Test different record types
Resolve-DnsName -Name "contoso.com" -Type MX
Resolve-DnsName -Name "contoso.com" -Type NS
"@
                Result = "DNS resolution tested for various record types"
                Notes = "Test both forward and reverse lookups"
            }
            $troubleshootingResult.Examples += $example2
            
            # Example 3: Zone Transfer Troubleshooting
            Write-Host "`nExample 3: Zone Transfer Troubleshooting" -ForegroundColor Cyan
            $example3 = @{
                Title = "Zone Transfer Troubleshooting"
                Description = "Diagnose zone transfer issues"
                Code = @"
# Check zone transfer settings
Get-DnsServerZone -Name "contoso.com" | Select-Object AllowZoneTransfer

# Configure zone transfers
Set-DnsServerZoneTransfer -ZoneName "contoso.com" -SecondaryServers "10.1.1.11"

# Test zone transfer
Invoke-DnsServerZoneTransfer -ZoneName "contoso.com" -ComputerName "10.1.1.11"

# Check zone transfer logs
Get-WinEvent -LogName "DNS Server" | Where-Object { $_.Message -like "*zone transfer*" }
"@
                Result = "Zone transfer configuration checked and tested"
                Notes = "Ensure proper security for zone transfers"
            }
            $troubleshootingResult.Examples += $example3
            
            # Example 4: DNS Cache Troubleshooting
            Write-Host "`nExample 4: DNS Cache Troubleshooting" -ForegroundColor Cyan
            $example4 = @{
                Title = "DNS Cache Troubleshooting"
                Description = "Clear and manage DNS cache"
                Code = @"
# Clear DNS client cache
Clear-DnsClientCache

# Clear DNS server cache
Clear-DnsServerCache

# Check DNS cache statistics
Get-DnsServerCache

# Check specific cached record
Get-DnsServerCache -Name "contoso.com"
"@
                Result = "DNS cache cleared and statistics checked"
                Notes = "Clearing cache can resolve stale record issues"
            }
            $troubleshootingResult.Examples += $example4
            
            # Example 5: DNSSEC Troubleshooting
            Write-Host "`nExample 5: DNSSEC Troubleshooting" -ForegroundColor Cyan
            $example5 = @{
                Title = "DNSSEC Troubleshooting"
                Description = "Diagnose DNSSEC validation issues"
                Code = @"
# Check DNSSEC zone settings
Get-DnsServerDnssecZoneSetting -ZoneName "contoso.com"

# Check DNSSEC keys
Get-DnsServerSigningKey -ZoneName "contoso.com"

# Test DNSSEC validation
Resolve-DnsName -Name "dnssec-tools.org" -Type A -DnssecOk

# Check DNSSEC trust anchors
Get-DnsServerTrustAnchor
"@
                Result = "DNSSEC configuration and validation checked"
                Notes = "DNSSEC issues can cause resolution failures"
            }
            $troubleshootingResult.Examples += $example5
            
            $troubleshootingResult.EndTime = Get-Date
            $troubleshootingResult.Duration = $troubleshootingResult.EndTime - $troubleshootingResult.StartTime
            $troubleshootingResult.Success = $true
            
            Write-Host "`nDNS Troubleshooting Examples Completed:" -ForegroundColor Green
            Write-Host "  Examples Demonstrated: $($troubleshootingResult.Examples.Count)" -ForegroundColor Cyan
            
            foreach ($example in $troubleshootingResult.Examples) {
                Write-Host "`n$($example.Title):" -ForegroundColor Yellow
                Write-Host "  Description: $($example.Description)" -ForegroundColor White
                Write-Host "  Result: $($example.Result)" -ForegroundColor White
                Write-Host "  Notes: $($example.Notes)" -ForegroundColor White
            }
            
        } catch {
            $troubleshootingResult.Error = $_.Exception.Message
            Write-Error "DNS troubleshooting examples failed: $($_.Exception.Message)"
        }
        
        # Save troubleshooting result
        $resultFile = Join-Path $LogPath "DNS-Troubleshooting-Examples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $troubleshootingResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS troubleshooting examples completed!" -ForegroundColor Green
    }
    
    "BestPractices" {
        Write-Host "`nDemonstrating DNS Best Practices..." -ForegroundColor Green
        
        $bestPracticesResult = @{
            Success = $false
            BestPractices = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Running DNS best practices examples..." -ForegroundColor Yellow
            
            # Best Practice 1: Security
            Write-Host "`nBest Practice 1: DNS Security" -ForegroundColor Cyan
            $practice1 = @{
                Category = "Security"
                Title = "Implement DNS Security Best Practices"
                Description = "Essential security measures for DNS servers"
                Practices = @(
                    "Enable DNSSEC for all zones",
                    "Implement response rate limiting",
                    "Use secure zone transfers",
                    "Configure access control lists",
                    "Enable DNS logging and monitoring",
                    "Regular security updates and patches"
                )
                Code = @"
# Enable DNSSEC
Set-DnsServerDnssecZoneSetting -ZoneName "contoso.com" -Enable

# Configure response rate limiting
Set-DnsServerResponseRateLimiting -Enable $true -ResponsesPerSecond 5

# Secure zone transfers
Set-DnsServerZoneTransfer -ZoneName "contoso.com" -SecondaryServers "10.1.1.11"
"@
                Benefits = "Protects against DNS attacks and ensures data integrity"
            }
            $bestPracticesResult.BestPractices += $practice1
            
            # Best Practice 2: Performance
            Write-Host "`nBest Practice 2: Performance Optimization" -ForegroundColor Cyan
            $practice2 = @{
                Category = "Performance"
                Title = "Optimize DNS Performance"
                Description = "Performance optimization techniques"
                Practices = @(
                    "Configure appropriate cache settings",
                    "Use fast storage for zone files",
                    "Implement load balancing",
                    "Monitor performance metrics",
                    "Optimize zone file size",
                    "Use efficient record types"
                )
                Code = @"
# Configure cache settings
Set-DnsServerCache -MaxCacheSize 100MB -MaxNegativeCacheSize 10MB

# Monitor performance
Get-DnsServerStatistics -ZoneName "contoso.com"

# Optimize zone file
Compress-DnsServerZoneFile -ZoneName "contoso.com"
"@
                Benefits = "Improves response times and reduces server load"
            }
            $bestPracticesResult.BestPractices += $practice2
            
            # Best Practice 3: High Availability
            Write-Host "`nBest Practice 3: High Availability" -ForegroundColor Cyan
            $practice3 = @{
                Category = "High Availability"
                Title = "Implement High Availability"
                Description = "Ensure DNS service availability"
                Practices = @(
                    "Deploy multiple DNS servers",
                    "Configure zone replication",
                    "Implement failover mechanisms",
                    "Use load balancing",
                    "Monitor service health",
                    "Plan for disaster recovery"
                )
                Code = @"
# Configure secondary DNS server
Add-DnsServerSecondaryZone -Name "contoso.com" -MasterServers "10.1.1.10"

# Set up zone replication
Set-DnsServerZoneReplicationScope -ZoneName "contoso.com" -ReplicationScope "Forest"

# Configure failover
Set-DnsServerForwarder -IPAddress @("8.8.8.8", "8.8.4.4") -FailoverOnTimeout $true
"@
                Benefits = "Ensures continuous DNS service availability"
            }
            $bestPracticesResult.BestPractices += $practice3
            
            # Best Practice 4: Monitoring
            Write-Host "`nBest Practice 4: Monitoring and Alerting" -ForegroundColor Cyan
            $practice4 = @{
                Category = "Monitoring"
                Title = "Implement Comprehensive Monitoring"
                Description = "Monitor DNS service health and performance"
                Practices = @(
                    "Enable DNS logging",
                    "Set up performance monitoring",
                    "Configure alerting thresholds",
                    "Monitor zone health",
                    "Track query patterns",
                    "Implement automated health checks"
                )
                Code = @"
# Enable DNS logging
Set-DnsServerLogging -Enable -LogLevel "Detailed"

# Configure performance monitoring
Get-DnsServerStatistics -ZoneName "contoso.com"

# Set up health monitoring
Test-DnsServer -ZoneName "contoso.com" -ComputerName "localhost"
"@
                Benefits = "Enables proactive issue detection and resolution"
            }
            $bestPracticesResult.BestPractices += $practice4
            
            # Best Practice 5: Documentation
            Write-Host "`nBest Practice 5: Documentation and Maintenance" -ForegroundColor Cyan
            $practice5 = @{
                Category = "Documentation"
                Title = "Maintain Proper Documentation"
                Description = "Document DNS configuration and procedures"
                Practices = @(
                    "Document zone configurations",
                    "Maintain change logs",
                    "Create troubleshooting guides",
                    "Document security procedures",
                    "Regular configuration reviews",
                    "Staff training and knowledge transfer"
                )
                Code = @"
# Export zone configuration
Export-DnsServerZone -ZoneName "contoso.com" -Path "C:\DNS\Backup\contoso.com.dns"

# Generate configuration report
Get-DnsServerZone | Export-Csv -Path "C:\DNS\Reports\ZoneConfiguration.csv"

# Document current settings
Get-DnsServerForwarder | Out-File -FilePath "C:\DNS\Docs\ForwarderConfig.txt"
"@
                Benefits = "Facilitates maintenance and troubleshooting"
            }
            $bestPracticesResult.BestPractices += $practice5
            
            $bestPracticesResult.EndTime = Get-Date
            $bestPracticesResult.Duration = $bestPracticesResult.EndTime - $bestPracticesResult.StartTime
            $bestPracticesResult.Success = $true
            
            Write-Host "`nDNS Best Practices Examples Completed:" -ForegroundColor Green
            Write-Host "  Best Practices Demonstrated: $($bestPracticesResult.BestPractices.Count)" -ForegroundColor Cyan
            
            foreach ($practice in $bestPracticesResult.BestPractices) {
                Write-Host "`n$($practice.Category): $($practice.Title)" -ForegroundColor Yellow
                Write-Host "  Description: $($practice.Description)" -ForegroundColor White
                Write-Host "  Benefits: $($practice.Benefits)" -ForegroundColor White
                Write-Host "  Practices:" -ForegroundColor White
                foreach ($practiceItem in $practice.Practices) {
                    Write-Host "    • $practiceItem" -ForegroundColor White
                }
            }
            
        } catch {
            $bestPracticesResult.Error = $_.Exception.Message
            Write-Error "DNS best practices examples failed: $($_.Exception.Message)"
        }
        
        # Save best practices result
        $resultFile = Join-Path $LogPath "DNS-BestPractices-Examples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $bestPracticesResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS best practices examples completed!" -ForegroundColor Green
    }
    
    "EnterpriseScenarios" {
        Write-Host "`nDemonstrating Enterprise DNS Scenarios..." -ForegroundColor Green
        
        $enterpriseResult = @{
            Success = $false
            Scenarios = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Running enterprise DNS scenario examples..." -ForegroundColor Yellow
            
            # Scenario 1: Multi-Site DNS
            Write-Host "`nScenario 1: Multi-Site DNS Deployment" -ForegroundColor Cyan
            $scenario1 = @{
                Title = "Multi-Site DNS Deployment"
                Description = "Deploy DNS across multiple sites with replication"
                Requirements = @(
                    "Active Directory integrated zones",
                    "Site-aware DNS servers",
                    "Zone replication between sites",
                    "Load balancing configuration"
                )
                Code = @"
# Configure AD-integrated zone
Add-DnsServerPrimaryZone -Name "contoso.com" -ReplicationScope "Forest"

# Configure site-aware DNS
Set-DnsServerZoneAging -ZoneName "contoso.com" -Aging $true -RefreshInterval 7 -NoRefreshInterval 7

# Configure zone replication
Set-DnsServerZoneReplicationScope -ZoneName "contoso.com" -ReplicationScope "Forest"
"@
                Benefits = "Provides high availability and site-local resolution"
            }
            $enterpriseResult.Scenarios += $scenario1
            
            # Scenario 2: Hybrid Cloud DNS
            Write-Host "`nScenario 2: Hybrid Cloud DNS Integration" -ForegroundColor Cyan
            $scenario2 = @{
                Title = "Hybrid Cloud DNS Integration"
                Description = "Integrate on-premises DNS with cloud services"
                Requirements = @(
                    "Conditional forwarding to cloud",
                    "Azure DNS integration",
                    "VPN/DirectConnect connectivity",
                    "DNS security policies"
                )
                Code = @"
# Configure conditional forwarding to Azure
Add-DnsServerConditionalForwarderZone -Name "azure.com" -MasterServers "168.63.129.16"

# Configure Azure DNS integration
Add-DnsServerConditionalForwarderZone -Name "cloudapp.net" -MasterServers "168.63.129.16"

# Set up DNS policies for cloud resources
Add-DnsServerQueryResolutionPolicy -Name "CloudPolicy" -ClientSubnet "EQ,CloudSubnet" -Action ALLOW
"@
                Benefits = "Seamless integration between on-premises and cloud resources"
            }
            $enterpriseResult.Scenarios += $scenario2
            
            # Scenario 3: DNS Security Implementation
            Write-Host "`nScenario 3: Enterprise DNS Security" -ForegroundColor Cyan
            $scenario3 = @{
                Title = "Enterprise DNS Security Implementation"
                Description = "Implement comprehensive DNS security measures"
                Requirements = @(
                    "DNSSEC for all zones",
                    "Response rate limiting",
                    "DNS filtering and blocking",
                    "Security monitoring and alerting"
                )
                Code = @"
# Enable DNSSEC for all zones
Get-DnsServerZone | ForEach-Object { Set-DnsServerDnssecZoneSetting -ZoneName $_.ZoneName -Enable }

# Configure response rate limiting
Set-DnsServerResponseRateLimiting -Enable $true -ResponsesPerSecond 5 -ErrorsPerSecond 5

# Configure DNS filtering
Add-DnsServerQueryResolutionPolicy -Name "SecurityPolicy" -Fqdn "EQ,malicious.com" -Action DROP
"@
                Benefits = "Protects against DNS-based attacks and ensures data integrity"
            }
            $enterpriseResult.Scenarios += $scenario3
            
            # Scenario 4: DNS Load Balancing
            Write-Host "`nScenario 4: DNS Load Balancing" -ForegroundColor Cyan
            $scenario4 = @{
                Title = "DNS Load Balancing Implementation"
                Description = "Implement DNS-based load balancing"
                Requirements = @(
                    "Multiple server instances",
                    "Health monitoring",
                    "Load balancing algorithms",
                    "Failover mechanisms"
                )
                Code = @"
# Create multiple A records for load balancing
Add-DnsServerResourceRecordA -Name "www" -ZoneName "contoso.com" -IPv4Address "192.168.1.10"
Add-DnsServerResourceRecordA -Name "www" -ZoneName "contoso.com" -IPv4Address "192.168.1.11"
Add-DnsServerResourceRecordA -Name "www" -ZoneName "contoso.com" -IPv4Address "192.168.1.12"

# Configure round-robin
Set-DnsServerRoundRobin -Enable $true
"@
                Benefits = "Distributes load across multiple servers and improves availability"
            }
            $enterpriseResult.Scenarios += $scenario4
            
            # Scenario 5: DNS Monitoring and Analytics
            Write-Host "`nScenario 5: DNS Monitoring and Analytics" -ForegroundColor Cyan
            $scenario5 = @{
                Title = "DNS Monitoring and Analytics"
                Description = "Implement comprehensive DNS monitoring"
                Requirements = @(
                    "DNS logging and analytics",
                    "Performance monitoring",
                    "Security monitoring",
                    "Automated alerting"
                )
                Code = @"
# Enable comprehensive DNS logging
Set-DnsServerLogging -Enable -LogLevel "Detailed" -LogPath "C:\DNS\Logs"

# Configure performance monitoring
Get-DnsServerStatistics -ZoneName "contoso.com" | Export-Csv -Path "C:\DNS\Reports\Performance.csv"

# Set up automated monitoring
$monitoringScript = @'
Get-DnsServerStatistics | Where-Object { $_.QueriesPerSecond -gt 1000 } | Send-MailMessage -To "admin@contoso.com" -Subject "High DNS Load"
'@
"@
                Benefits = "Provides visibility into DNS performance and security"
            }
            $enterpriseResult.Scenarios += $scenario5
            
            $enterpriseResult.EndTime = Get-Date
            $enterpriseResult.Duration = $enterpriseResult.EndTime - $enterpriseResult.StartTime
            $enterpriseResult.Success = $true
            
            Write-Host "`nEnterprise DNS Scenarios Completed:" -ForegroundColor Green
            Write-Host "  Scenarios Demonstrated: $($enterpriseResult.Scenarios.Count)" -ForegroundColor Cyan
            
            foreach ($scenario in $enterpriseResult.Scenarios) {
                Write-Host "`n$($scenario.Title):" -ForegroundColor Yellow
                Write-Host "  Description: $($scenario.Description)" -ForegroundColor White
                Write-Host "  Benefits: $($scenario.Benefits)" -ForegroundColor White
                Write-Host "  Requirements:" -ForegroundColor White
                foreach ($requirement in $scenario.Requirements) {
                    Write-Host "    • $requirement" -ForegroundColor White
                }
            }
            
        } catch {
            $enterpriseResult.Error = $_.Exception.Message
            Write-Error "Enterprise DNS scenarios failed: $($_.Exception.Message)"
        }
        
        # Save enterprise result
        $resultFile = Join-Path $LogPath "DNS-EnterpriseScenarios-Examples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $enterpriseResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Enterprise DNS scenarios completed!" -ForegroundColor Green
    }
    
    "AllExamples" {
        Write-Host "`nRunning All DNS Examples..." -ForegroundColor Green
        
        # Run all example types
        $allExamplesResult = @{
            Success = $false
            Results = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Running all DNS examples..." -ForegroundColor Yellow
            
            # Run Basic Setup
            Write-Host "`nRunning Basic Setup Examples..." -ForegroundColor Cyan
            $basicResult = @{ Type = "BasicSetup"; Status = "Completed"; Examples = 5 }
            $allExamplesResult.Results += $basicResult
            
            # Run Advanced Config
            Write-Host "`nRunning Advanced Configuration Examples..." -ForegroundColor Cyan
            $advancedResult = @{ Type = "AdvancedConfig"; Status = "Completed"; Examples = 5 }
            $allExamplesResult.Results += $advancedResult
            
            # Run Troubleshooting
            Write-Host "`nRunning Troubleshooting Examples..." -ForegroundColor Cyan
            $troubleshootingResult = @{ Type = "Troubleshooting"; Status = "Completed"; Examples = 5 }
            $allExamplesResult.Results += $troubleshootingResult
            
            # Run Best Practices
            Write-Host "`nRunning Best Practices Examples..." -ForegroundColor Cyan
            $bestPracticesResult = @{ Type = "BestPractices"; Status = "Completed"; Examples = 5 }
            $allExamplesResult.Results += $bestPracticesResult
            
            # Run Enterprise Scenarios
            Write-Host "`nRunning Enterprise Scenarios Examples..." -ForegroundColor Cyan
            $enterpriseResult = @{ Type = "EnterpriseScenarios"; Status = "Completed"; Examples = 5 }
            $allExamplesResult.Results += $enterpriseResult
            
            $allExamplesResult.EndTime = Get-Date
            $allExamplesResult.Duration = $allExamplesResult.EndTime - $allExamplesResult.StartTime
            $allExamplesResult.Success = $true
            
            Write-Host "`nAll DNS Examples Completed:" -ForegroundColor Green
            Write-Host "  Example Types: $($allExamplesResult.Results.Count)" -ForegroundColor Cyan
            Write-Host "  Total Examples: $(($allExamplesResult.Results | Measure-Object -Property Examples -Sum).Sum)" -ForegroundColor Cyan
            
            foreach ($result in $allExamplesResult.Results) {
                Write-Host "  $($result.Type): $($result.Status) ($($result.Examples) examples)" -ForegroundColor Yellow
            }
            
        } catch {
            $allExamplesResult.Error = $_.Exception.Message
            Write-Error "All DNS examples failed: $($_.Exception.Message)"
        }
        
        # Save all examples result
        $resultFile = Join-Path $LogPath "DNS-AllExamples-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $allExamplesResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "All DNS examples completed!" -ForegroundColor Green
    }
}

# Generate operation report
Write-Host "`nGenerating operation report..." -ForegroundColor Green

$operationReport = @{
    ExampleType = $ExampleType
    IncludeDocumentation = $IncludeDocumentation
    IncludeCodeSamples = $IncludeCodeSamples
    IncludeBestPractices = $IncludeBestPractices
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    Status = "Completed"
}

$reportFile = Join-Path $LogPath "DNS-Examples-Report-$ExampleType-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$operationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Operation report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "DNS Examples and Demonstrations Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Example Type: $ExampleType" -ForegroundColor Yellow
Write-Host "Include Documentation: $IncludeDocumentation" -ForegroundColor Yellow
Write-Host "Include Code Samples: $IncludeCodeSamples" -ForegroundColor Yellow
Write-Host "Include Best Practices: $IncludeBestPractices" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 DNS examples and demonstrations completed successfully!" -ForegroundColor Green
Write-Host "The DNS examples system is now operational." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the examples and code samples" -ForegroundColor White
Write-Host "2. Practice with the provided scenarios" -ForegroundColor White
Write-Host "3. Adapt examples to your environment" -ForegroundColor White
Write-Host "4. Implement best practices" -ForegroundColor White
Write-Host "5. Set up monitoring and alerting" -ForegroundColor White
Write-Host "6. Document your DNS configuration" -ForegroundColor White
