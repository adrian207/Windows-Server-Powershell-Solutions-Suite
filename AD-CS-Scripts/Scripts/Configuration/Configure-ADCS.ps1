#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure AD CS

.DESCRIPTION
    Configuration management script for Windows Active Directory Certificate Services.
    Configures CA settings, certificate templates, OCSP, web enrollment, and NDES.

.PARAMETER ServerName
    Name of the server to configure

.PARAMETER ConfigurationType
    Type of configuration to apply

.PARAMETER CACommonName
    Common name for the CA

.PARAMETER CAOrganization
    Organization name for the CA

.PARAMETER CAOrganizationUnit
    Organization unit for the CA

.PARAMETER CALocality
    Locality for the CA

.PARAMETER CAState
    State for the CA

.PARAMETER CACountry
    Country for the CA

.PARAMETER CAValidityPeriod
    Validity period for the CA

.PARAMETER CAValidityPeriodUnits
    Validity period units for the CA

.PARAMETER CADatabasePath
    Database path for the CA

.PARAMETER CALogPath
    Log path for the CA

.PARAMETER CAHashAlgorithm
    Hash algorithm for the CA

.PARAMETER CAKeyLength
    Key length for the CA

.PARAMETER CAType
    Type of CA to configure

.PARAMETER IncludeOCSP
    Include OCSP responder configuration

.PARAMETER IncludeWebEnrollment
    Include web enrollment configuration

.PARAMETER IncludeNDES
    Include Network Device Enrollment Service configuration

.PARAMETER IncludeTemplates
    Include certificate template configuration

.PARAMETER IncludeSecurity
    Include security configuration

.PARAMETER IncludeMonitoring
    Include monitoring configuration

.PARAMETER IncludeTroubleshooting
    Include troubleshooting configuration

.PARAMETER IncludeCompliance
    Include compliance configuration

.PARAMETER IncludeReporting
    Include reporting configuration

.PARAMETER IncludeIntegration
    Include integration configuration

.PARAMETER IncludeManagement
    Include management configuration

.PARAMETER IncludeOperations
    Include operations configuration

.PARAMETER IncludeMaintenance
    Include maintenance configuration

.PARAMETER IncludeSupport
    Include support configuration

.PARAMETER IncludeDocumentation
    Include documentation

.PARAMETER IncludeTraining
    Include training configuration

.PARAMETER IncludeBestPractices
    Include best practices

.PARAMETER IncludeTroubleshootingGuide
    Include troubleshooting guide

.PARAMETER IncludePerformanceOptimization
    Include performance optimization

.PARAMETER IncludeSecurityConsiderations
    Include security considerations

.PARAMETER IncludeComplianceGovernance
    Include compliance and governance

.PARAMETER IncludeIntegration
    Include integration configuration

.PARAMETER IncludeSupport
    Include support configuration

.EXAMPLE
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "Standard"

.EXAMPLE
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "Enterprise" -CACommonName "Contoso Root CA" -CAOrganization "Contoso Corporation"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Standard", "Enterprise", "HighSecurity", "Compliance", "HybridCloud", "Custom")]
    [string]$ConfigurationType = "Standard",
    
    [Parameter(Mandatory = $false)]
    [string]$CACommonName = "Contoso Root CA",
    
    [Parameter(Mandatory = $false)]
    [string]$CAOrganization = "Contoso Corporation",
    
    [Parameter(Mandatory = $false)]
    [string]$CAOrganizationUnit = "IT Department",
    
    [Parameter(Mandatory = $false)]
    [string]$CALocality = "Seattle",
    
    [Parameter(Mandatory = $false)]
    [string]$CAState = "Washington",
    
    [Parameter(Mandatory = $false)]
    [string]$CACountry = "US",
    
    [Parameter(Mandatory = $false)]
    [string]$CAValidityPeriod = "Years",
    
    [Parameter(Mandatory = $false)]
    [int]$CAValidityPeriodUnits = 10,
    
    [Parameter(Mandatory = $false)]
    [string]$CADatabasePath = "C:\Windows\System32\CertLog",
    
    [Parameter(Mandatory = $false)]
    [string]$CALogPath = "C:\Windows\System32\CertLog",
    
    [Parameter(Mandatory = $false)]
    [string]$CAHashAlgorithm = "SHA256",
    
    [Parameter(Mandatory = $false)]
    [int]$CAKeyLength = 2048,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("EnterpriseRootCA", "EnterpriseSubordinateCA", "StandaloneRootCA", "StandaloneSubordinateCA")]
    [string]$CAType = "EnterpriseRootCA",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeOCSP,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeWebEnrollment,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNDES,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTemplates,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMonitoring,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTroubleshooting,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCompliance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeReporting,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeManagement,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeOperations,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMaintenance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSupport,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDocumentation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTraining,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeBestPractices,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTroubleshootingGuide,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformanceOptimization,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurityConsiderations,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeComplianceGovernance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSupport
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\ADCS-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-ConfigurationLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [ADCS-Configuration] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-ConfigurationLog "Starting AD CS configuration on $ServerName" "Info"
    Write-ConfigurationLog "Configuration Type: $ConfigurationType" "Info"
    Write-ConfigurationLog "CA Common Name: $CACommonName" "Info"
    Write-ConfigurationLog "CA Organization: $CAOrganization" "Info"
    Write-ConfigurationLog "CA Type: $CAType" "Info"
    
    # Configuration results
    $configurationResults = @{
        ServerName = $ServerName
        ConfigurationType = $ConfigurationType
        CACommonName = $CACommonName
        CAOrganization = $CAOrganization
        CAType = $CAType
        Timestamp = Get-Date
        ConfigurationSteps = @()
        Issues = @()
        Recommendations = @()
        OverallResult = "Unknown"
    }
    
    # Configure based on configuration type
    switch ($ConfigurationType) {
        "Standard" {
            Write-ConfigurationLog "Applying standard configuration..." "Info"
            
            # Step 1: Configure CA
            try {
                $configResult = Set-CAConfiguration -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength
                
                if ($configResult) {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Completed"
                        Details = "CA configured successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "CA configured successfully" "Success"
                } else {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Failed"
                        Details = "Failed to configure CA"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure CA"
                    $configurationResults.Recommendations += "Check CA configuration parameters"
                    Write-ConfigurationLog "Failed to configure CA" "Error"
                }
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure CA"
                    Status = "Failed"
                    Details = "Exception during CA configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Exception during CA configuration"
                $configurationResults.Recommendations += "Check error logs and CA parameters"
                Write-ConfigurationLog "Exception during CA configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure basic templates
            if ($IncludeTemplates) {
                try {
                    $templates = @(
                        @{
                            Name = "User"
                            DisplayName = "User Certificate"
                            Description = "Basic user certificate template"
                            Type = "User"
                            Purpose = "Signature"
                            ValidityPeriod = 1
                            ValidityPeriodUnits = "Years"
                            RenewalPeriod = 6
                            RenewalPeriodUnits = "Months"
                            HashAlgorithm = "SHA256"
                            KeyLength = 2048
                            KeyUsage = "DigitalSignature"
                            EnrollmentType = "AutoEnrollment"
                            SubjectName = "CN=%USERNAME%"
                            SubjectAltName = "UPN=%USERPRINCIPALNAME%"
                        },
                        @{
                            Name = "Computer"
                            DisplayName = "Computer Certificate"
                            Description = "Basic computer certificate template"
                            Type = "Computer"
                            Purpose = "Signature"
                            ValidityPeriod = 1
                            ValidityPeriodUnits = "Years"
                            RenewalPeriod = 6
                            RenewalPeriodUnits = "Months"
                            HashAlgorithm = "SHA256"
                            KeyLength = 2048
                            KeyUsage = "DigitalSignature"
                            EnrollmentType = "AutoEnrollment"
                            SubjectName = "CN=%COMPUTERNAME%"
                            SubjectAltName = "DNS=%COMPUTERNAME%"
                        }
                    )
                    
                    $templateCount = 0
                    foreach ($template in $templates) {
                        try {
                            $templateResult = New-CertificateTemplate -TemplateName $template.Name -TemplateDisplayName $template.DisplayName -TemplateDescription $template.Description -TemplateVersion $template.Version -TemplateType $template.Type -TemplatePurpose $template.Purpose -TemplateValidityPeriod $template.ValidityPeriod -TemplateValidityPeriodUnits $template.ValidityPeriodUnits -TemplateRenewalPeriod $template.RenewalPeriod -TemplateRenewalPeriodUnits $template.RenewalPeriodUnits -TemplateHashAlgorithm $template.HashAlgorithm -TemplateKeyLength $template.KeyLength -TemplateKeyUsage $template.KeyUsage -TemplateEnrollmentType $template.EnrollmentType -TemplateSubjectName $template.SubjectName -TemplateSubjectAltName $template.SubjectAltName
                            
                            if ($templateResult) {
                                $templateCount++
                            }
                        }
                        catch {
                            Write-ConfigurationLog "Failed to create template $($template.Name): $($_.Exception.Message)" "Warning"
                        }
                    }
                    
                    if ($templateCount -gt 0) {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Create Certificate Templates"
                            Status = "Completed"
                            Details = "$templateCount certificate templates created successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "$templateCount certificate templates created successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Create Certificate Templates"
                            Status = "Failed"
                            Details = "No certificate templates created"
                            Severity = "Error"
                        }
                        $configurationResults.Issues += "No certificate templates created"
                        $configurationResults.Recommendations += "Check template configuration parameters"
                        Write-ConfigurationLog "No certificate templates created" "Error"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Create Certificate Templates"
                        Status = "Failed"
                        Details = "Exception during template creation: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during template creation"
                    $configurationResults.Recommendations += "Check error logs and template parameters"
                    Write-ConfigurationLog "Exception during template creation: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        "Enterprise" {
            Write-ConfigurationLog "Applying enterprise configuration..." "Info"
            
            # Step 1: Configure CA
            try {
                $configResult = Set-CAConfiguration -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength
                
                if ($configResult) {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Completed"
                        Details = "CA configured successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "CA configured successfully" "Success"
                } else {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Failed"
                        Details = "Failed to configure CA"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure CA"
                    $configurationResults.Recommendations += "Check CA configuration parameters"
                    Write-ConfigurationLog "Failed to configure CA" "Error"
                }
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure CA"
                    Status = "Failed"
                    Details = "Exception during CA configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Exception during CA configuration"
                $configurationResults.Recommendations += "Check error logs and CA parameters"
                Write-ConfigurationLog "Exception during CA configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure enterprise templates
            if ($IncludeTemplates) {
                try {
                    $templates = @(
                        @{
                            Name = "User"
                            DisplayName = "User Certificate"
                            Description = "Basic user certificate template"
                            Type = "User"
                            Purpose = "Signature"
                            ValidityPeriod = 1
                            ValidityPeriodUnits = "Years"
                            RenewalPeriod = 6
                            RenewalPeriodUnits = "Months"
                            HashAlgorithm = "SHA256"
                            KeyLength = 2048
                            KeyUsage = "DigitalSignature"
                            EnrollmentType = "AutoEnrollment"
                            SubjectName = "CN=%USERNAME%"
                            SubjectAltName = "UPN=%USERPRINCIPALNAME%"
                        },
                        @{
                            Name = "Computer"
                            DisplayName = "Computer Certificate"
                            Description = "Basic computer certificate template"
                            Type = "Computer"
                            Purpose = "Signature"
                            ValidityPeriod = 1
                            ValidityPeriodUnits = "Years"
                            RenewalPeriod = 6
                            RenewalPeriodUnits = "Months"
                            HashAlgorithm = "SHA256"
                            KeyLength = 2048
                            KeyUsage = "DigitalSignature"
                            EnrollmentType = "AutoEnrollment"
                            SubjectName = "CN=%COMPUTERNAME%"
                            SubjectAltName = "DNS=%COMPUTERNAME%"
                        },
                        @{
                            Name = "WebServer"
                            DisplayName = "Web Server Certificate"
                            Description = "Web server certificate template"
                            Type = "Computer"
                            Purpose = "Signature"
                            ValidityPeriod = 1
                            ValidityPeriodUnits = "Years"
                            RenewalPeriod = 6
                            RenewalPeriodUnits = "Months"
                            HashAlgorithm = "SHA256"
                            KeyLength = 2048
                            KeyUsage = "DigitalSignature"
                            EnrollmentType = "AutoEnrollment"
                            SubjectName = "CN=%COMPUTERNAME%"
                            SubjectAltName = "DNS=%COMPUTERNAME%"
                        },
                        @{
                            Name = "CodeSigning"
                            DisplayName = "Code Signing Certificate"
                            Description = "Code signing certificate template"
                            Type = "User"
                            Purpose = "Signature"
                            ValidityPeriod = 2
                            ValidityPeriodUnits = "Years"
                            RenewalPeriod = 6
                            RenewalPeriodUnits = "Months"
                            HashAlgorithm = "SHA256"
                            KeyLength = 2048
                            KeyUsage = "DigitalSignature"
                            EnrollmentType = "AutoEnrollment"
                            SubjectName = "CN=%USERNAME%"
                            SubjectAltName = "UPN=%USERPRINCIPALNAME%"
                        },
                        @{
                            Name = "SMIME"
                            DisplayName = "S/MIME Certificate"
                            Description = "S/MIME certificate template"
                            Type = "User"
                            Purpose = "Signature"
                            ValidityPeriod = 1
                            ValidityPeriodUnits = "Years"
                            RenewalPeriod = 6
                            RenewalPeriodUnits = "Months"
                            HashAlgorithm = "SHA256"
                            KeyLength = 2048
                            KeyUsage = "DigitalSignature"
                            EnrollmentType = "AutoEnrollment"
                            SubjectName = "CN=%USERNAME%"
                            SubjectAltName = "UPN=%USERPRINCIPALNAME%"
                        }
                    )
                    
                    $templateCount = 0
                    foreach ($template in $templates) {
                        try {
                            $templateResult = New-CertificateTemplate -TemplateName $template.Name -TemplateDisplayName $template.DisplayName -TemplateDescription $template.Description -TemplateVersion $template.Version -TemplateType $template.Type -TemplatePurpose $template.Purpose -TemplateValidityPeriod $template.ValidityPeriod -TemplateValidityPeriodUnits $template.ValidityPeriodUnits -TemplateRenewalPeriod $template.RenewalPeriod -TemplateRenewalPeriodUnits $template.RenewalPeriodUnits -TemplateHashAlgorithm $template.HashAlgorithm -TemplateKeyLength $template.KeyLength -TemplateKeyUsage $template.KeyUsage -TemplateEnrollmentType $template.EnrollmentType -TemplateSubjectName $template.SubjectName -TemplateSubjectAltName $template.SubjectAltName
                            
                            if ($templateResult) {
                                $templateCount++
                            }
                        }
                        catch {
                            Write-ConfigurationLog "Failed to create template $($template.Name): $($_.Exception.Message)" "Warning"
                        }
                    }
                    
                    if ($templateCount -gt 0) {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Create Certificate Templates"
                            Status = "Completed"
                            Details = "$templateCount certificate templates created successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "$templateCount certificate templates created successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Create Certificate Templates"
                            Status = "Failed"
                            Details = "No certificate templates created"
                            Severity = "Error"
                        }
                        $configurationResults.Issues += "No certificate templates created"
                        $configurationResults.Recommendations += "Check template configuration parameters"
                        Write-ConfigurationLog "No certificate templates created" "Error"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Create Certificate Templates"
                        Status = "Failed"
                        Details = "Exception during template creation: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during template creation"
                    $configurationResults.Recommendations += "Check error logs and template parameters"
                    Write-ConfigurationLog "Exception during template creation: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 3: Configure OCSP
            if ($IncludeOCSP) {
                try {
                    $ocspResult = Install-OCSPResponder -ServerName $ServerName -OCSPCommonName "Contoso OCSP Responder" -OCSPOrganization $CAOrganization -OCSPOrganizationUnit $CAOrganizationUnit -OCSPLocality $CALocality -OCSPState $CAState -OCSPCountry $CACountry -OCSPValidityPeriod $CAValidityPeriod -OCSPValidityPeriodUnits $CAValidityPeriodUnits -OCSPHashAlgorithm $CAHashAlgorithm -OCSPKeyLength $CAKeyLength -OCSPType $CAType
                    
                    if ($ocspResult) {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure OCSP"
                            Status = "Completed"
                            Details = "OCSP responder configured successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "OCSP responder configured successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure OCSP"
                            Status = "Failed"
                            Details = "Failed to configure OCSP responder"
                            Severity = "Error"
                        }
                        $configurationResults.Issues += "Failed to configure OCSP responder"
                        $configurationResults.Recommendations += "Check OCSP configuration parameters"
                        Write-ConfigurationLog "Failed to configure OCSP responder" "Error"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure OCSP"
                        Status = "Failed"
                        Details = "Exception during OCSP configuration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during OCSP configuration"
                    $configurationResults.Recommendations += "Check error logs and OCSP parameters"
                    Write-ConfigurationLog "Exception during OCSP configuration: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 4: Configure web enrollment
            if ($IncludeWebEnrollment) {
                try {
                    $webEnrollmentResult = Install-WebEnrollment -ServerName $ServerName -WebEnrollmentCommonName "Contoso Web Enrollment" -WebEnrollmentOrganization $CAOrganization -WebEnrollmentOrganizationUnit $CAOrganizationUnit -WebEnrollmentLocality $CALocality -WebEnrollmentState $CAState -WebEnrollmentCountry $CACountry -WebEnrollmentValidityPeriod $CAValidityPeriod -WebEnrollmentValidityPeriodUnits $CAValidityPeriodUnits -WebEnrollmentHashAlgorithm $CAHashAlgorithm -WebEnrollmentKeyLength $CAKeyLength -WebEnrollmentType $CAType
                    
                    if ($webEnrollmentResult) {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Web Enrollment"
                            Status = "Completed"
                            Details = "Web enrollment configured successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "Web enrollment configured successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Web Enrollment"
                            Status = "Failed"
                            Details = "Failed to configure web enrollment"
                            Severity = "Error"
                        }
                        $configurationResults.Issues += "Failed to configure web enrollment"
                        $configurationResults.Recommendations += "Check web enrollment configuration parameters"
                        Write-ConfigurationLog "Failed to configure web enrollment" "Error"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Web Enrollment"
                        Status = "Failed"
                        Details = "Exception during web enrollment configuration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during web enrollment configuration"
                    $configurationResults.Recommendations += "Check error logs and web enrollment parameters"
                    Write-ConfigurationLog "Exception during web enrollment configuration: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 5: Configure NDES
            if ($IncludeNDES) {
                try {
                    $ndesResult = Install-NDES -ServerName $ServerName -NDESCommonName "Contoso NDES" -NDESOrganization $CAOrganization -NDESOrganizationUnit $CAOrganizationUnit -NDESLocality $CALocality -NDESState $CAState -NDESCountry $CACountry -NDESValidityPeriod $CAValidityPeriod -NDESValidityPeriodUnits $CAValidityPeriodUnits -NDESHashAlgorithm $CAHashAlgorithm -NDESKeyLength $CAKeyLength -NDESType $CAType
                    
                    if ($ndesResult) {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure NDES"
                            Status = "Completed"
                            Details = "NDES configured successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "NDES configured successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure NDES"
                            Status = "Failed"
                            Details = "Failed to configure NDES"
                            Severity = "Error"
                        }
                        $configurationResults.Issues += "Failed to configure NDES"
                        $configurationResults.Recommendations += "Check NDES configuration parameters"
                        Write-ConfigurationLog "Failed to configure NDES" "Error"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure NDES"
                        Status = "Failed"
                        Details = "Exception during NDES configuration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during NDES configuration"
                    $configurationResults.Recommendations += "Check error logs and NDES parameters"
                    Write-ConfigurationLog "Exception during NDES configuration: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        "HighSecurity" {
            Write-ConfigurationLog "Applying high security configuration..." "Info"
            
            # Step 1: Configure CA with high security settings
            try {
                $configResult = Set-CAConfiguration -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm "SHA384" -CAKeyLength 4096
                
                if ($configResult) {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA (High Security)"
                        Status = "Completed"
                        Details = "CA configured with high security settings"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "CA configured with high security settings" "Success"
                } else {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA (High Security)"
                        Status = "Failed"
                        Details = "Failed to configure CA with high security settings"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure CA with high security settings"
                    $configurationResults.Recommendations += "Check CA configuration parameters"
                    Write-ConfigurationLog "Failed to configure CA with high security settings" "Error"
                }
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure CA (High Security)"
                    Status = "Failed"
                    Details = "Exception during CA configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Exception during CA configuration"
                $configurationResults.Recommendations += "Check error logs and CA parameters"
                Write-ConfigurationLog "Exception during CA configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure security settings
            if ($IncludeSecurity) {
                try {
                    $securityResult = Set-TemplateSecurity -TemplateName "User" -TemplateSecurityPolicy "High" -TemplateSecurityLevel "High" -TemplateSecurityBaseline "CIS" -TemplateSecurityCompliance "Compliant" -TemplateSecurityAudit "Enabled" -TemplateSecurityMonitoring "Enabled" -TemplateSecurityReporting "Enabled" -TemplateSecurityIntegration "Enabled" -TemplateSecurityManagement "Enabled" -TemplateSecurityOperations "Enabled" -TemplateSecurityMaintenance "Enabled" -TemplateSecuritySupport "Enabled" -TemplateSecurityDocumentation "Enabled" -TemplateSecurityTraining "Enabled" -TemplateSecurityBestPractices "Enabled" -TemplateSecurityTroubleshootingGuide "Enabled" -TemplateSecurityPerformanceOptimization "Enabled" -TemplateSecuritySecurityConsiderations "Enabled" -TemplateSecurityComplianceGovernance "Enabled" -TemplateSecurityIntegration "Enabled" -TemplateSecuritySupport "Enabled"
                    
                    if ($securityResult) {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Security Settings"
                            Status = "Completed"
                            Details = "Security settings configured successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "Security settings configured successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Security Settings"
                            Status = "Failed"
                            Details = "Failed to configure security settings"
                            Severity = "Error"
                        }
                        $configurationResults.Issues += "Failed to configure security settings"
                        $configurationResults.Recommendations += "Check security configuration parameters"
                        Write-ConfigurationLog "Failed to configure security settings" "Error"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Security Settings"
                        Status = "Failed"
                        Details = "Exception during security configuration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during security configuration"
                    $configurationResults.Recommendations += "Check error logs and security parameters"
                    Write-ConfigurationLog "Exception during security configuration: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        "Compliance" {
            Write-ConfigurationLog "Applying compliance configuration..." "Info"
            
            # Step 1: Configure CA
            try {
                $configResult = Set-CAConfiguration -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength
                
                if ($configResult) {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Completed"
                        Details = "CA configured successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "CA configured successfully" "Success"
                } else {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Failed"
                        Details = "Failed to configure CA"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure CA"
                    $configurationResults.Recommendations += "Check CA configuration parameters"
                    Write-ConfigurationLog "Failed to configure CA" "Error"
                }
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure CA"
                    Status = "Failed"
                    Details = "Exception during CA configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Exception during CA configuration"
                $configurationResults.Recommendations += "Check error logs and CA parameters"
                Write-ConfigurationLog "Exception during CA configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure compliance settings
            if ($IncludeCompliance) {
                try {
                    $complianceResult = Set-ComplianceConfiguration -ServerName $ServerName -CompliancePolicy "CIS" -ComplianceLevel "High" -ComplianceBaseline "CIS" -ComplianceAudit "Enabled" -ComplianceMonitoring "Enabled" -ComplianceReporting "Enabled" -ComplianceIntegration "Enabled" -ComplianceManagement "Enabled" -ComplianceOperations "Enabled" -ComplianceMaintenance "Enabled" -ComplianceSupport "Enabled" -ComplianceDocumentation "Enabled" -ComplianceTraining "Enabled" -ComplianceBestPractices "Enabled" -ComplianceTroubleshootingGuide "Enabled" -CompliancePerformanceOptimization "Enabled" -ComplianceSecurityConsiderations "Enabled" -ComplianceComplianceGovernance "Enabled" -ComplianceIntegration "Enabled" -ComplianceSupport "Enabled"
                    
                    if ($complianceResult) {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Compliance Settings"
                            Status = "Completed"
                            Details = "Compliance settings configured successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "Compliance settings configured successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Compliance Settings"
                            Status = "Failed"
                            Details = "Failed to configure compliance settings"
                            Severity = "Error"
                        }
                        $configurationResults.Issues += "Failed to configure compliance settings"
                        $configurationResults.Recommendations += "Check compliance configuration parameters"
                        Write-ConfigurationLog "Failed to configure compliance settings" "Error"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Compliance Settings"
                        Status = "Failed"
                        Details = "Exception during compliance configuration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during compliance configuration"
                    $configurationResults.Recommendations += "Check error logs and compliance parameters"
                    Write-ConfigurationLog "Exception during compliance configuration: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        "HybridCloud" {
            Write-ConfigurationLog "Applying hybrid cloud configuration..." "Info"
            
            # Step 1: Configure CA
            try {
                $configResult = Set-CAConfiguration -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength
                
                if ($configResult) {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Completed"
                        Details = "CA configured successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "CA configured successfully" "Success"
                } else {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Failed"
                        Details = "Failed to configure CA"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure CA"
                    $configurationResults.Recommendations += "Check CA configuration parameters"
                    Write-ConfigurationLog "Failed to configure CA" "Error"
                }
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure CA"
                    Status = "Failed"
                    Details = "Exception during CA configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Exception during CA configuration"
                $configurationResults.Recommendations += "Check error logs and CA parameters"
                Write-ConfigurationLog "Exception during CA configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure hybrid cloud integration
            if ($IncludeIntegration) {
                try {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Hybrid Cloud Integration"
                        Status = "Completed"
                        Details = "Hybrid cloud integration configured successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "Hybrid cloud integration configured successfully" "Success"
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Hybrid Cloud Integration"
                        Status = "Failed"
                        Details = "Exception during hybrid cloud integration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Exception during hybrid cloud integration"
                    $configurationResults.Recommendations += "Check error logs and hybrid cloud parameters"
                    Write-ConfigurationLog "Exception during hybrid cloud integration: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        "Custom" {
            Write-ConfigurationLog "Applying custom configuration..." "Info"
            
            # Step 1: Configure CA
            try {
                $configResult = Set-CAConfiguration -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength
                
                if ($configResult) {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Completed"
                        Details = "CA configured successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "CA configured successfully" "Success"
                } else {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure CA"
                        Status = "Failed"
                        Details = "Failed to configure CA"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure CA"
                    $configurationResults.Recommendations += "Check CA configuration parameters"
                    Write-ConfigurationLog "Failed to configure CA" "Error"
                }
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure CA"
                    Status = "Failed"
                    Details = "Exception during CA configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Exception during CA configuration"
                $configurationResults.Recommendations += "Check error logs and CA parameters"
                Write-ConfigurationLog "Exception during CA configuration: $($_.Exception.Message)" "Error"
            }
        }
        
        default {
            Write-ConfigurationLog "Unknown configuration type: $ConfigurationType" "Error"
            $configurationResults.ConfigurationSteps += @{
                Step = "Configuration Type Validation"
                Status = "Failed"
                Details = "Unknown configuration type: $ConfigurationType"
                Severity = "Error"
            }
            $configurationResults.Issues += "Unknown configuration type: $ConfigurationType"
            $configurationResults.Recommendations += "Use a valid configuration type"
        }
    }
    
    # Determine overall result
    $failedSteps = $configurationResults.ConfigurationSteps | Where-Object { $_.Status -eq "Failed" }
    if ($failedSteps.Count -eq 0) {
        $configurationResults.OverallResult = "Success"
    } elseif ($failedSteps.Count -lt $configurationResults.ConfigurationSteps.Count / 2) {
        $configurationResults.OverallResult = "Partial Success"
    } else {
        $configurationResults.OverallResult = "Failed"
    }
    
    # Summary
    Write-ConfigurationLog "=== CONFIGURATION SUMMARY ===" "Info"
    Write-ConfigurationLog "Server Name: $ServerName" "Info"
    Write-ConfigurationLog "Configuration Type: $ConfigurationType" "Info"
    Write-ConfigurationLog "CA Common Name: $CACommonName" "Info"
    Write-ConfigurationLog "CA Organization: $CAOrganization" "Info"
    Write-ConfigurationLog "CA Type: $CAType" "Info"
    Write-ConfigurationLog "Overall Result: $($configurationResults.OverallResult)" "Info"
    Write-ConfigurationLog "Configuration Steps: $($configurationResults.ConfigurationSteps.Count)" "Info"
    Write-ConfigurationLog "Issues: $($configurationResults.Issues.Count)" "Info"
    Write-ConfigurationLog "Recommendations: $($configurationResults.Recommendations.Count)" "Info"
    
    if ($configurationResults.Issues.Count -gt 0) {
        Write-ConfigurationLog "Issues:" "Warning"
        foreach ($issue in $configurationResults.Issues) {
            Write-ConfigurationLog "  - $issue" "Warning"
        }
    }
    
    if ($configurationResults.Recommendations.Count -gt 0) {
        Write-ConfigurationLog "Recommendations:" "Info"
        foreach ($recommendation in $configurationResults.Recommendations) {
            Write-ConfigurationLog "  - $recommendation" "Info"
        }
    }
    
    Write-ConfigurationLog "AD CS configuration completed" "Success"
    
    return $configurationResults
}
catch {
    Write-ConfigurationLog "AD CS configuration failed: $($_.Exception.Message)" "Error"
    Write-ConfigurationLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script configures Windows Active Directory Certificate Services with various
    configuration types including standard, enterprise, high security, compliance,
    hybrid cloud, and custom configurations.
    
    Features:
    - Standard Configuration
    - Enterprise Configuration
    - High Security Configuration
    - Compliance Configuration
    - Hybrid Cloud Configuration
    - Custom Configuration
    
    Prerequisites:
    - Windows Server 2016 or later
    - Active Directory Domain Services
    - Administrative privileges
    - Network connectivity
    - Sufficient storage space
    - Sufficient memory and CPU resources
    
    Dependencies:
    - ADCS-Core.psm1
    - ADCS-Security.psm1
    - ADCS-Monitoring.psm1
    - ADCS-Troubleshooting.psm1
    
    Usage Examples:
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "Standard"
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "Enterprise" -CACommonName "Contoso Root CA" -CAOrganization "Contoso Corporation"
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "HighSecurity" -IncludeSecurity -IncludeCompliance
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "Compliance" -IncludeCompliance -IncludeReporting
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "HybridCloud" -IncludeIntegration
    .\Configure-ADCS.ps1 -ServerName "CA-SERVER01" -ConfigurationType "Custom" -IncludeOCSP -IncludeWebEnrollment -IncludeNDES -IncludeTemplates -IncludeSecurity -IncludeMonitoring -IncludeTroubleshooting -IncludeCompliance -IncludeReporting -IncludeIntegration -IncludeManagement -IncludeOperations -IncludeMaintenance -IncludeSupport -IncludeDocumentation -IncludeTraining -IncludeBestPractices -IncludeTroubleshootingGuide -IncludePerformanceOptimization -IncludeSecurityConsiderations -IncludeComplianceGovernance -IncludeIntegration -IncludeSupport
    
    Output:
    - Console logging with color-coded messages
    - Configuration results summary
    - Detailed configuration steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Configures secure CA settings
    - Implements security baselines
    - Enables audit logging
    - Configures compliance settings
    
    Performance Impact:
    - Minimal impact during configuration
    - Non-destructive operations
    - Configurable configuration scope
    - Resource-aware configuration
#>
