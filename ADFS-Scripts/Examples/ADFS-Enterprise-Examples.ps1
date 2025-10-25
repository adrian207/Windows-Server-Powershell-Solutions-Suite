#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    ADFS Enterprise Scenarios Examples

.DESCRIPTION
    This script provides comprehensive examples of ADFS enterprise scenarios
    including SSO, federation, MFA, and hybrid cloud integrations.

.EXAMPLE
    .\ADFS-Enterprise-Examples.ps1
#>

# Import ADFS modules
try {
    Import-Module "..\..\Modules\ADFS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Federation.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Security.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Troubleshooting.psm1" -Force
} catch {
    Write-Error "Failed to import ADFS modules: $($_.Exception.Message)"
    exit 1
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Enterprise Scenarios Examples" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Example 1: Deploy SSO for Salesforce
Write-Host "Example 1: Deploy SSO for Salesforce" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$salesforceConfig = @{
    Name = "Salesforce"
    MetadataUrl = "https://login.salesforce.com/.well-known/openid_configuration"
    Identifier = "https://saml.salesforce.com"
    ClaimRules = @("Email", "Name", "Groups")
    EnableSSO = $true
    EnableClaims = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$salesforceConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 2: Deploy MFA with Azure MFA
Write-Host "`nExample 2: Deploy MFA with Azure MFA" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$azureMFAConfig = @{
    Provider = "AzureMFA"
    TenantId = "your-tenant-id"
    ClientId = "your-client-id"
    ClientSecret = "your-client-secret"
    EnableConditionalMFA = $true
    EnablePerAppMFA = $true
    EnableLocationBasedMFA = $true
    EnableDeviceBasedMFA = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$azureMFAConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 3: Deploy Hybrid Cloud Integration
Write-Host "`nExample 3: Deploy Hybrid Cloud Integration" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$hybridCloudConfig = @{
    AzureTenantId = "your-tenant-id"
    EnableOffice365Federation = $true
    EnableAzureADIntegration = $true
    EnableHybridIdentity = $true
    EnableConditionalAccess = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$hybridCloudConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 4: Deploy Federation with Partners
Write-Host "`nExample 4: Deploy Federation with Partners" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$federationConfig = @{
    Partners = @(
        @{
            Name = "Partner1"
            MetadataUrl = "https://partner1.com/federationmetadata"
            Identifier = "https://partner1.com"
            ClaimRules = @("Email", "Name", "Groups")
            EnableSSO = $true
            EnableClaims = $true
            EnableAuditing = $true
        },
        @{
            Name = "Partner2"
            MetadataUrl = "https://partner2.com/federationmetadata"
            Identifier = "https://partner2.com"
            ClaimRules = @("Email", "Name", "Groups")
            EnableSSO = $true
            EnableClaims = $true
            EnableAuditing = $true
        }
    )
}

Write-Host "Configuration:" -ForegroundColor Yellow
$federationConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 5: Deploy OAuth2 and OpenID Connect
Write-Host "`nExample 5: Deploy OAuth2 and OpenID Connect" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$oauth2Config = @{
    EnableOAuth2 = $true
    EnableOpenIDConnect = $true
    EnableJWT = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$oauth2Config | ConvertTo-Json -Depth 3 | Write-Host

# Example 6: Deploy Web Application Proxy
Write-Host "`nExample 6: Deploy Web Application Proxy" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$wapConfig = @{
    EnableWebApplicationProxy = $true
    EnablePreAuthentication = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$wapConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 7: Deploy Custom Branding
Write-Host "`nExample 7: Deploy Custom Branding" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$brandingConfig = @{
    EnableCustomBranding = $true
    CustomLogo = "C:\ADFS\Branding\logo.png"
    CustomCSS = "C:\ADFS\Branding\custom.css"
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$brandingConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 8: Deploy Device Registration Service
Write-Host "`nExample 8: Deploy Device Registration Service" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$drsConfig = @{
    EnableDeviceRegistration = $true
    EnableWorkplaceJoin = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$drsConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 9: Deploy Multi-Forest Federation
Write-Host "`nExample 9: Deploy Multi-Forest Federation" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$multiForestConfig = @{
    EnableMultiForestFederation = $true
    EnableCrossForestTrust = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$multiForestConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 10: Deploy B2B Federation
Write-Host "`nExample 10: Deploy B2B Federation" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$b2bConfig = @{
    EnableB2BFederation = $true
    EnablePartnerFederation = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$b2bConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 11: Deploy Office 365 Federation
Write-Host "`nExample 11: Deploy Office 365 Federation" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$office365Config = @{
    EnableOffice365Federation = $true
    EnableOffice365Integration = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$office365Config | ConvertTo-Json -Depth 3 | Write-Host

# Example 12: Deploy Claims Transformation
Write-Host "`nExample 12: Deploy Claims Transformation" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$claimsConfig = @{
    EnableClaimsTransformation = $true
    EnableCustomClaims = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$claimsConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 13: Deploy Certificate Management
Write-Host "`nExample 13: Deploy Certificate Management" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$certConfig = @{
    EnableCertificateManagement = $true
    EnableAutoRenewal = $true
    EnableCertificateMonitoring = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$certConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 14: Deploy Comprehensive Auditing
Write-Host "`nExample 14: Deploy Comprehensive Auditing" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$auditingConfig = @{
    EnableComprehensiveAuditing = $true
    EnableSIEMIntegration = $true
    EnablePerformanceMonitoring = $true
    EnableAuditing = $true
}

Write-Host "Configuration:" -ForegroundColor Yellow
$auditingConfig | ConvertTo-Json -Depth 3 | Write-Host

# Example 15: Deploy Complete Enterprise Solution
Write-Host "`nExample 15: Deploy Complete Enterprise Solution" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green

$enterpriseConfig = @{
    Environment = "Production"
    Scenarios = @{
        SSO = @{
            Enabled = $true
            Applications = @("Salesforce", "ServiceNow", "Workday")
        }
        Federation = @{
            Enabled = $true
            Partners = @("Partner1", "Partner2")
        }
        MFA = @{
            Enabled = $true
            Provider = "AzureMFA"
        }
        HybridCloud = @{
            Enabled = $true
            AzureTenantId = "your-tenant-id"
        }
        OAuth2 = @{
            Enabled = $true
        }
        WAP = @{
            Enabled = $true
        }
        CustomBranding = @{
            Enabled = $true
        }
        DRS = @{
            Enabled = $true
        }
        MultiForest = @{
            Enabled = $true
        }
        B2B = @{
            Enabled = $true
        }
        Office365 = @{
            Enabled = $true
        }
        ClaimsTransformation = @{
            Enabled = $true
        }
        CertificateManagement = @{
            Enabled = $true
        }
        Auditing = @{
            Enabled = $true
        }
    }
    Security = @{
        EnableMFA = $true
        EnableConditionalAccess = $true
        EnableSmartcardAuth = $true
        EnableAuditing = $true
        SecurityLevel = "Maximum"
    }
    Monitoring = @{
        EnableMonitoring = $true
        EnableSIEMIntegration = $true
        EnablePerformanceMonitoring = $true
        EnableCertificateMonitoring = $true
        EnableTrustMonitoring = $true
        AlertThreshold = "High"
    }
    Backup = @{
        EnableBackup = $true
        BackupPath = "C:\ADFS\Backup"
        IncludeCertificates = $true
        IncludeTrusts = $true
        IncludePolicies = $true
    }
}

Write-Host "Configuration:" -ForegroundColor Yellow
$enterpriseConfig | ConvertTo-Json -Depth 3 | Write-Host

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Enterprise Scenarios Examples Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`nUsage Examples:" -ForegroundColor Yellow
Write-Host "1. Deploy SSO for Salesforce:" -ForegroundColor White
Write-Host "   .\Deploy-ADFSSSOScenario.ps1 -Applications @('Salesforce') -Environment 'Production' -EnableMFA -EnableConditionalAccess" -ForegroundColor Gray

Write-Host "`n2. Deploy MFA with Azure MFA:" -ForegroundColor White
Write-Host "   .\Deploy-ADFSMFAScenario.ps1 -MFAProvider 'AzureMFA' -Environment 'Production' -EnableConditionalMFA -EnablePerAppMFA" -ForegroundColor Gray

Write-Host "`n3. Deploy Hybrid Cloud Integration:" -ForegroundColor White
Write-Host "   .\Deploy-ADFSHybridCloudScenario.ps1 -AzureTenantId 'your-tenant-id' -Environment 'Production' -EnableOffice365Federation -EnableAzureADIntegration" -ForegroundColor Gray

Write-Host "`n4. Deploy All Enterprise Scenarios:" -ForegroundColor White
Write-Host "   .\Deploy-ADFSEnterpriseScenarios.ps1 -Scenario 'All' -Environment 'Production' -EnableBackup -EnableValidation -EnableMonitoring" -ForegroundColor Gray

Write-Host "`n5. Deploy Specific Scenario:" -ForegroundColor White
Write-Host "   .\Deploy-ADFSEnterpriseScenarios.ps1 -Scenario 'SSO' -ConfigurationFile '.\Config\SSO-Config.json' -Environment 'Development'" -ForegroundColor Gray
