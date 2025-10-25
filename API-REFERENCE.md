# API Reference Documentation - Windows Server PowerShell Solutions Suite

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 2.0.0  
**Date:** December 2024  
**Document Type:** API Reference Specification

---

## 🔌 **API Overview**

The Windows Server PowerShell Solutions Suite provides a comprehensive set of PowerShell cmdlets and functions designed for enterprise Windows Server management. This API reference documents all available functions, their parameters, return values, and usage examples.

## 📚 **API Structure**

### **Module Organization**

The API is organized into the following modules:

| Module | Description | Functions |
|--------|-------------|-----------|
| **AD-Core** | Active Directory core operations | 45+ |
| **AD-Security** | Active Directory security features | 35+ |
| **AD-Monitoring** | Active Directory monitoring | 30+ |
| **AD-Troubleshooting** | Active Directory diagnostics | 25+ |
| **ADCS-Core** | Certificate Services operations | 40+ |
| **DNS-Core** | DNS management operations | 35+ |
| **DHCP-Core** | DHCP management operations | 30+ |
| **File-Core** | File Services operations | 40+ |
| **HyperV-Core** | Hyper-V management operations | 50+ |
| **Cluster-Core** | Failover Clustering operations | 35+ |

## 🎯 **Core API Functions**

### **Active Directory Core Module**

#### **New-ADDomainController**
Creates a new Active Directory domain controller.

```powershell
New-ADDomainController
    [-DomainName] <String>
    [-SiteName] <String>
    [-DatabasePath] <String>
    [-LogPath] <String>
    [-SysvolPath] <String>
    [-SafeModeAdministratorPassword] <SecureString>
    [-InstallDNS] <Boolean>
    [-CreateDNSDelegation] <Boolean>
    [-NoRebootOnCompletion] <Boolean>
    [-Force] <Boolean>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `DomainName`: The FQDN of the domain
- `SiteName`: The Active Directory site name
- `DatabasePath`: Path for the AD database
- `LogPath`: Path for the AD log files
- `SysvolPath`: Path for the SYSVOL folder
- `SafeModeAdministratorPassword`: Safe mode administrator password

**Returns:** `Microsoft.ActiveDirectory.Management.ADDomainController`

**Example:**
```powershell
$SecurePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
New-ADDomainController -DomainName "contoso.com" -SiteName "Default-First-Site-Name" -SafeModeAdministratorPassword $SecurePassword -InstallDNS
```

#### **Set-ADSecurityPolicies**
Configures Active Directory security policies.

```powershell
Set-ADSecurityPolicies
    [-DomainName] <String>
    [-PasswordPolicy] <ADPasswordPolicy>
    [-AccountLockoutPolicy] <ADAccountLockoutPolicy>
    [-KerberosPolicy] <ADKerberosPolicy>
    [-AuditPolicy] <ADAuditPolicy>
    [-EnableAdvancedThreatProtection] <Boolean>
    [-EnablePrivilegedAccessManagement] <Boolean>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `DomainName`: Target domain name
- `PasswordPolicy`: Password policy configuration
- `AccountLockoutPolicy`: Account lockout policy configuration
- `KerberosPolicy`: Kerberos policy configuration
- `AuditPolicy`: Audit policy configuration

**Returns:** `System.Boolean`

**Example:**
```powershell
$PasswordPolicy = @{
    MinPasswordLength = 14
    PasswordComplexity = $true
    PasswordHistory = 24
    MaxPasswordAge = 90
    MinPasswordAge = 1
}

Set-ADSecurityPolicies -DomainName "contoso.com" -PasswordPolicy $PasswordPolicy -EnableAdvancedThreatProtection
```

#### **Get-ADHealthStatus**
Retrieves Active Directory health status.

```powershell
Get-ADHealthStatus
    [-DomainName] <String>
    [-DetailedReport] <Boolean>
    [-IncludePerformanceMetrics] <Boolean>
    [-IncludeSecurityStatus] <Boolean>
    [-OutputFormat] <String>
    [<CommonParameters>]
```

**Parameters:**
- `DomainName`: Target domain name
- `DetailedReport`: Generate detailed health report
- `IncludePerformanceMetrics`: Include performance metrics
- `IncludeSecurityStatus`: Include security status information
- `OutputFormat`: Output format (JSON, XML, HTML, CSV)

**Returns:** `ADHealthStatus`

**Example:**
```powershell
$HealthStatus = Get-ADHealthStatus -DomainName "contoso.com" -DetailedReport -IncludePerformanceMetrics
$HealthStatus | Export-Csv -Path "ADHealthReport.csv" -NoTypeInformation
```

### **Certificate Services Core Module**

#### **New-EnterpriseRootCA**
Creates a new Enterprise Root Certificate Authority.

```powershell
New-EnterpriseRootCA
    [-CACommonName] <String>
    [-CAOrganization] <String>
    [-CAOrganizationalUnit] <String>
    [-CALocality] <String>
    [-CAState] <String>
    [-CACountry] <String>
    [-ValidityPeriod] <Int32>
    [-KeyLength] <Int32>
    [-HashAlgorithm] <String>
    [-DatabasePath] <String>
    [-LogPath] <String>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `CACommonName`: Common name for the CA
- `CAOrganization`: Organization name
- `CAOrganizationalUnit`: Organizational unit
- `CALocality`: Locality
- `CAState`: State or province
- `CACountry`: Country code
- `ValidityPeriod`: Certificate validity period in years
- `KeyLength`: Key length in bits
- `HashAlgorithm`: Hash algorithm (SHA256, SHA384, SHA512)

**Returns:** `Microsoft.CertificateServices.ADCS.CertificateAuthority`

**Example:**
```powershell
New-EnterpriseRootCA -CACommonName "Contoso Root CA" -CAOrganization "Contoso Corporation" -ValidityPeriod 20 -KeyLength 4096 -HashAlgorithm "SHA256"
```

#### **New-CertificateTemplate**
Creates a new certificate template.

```powershell
New-CertificateTemplate
    [-TemplateName] <String>
    [-TemplateDisplayName] <String>
    [-TemplateVersion] <Int32>
    [-ValidityPeriod] <Int32>
    [-RenewalPeriod] <Int32>
    [-KeyUsage] <String[]>
    [-EnhancedKeyUsage] <String[]>
    [-SubjectName] <String>
    [-AutoEnrollment] <Boolean>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `TemplateName`: Template name
- `TemplateDisplayName`: Display name for the template
- `TemplateVersion`: Template version number
- `ValidityPeriod`: Certificate validity period in days
- `RenewalPeriod`: Renewal period in days
- `KeyUsage`: Key usage extensions
- `EnhancedKeyUsage`: Enhanced key usage extensions
- `SubjectName`: Subject name format
- `AutoEnrollment`: Enable automatic enrollment

**Returns:** `Microsoft.CertificateServices.ADCS.CertificateTemplate`

**Example:**
```powershell
New-CertificateTemplate -TemplateName "UserAuthentication" -TemplateDisplayName "User Authentication Certificate" -ValidityPeriod 365 -KeyUsage @("DigitalSignature", "KeyEncipherment") -EnhancedKeyUsage @("Client Authentication") -AutoEnrollment
```

### **DNS Core Module**

#### **New-DNSZone**
Creates a new DNS zone.

```powershell
New-DNSZone
    [-ZoneName] <String>
    [-ZoneType] <String>
    [-ReplicationScope] <String>
    [-DirectoryPartitionName] <String>
    [-DynamicUpdate] <String>
    [-Aging] <Boolean>
    [-RefreshInterval] <TimeSpan>
    [-RetryInterval] <TimeSpan>
    [-ExpireAfter] <TimeSpan>
    [-MinimumTimeToLive] <TimeSpan>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `ZoneName`: DNS zone name
- `ZoneType`: Zone type (Primary, Secondary, Stub, Forwarder)
- `ReplicationScope`: Replication scope (Domain, Forest, Custom)
- `DirectoryPartitionName`: Directory partition name
- `DynamicUpdate`: Dynamic update setting
- `Aging`: Enable aging and scavenging
- `RefreshInterval`: Refresh interval
- `RetryInterval`: Retry interval
- `ExpireAfter`: Expire after time
- `MinimumTimeToLive`: Minimum TTL

**Returns:** `Microsoft.Dns.PowerShell.DnsZone`

**Example:**
```powershell
New-DNSZone -ZoneName "contoso.com" -ZoneType "Primary" -ReplicationScope "Domain" -DynamicUpdate "Secure" -Aging
```

#### **Add-DNSResourceRecord**
Adds a DNS resource record.

```powershell
Add-DNSResourceRecord
    [-ZoneName] <String>
    [-Name] <String>
    [-RecordType] <String>
    [-RecordData] <String[]>
    [-TimeToLive] <TimeSpan>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `ZoneName`: DNS zone name
- `Name`: Record name
- `RecordType`: Record type (A, AAAA, CNAME, MX, NS, PTR, SRV, TXT)
- `RecordData`: Record data
- `TimeToLive`: Time to live

**Returns:** `Microsoft.Dns.PowerShell.DnsResourceRecord`

**Example:**
```powershell
Add-DNSResourceRecord -ZoneName "contoso.com" -Name "www" -RecordType "A" -RecordData "192.168.1.100" -TimeToLive "01:00:00"
```

### **DHCP Core Module**

#### **New-DHCPScope**
Creates a new DHCP scope.

```powershell
New-DHCPScope
    [-ScopeId] <String>
    [-Name] <String>
    [-StartRange] <String>
    [-EndRange] <String>
    [-SubnetMask] <String>
    [-State] <String>
    [-LeaseDuration] <TimeSpan>
    [-Description] <String>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `ScopeId`: Scope ID (subnet)
- `Name`: Scope name
- `StartRange`: Start IP address range
- `EndRange`: End IP address range
- `SubnetMask`: Subnet mask
- `State`: Scope state (Active, Inactive)
- `LeaseDuration`: Lease duration
- `Description`: Scope description

**Returns:** `Microsoft.Dhcp.PowerShell.DhcpScope`

**Example:**
```powershell
New-DHCPScope -ScopeId "192.168.1.0" -Name "Corporate Network" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0" -LeaseDuration "08:00:00"
```

#### **Set-DHCPOptionValue**
Sets DHCP option values.

```powershell
Set-DHCPOptionValue
    [-OptionId] <Int32>
    [-Value] <String[]>
    [-ScopeId] <String>
    [-ReservedIP] <String>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `OptionId`: DHCP option ID
- `Value`: Option value
- `ScopeId`: Scope ID (optional)
- `ReservedIP`: Reserved IP address (optional)

**Returns:** `System.Boolean`

**Example:**
```powershell
Set-DHCPOptionValue -OptionId 3 -Value "192.168.1.1" -ScopeId "192.168.1.0"
Set-DHCPOptionValue -OptionId 6 -Value "192.168.1.10,192.168.1.11" -ScopeId "192.168.1.0"
```

### **Hyper-V Core Module**

#### **New-VM**
Creates a new virtual machine.

```powershell
New-VM
    [-Name] <String>
    [-MemoryStartupBytes] <Int64>
    [-Generation] <Int32>
    [-NewVHDPath] <String>
    [-NewVHDSizeBytes] <Int64>
    [-BootDevice] <String>
    [-Path] <String>
    [-SwitchName] <String>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `Name`: Virtual machine name
- `MemoryStartupBytes`: Startup memory in bytes
- `Generation`: VM generation (1 or 2)
- `NewVHDPath`: Path for new VHD
- `NewVHDSizeBytes`: VHD size in bytes
- `BootDevice`: Boot device (VHD, CD, NetworkAdapter, Floppy)
- `Path`: VM configuration path
- `SwitchName`: Virtual switch name

**Returns:** `Microsoft.HyperV.PowerShell.VirtualMachine`

**Example:**
```powershell
New-VM -Name "WebServer01" -MemoryStartupBytes 4GB -Generation 2 -NewVHDPath "C:\VMs\WebServer01.vhdx" -NewVHDSizeBytes 100GB -SwitchName "External"
```

#### **Set-VMMemory**
Configures virtual machine memory.

```powershell
Set-VMMemory
    [-VMName] <String[]>
    [-DynamicMemoryEnabled] <Boolean>
    [-MinimumBytes] <Int64>
    [-MaximumBytes] <Int64>
    [-StartupBytes] <Int64>
    [-Buffer] <Int32>
    [-Priority] <String>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `VMName`: Virtual machine name
- `DynamicMemoryEnabled`: Enable dynamic memory
- `MinimumBytes`: Minimum memory in bytes
- `MaximumBytes`: Maximum memory in bytes
- `StartupBytes`: Startup memory in bytes
- `Buffer`: Memory buffer percentage
- `Priority`: Memory priority (Low, Normal, High)

**Returns:** `System.Boolean`

**Example:**
```powershell
Set-VMMemory -VMName "WebServer01" -DynamicMemoryEnabled -MinimumBytes 2GB -MaximumBytes 8GB -StartupBytes 4GB -Buffer 20
```

### **Failover Clustering Core Module**

#### **New-Cluster**
Creates a new failover cluster.

```powershell
New-Cluster
    [-Name] <String>
    [-Node] <String[]>
    [-StaticAddress] <String[]>
    [-NoStorage] <Boolean>
    [-IgnoreNetwork] <String[]>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `Name`: Cluster name
- `Node`: Cluster node names
- `StaticAddress`: Static IP addresses
- `NoStorage`: Create cluster without storage
- `IgnoreNetwork`: Networks to ignore

**Returns:** `Microsoft.FailoverClusters.PowerShell.Cluster`

**Example:**
```powershell
New-Cluster -Name "ProductionCluster" -Node "Node01", "Node02", "Node03" -StaticAddress "192.168.1.10"
```

#### **Add-ClusterNode**
Adds a node to an existing cluster.

```powershell
Add-ClusterNode
    [-Cluster] <String>
    [-Name] <String>
    [-WhatIf] <Boolean>
    [-Confirm] <Boolean>
    [<CommonParameters>]
```

**Parameters:**
- `Cluster`: Cluster name
- `Name`: Node name to add

**Returns:** `Microsoft.FailoverClusters.PowerShell.ClusterNode`

**Example:**
```powershell
Add-ClusterNode -Cluster "ProductionCluster" -Name "Node04"
```

## 🔧 **Common Parameters**

All cmdlets support the following common parameters:

### **WhatIf Parameter**
```powershell
-WhatIf [<SwitchParameter>]
```
Shows what would happen if the cmdlet runs without actually executing the command.

### **Confirm Parameter**
```powershell
-Confirm [<SwitchParameter>]
```
Prompts for confirmation before running the cmdlet.

### **Verbose Parameter**
```powershell
-Verbose [<SwitchParameter>]
```
Provides detailed information about the operation.

### **Debug Parameter**
```powershell
-Debug [<SwitchParameter>]
```
Provides debugging information.

### **ErrorAction Parameter**
```powershell
-ErrorAction [<ActionPreference>]
```
Specifies how the cmdlet responds to errors.

### **ErrorVariable Parameter**
```powershell
-ErrorVariable [<String>]
```
Stores error information in a variable.

### **OutVariable Parameter**
```powershell
-OutVariable [<String>]
```
Stores output in a variable.

### **OutBuffer Parameter**
```powershell
-OutBuffer [<Int32>]
```
Specifies the number of objects to buffer before calling the next cmdlet.

## 📊 **Return Types**

### **Common Return Types**

| Type | Description | Example |
|------|-------------|---------|
| `System.Boolean` | Success/failure status | `True` |
| `System.String` | Text output | `"Operation completed successfully"` |
| `System.Int32` | Integer values | `42` |
| `System.DateTime` | Date and time | `2024-12-01T10:30:00Z` |
| `System.TimeSpan` | Time duration | `00:30:00` |
| `System.Array` | Array of objects | `@("Item1", "Item2", "Item3")` |
| `System.Hashtable` | Key-value pairs | `@{Key1="Value1"; Key2="Value2"}` |

### **Custom Return Types**

#### **ADHealthStatus**
```powershell
class ADHealthStatus {
    [string] $DomainName
    [string] $OverallHealth
    [System.Collections.Generic.List[ADHealthCheck]] $HealthChecks
    [System.Collections.Generic.List[ADPerformanceMetric]] $PerformanceMetrics
    [System.Collections.Generic.List[ADSecurityStatus]] $SecurityStatus
    [DateTime] $LastUpdated
}
```

#### **ADHealthCheck**
```powershell
class ADHealthCheck {
    [string] $CheckName
    [string] $Status
    [string] $Description
    [string] $Recommendation
    [DateTime] $LastChecked
}
```

## 🚨 **Error Handling**

### **Error Codes**

| Code | Description | Resolution |
|------|-------------|------------|
| `AD001` | Domain controller not found | Verify domain controller connectivity |
| `AD002` | Insufficient permissions | Check user permissions |
| `AD003` | Invalid domain name | Verify domain name format |
| `DNS001` | Zone already exists | Use different zone name or remove existing |
| `DNS002` | Invalid IP address | Verify IP address format |
| `DHCP001` | Scope already exists | Use different scope ID |
| `DHCP002` | Invalid IP range | Verify IP range validity |
| `VM001` | Insufficient resources | Check available resources |
| `VM002` | Invalid VM configuration | Verify VM parameters |

### **Exception Handling**

```powershell
try {
    New-ADDomainController -DomainName "contoso.com" -SiteName "Default-First-Site-Name"
}
catch [System.Exception] {
    Write-Error "Failed to create domain controller: $($_.Exception.Message)"
    # Handle specific error types
    switch ($_.Exception.GetType().Name) {
        "ADException" { Write-Warning "Active Directory specific error" }
        "NetworkException" { Write-Warning "Network connectivity issue" }
        "SecurityException" { Write-Warning "Security/permission issue" }
        default { Write-Warning "Unknown error occurred" }
    }
}
finally {
    # Cleanup code
    Write-Host "Operation completed"
}
```

## 📈 **Performance Considerations**

### **Best Practices**

1. **Use Pipeline Operations**
   ```powershell
   Get-ADUser -Filter * | Set-ADUser -PasswordNeverExpires $true
   ```

2. **Batch Operations**
   ```powershell
   $Users = Get-ADUser -Filter * -Properties *
   $Users | ForEach-Object { Set-ADUser -Identity $_.SamAccountName -PasswordNeverExpires $true }
   ```

3. **Use Appropriate Filters**
   ```powershell
   Get-ADUser -Filter "Enabled -eq $true" -Properties *
   ```

4. **Limit Properties**
   ```powershell
   Get-ADUser -Filter * -Properties SamAccountName, DisplayName
   ```

### **Performance Monitoring**

```powershell
# Measure execution time
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
New-ADDomainController -DomainName "contoso.com"
$Stopwatch.Stop()
Write-Host "Operation completed in $($Stopwatch.ElapsedMilliseconds) milliseconds"
```

## 🔒 **Security Considerations**

### **Authentication**

```powershell
# Use secure authentication
$Credential = Get-Credential
New-ADDomainController -DomainName "contoso.com" -Credential $Credential
```

### **Authorization**

```powershell
# Check permissions before operations
if (Test-ADPermission -Operation "CreateDomainController") {
    New-ADDomainController -DomainName "contoso.com"
} else {
    Write-Error "Insufficient permissions to create domain controller"
}
```

### **Data Protection**

```powershell
# Use secure strings for sensitive data
$SecurePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
New-ADDomainController -SafeModeAdministratorPassword $SecurePassword
```

---

## 📞 **API Support**

For API questions and support, please contact:

**Author:** Adrian Johnson  
**Email:** adrian207@gmail.com  
**LinkedIn:** [Adrian Johnson](https://linkedin.com/in/adrian-johnson)

---

*This API reference provides comprehensive documentation for all functions and cmdlets in the Windows Server PowerShell Solutions Suite, enabling developers and administrators to effectively utilize the automation capabilities.*
