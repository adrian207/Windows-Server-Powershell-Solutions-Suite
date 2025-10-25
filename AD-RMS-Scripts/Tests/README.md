# AD RMS PowerShell Scripts - Test Suite

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

This directory contains Pester test files for validating the AD RMS PowerShell scripts functionality.

## Test Structure

```
Tests/
├── ADRMS-Core.Tests.ps1          # Tests for core module functions
├── ADRMS-Configuration.Tests.ps1  # Tests for configuration module
├── ADRMS-Diagnostics.Tests.ps1   # Tests for diagnostics module
├── Implementation.Tests.ps1       # Tests for implementation scripts
├── Configuration.Tests.ps1        # Tests for configuration scripts
├── Troubleshooting.Tests.ps1     # Tests for troubleshooting scripts
└── Integration.Tests.ps1         # Integration tests
```

## Running Tests

### Prerequisites

Install Pester module:
```powershell
Install-Module -Name Pester -Force -SkipPublisherCheck
```

### Run All Tests

```powershell
# Run all tests
Invoke-Pester -Path .\Tests\ -OutputFile TestResults.xml -OutputFormat NUnitXml
```

### Run Specific Test Files

```powershell
# Run core module tests
Invoke-Pester -Path .\Tests\ADRMS-Core.Tests.ps1

# Run configuration tests
Invoke-Pester -Path .\Tests\Configuration.Tests.ps1
```

### Run Tests with Coverage

```powershell
# Run tests with code coverage
Invoke-Pester -Path .\Tests\ -CodeCoverage .\Modules\*.psm1 -CodeCoverageOutputFile Coverage.xml
```

## Test Categories

### Unit Tests
- Test individual functions in isolation
- Mock external dependencies
- Validate input/output parameters
- Test error handling

### Integration Tests
- Test complete workflows
- Validate end-to-end functionality
- Test script interactions
- Validate real-world scenarios

### Performance Tests
- Test performance under load
- Validate resource usage
- Test scalability
- Monitor response times

## Test Examples

### Example Unit Test

```powershell
Describe "Test-ADRMSPrerequisites" {
    Context "When prerequisites are met" {
        It "Should return true" {
            # Mock the prerequisite checks
            Mock Get-WindowsFeature { return @{ InstallState = 'Installed' } }
            Mock Get-WmiObject { return @{ PartOfDomain = $true } }
            
            $result = Test-ADRMSPrerequisites
            $result | Should -Be $true
        }
    }
    
    Context "When prerequisites are not met" {
        It "Should return false" {
            # Mock failed prerequisite checks
            Mock Get-WindowsFeature { return @{ InstallState = 'Available' } }
            
            $result = Test-ADRMSPrerequisites
            $result | Should -Be $false
        }
    }
}
```

### Example Integration Test

```powershell
Describe "AD RMS Installation Workflow" {
    Context "Complete installation process" {
        It "Should install AD RMS successfully" {
            # Test the complete installation workflow
            $securePassword = ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force
            
            # Mock external dependencies
            Mock Install-WindowsFeature { return @{ Success = $true } }
            Mock Start-Service { return $true }
            
            # Run installation
            $result = .\Scripts\Implementation\Install-ADRMS.ps1 -DomainName "test.com" -ServiceAccountPassword $securePassword
            
            # Validate results
            $LASTEXITCODE | Should -Be 0
        }
    }
}
```

## Continuous Integration

### Azure DevOps Pipeline

```yaml
trigger:
- main

pool:
  vmImage: 'windows-latest'

steps:
- task: PowerShell@2
  displayName: 'Install Pester'
  inputs:
    targetType: 'inline'
    script: |
      Install-Module -Name Pester -Force -SkipPublisherCheck

- task: PowerShell@2
  displayName: 'Run Tests'
  inputs:
    targetType: 'inline'
    script: |
      Invoke-Pester -Path .\Tests\ -OutputFile TestResults.xml -OutputFormat NUnitXml

- task: PublishTestResults@2
  displayName: 'Publish Test Results'
  inputs:
    testResultsFiles: 'TestResults.xml'
    testRunTitle: 'AD RMS PowerShell Scripts Tests'
```

### GitHub Actions

```yaml
name: Test AD RMS Scripts

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Install Pester
      run: |
        Install-Module -Name Pester -Force -SkipPublisherCheck
    
    - name: Run Tests
      run: |
        Invoke-Pester -Path .\Tests\ -OutputFile TestResults.xml -OutputFormat NUnitXml
    
    - name: Upload Test Results
      uses: actions/upload-artifact@v2
      with:
        name: test-results
        path: TestResults.xml
```

## Test Data

### Mock Data

Create mock data for testing:

```powershell
# Mock AD RMS configuration
$mockADRMSConfig = @{
    Installed = $true
    ServiceStatus = 'Running'
    ClusterUrl = 'https://rms.test.com/_wmcs'
    LicensingUrl = 'https://rms.test.com/_wmcs/licensing'
    IISStatus = 'Running'
}

# Mock service information
$mockServices = @{
    MSDRMS = @{
        Status = 'Running'
        StartType = 'Automatic'
        DisplayName = 'Active Directory Rights Management Services'
    }
    W3SVC = @{
        Status = 'Running'
        StartType = 'Automatic'
        DisplayName = 'World Wide Web Publishing Service'
    }
}
```

### Test Scenarios

Define test scenarios:

```powershell
# Test scenarios
$testScenarios = @{
    Healthy = @{
        Services = @{ MSDRMS = 'Running'; W3SVC = 'Running' }
        Configuration = @{ Overall = 'Fully Configured' }
        Connectivity = @{ Overall = 'All Accessible' }
        ExpectedResult = 'Healthy'
    }
    Degraded = @{
        Services = @{ MSDRMS = 'Running'; W3SVC = 'Stopped' }
        Configuration = @{ Overall = 'Fully Configured' }
        Connectivity = @{ Overall = 'Partially Accessible' }
        ExpectedResult = 'Degraded'
    }
    Unhealthy = @{
        Services = @{ MSDRMS = 'Stopped'; W3SVC = 'Stopped' }
        Configuration = @{ Overall = 'Not Configured' }
        Connectivity = @{ Overall = 'Not Accessible' }
        ExpectedResult = 'Unhealthy'
    }
}
```

## Best Practices

### Test Organization

1. **Group related tests**: Use Describe blocks to group related functionality
2. **Use meaningful names**: Test names should clearly describe what is being tested
3. **Test edge cases**: Include tests for boundary conditions and error scenarios
4. **Mock external dependencies**: Don't rely on external systems for unit tests

### Test Data Management

1. **Use consistent test data**: Create reusable test data sets
2. **Clean up after tests**: Ensure tests don't leave residual data
3. **Isolate test environments**: Use separate test environments when possible
4. **Validate test data**: Ensure test data is valid and realistic

### Performance Testing

1. **Measure response times**: Test script execution times
2. **Monitor resource usage**: Track CPU, memory, and disk usage
3. **Test scalability**: Validate performance under load
4. **Set performance benchmarks**: Define acceptable performance thresholds

## Troubleshooting Tests

### Common Issues

1. **Test failures due to permissions**
   - Ensure tests run with appropriate privileges
   - Mock privileged operations when possible

2. **Tests failing due to external dependencies**
   - Mock external services and APIs
   - Use test doubles for external resources

3. **Tests not finding modules**
   - Ensure modules are imported correctly
   - Use relative paths for module imports

### Debugging Tests

```powershell
# Run tests with verbose output
Invoke-Pester -Path .\Tests\ -Verbose

# Run specific test with debug information
Invoke-Pester -Path .\Tests\ADRMS-Core.Tests.ps1 -Tag "SpecificTest" -Verbose

# Run tests and stop on first failure
Invoke-Pester -Path .\Tests\ -StopOnFailure
```

## Test Coverage

### Coverage Goals

- **Unit Tests**: 90%+ code coverage
- **Integration Tests**: Cover all major workflows
- **Error Handling**: Test all error scenarios
- **Edge Cases**: Test boundary conditions

### Coverage Reporting

```powershell
# Generate coverage report
Invoke-Pester -Path .\Tests\ -CodeCoverage .\Modules\*.psm1 -CodeCoverageOutputFile Coverage.xml

# View coverage results
Import-Module Pester
$coverage = Import-Clixml Coverage.xml
$coverage | Format-Table
```

## Conclusion

This test suite provides comprehensive validation of the AD RMS PowerShell scripts. Regular testing ensures reliability and helps identify issues early in the development process. Use these tests as part of your continuous integration pipeline to maintain code quality and reliability.
