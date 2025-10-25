# RDS Test Configuration

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

This file contains configuration settings for the RDS test suite.

## Test Configuration

### General Settings
- **Test Timeout**: 300 seconds
- **Test Data Path**: .\TestData
- **Log Path**: .\TestLogs
- **Output Path**: .\TestResults
- **Coverage Path**: .\Coverage

### Test Types
- **Unit Tests**: Test individual functions and modules
- **Integration Tests**: Test module interactions and dependencies
- **Deployment Tests**: Test deployment scripts and automation

### Test Categories
- **RDS-Core**: Core functionality and prerequisites
- **RDS-SessionHost**: Session Host management
- **RDS-ConnectionBroker**: Connection Broker and High Availability
- **RDS-Gateway**: Gateway configuration and management
- **RDS-WebAccess**: Web Access and application publishing
- **RDS-Licensing**: Licensing server management
- **RDS-Monitoring**: Monitoring and diagnostics
- **RDS-Security**: Security and compliance
- **RDS-Deployment**: Deployment scripts and automation

### Test Requirements
- **PowerShell Version**: 5.1 or higher
- **Pester Module**: 5.0 or higher
- **Administrator Privileges**: Required for some tests
- **Windows Server**: 2016 or higher

### Test Output Formats
- **NUnitXml**: NUnit XML format for CI/CD integration
- **JUnitXml**: JUnit XML format for Jenkins integration
- **CoverageGutters**: Coverage report format for VS Code

### Test Data
Test data files should be placed in the TestData directory:
- Configuration files
- Sample data
- Test certificates
- Test scripts

### Test Logs
Test logs are written to the TestLogs directory:
- Test execution logs
- Error logs
- Performance logs
- Coverage logs

### Test Results
Test results are written to the TestResults directory:
- XML test results
- HTML reports
- Coverage reports
- Performance reports

## Running Tests

### Run All Tests
```powershell
.\Tests\Run-RDSTests.ps1 -TestType "All"
```

### Run Unit Tests Only
```powershell
.\Tests\Run-RDSTests.ps1 -TestType "Unit"
```

### Run Tests for Specific Module
```powershell
.\Tests\Run-RDSTests.ps1 -ModuleName "RDS-Core" -TestType "Unit"
```

### Run Tests with Coverage
```powershell
.\Tests\Run-RDSTests.ps1 -TestType "Unit" -OutputFormat "CoverageGutters"
```

### Run Tests with Custom Output
```powershell
.\Tests\Run-RDSTests.ps1 -TestType "All" -OutputPath "C:\CustomTestResults" -CoveragePath "C:\CustomCoverage"
```

## Test Development

### Creating New Tests
1. Create test file in Tests directory
2. Follow naming convention: ModuleName.Tests.ps1
3. Include comprehensive test coverage
4. Add proper error handling
5. Include performance tests
6. Add integration tests

### Test Best Practices
1. Use descriptive test names
2. Include setup and teardown
3. Test both success and failure scenarios
4. Include edge cases
5. Test performance characteristics
6. Include security tests
7. Test error handling
8. Include integration tests

### Test Categories
- **Smoke Tests**: Basic functionality verification
- **Unit Tests**: Individual function testing
- **Integration Tests**: Module interaction testing
- **Performance Tests**: Performance and scalability testing
- **Security Tests**: Security and compliance testing
- **Deployment Tests**: Deployment and automation testing

## Continuous Integration

### CI/CD Integration
The test suite is designed to integrate with CI/CD pipelines:
- NUnit XML output for Azure DevOps
- JUnit XML output for Jenkins
- Coverage reports for SonarQube
- Performance metrics for monitoring

### Test Automation
Tests can be automated using:
- Azure DevOps Pipelines
- Jenkins
- GitHub Actions
- TeamCity
- Other CI/CD platforms

### Test Reporting
Test results are available in multiple formats:
- Console output
- XML reports
- HTML reports
- Coverage reports
- Performance reports

## Troubleshooting

### Common Issues
1. **Pester Module Not Found**: Install Pester module
2. **Administrator Privileges Required**: Run as administrator
3. **Test Files Missing**: Ensure all test files are present
4. **Module Files Missing**: Ensure all module files are present
5. **PowerShell Version**: Ensure PowerShell 5.1 or higher

### Debug Mode
Run tests in debug mode for detailed output:
```powershell
.\Tests\Run-RDSTests.ps1 -TestType "All" -Verbose
```

### Test Logs
Check test logs for detailed information:
- Test execution details
- Error messages
- Performance metrics
- Coverage information

## Maintenance

### Regular Maintenance
1. Update test data regularly
2. Review test coverage
3. Update test requirements
4. Maintain test documentation
5. Review test performance
6. Update test configuration

### Test Updates
When updating modules:
1. Update corresponding tests
2. Add new test cases
3. Update test data
4. Review test coverage
5. Update documentation

### Test Performance
Monitor test performance:
1. Test execution time
2. Memory usage
3. CPU usage
4. Test coverage
5. Test reliability

## Support

For test-related issues:
1. Check test logs
2. Review test configuration
3. Verify prerequisites
4. Check test data
5. Review test documentation
6. Create issue in repository
