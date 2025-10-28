<#
.SYNOPSIS
    Enhanced error handling module for Windows Server PowerShell Solutions Suite

.DESCRIPTION
    Provides comprehensive error handling, retry logic, error recovery,
    and exception management for enterprise PowerShell operations.

.PARAMETER None

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: rememberedVersion = '1.0.0'
    Last Updated: December 2024
    
    Features:
    - Automatic retry with exponential backoff
    - Error recovery strategies
    - Exception translation
    - Error aggregation and reporting
    - Performance monitoring
    - Graceful degradation
#>

[CmdletBinding()]
param()

# Module Variables
$script:ModuleVersion = '1.0.0'
$script:ErrorActionPreference = 'Stop'

#region Public Functions

function Invoke-CommandWithRetry {
    <#
    .SYNOPSIS
        Executes a command with automatic retry logic
    
    .DESCRIPTION
        Executes a PowerShell command with configurable retry logic including
        exponential backoff and custom error handling.
    
    .PARAMETER ScriptBlock
        The script block to execute
    
    .PARAMETER MaxRetries
        Maximum number of retry attempts
    
    .PARAMETER RetryInterval
        Initial retry interval in seconds
    
    .PARAMETER BackoffMultiplier
        Multiplier for exponential backoff
    
    .PARAMETER RetryOn
        Error types to retry on
    
    .EXAMPLE
        Invoke-CommandWithRetry -ScriptBlock { Get-Service -Name "NonExistent" } -MaxRetries 3
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryInterval = 2,
        
        [Parameter(Mandatory = $false)]
        [double]$BackoffMultiplier = 2.0,
        
        [Parameter(Mandatory = $false)]
        [string[]]$RetryOn = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$OperationName = "Command"
    )
    
    $currentRetry = 0
    $lastException = $null
    
    while ($currentRetry -le $MaxRetries) {
        try {
            $result = Invoke-Command -ScriptBlock $ScriptBlock -ErrorAction Stop
            
            if ($currentRetry -gt 0) {
                Write-Log -Message "$OperationName succeeded after $currentRetry retry attempts" -Level INFO -Component "ErrorHandling"
            }
            
            return $result
            
        } catch {
            $lastException = $_
            $currentRetry++
            
            if ($currentRetry -gt $MaxRetries) {
                Write-Log -Message "$OperationName failed after $MaxRetries attempts" -Level ERROR -Component "ErrorHandling" -Exception $_
                throw $_
            }
            
            # Check if we should retry based on exception type
            if ($RetryOn -and $_.Exception.GetType().FullName -notin $RetryOn) {
                Write-Log -Message "Exception type not in retry list: $($_.Exception.GetType().FullName)" -Level ERROR -Component "ErrorHandling"
                throw $_
            }
            
            $waitTime = $RetryInterval * [Math]::Pow($BackoffMultiplier, ($currentRetry - 1))
            Write-Log -Message "$OperationName failed (attempt $currentRetry/$MaxRetries): $($_.Message). Retrying in $waitTime seconds..." -Level WARNING -Component "ErrorHandling"
            
            Start-Sleep -Seconds $waitTime
        }
    }
}

function Invoke-TryCatchFinally {
    <#
    .SYNOPSIS
        Executes code with try-catch-finally semantics
    
    .DESCRIPTION
        Provides structured error handling with try, catch, and finally blocks
    
    .PARAMETER Try
        Script block to execute (try block)
    
    .PARAMETER Catch
        Script block to execute on error (catch block)
    
    .PARAMETER Finally
        Script block to always execute (finally block)
    
    .PARAMETER SilentlyContinue
        Suppress errors and continue execution
    
    .EXAMPLE
        Invoke-TryCatchFinally -Try { Get-Process -Name "NonExistent" } -Catch { Write-Log "Error occurred" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$Try,
        
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$Catch,
        
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$Finally,
        
        [Parameter(Mandatory = $false)]
        [switch]$SilentlyContinue
    )
    
    try {
        Invoke-Command -ScriptBlock $Try -ErrorAction Stop
    }
    catch {
        $errorObject = $_
        
        if (-not $SilentlyContinue) {
            Write-Log -Message "Error in try block: $($_.Message)" -Level ERROR -Component "ErrorHandling" -Exception $_
        }
        
        if ($Catch) {
            Invoke-Command -ScriptBlock $Catch -ErrorAction Continue
        }
        
        if (-not $SilentlyContinue) {
            throw
        }
    }
    finally {
        if ($Finally) {
            Invoke-Command -ScriptBlock $Finally -ErrorAction Continue
        }
    }
}

function Get-ErrorDetails {
    <#
    .SYNOPSIS
        Extracts detailed information from an error
    
    .DESCRIPTION
        Parses exception objects to extract comprehensive error details
    
    .PARAMETER ErrorObject
        The error object to analyze
    
    .EXAMPLE
        Get-ErrorDetails -ErrorObject $_
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorObject
    )
    
    $details = @{
        Type = $ErrorObject.Exception.GetType().FullName
        Message = $ErrorObject.Exception.Message
        InnerException = if ($ErrorObject.Exception.InnerException) {
            @{
                Type = $ErrorObject.Exception.InnerException.GetType().FullName
                Message = $ErrorObject.Exception.InnerException.Message
            }
        } else { $null }
        StackTrace = $ErrorObject.ScriptStackTrace
        Category = $ErrorObject.CategoryInfo.Category
        TargetName = $ErrorObject.TargetObject
        FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
        Line = $ErrorObject.InvocationInfo.Line
        ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
        PositionMessage = $ErrorObject.InvocationInfo.PositionMessage
    }
    
    return $details
}

function Send-ErrorReport {
    <#
    .SYNOPSIS
        Sends an error report to administrators
    
    .DESCRIPTION
        Aggregates error information and sends it via configured channels
    
    .PARAMETER ErrorDetails
        Error details object
    
    .PARAMETER Severity
        Error severity level
    
    .PARAMETER Component
        Component where error occurred
    
    .EXAMPLE
        Send-ErrorReport -ErrorDetails (Get-ErrorDetails -ErrorObject $_) -Severity CRITICAL
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ErrorDetails,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$Severity = 'ERROR',
        
        [Parameter(Mandatory = $false)]
        [string]$Component = 'Unknown'
    )
    
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Severity = $Severity
        Component = $Component
        ErrorDetails = $ErrorDetails
        Host = $env:COMPUTERNAME
        User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ProcessInfo = @{
            ProcessId = $PID
            ProcessName = (Get-Process -Id $PID).ProcessName
        }
    }
    
    Write-Log -Message "Error report generated" -Level $Severity -Component "ErrorHandling" -Data $report
    
    # TODO: Implement email/SMS/webhook notifications for CRITICAL errors
    
}

#endregion Public Functions

#region Error Recovery Functions

function Enable-GracefulDegradation {
    <#
    .SYNOPSIS
        Enables graceful degradation mode
    
    .DESCRIPTION
        Configures error handling to degrade gracefully rather than fail completely
    
    .PARAMETER FallbackActions
        Hashtable of fallback actions for different error types
    
    .EXAMPLE
        Enable-GracefulDegradation -FallbackActions @{
            'FileNotFound' = { Write-Log "Using default configuration" }
            'AccessDenied' = { Request-Elevation }
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$FallbackActions = @{}
    )
    
    $script:GracefulDegradationEnabled = $true
    $script:FallbackActions = $FallbackActions
    
    Write-Log -Message "Graceful degradation mode enabled" -Level INFO -Component "ErrorHandling"
}

function Invoke-FallbackAction {
    <#
    .SYNOPSIS
        Invokes fallback action for an error
    
    .DESCRIPTION
        Executes the configured fallback action for a given error type
    
    .PARAMETER ErrorType
        Type of error that occurred
    
    .PARAMETER ErrorDetails
        Additional error details
    
    .EXAMPLE
        Invoke-FallbackAction -ErrorType "FileNotFound" -ErrorDetails $details
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ErrorType,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$ErrorDetails = @{}
    )
    
    if ($script:GracefulDegradationEnabled -and $script:FallbackActions.ContainsKey($ErrorType)) {
        $action = $script:FallbackActions[$ErrorType]
        Write-Log -Message "Executing fallback action for: $ErrorType" -Level WARNING -Component "ErrorHandling"
        Invoke-Command -ScriptBlock $action
    } else {
        Write-Log -Message "No fallback action configured for: $ErrorType" -Level ERROR -Component "ErrorHandling"
    }
}

#endregion Error Recovery Functions

# Export Functions
Export-ModuleMember -Function Invoke-CommandWithRetry, Invoke-TryCatchFinally, Get-ErrorDetails, Send-ErrorReport, Enable-GracefulDegradation, Invoke-FallbackAction

# Module Metadata
$script:ModuleInfo = @{
    Name = 'Error-Handling'
    Version = $script:ModuleVersion
    Author = 'Adrian Johnson (adrian207@gmail.com)'
    Description = 'Enhanced error handling module for Windows Server PowerShell Solutions Suite'
}

