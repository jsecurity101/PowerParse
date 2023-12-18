function Get-TTPs
{
<#
.SYNOPSIS

Pulls ASCII and Unicode strings and then parses to find functions known to be within a technique. 

The strings portion is altered from Matt Graeber's original Get-Strings cmdlet. The original can be found here: https://github.com/mattifestation/PowerShellArsenal/blob/9149c29e829455c763e211a2f9501ae6395360da/Misc/Get-Strings.ps1

.DESCRIPTION
Get-TTPs pulls ASCII and Unicode strings and then parses to find functions known to be within a technique.

.PARAMETER FilePath
The path to the PE file.

.OUTPUTS
A PSCustomObject with the following properties:
* FilePath - The path to the PE file.
* FileHash - The SHA256 hash of the PE file.
* TA0002_CreateProcess - Whether or not the PE file has a function known to be within the Create Process technique.
* T1055_ProcessInjection - Whether or not the PE file has a function known to be within the Process Injection technique.
* T1055_012_ProcessHollowing - Whether or not the PE file has a function known to be within the Process Hollowing technique.
* T1134_TokenImpersonation - Whether or not the PE file has a function known to be within the Token Impersonation technique.
* T1543_003_ServiceCreation - Whether or not the PE file has a function known to be within the Service Creation technique.
* T1569_002_ServiceExecution - Whether or not the PE file has a function known to be within the Service Execution technique.
* T1003_001_LSASSDump - Whether or not the PE file has a function known to be within the LSASS Dump technique.
* TX_VulnerableDriver - Whether or not the PE file has a function known to be within the Vulnerable Driver technique.
* TX_DebuggingCheck - Whether or not the PE file has a function known to be within the Debugging Check technique.
* TX_COMInitialization - Whether or not the PE file has a function known to be within the COM Initialization technique.

.EXAMPLE
Get-TTPs -FilePath C:\Windows\System32\cmd.exe

Gets TTPs for the cmd.exe file.

.EXAMPLE

ls C:\Windows\System32\cmd.exe | Get-TTPs

Gets TTPs for the cmd.exe file.

#>

    param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('FullName')]
        $FilePath
        
    )

    $ResolvedFilePath = Resolve-Path -Path $FilePath
    $FileHash = Get-FileHash -Path $ResolvedFilePath.Path -Algorithm SHA256

    $MinimumLength = 4
    $Results = @()
    foreach ($File in $ResolvedFilePath)
    {
        #Pulling Unicode Strings
        $UnicodeFileContents = Get-Content -Encoding 'Unicode' $File
        $UnicodeRegex = [Regex] "[\u0020-\u007E]{$MinimumLength,}"
        $Results += $UnicodeRegex.Matches($UnicodeFileContents)
       
        #Pulling Ascii Strings
        $AsciiFileContents = Get-Content -Encoding 'UTF7' $File
        $AsciiRegex = [Regex] "[\x20-\x7E]{$MinimumLength,}"
        $Results = $AsciiRegex.Matches($AsciiFileContents)

    }
    
    $CreateProcessFunctions = @(
        'CreateProcessA',
        'CreateProcessW',
        'CreateProcessAsUserA',
        'CreateProcessAsUserW',
        'NtCreateUserProcess',
        'NtCreateProcess'
    )

    $TokenImpersonationFunctions = @(
        'CreateProcessWithLogonA',
        'CreateProcessWithLogonW',
        'CreateProcessWithTokenA',
        'CreateProcessWithTokenW',
        'CreateProcessWithTokenExA',
        'CreateProcessWithTokenExW',
        'ImpersonateLoggedOnUser'
    )

    $OpenProcessFunctions = @(
        'OpenProcess',
        'NtOpenProcess',
        'CreateToolhelp32Snapshot'
    )

    $CreateProcess = $false
    foreach ($Function in $CreateProcessFunctions) {
        if ($Results.Value -match $Function) {
            $CreateProcess = $true
            break # Exit the loop after the first match
        }
    }

    $TokenImpersonation = $false
    foreach ($Function in $TokenImpersonationFunctions) {
        if ($Results.Value -match $Function) {
            $TokenImpersonation = $true
            break # Exit the loop after the first match
        }
    }
    if($TokenImpersonation -eq $false)
    {
        if($Results.Value -match 'DuplicateToken' -and $Results.Value -match 'SetThreadToken')
        {
            $TokenImpersonation = $true
        }
    }

    $ClassicProcessInjection = $false
    if(($Results.Value -match 'VirtualAllocEx' -and $Results.Value -match 'WriteProcessMemory') -and ($Results.Value -match 'CreateRemoteThread' -or $Results.Value -match 'NtCreateThreadEx' -or  $Results.Value -match 'RtlCreateUserThread' -or  $Results.Value -match 'LoadLibrary'))
    {
        $ClassicProcessInjection = $true
    }

    $ProcessHollowing = $false

    $CreateProcessPattern = '^(CreateProcess|NtCreateProcess)[AW]?$'
    if(($Results.Value -match $CreateProcessPattern) -and ($Results.Value -match 'ZwUnmapViewOfSection' -or $Results.Value -match 'NtUnmapViewOfSection') -and  ($Results.Value -match 'SetThreadContext' -and  $Results.Value -match 'ResumeThread'))
    {
        $ProcessHollowing = $true
    }

    #LSASSDump
    $LSASSDump = $false
    foreach($Function in $OpenProcessFunctions)
    {
        if($Results.Value -match $Function -and ($Results.Value -match 'MiniDumpWriteDump' -or $Results.Value -match 'NtReadVirtualMemory' -or $Results.Value -match 'ReadProcessMemory'))
        {
            $LSASSDump = $true
            break
        }
    }

    # Vulnerable Driver
    $VulnerableDriver = $false
    $CreateFilePattern = '^(CreateFile|NtCreateFile)[AW]?$'
    if($Results.Value -match $CreateFilePattern -and ($Results.Value -match 'DeviceIoControl' -or $Results.Value -match 'NtFsControlFile'))
    {
        $VulnerableDriver = $true
    }

    # Service Creation
    $ServiceCreation = $false
    $CreateServicePattern = '^(CreateService)[AW]?$'
    if($Results.Value -match $CreateServicePattern)
    {
        $ServiceCreation = $true
    }

    # Service Execution
    $ServiceExecution = $false
    $StartServicePattern = '^(StartService)[AW]?$'
    if($Results.Value -match $StartServicePattern)
    {
        $ServiceExecution = $true
    }

    #Debugging Checks
    $IsDebugPresent = $false
    if($Results.Value -match 'IsDebuggerPresent')
    {
        $IsDebugPresent = $true
    }

    #COM Checks
    $COMInitialization = $false
    if($Results.Value -match 'CoCreateInstance' -or $Results.Value -match 'CoCreateInstanceEx' -or $Results.Value -match 'CoGetClassObject')
    {
        $COMInitialization = $true
    }
    
    [PSCustomObject] @{
        FilePath = $ResolvedFilePath.Path
        FileHash = $FileHash.Hash
        TA0002_CreateProcess = $CreateProcess
        T1055_ProcessInjection = $ClassicProcessInjection
        T1055_012_ProcessHollowing = $ProcessHollowing
        T1134_TokenImpersonation = $TokenImpersonation
        T1543_003_ServiceCreation = $ServiceCreation
        T1569_002_ServiceExecution = $ServiceExecution
        T1003_001_LSASSDump = $LSASSDump
        TX_VulnerableDriver = $VulnerableDriver
        TX_DebuggingCheck = $IsDebugPresent
        TX_COMInitialization = $COMInitialization

    }

}