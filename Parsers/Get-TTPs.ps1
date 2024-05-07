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

.PARAMETER APIFilePath
The path to the API.json file.

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
* T1486_Encryption - Whether or not the PE file has a function known to be within the Encryption technique.
* T1078_UserLogon - Whether or not the PE file has a function known to be within the User Logon technique.
* T1497_AntiAnalysis - Whether or not the PE file has a function known to be within the Anti-Analysis technique.
* TX_VulnerableDriver - Whether or not the PE file has a function known to be within the Vulnerable Driver technique.
* TX_COMInitialization - Whether or not the PE file has a function known to be within the COM Initialization technique.
* TX_NamedPipeCreation - Whether or not the PE file has a function known to be within the Named Pipe Creation technique.
* TX_MailslotCreation - Whether or not the PE file has a function known to be within Mailslot creations.
* TX_MiscAction - Whether or not the PE file has a function known to be within the Misc Action technique.
* TA0002_CreateProcess_APIs - The APIs found within the Create Process technique.
* T1055_ProcessInjection_APIs - The APIs found within the Process Injection technique.
* T1055_012_ProcessHollowing_APIs - The APIs found within the Process Hollowing technique.
* T1134_TokenImpersonation_APIs - The APIs found within the Token Impersonation technique.
* T1543_003_ServiceCreation_APIs - The APIs found within the Service Creation technique.
* T1569_002_ServiceExecution_APIs - The APIs found within the Service Execution technique.
* T1003_001_LSASSDump_APIs - The APIs found within the LSASS Dump technique.
* T1486_Encryption_APIs - The APIs found within the Encryption technique.
* T1078_UserLogon_APIs - The APIs found within the User Logon technique.
* T1497_AntiAnalysis_APIs - The APIs found within the Anti-Analysis technique.
* TX_VulnerableDriver_APIs - The APIs found within the Vulnerable Driver technique.
* TX_COMInitialization_APIs - The APIs found within the COM Initialization technique.
* TX_NamedPipeCreation_APIs - The APIs found within the Named Pipe Creation technique.
* TX_MailslotCreation_APIs - The APIs found within mailslot creations.
* TX_MiscAction_APIs - The APIs found within the Misc Action technique.


.EXAMPLE
Get-TTPs -FilePath C:\Windows\System32\cmd.exe

Gets TTPs for the cmd.exe file.

.EXAMPLE
Get-TTPs -FilePath C:\Windows\System32\cmd.exe -APIFilePath C:\Users\user\Desktop\APIs\APIs.json

Gets TTPs for the cmd.exe file while specifying the API folder path.

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
        $FilePath,

	    [String]
        $APIFilePath = "$PWD\APIs\APIs.json"
        
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
        $Results += $AsciiRegex.Matches($AsciiFileContents)

    }

    $jsonPath =  $APIFilePath
    $jsonContent = Get-Content $jsonPath -Raw
    $apiList = ConvertFrom-Json -InputObject $jsonContent


    $MiscListAPIs = @()
    $T1486_Encryption_APIs = @()
    $T1497_AntiAnalysis_APIs = @()
    $TX_NamedPipeCreation_APIs = @()
    $TX_MailslotCreation_APIs = @()
    $TX_COMInitialization_APIs = @()
    $T1569_002_ServiceExecution_APIs = @()
    $T1543_003_ServiceCreation_APIs = @()
    $T1134_TokenImpersonation_APIs = @()
    $T1003_001_LSASSDump_APIs = @()
    $T1055_012_ProcessHollowing_APIs = @()
    $T1055_ProcessInjection_APIs = @()
    $TA0002_CreateProcess_APIs = @()
    $TX_VulnerableDriver_APIs = @()
    $SectionMapping_APIs = @()
    $ThreadContinuation_APIs = @()
    $ThreadSet_APIs = @()
    $ProcessOpen_APIs = @()
    $DuplicateToken_APIs = @()
    $ThreadTokenSet_APIs = @()
    $ProcessRead_APIs = @()
    $ProcessInjection_Write_APIs = @()
    $ProcessInjection_Execute_APIs = @()
    $LogonUser_APIs = @()

    $MiscAction = $false
    $CreateProcess = $false
    $LSASSDump = $false
    $ProcessHollowing = $false
    $COMInitialization = $false
    $CreateNamedPipe = $false
    $CreateMailslot = $false
    $VulnerableDriver = $false
    $ServiceCreation = $false
    $ServiceExecution = $false
    $AntiAnalysisCheck = $false
    $TokenImpersonation = $false
    $ProcessInjection = $false
    $SectionMapping = $false
    $ThreadContinuation = $false
    $ThreadSet = $false
    $T1486_Encryption = $false
    $DuplicateToken = $false
    $ThreadTokenSet = $false
    $ProcessInjection_Write = $false
    $ProcessInjection_Execute = $false
    $ProcessRead = $false
    $ProcessOpen = $false
    $LogonUser = $false

    foreach ($api in $apiList.apis) {
        # Access API details
        $apiName = $api.name
        $apiTag = $api.tag 

        # Perform your specific checks or actions here
        $matchResults = $Results.Value | Select-String -Pattern $apiName -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }

        if ($null -ne $matchResults) {

            # Check if the tag of the API matches and update the corresponding variable
            switch($apiTag){
                "TX_MiscAction" 
                {
                    $MiscAction = $true
                    $MiscListAPIs += $matchResults
                    break
                }
                "TA0002_CreateProcess" 
                {
                    $CreateProcess = $true
                    $TA0002_CreateProcess_APIs += $matchResults
                    break
                }
                "SectionMapping"
                {
                    $SectionMapping = $true
                    $SectionMapping_APIs += $matchResults
                    break
                }
                "ThreadContinuation"{
                    $ThreadContinuation = $true
                    $ThreadContinuation_APIs += $matchResults
                    break
                }
                "ThreadSet"
                {
                    $ThreadSet = $true
                    $ThreadSet_APIs += $matchResults
                    break
                }
                "TX_ProcessHandle" 
                {
                    $ProcessOpen = $true
                    $ProcessOpen_APIs += $matchResults
                    break
                }
                "ProcessRead"
                {
                    $ProcessRead = $true
                    $ProcessRead_APIs += $matchResults
                    break
                }
                "TX_COMInitialization"
                {
                    $COMInitialization = $true
                    $TX_COMInitialization_APIs += $matchResults
                    break
                }
                "TX_NamedPipeCreation"
                {
                    $CreateNamedPipe = $true
                    $TX_NamedPipeCreation_APIs += $matchResults
                    break
                }
                "TX_MailslotCreation"
                {
                    $CreateMailslot = $true
                    $TX_MailslotCreation_APIs += $matchResults
                    break
                }
                "DeviceCodeExecution"
                {
                    $VulnerableDriver = $true
                    $TX_VulnerableDriver_APIs += $matchResults
                    break
                }
                "T1543_003_ServiceCreation"
                {
                    $ServiceCreation = $true   
                    $T1543_003_ServiceCreation_APIs += $matchResults
                    break
                }
                "T1569_002_ServiceExecution"
                {
                    $ServiceExecution = $true   
                    $T1569_002_ServiceExecution_APIs += $matchResults
                    break
                }
                "T1497_AntiAnalysis"
                {
                    $AntiAnalysisCheck = $true
                    $T1497_AntiAnalysis_APIs += $matchResults
                    break
                }
                "T1134_TokenImpersonation"
                {
                    $TokenImpersonation = $true
                    $T1134_TokenImpersonation_APIs += $matchResults
                    break
                }
                "ProcessInjection_Write"
                {
                    $ProcessInjection_Write = $true
                    $ProcessInjection_Write_APIs += $matchResults
                    break
                }
                "ProcessInjection_Execute"
                {
                    $ProcessInjection_Execute = $true
                    $ProcessInjection_Execute_APIs += $matchResults
                    break
                }
                "T1486_Encryption"
                {
                    $T1486_Encryption = $true
                    $T1486_Encryption_APIs += $matchResults
                    break
                }
                "TokenDuplicate"
                {
                    $DuplicateToken = $true
                    $DuplicateToken_APIs += $matchResults
                    break
                }
                "ThreadTokenSet"
                {
                    $ThreadTokenSet = $true
                    $ThreadTokenSet_APIs += $matchResults
                    break
                }
                "UserLogon"
                {
                    $LogonUser = $true
                    $LogonUser_APIs += $matchResults
                    break
                }
            }
        }
    }

    if($ProcessInjection_Execute -eq $true -and $ProcessInjection_Write -eq $true)
    {
        $ProcessInjection = $true
        $T1055_ProcessInjection_APIs = $ProcessInjection_Write_APIs + $ProcessInjection_Execute_APIs 
    }

    if($SectionMapping -eq $true -and $CreateProcess -eq $true -and $ThreadContinuation -eq $true -and $ThreadSet -eq $true)
    {
        $ProcessHollowing = $true
        $T1055_012_ProcessHollowing_APIs = $SectionMapping_APIs + $TA0002_CreateProcess_APIs + $ThreadContinuation_APIs + $ThreadSet_APIs
    }

    if($TokenImpersonation -eq $false -and $DuplicateToken -eq $true -and $ThreadTokenSet -eq $true)
    {
        $TokenImpersonation = $true
    }
    if($ProcessRead -eq $true -and $ProcessOpen -eq $true)
    {
        $LSASSDump = $true
        $T1003_001_LSASSDump_APIs = $ProcessOpen_APIs + $ProcessRead_APIs 
    }
    
    [PSCustomObject] @{
        FilePath =                          $ResolvedFilePath.Path
        FileHash =                          $FileHash.Hash
        TA0002_CreateProcess =              $CreateProcess
        T1055_ProcessInjection =            $ProcessInjection
        T1055_012_ProcessHollowing =        $ProcessHollowing
        T1134_TokenImpersonation =          $TokenImpersonation
        T1543_003_ServiceCreation =         $ServiceCreation
        T1569_002_ServiceExecution =        $ServiceExecution
        T1003_001_LSASSDump =               $LSASSDump
        T1486_Encryption =                  $T1486_Encryption
        T1078_UserLogon =                   $LogonUser
        T1497_AntiAnalysis =                $AntiAnalysisCheck
        TX_VulnerableDriver =               $VulnerableDriver
        TX_COMInitialization =              $COMInitialization
        TX_NamedPipeCreation =              $CreateNamedPipe
        TX_MailslotCreation =               $CreateMailslot
        TX_MiscAction =                     $MiscAction
        TA0002_CreateProcess_APIs =         $TA0002_CreateProcess_APIs | Select-Object -Unique
        T1055_ProcessInjection_APIs =       $T1055_ProcessInjection_APIs | Select-Object -Unique
        T1055_012_ProcessHollowing_APIs =   $T1055_012_ProcessHollowing_APIs | Select-Object -Unique
        T1134_TokenImpersonation_APIs   =   $T1134_TokenImpersonation_APIs | Select-Object -Unique
        T1543_003_ServiceCreation_APIs  =   $T1543_003_ServiceCreation_APIs  | Select-Object -Unique
        T1569_002_ServiceExecution_APIs =   $T1569_002_ServiceExecution_APIs | Select-Object -Unique
        T1003_001_LSASSDump_APIs =          $T1003_001_LSASSDump_APIs | Select-Object -Unique
        T1486_Encryption_APIs =             $T1486_Encryption_APIs | Select-Object -Unique
        T1078_UserLogon_APIs =              $LogonUser_APIs | Select-Object -Unique
        TX_VulnerableDriver_APIs =          $TX_VulnerableDriver_APIs | Select-Object -Unique
        T1497_AntiAnalysis_APIs =           $T1497_AntiAnalysis_APIs | Select-Object -Unique
        TX_COMInitialization_APIs =         $TX_COMInitialization_APIs | Select-Object -Unique
        TX_NamedPipeCreation_APIs =         $TX_NamedPipeCreation_APIs | Select-Object -Unique
        TX_MailslotCreation_APIs =          $TX_MailslotCreation_APIs | Select-Object -Unique
        TX_MiscAction_APIs =                $MiscListAPIs

    }

}