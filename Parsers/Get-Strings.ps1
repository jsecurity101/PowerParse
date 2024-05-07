function Get-Strings
{
<#
.SYNOPSIS

Pulls ASCII and Unicode strings. 

The strings portion is altered from Matt Graeber's original Get-Strings cmdlet. The original can be found here: https://github.com/mattifestation/PowerShellArsenal/blob/9149c29e829455c763e211a2f9501ae6395360da/Misc/Get-Strings.ps1

.DESCRIPTION
Get-Strings pulls ASCII and Unicode strings from a file. The strings are then returned in a PSCustomObject.

.PARAMETER FilePath
The path to the PE file.

.OUTPUTS
A PSCustomObject with the following properties:
* Strings - The strings found in the file.


.EXAMPLE
Get-Strings -FilePath C:\Windows\System32\cmd.exe

Gets the strings from cmd.exe.


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
   
    $MinimumLength = 4
    $Results = @()
    foreach ($File in $ResolvedFilePath)
    {
        #Pulling Unicode Strings
        $UnicodeFileContents = Get-Content -Encoding 'Unicode' $File
        $UnicodeRegex = [Regex] "[\u0020-\u007E]{$MinimumLength,}"
        $Results += ($UnicodeRegex.Matches($UnicodeFileContents)).Value
       
        #Pulling Ascii Strings
        $AsciiFileContents = Get-Content -Encoding 'UTF7' $File
        $AsciiRegex = [Regex] "[\x20-\x7E]{$MinimumLength,}"
        $Results += ($AsciiRegex.Matches($AsciiFileContents)).Value

    }
    $Strings = $Results | Select-Object -Unique

    [PSCustomObject] @{
        Strings = $Strings
    }
    
}