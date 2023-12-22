function Get-MZHeaders{
    <#
    .SYNOPSIS
    Gets the number of MZ headers in a file.

    .DESCRIPTION
    Get-MZHeaders gets the number of MZ headers in a file. This is helpful in situations where malware has dropped one file but has multiple PEs embedded within it. 

    .PARAMETER FilePath
    The path to the PE file.

    .PARAMETER FileBytes
    The bytes of the PE file. This is used to speed up the process of getting the number of MZ headers. If this is not provided, the function will read the bytes from the file.

    .OUTPUTS
    A PSCustomObject with the following properties:
    * NumOfMz - The number of MZ headers.
    * Offsets - The offsets of the MZ headers.
    * IntOffsets - The offsets of the MZ headers as integers.

    .EXAMPLE
    Get-MZHeaders -FilePath C:\Windows\System32\cmd.exe

    Gets the number of MZ headers in the cmd.exe file.

    .EXAMPLE
    Get-MZHeaders -FilePath C:\Windows\System32\cmd.exe -FileBytes $FileBytes

    Gets the number of MZ headers in the cmd.exe file. The FileBytes parameter is used to speed up the process of getting the number of MZ headers.
    
    #>

    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('FullName')]
        $FilePath,

        [Parameter()]
        [byte[]]
        $FileBytes
    )

    $RelativeFilePath = Resolve-Path -Path $FilePath

    if($FileBytes -eq $null){
        $FileBytes = [System.IO.File]::ReadAllBytes($RelativeFilePath)
    }
    
    $byteSequence = [byte[]](0x4D, 0x5A)
    $occurrences = 0
    $offset = @()
    $intOffsets = @()

    

    for ($i = 0; $i -lt ($FileBytes.Length - $byteSequence.Length + 1); $i++) 
    {
        $subArray = $FileBytes[$i..($i + $byteSequence.Length - 1)]

    
        # Check if the current bytes match the desired sequence
        if (-join $subArray -eq -join $byteSequence) {
            $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$FileBytes)
            $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream

            $E_LFANEW_Offset = ($i + 0x3C)
            $null = $MemoryStream.Seek($E_LFANEW_Offset, 'Begin')
           
            $E_LFANEW_Value = $BinaryReader.ReadUInt32()
           
            $E_LFANEW = $E_LFANEW_Value + $i
            
            #Check to see if the E_LFANEW is within the bounds of the file
            if($E_LFANEW -gt $FileBytes.Length){
                $MemoryStream.Dispose()
                $BinaryReader.Dispose()
                continue
            }

            # Seek to the PE signature from the beginning of the stream
            $null = $MemoryStream.Seek($E_LFANEW, 'Begin')
            # Check if there are enough bytes available to read the PE signature
            $PESignature = $BinaryReader.ReadBytes(4)
            # Check if it is a valid PE signature
            if ([Text.Encoding]::ASCII.GetString($PESignature[0..1]) -eq 'PE') {
                $occurrences++
                $offset += $i.ToString("X")
                $intOffsets += $i
               
            }
            $MemoryStream.Dispose()
            $BinaryReader.Dispose()
        }

    }
    [PSCustomObject] @{
        NumOfMz = $occurrences
        Offsets = $offset
        IntOffsets = $intOffsets
    }
}