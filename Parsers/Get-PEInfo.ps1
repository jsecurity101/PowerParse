function Get-PEInfo {
<#
.SYNOPSIS

Gets information about a PE file.

.DESCRIPTION
 Get-PEInfo was designed to pull information about a file, such as the PE Arch, PE Type, if it is a .NET binary, the number of MZ headers, etc. 

.PARAMETER FilePath
The path to the PE file.

.PARAMETER Export
Exports a PE file if there are multiple MZ headers.

.PARAMETER GetVTScore
Gets the VirusTotal score for each PE file.

.PARAMETER VTAPI
The VirusTotal API key.

.PARAMETER GetTTPs
Gets the TTPs for each PE file.

.OUTPUTS
A PSCustomObject with the following properties:
* PEFilePath - The path to the PE file.
* MagicValueOffset - The offset of the Magic Value.
* PEArch - The PE architecture.
* PEType - The PE type.
* FileSizeBytes - The size of the file in bytes.
* NumberofSections - The number of sections in the PE file.
* Sha256 - The SHA256 hash of the PE file.
* ImportTableAddress - The address of the Import Table.
* ImportTableAddressOffset - The offset of the Import Table.
* IsDotNetBinary - Whether or not the PE file is a .NET binary.
* NumberOfPEs - The number of MZ headers.
* PEOffsets - The offsets of the MZ headers.
* PESizes - The sizes of the MZ headers.
* PEExported - Whether or not the PE file was exported.
* NewPEFilePath - The path to the exported PE file.
* VTPositiveResults - The VirusTotal score for each PE file.
* TTPs - The TTPs for each PE file.


.EXAMPLE

Get-PEInfo -FilePath C:\Windows\System32\cmd.exe

Gets information about the cmd.exe file. Will not grab information about TTps or VirusTotal score.

.EXAMPLE

ls C:\Windows\System32\cmd.exe | Get-PEInfo

Gets information about the cmd.exe file. Will not grab information about TTps or VirusTotal score.

.EXAMPLE
Get-PEInfo -FilePath C:\Windows\System32\cmd.exe -TTPs

Gets information about the cmd.exe file. Will grab information about TTPs.

.EXAMPLE
Get-PEInfo -FilePath C:\Windows\System32\cmd.exe -GetVTScore -VTAPI <API Key>

Gets information about the cmd.exe file. Will grab information about the VirusTotal score.

.EXAMPLE
Get-PEInfo -FilePath C:\Windows\System32\cmd.exe -Export

Gets information about the cmd.exe file. Will export the PE file if there are multiple MZ headers.

#>

    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('FullName')]
        $FilePath,

        [Parameter()]
        [Switch]
        $Export,

        [Parameter()]
        [Switch]
        $GetVTScore, 

        [Parameter()]
        [String]
        $VTAPI, 

        [Parameter()]
        [Switch]
        $GetTTPs 

    )

    $RelativeFilePath = Resolve-Path -Path $FilePath

    $FileBytes = [IO.File]::ReadAllBytes($RelativeFilePath)

    $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$FileBytes)
    $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream

    #Checking to see if valid PE 
    $null = $MemoryStream.Seek(0x3C, 'Begin')

    $E_LFANEW = $BinaryReader.ReadUInt32()

    # Seek to NT headers
    $null = $MemoryStream.Seek($E_LFANEW, 'Begin')

    $PESignature = $BinaryReader.ReadBytes(4)

    $Machine = $BinaryReader.ReadUInt16()

    # 2 bytes after machine type holds the number of sections
    $numberOfSections = $BinaryReader.ReadUInt16()


    # 14 bytes after numberOfSections holds the PE Characteristics
    $null = $MemoryStream.Seek(0xE, 'Current')
    $Characteristics = $BinaryReader.ReadUInt16()
    $PEType = $null
    if(($Characteristics -band 0x0002) -eq 0x0002)
    {
        $PEType = "EXE"
    }

    if(($Characteristics -band 0x2000) -eq 0x2000)
    {
        $PEType = "DLL"
    }

    # 2 bytes after Characteristics holds the MagicValue
    $MagicValueOffset = $BinaryReader.BaseStream.Position
    $MagicValue = $BinaryReader.ReadUInt16()
   

     # Checking to see if the binary is a .NET binary: 
    $MachineHex = $Machine.ToString("X")
    $machineType = "NotSupported"
    $PEArch = "NotSupported"
    switch($MachineHex)
    {
        "8664" {
            $machineType = "IMAGE_FILE_MACHINE_AMD64"
            $PEArch = "AMD64"
            $null = $MemoryStream.Seek(0xDE, 'Current')
            $NetfileOffset = $binaryReader.BaseStream.Position
            $NetDirectoryValue = $BinaryReader.ReadUInt32()

            # Add MagicValueOffset to 0x78 to get Import Table Address Offset
            $ImportTableAddressOffset = $MagicValueOffset + 0x78
            $null = $MemoryStream.Seek($ImportTableAddressOffset, 'Begin')
            $ImportTableAddress = $BinaryReader.ReadUInt32()
            
        }
        "14c" {
            $machineType = "IMAGE_FILE_MACHINE_I386"
            $PEArch = "PE32"
            $null = $MemoryStream.Seek(0xCE, 'Current')
            $NetfileOffset = $binaryReader.BaseStream.Position
            $NetDirectoryValue = $BinaryReader.ReadUInt32()

            # Add MagicValueOffset to 0x68 to get Import Table Address Offset
            $ImportTableAddressOffset = $MagicValueOffset + 0x68
            $null = $MemoryStream.Seek($ImportTableAddressOffset, 'Begin')
            $ImportTableAddress = $BinaryReader.ReadUInt32()
        }
        "AA64" {
            Write-Error "File type is not supported"
            return
        }
        "AA64" {
            Write-Error "ARM64 filetype is not supported"
            return
        }
        "1C0"{
            Write-Error "ARM32 filetype is not supported"
            return
        }

    }
    #If NetDirectoryValue is not equal to 00000000, then it is a .NET binary
    if($NetDirectoryValue -ne 0){
        $DotNetBinary = $true
    }
    else{
        $DotNetBinary = $false
    }


    # Search for number of MZ headers
    $null = $MemoryStream.Seek(0x0, 'Begin')
    $MZValue = $BinaryReader.ReadBytes(4)
    

    if([Text.Encoding]::ASCII.GetString($MZValue[0..1]) -cne 'MZ') {
        Write-Error "Not a valid PE"
            return
    }

    #Pulling Number of MZ Headers to see if there are any embedded files
    $numOfMzHeaders =  Get-MZHeaders -FilePath $RelativeFilePath -FileBytes $FileBytes
    $BinaryReader.Close()
    $MemoryStream.Close()

    $PESize = @()
    $Exported = @()
    $PESizeCount = ($numOfMzHeaders.intOffsets | Measure).Count

    if ($PESizeCount -eq 1) {

        $PESize = (Get-Item -LiteralPath $RelativeFilePath).Length

    } elseif ($PESizeCount -gt 1) {
        # Subtract each offset from the next one
        for ($i = 0; $i -lt $PESizeCount - 1; $i++) {
            $adjustedSize = (Get-PESize -PEStart $numOfMzHeaders.intOffsets[$i] -PEEnd $numOfMzHeaders.intOffsets[$i + 1]).PESizeBytes
            if($Export){
                $Exported += (Export-PE -FilePath $RelativeFilePath.Path -PEStart $numOfMzHeaders.intOffsets[$i] -PEEnd $numOfMzHeaders.intOffsets[$i + 1]).FilePath
            }

            $PESize += $adjustedSize
        }

        # Add the size between the last offset and the file length
        $lastAdjustedSize = (Get-PESize -PEStart $numOfMzHeaders.intOffsets[-1] -PEEnd (Get-Item -LiteralPath $RelativeFilePath).Length).PESizeBytes
        if($Export){
               $Exported += (Export-PE -FilePath $RelativeFilePath.Path -PEStart $numOfMzHeaders.intOffsets[-1] -PEEnd (Get-Item -LiteralPath $RelativeFilePath).Length).FilePath
            }
        $PESize += $lastAdjustedSize
    }

    if($GetVTScore){
        $Hashes = @()
        $VTResults = @()
        if($Export){
            $CurrentFolder = Get-ChildItem -Path .
            $CurrentFolder | % {$Hashes += (Get-FileHash $_.Name).Hash}
            foreach ($Hash in $Hashes){
                $Results = (Get-VTScore -Hash $Hash -VTAPI $VTAPI -ReturnPositive).Hash
                if($Results -ne $null){
                    $VTResults += $Results
                }
               
        }
    }
        else{
            $FileHash = Get-FileHash -Path $RelativeFilePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
            $Results = (Get-VTScore -Hash $FileHash -VTAPI $VTAPI -ReturnPositive).Hash
            if($Results -ne $null){
            $VTResults += $Results
        }
        }
    }

    if($GetTTPs){
        $TTPs = (Get-TTPs -FilePath $RelativeFilePath)
    }

    [PSCustomObject] @{
        PEFilePath = $RelativeFilePath.Path
        MagicValueOffset = $MagicValueOffset
        PEArch = $PEArch
        PEType = $PEType
        FileSizeBytes = (Get-Item -LiteralPath $RelativeFilePath).Length
        NumberofSections = $numberOfSections
        Sha256 = (Get-FileHash -LiteralPath $RelativeFilePath -Algorithm SHA256).Hash
        ImportTableAddress = $ImportTableAddress
        ImportTableAddressOffset = $ImportTableAddressOffset
        IsDotNetBinary = $DotNetBinary
        NumberOfPEs = $numOfMzHeaders.numOfMz
        PEOffsets = $numOfMzHeaders.offsets
        PESizes = $PESize 
        PEExported = $Export
        NewPEFilePath = $Exported
        VTPositiveResults = $VTResults
        TTPs = $TTPs
        Strings = (Get-Strings -FilePath $RelativeFilePath).Strings
    }     
}