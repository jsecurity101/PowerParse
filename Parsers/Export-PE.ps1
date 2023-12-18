function Export-PE{
<#
.SYNOPSIS

Exports a PE file based off of the beginning and end of the PE file.

.DESCRIPTION
Export-PE exports a PE file based off of the beginning and end of the PE file.

.PARAMETER PEStart
The starting address of the PE file.

.PARAMETER PEEnd
The ending address of the PE file.

.PARAMETER FilePath
The path to the PE to extract the PE file from.

.OUTPUTS
A PSCustomObject with the following properties:
* FilePath - The path to the exported PE file.

.EXAMPLE
Export-PE -FilePath $RelativeFilePath.Path -PEStart 1000 -PEEnd 2000

Exports the PE file from the beginning address of 1000 to the ending address of 2000.

#>
    
    param(
        [Parameter(Mandatory)]
        [Int32]
        $PEStart,

        [Parameter(Mandatory)]
        [Int32]
        $PEEnd,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('FullName')]
        $FilePath,

        [Parameter()]
        [String]
        [ValidateSet('SHA256', 'MD5', 'SHA1')]
        $Algorithm = 'SHA256'
    )

    $NewFilePath = "pe"
    $null = New-Item $NewFilePath

    $ResolvedPath = Resolve-Path -Path $NewFilePath

    $fileStream = [System.IO.File]::OpenRead($FilePath)
    $fileStream.Seek($PEStart, [System.IO.SeekOrigin]::Begin)
    $bufferLength = $PEEnd - $PEStart
    $buffer = New-Object byte[] $bufferLength
    $fileStream.Read($buffer, 0, $bufferLength)

    $null = [System.IO.File]::WriteAllBytes($ResolvedPath, $buffer)

    $Hash = (Get-FileHash -Path "pe" -Algorithm $Algorithm).Hash

    $null = Rename-Item -Path $NewFilePath -NewName $Hash

    $RenamedFile = (Resolve-Path -Path $Hash).Path

    $fileStream.Close()


    [PSCustomObject] @{
            FilePath = $RenamedFile
    }

}