function Get-PESize{

    <#
    .SYNOPSIS
    Gets the size of the PE file.

    .DESCRIPTION
    Get-PESize gets the size of the PE file. It does this by either getting the size of the file or by subtracting the PEStart from the PEEnd. Future versions will be able to get the size of the PE file based off of the last section information.

    .PARAMETER PEStart
    The starting address of the PE file.

    .PARAMETER PEEnd
    The ending address of the PE file.

    .PARAMETER FilePath
    The path to the PE.

    .OUTPUTS
    A PSCustomObject with the following properties:
    * PESizeBytes - The size of the PE file in bytes.

    .EXAMPLE
    Get-PESize -FilePath C:\Windows\System32\cmd.exe
    Gets the size of the cmd.exe file.

    .EXAMPLE
    Get-PESize -PEStart 1000 -PEEnd 2000

    Gets the size of the PE file from the beginning address of 1000 to the ending address of 2000.
    
    #>

    [CmdletBinding(DefaultParameterSetName = 'FilePath')]
    param(
        [Parameter(ParameterSetName = 'Address')]
        [Int32]
        $PEStart,

        [Parameter(ParameterSetName = 'Address')]
        [Int32]
        $PEEnd,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'FilePath')]
        [Alias('FullName')]
        [String]
        $FilePath
    )
$PESize = @()

    switch ($PSCmdlet.ParameterSetName) {
        'FilePath'{
            $RelativeFilePath = Resolve-Path -Path $FilePath

            $FileBytes = [IO.File]::ReadAllBytes($RelativeFilePath)

            $numOfMzHeaders =  Get-MZHeaders -FilePath $RelativeFilePath -FileBytes $FileBytes
            $PESizeCount = ($numOfMzHeaders.intOffsets | Measure).Count

            if ($PESizeCount -eq 1) {

            $PESize = (Get-Item -LiteralPath $RelativeFilePath).Length

            } 
            else  {
            # Only will get the first PESize
            $adjustedSize = (Get-PESize -PEStart $numOfMzHeaders.intOffsets[$i] -PEEnd $numOfMzHeaders.intOffsets[$i + 1]).PESize

            $PESize = $adjustedSize
            }
        }
        'Address'{
            $PESize = ($PEEnd - $PEStart)
        }

    }
    
    [PSCustomObject] @{
        PESizeBytes = $PESize
    }

}