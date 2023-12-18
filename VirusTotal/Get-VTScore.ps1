function Get-VTScore{
    <#
    .SYSNOPSIS
    Gets the VirusTotal score for a file hash.

    .DESCRIPTION
    Get-VTScore gets the VirusTotal score for a file hash. It does this by using the VirusTotal API.

    .PARAMETER FilePath
    The path to the file to get the VirusTotal score for.

    .PARAMETER Hash
    The hash of the file to get the VirusTotal score for.

    .PARAMETER VTAPI
    The VirusTotal API key. This is required to get the VirusTotal score.

    .PARAMETER ReturnPositive
    If this switch is used, the function will only return the VirusTotal score if it is positive.

    .OUTPUTS
    A PSCustomObject with the following properties:
    * PositiveHits - The number of positive hits.
    * Hash - The hash of the file.

    #>

    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        [Alias('FullName')]
        $FilePath,

        [Parameter()]
        [String]
        $Hash, 

        [Parameter(Mandatory)]
        [String]
        $VTAPI, 

        [Parameter()]
        [Switch]
        $ReturnPositive
    )
    
    if($FilePath){
        $ResolvedPath = Resolve-Path -Path $FilePath
        $Hash = Get-FileHash -Path $ResolvedPath.Path -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        $global:foo = $Hash
    }

    $MsgBody =  @{resource = $Hash; apikey = $VTAPI}
    $ReturnedResult = $null
    $VirtusTotalResult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $MsgBody
    if($ReturnPositive){
        if($VirtusTotalResult.positives -gt 0){
            $ReturnedResult =  $VirtusTotalResult
        }
    }
    else{
        $ReturnedResult = $VirtusTotalResult
    }

    if($VirtusTotalResult.response_code -eq 0){
        $ResultCode = 1 #No matches
    }
    else{
        $PositiveHits = $ReturnedResult.positives
        $VTHash = $ReturnedResult.sha256
        $ResultCode = 0
    }

    [PSCustomObject] @{
        PositiveHits = $PositiveHits
        Hash         = $VTHash
        ResultCode   = $ResultCode
    }

}