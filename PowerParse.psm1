Get-ChildItem $PSScriptRoot |
    ? {$_.PSIsContainer} |
    % {Get-ChildItem "$($_.FullName)\*" -Include '*.ps1'} |
    % {. $_.FullName}