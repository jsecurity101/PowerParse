@{

# Script module or binary module file associated with this manifest.
RootModule = 'PowerParse.psm1'

# Version number of this module.
ModuleVersion = '0.0.0.1'

# ID used to uniquely identify this module
GUID = '7c94a7a6-1f58-42ca-b7f2-11c052fb121b'

# Author of this module
Author = 'Jonathan Johnson'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = ''

# Description of the functionality provided by this module
Description = 'A module to facilitate the testing of attack techniques and their corresponding procedures.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Get-VTScore',
                    'Export-PE',
                    'Get-PESize',
                    'Get-MZHeaders',
                    'Get-PEInfo',
		            'Get-TTPs',
                    'Get-Strings'
                    

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('Security', 'Defense')

        # A URL to the license for this module.
        LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = @'

'@

    } # End of PSData hashtable

} # End of PrivateData hashtable

}
