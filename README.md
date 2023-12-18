# PowerParse v0.01
PowerShell PE Parser designed to help and aid reverse engineers. Module allows initial triage of a PE by supporting modules that do the following: 
* Obtain basic information about a PE. 
* Identify if the PE in question has multiple embedded PEs within it. If there is, an option to export each PE is available. 
* Ability to ship up a VT search. 
* Ability to identify if certain behaviors (TTPs) are performed within the PE.

# Usage

To use this module, type: `Import-Module PowerParse.psd1`. 

The following functions are supported: 

* `Get-PEInfo`
    
Obtains information about a PE (type, architectrue, etc), checks to see if multiple PEs are embedded within the binary. Has switches `-Export` to export embedded PEs, `GetVTScore` to get the score of the PE, and `GetTTPs` to run analysis on what behaviors the PE executes.

* `Get-MZHeaders`

Identifies how many PEs are embedded within 1 file. 

* `Get-PESize`

Obtains the size of a PE file. 

* `Export-PE`

Helper function to export PEs. Used within Get-PEInfo. 

* `Get-VTScore`
  
Obtains the positive results of a PE based off a file's hash. Future versions will allow for more dynamic queries. Need to supply VTAPI for query to work. 

* `Get-TTPs`
  
Uses string matching to identify if certain behaviors are being performed within a PE. 


# Acknowledgements
* Matt Graeber - PowerShell Arsenal was a huge inspiration for this module. Also thank you to Matt for reviewing this module and giving suggestions which will be added to future versions. 
* Matt Hand - Talking to me about this module and giving me ideas to implement. 
