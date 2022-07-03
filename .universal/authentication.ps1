<#
    Copyright (C) 2022  KeepCodeOpen - The ultimate IT-Support dashboard
    <https://stolpe.io>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

Set-PSUAuthenticationMethod -ScriptBlock {
    param(
        [PSCredential]$Credential
    )

    $Result = [Security.AuthenticationResult]::new()

    # Write your domain here for example; "LDAP://DC=Franky,DC=com"
    $AuthDomain = ""

    # Write the SID of the Franky.Access group in the variable below.
    $FrankyAccessSID = ""
    
    $domain = New-Object System.DirectoryServices.DirectoryEntry($AuthDomain, ($Credential.UserName), $Credential.GetNetworkCredential().password)
    
    if ($domain.name -eq $null) {
        write-host "Authentication failed - please verify your username and password."
        $Result.UserName = ($Credential.UserName)
        $Result.Success = $false 
    }
    else {
        write-host "Successfully authenticated with domain $($domain.name)"
        $Result.UserName = ($Credential.UserName)
        $winident = [System.Security.Principal.WindowsIdentity]::new($domain.UserName)
        #Replace xxx below with the ID for your group that can access PSU
        if ($winident.HasClaim("http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", 'xxx')) {
            $Result.Success = $true
                
        }
        else {
            $Result.Success = $false
        }

    }
    
    $Result
}