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

# In $Searcher.Filter you need to write the hole path to the OU like; CN=PSU.Execute,OU=Groups,DC=Franky,DC=com
# Enter your Domain LDAP adress here like LDAP://DC=Franky,DC=COM
$RoleDomain = "LDAP://DC=PSU,DC=KeepCodeOpen,DC=com"

New-PSURole -Name "Reader" -Description "Readers have read-only access to UA. They cannot make changes to any entity within the system." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        

    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=CN=Franky.Reader,OU=Groups,DC=psu,DC=keepcodeopen,DC=com))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "Execute" -Description "Execute scripts within Universal Automation." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=CN=Franky.Execute,OU=Groups,DC=psu,DC=keepcodeopen,DC=com))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "Administrator" -Description "Administrators can manage settings of UA, create and edit any entity within UA and view all the entities within UA." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=CN=Franky.Administrator,OU=Groups,DC=psu,DC=keepcodeopen,DC=com))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "Operator" -Description "Operators have access to manage and execute scripts, create other entities within UA but cannot manage UA itself." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=CN=Franky.Operator,OU=Groups,DC=psu,DC=keepcodeopen,DC=com))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "PowerUser" -Description "User with rights to all sites and functions" -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=CN=Franky.PowerUser,OU=Groups,DC=psu,DC=keepcodeopen,DC=com))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 

New-PSURole -Name "Franky" -Description "Gives change access to Franky Dashboard" -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=CN=Franky,OU=Groups,DC=psu,DC=keepcodeopen,DC=com))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
}