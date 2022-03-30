<#
    Copyright (C) 2022  KeepCodeOpen - The ultimate IT-Support dashboard
    <https://keepcodeopen.com>

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

<# OPTIONAL SETTINGS
Here you have two options, either activate Load Balancing or if you only have one PowerShell Universal server you should just
leave it at the default $false. If you don't activate Load Balancing or fill out an AppToken for singel PSU server some functions
will not work.
If you activate Load Balancing remember to fill out the hostname the AppTokens for each host in the LoadBalancing component.
#>
[bool]$ActivateLoadBalancing = $false

if ($ActivateLoadBalancing -eq $true) {
    $GetAppToken = Get-AppToken
    $AppToken = $GetAppToken.CurrentAppToken
}
else {
    $AppToken = ""
}

#Check what host then give the right hostname depending on what host it is
$CheckHost = [System.Net.Dns]::GetHostName()
$CurrentHost = $CheckHost + "." + $YourFullDomain + ":" + $AccessPort

# Make sure that your connecting to the current host
$TargetDomain = $CheckHost + "." + $YourFullDomain

$Navigation = @(
    New-UDListItem -Label 'Users' -Icon (New-UDIcon -Icon user -Size lg) -OnClick { Invoke-UDRedirect '/ADUsers' }
    New-UDListItem -Label 'Computers' -Icon (New-UDIcon -Icon desktop -Size lg) -OnClick { Invoke-UDRedirect '/ADComputers' }
    New-UDListItem -Label 'Groups' -Icon (New-UDIcon -Icon users -Size lg) -OnClick { Invoke-UDRedirect '/ADGroups' }
    New-UDListItem -Label 'Bulk changes' -Icon (New-UDIcon -Icon list_ul -Size lg) -Children {
        New-UDListItem -Label 'Add to group' -OnClick { 
            Add-ToGroupExcel -ActiveEventLog $ActiveEventLog -EventLogName $EventLogName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
        }
    }
    New-UDListItem -Label 'Generate reports' -Icon (New-UDIcon -Icon list_ul -Size lg) -Children {
        New-UDListItem -Label 'User reports' -OnClick { 
            Get-UserReports -ActiveEventLog $ActiveEventLog -EventLogName $EventLogName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
        }
        New-UDListItem -Label 'Computer reports' -OnClick { 
            Get-ComputerReport -ActiveEventLog $ActiveEventLog -EventLogName $EventLogName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
        }
        New-UDListItem -Label 'Group reports' -OnClick { 
            Get-ReportGroups -ActiveEventLog $ActiveEventLog -EventLogName $EventLogName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
        }
    }
)

$Pages = @()

$Pages += New-UDPage -Name 'Active Directory - Users' -Url 'ADUsers' -Logo $NavBarLogo -DefaultHomePage -Content {

    . "$UDScriptRoot\Pages\ADUserPage.ps1"  

} -Navigation $Navigation

$Pages += New-UDPage -Name 'Active Directory - Computers' -Url 'ADComputers' -Logo $NavBarLogo -Content {

    . "$UDScriptRoot\Pages\ADComputerPage.ps1"  

} -Navigation $Navigation

$Pages += New-UDPage -Name 'Active Directory - Groups' -Url 'ADGroups' -Logo $NavBarLogo -Content {

    . "$UDScriptRoot\Pages\ADGroupPage.ps1"  

} -Navigation $Navigation

$Theme = @{
    palette = @{
        primary = @{
            main = 'rgba(0, 151, 207, 0.6)'
        }
        grey    = @{
            '300' = 'rgba(0, 151, 207, 0.6)'
        }
        action  = @{
            hover = 'rgba(0, 151, 207, 0.6)'
        }
    }
}

New-UDDashboard -DisableThemeToggle -Title 'Pages' -Theme $Theme -Pages $Pages