<#
    Copyright (C) 2022  Stolpe.io - The ultimate IT-Support dashboard
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

<# OPTIONAL SETTINGS
Here you have two options, either activate Load Balancing or if you only have one PowerShell Universal server you should just
leave it at the default $false. If you don't activate Load Balancing or fill out an AppToken for singel PSU server some functions
will not work.
If you activate Load Balancing remember to fill out the hostname the AppTokens for each host in the LoadBalancing component.
#>

# SO let's see if this sync now!
#Testing again


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


$Theme = @{
    palette   = @{
        primary = @{
            main = 'rgba(0, 151, 207, 0.6)'
        }
        grey    = @{
            '300' = 'rgba(0, 151, 207, 0.6)'
        }
        action  = @{
            hover = 'rgba(80, 184, 72, 0.3)'
        }
    }
    overrides = @{
        MuiSwitch     = @{
            switchBase = @{
                '&.Mui-checked + .MuiSwitch-track' = @{
                    opacity            = '1'
                    'background-color' = 'rgba(80, 184, 72, 0.6)'
                }
            }
            track      = @{
                opacity            = '1'
                'background-color' = 'rgba(0, 151, 207, 0.6)'
            }
        }
        MuiButton     = @{
            contained = @{
                'background-color' = 'rgba(0, 151, 207, 0.6)'
                color              = '#FFFFFF'
                '&:hover'          = @{
                    color              = 'rgba(0, 151, 207, 0.6)'
                    'background-color' = 'rgba(80, 184, 72, 0.3)'
                }
            }
        }
        MuiIconButton = @{
            root = @{
                '&:hover' = @{
                    'background-color' = 'rgba(80, 184, 72, 0.3)'
                }
            }
        }
    }
}

New-UDDashboard -DisableThemeToggle -Title 'Pages' -Theme $Theme -Pages @(
    New-UDPage -Name 'Active Directory - Users' -Url 'ADUsers' -Logo $NavBarLogo -DefaultHomePage -Content {
        . "$UDScriptRoot\Franky\Pages\ADUserPage.ps1"  
    }
    New-UDPage -Name 'Active Directory - Computers' -Url 'ADComputers' -Logo $NavBarLogo -Content {
        . "$UDScriptRoot\Franky\\Pages\ADComputerPage.ps1"  
    }
    New-UDPage -Name 'Active Directory - Groups' -Url 'ADGroups' -Logo $NavBarLogo -Content {
        . "$UDScriptRoot\Franky\\Pages\ADGroupPage.ps1"  
    }
) -LoadNavigation {
    New-UDListItem -Label 'Users' -Icon (New-UDIcon -Icon user -Size lg) -OnClick { Invoke-UDRedirect '/ADUsers' }
    New-UDListItem -Label 'Computers' -Icon (New-UDIcon -Icon desktop -Size lg) -OnClick { Invoke-UDRedirect '/ADComputers' }
    New-UDListItem -Label 'Groups' -Icon (New-UDIcon -Icon users -Size lg) -OnClick { Invoke-UDRedirect '/ADGroups' }
    New-UDListItem -Label 'Bulk changes' -Icon (New-UDIcon -Icon list_ul -Size lg) -Children {
        New-UDListItem -Label 'Add to group' -OnClick { 
            Add-ToGroupExcel
        }
    }
    New-UDListItem -Label 'Generate reports' -Icon (New-UDIcon -Icon list_ul -Size lg) -Children {
        New-UDListItem -Label 'User reports' -OnClick { 
            Get-UserReports
        }
        New-UDListItem -Label 'Computer reports' -OnClick { 
            Get-ComputerReport
        }
        New-UDListItem -Label 'Group reports' -OnClick { 
            Get-ReportGroups
        }
    }
}