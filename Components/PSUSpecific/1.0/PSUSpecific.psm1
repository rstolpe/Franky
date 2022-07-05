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

function New-RefreshUDElementBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$RefreshUDElement
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Reload the page"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon sync_alt) -size medium -Onclick {
            try {
                Sync-UDElement -Id $RefreshUDElement
            }
            catch {
                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                Break
            }
        }
    }
}

function New-MultiSearch {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][String]$txtBoxMultiSearch,
        [Parameter(Mandatory)][String]$MultiSearchObj,
        [Parameter(Mandatory)][String]$ElementSync,
        [Parameter(Mandatory)][String]$SearchFor
    )

    switch ($MultiSearchObj) {
        Computer {
            $ToolTip = "Extended computer search"
            $SearchText = "Search after computer"
        }
        User {
            $ToolTip = "Extended user search"
            $SearchText = "Search after user"
            if ($SearchFor -like "*@*") {
                $UsrTypSearch = "EmailAddress"
            }
            else {
                $UsrTypSearch = "samaccountname"
            }
        }
        Group {
            $ToolTip = "Extended group search"
            $SearchText = "Search after group"
        }
    }
    Show-UDModal -Header { $ToolTip } -Content {
        New-UDDynamic -Id 'MultiSearchList' -content {
            New-UDGrid -Spacing '1' -Container -Children {
                if ($MultiSearchObj -eq "User") {
                    $MoreData = Get-ADUser -Filter "$($UsrTypSearch) -like '$($SearchFor)*'"  -Properties samAccountName, Surname, Givenname, EmailAddress, Description | Foreach-Object { 
                        if ($null -ne ($moreuser = $_)) {
                            [PSCustomObject]@{
                                Name         = $moreuser.samAccountName
                                FullName     = $moreuser.Givenname + " " + $moreuser.Surname
                                EmailAddress = $moreuser.EmailAddress
                                Description  = $moreuser.Description
                            }
                        }
                    }
                    $MoreColumns = @(
                        New-UDTableColumn -Property Name -Title "Username" -IncludeInSearch -DefaultSortColumn
                        New-UDTableColumn -Property FullName -Title "Full Name" -IncludeInSearch
                        New-UDTableColumn -Property EmailAddress -Title "Mail" -IncludeInSearch
                        New-UDTableColumn -Property Description -Title "Description" -IncludeInSearch
                        New-UDTableColumn -Property Info -Title "." -Render {
                            New-UDTooltip -TooltipContent {
                                New-UDTypography -Text "Search for this user"
                            } -content { 
                                New-UDButton -Icon (New-UDIcon -Icon search_plus) -size small -Onclick {
                                    try {
                                        Set-UDElement -Id $txtBoxMultiSearch -Properties @{
                                            Value = $EventData.Name
                                        }
                                        Sync-UDElement -Id $ElementSync
                                        Hide-UDModal
                                    }
                                    catch {
                                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                            }
                        }
                    )
                }
                elseif ($MultiSearchObj -eq "Computer") {
                    $MoreData = Get-ADComputer -Filter "samaccountname -like '$($SearchFor)*'"  -Properties name, description | Select-Object @("Name", "Description")
                    $MoreColumns = @(
                        New-UDTableColumn -Property Name -Title "Name" -IncludeInSearch -DefaultSortColumn
                        New-UDTableColumn -Property Description -Title "Description" -IncludeInSearch
                        New-UDTableColumn -Property Info -Title "." -Render {
                            New-UDTooltip -TooltipContent {
                                New-UDTypography -Text "Search for this computer"
                            } -content { 
                                New-UDButton -Icon (New-UDIcon -Icon search_plus) -size small -Onclick {
                                    try {
                                        Set-UDElement -Id $txtBoxMultiSearch -Properties @{
                                            Value = $EventData.Name
                                        }
                                        Sync-UDElement -Id $ElementSync
                                        Hide-UDModal
                                    }
                                    catch {
                                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                            }
                        }
                    )
                }
                elseif ($MultiSearchObj -eq "Group") {
                    $MoreData = Get-ADGroup -Filter "samAccountName -like '$($SearchFor)*'"  -Properties samAccountName, Description | Select-Object @("samAccountName", "Description")
                    $MoreColumns = @(
                        New-UDTableColumn -Property samAccountName -Title "Name" -IncludeInSearch -DefaultSortColumn
                        New-UDTableColumn -Property Description -Title "Description" -IncludeInSearch
                        New-UDTableColumn -Property Info -Title "." -Render {
                            New-UDTooltip -TooltipContent {
                                New-UDTypography -Text "Search for this group"
                            } -content { 
                                New-UDButton -Icon (New-UDIcon -Icon search_plus) -size small -Onclick {
                                    try {
                                        Set-UDElement -Id $txtBoxMultiSearch -Properties @{
                                            Value = $EventData.samAccountName
                                        }
                                        Sync-UDElement -Id $ElementSync
                                        Hide-UDModal
                                    }
                                    catch {
                                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                            }
                        }
                    )
                }
                $SearchOption = New-UDTableTextOption -Search $SearchText
                if ([string]::IsNullOrEmpty($MoreData)) {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDAlert -Severity 'error' -Text "The search did end up with no results"
                    }
                }
                else {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTable -Id 'MoreADTable' -Data $MoreData -Columns $MoreColumns -TextOption $SearchOption -DefaultSortDirection "Ascending" -ShowSearch -ShowPagination -Dense -Sort -PageSize 200
                    }
                }
            }
        } -LoadingComponent {
            New-UDProgress -Circular
        }
    } -Footer {
        New-UDButton -Text "Close" -OnClick { Hide-UDModal }
                                        
    } -FullWidth -MaxWidth 'lg' -Persistent
}

Export-ModuleMember -Function "New-RefreshUDElementBtn", "New-MultiSearch"