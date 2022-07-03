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

Function New-ADGrp {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$BoxToSync,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Create new group"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon plus) -size large -Onclick {
            Show-UDModal -Header { "Create new group" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtGrpCN' -Label 'Enter group name (CN/Name) (Required)' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtGrpDisplayName' -Label 'Enter Display Name for the group' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtGrpsAmAccountName' -Label 'Enter sAmAccountName for the group (Required)' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtGrpDescription' -Label 'Enter description' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtGrpInfo' -Label 'Enter Info' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtGrpOwner' -Label 'Enter manage by (AD-User)' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDHtml -Markup "<br>"
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                        New-UDTypography -Text "Select Group Scope (Required)"
                        New-UDRadioGroup -id "radioScope" -Label "Group Scope" -Content {
                            New-UDRadio -Label "Domain Local" -Value 'DomainLocal'
                            New-UDRadio -Label Global -Value 'Global'
                            New-UDRadio -Label Universal -Value 'Universal'
                        } -value 'Global'
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                        New-UDTypography -Text "Select Group Category (Required)"
                        New-UDRadioGroup -id "radioCategory" -Label "Group Category" -Content {
                            New-UDRadio -Label Security -Value 'Security'
                            New-UDRadio -Label Distribution -Value 'Distribution'
                        } -value 'Security'
                    }
                }
            } -Footer {
                New-UDButton -text 'Create' -Onclick {
                    $GrpCN = (Get-UDElement -Id "txtGrpCN").value
                    $GrpsAmAccountName = (Get-UDElement -Id "txtGrpsAmAccountName").value
                    $GrpDisplayName = (Get-UDElement -Id "txtGrpDisplayName").value
                    $GrpDescription = (Get-UDElement -Id "txtGrpDescription").value
                    $GrpInfo = (Get-UDElement -Id "txtGrpInfo").value
                    $GrpScope = (Get-UDElement -Id "radioScope").value
                    $GrpCategory = (Get-UDElement -Id "radioCategory").value
                    $GrpOwner = (Get-UDElement -Id "txtGrpOwner").value
                    $GrpCN = $GrpCN.trim()
                    $GrpsAmAccountName = $GrpsAmAccountName.trim()

                  
                    if ([string]::IsNullOrEmpty($GrpsAmAccountName) -or [string]::IsNullOrEmpty($GrpCN) -or [string]::IsNullOrEmpty($GrpScope) -or [string]::IsNullOrEmpty($GrpCategory)) {
                        Show-UDToast -Message "You must enter all the required options above!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        if (Get-ADGroup -Filter "samaccountname -eq '$($GrpsAmAccountName)'" -properties SamAccountName) {
                            Show-UDToast -Message "It's already a group with the SamAccountName $($GrpsAmAccountName) in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                        else {
                            if ([string]::IsNullOrEmpty($GrpInfo)) {
                                $GrpInfo = "."
                            }
                            if ([string]::IsNullOrEmpty($GrpDisplayName)) {
                                $GrpDisplayName = $GrpsAmAccountName
                            }
                            if ([string]::IsNullOrEmpty($GrpOwner)) {
                                try {
                                    New-ADGroup -Name $GrpCN -SamAccountName $GrpsAmAccountName -GroupCategory $GrpCategory -GroupScope $GrpScope -DisplayName $GrpDisplayName -Path $OUGrpPath -Description $GrpDescription -OtherAttributes @{ 'info' = $GrpInfo }
                                    Show-UDToast -Message "$($GrpCN) has been created!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    if ($ActiveEventLog -eq "True") {
                                        Write-EventLog -LogName $EventLogName -Source "CreatedGroup" -EventID 10 -EntryType Information -Message "$($User) did create the group $($GrpCN)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                    }
                                    Set-UDElement -Id $BoxToSync -Properties @{
                                        Value = $GrpsAmAccountName
                                    }
                                    Sync-UDElement -id $RefreshOnClose
                                    Hide-UDModal
                                }
                                catch {
                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    Break
                                }
                            }
                            elseif (Get-ADUser -Filter "Samaccountname -eq '$($GrpOwner)'") {
                                try {
                                    New-ADGroup -Name $GrpCN -SamAccountName $GrpsAmAccountName -GroupCategory $GrpCategory -GroupScope $GrpScope -DisplayName $GrpDisplayName -Path $OUGrpPath -Description $GrpDescription -ManagedBy $GrpOwner -OtherAttributes @{ 'info' = $GrpInfo }
                                    Show-UDToast -Message "$($GrpCN) has been created!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    if ($ActiveEventLog -eq "True") {
                                        Write-EventLog -LogName $EventLogName -Source "CreatedGroup" -EventID 10 -EntryType Information -Message "$($User) did create the group $($GrpCN)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                    }
                                    Set-UDElement -Id $BoxToSync -Properties @{
                                        Value = $GrpsAmAccountName
                                    }
                                    Sync-UDElement -id $RefreshOnClose
                                    Hide-UDModal
                                }
                                catch {
                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    Break
                                }
                            }
                            else {
                                Show-UDToast -Message "$($GrpOwner) don't exist in the AD, please enter a new manager for the group" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                Break
                            }
                        }
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Add-MultiGroupBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ObjToAdd,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose

    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Add $($ObjToAdd) to multiple groups at the same time"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon users) -size large -Onclick {
            Show-UDModal -Header { "Add $($ObjToAdd) to multiple groups at the same time" } -Content {
                New-UDDynamic -Id 'MoreComputerSearchGroupList' -content {
                    $MoreADGroupData = Get-ADGroup -Filter * -Properties Info, samAccountName, Description | Select-Object @("samAccountName", "info", "Description")
                    $MoreADGroupColumns = @(
                        New-UDTableColumn -Property samAccountName -Title "Group name" -IncludeInSearch -DefaultSortColumn
                        New-UDTableColumn -Property Description -Title "Description" -IncludeInSearch
                        New-UDTableColumn -Property Info -Title "Info" -IncludeInSearch
                    )
                    New-UDTable -Id 'MoreADTable' -Data $MoreADGroupData -Columns $MoreADGroupColumns -Title "Select group" -DefaultSortDirection “Ascending” -ShowSearch -ShowPagination -Dense -Sort -PageSize 10 -PageSizeOptions @(10, 20) -DisablePageSizeAll -ShowSelection
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Add selected" -OnClick {
                    $MoreADTable = Get-UDElement -Id "MoreADTable"
                    $MoreADLog = @($MoreADTable.selectedRows.samAccountName)
                    if ($null -ne $MoreADTable.selectedRows.samAccountName) {
                        try {
                            @($MoreADTable.selectedRows.samAccountName.ForEach( { 
                                        Add-ADGroupMember -Identity $_ -Members $ObjToAdd  -Confirm:$False
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($_) to $($ObjToAdd)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                    } ) )
                            Show-UDToast -Message "$($ObjToAdd) are now member in $($MoreADLog -join ",")!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Sync-UDElement -Id $RefreshOnClose
                            Hide-UDModal
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    else {
                        Show-UDToast -Message "You must select a group!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -Persistent
        }
    }
}

function Edit-GroupInfoBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change info for $($GroupName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change info for $($GroupName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTextbox -Id "txtChangeinfo" -Label "Enter Info" -Value $CurrentValue -FullWidth
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewInfo = (Get-UDElement -Id "txtChangeinfo").value

                    try {
                        Set-ADGroup -Identity $GroupName  -Replace @{info = "$($NewInfo)" }
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "EditGroupInfo" -EventID 10 -EntryType Information -Message "$($User) did edit info on $($GroupName) to $($NewInfo)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Info for $($GroupName) has now been changed!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Clear" -OnClick {
                    try {
                        Set-ADGroup -Identity $GroupName  -Replace @{info = "$($null)" }
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ClearGroupInfo" -EventID 10 -EntryType Information -Message "$($User) did clear info on $($GroupName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Info for $($GroupName) has now been cleared!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'sm' -Persistent
        }
    }
}

function Set-GroupScopeBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory = $false)][string]$CurrentGroupScope,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change group scope for $($GroupName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change group scope for $($GroupName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDRadioGroup -id "radioScope" -Label "Group Scope" -Content {
                            New-UDRadio -Label Global -Value 'Global'
                            New-UDRadio -Label Universal -Value 'Universal'
                        }
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewScope = (Get-UDElement -Id "radioScope").value
                    try {
                        Set-ADGroup -Identity $GroupName  -GroupScope $NewScope
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ChangeGroupScope" -EventID 10 -EntryType Information -Message "$($User) did change group scope for $($GroupName) from $($CurrentGroupScope) to $($NewScope)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Group Scope for $($GroupName) are now set to $($NewScope)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

function Set-GroupCategoryBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory = $false)][string]$CurrentGroupCategory,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change group category for $($GroupName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change group category for $($GroupName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDRadioGroup -id "radioCategory" -Label "Group Category" -Content {
                            New-UDRadio -Label Security -Value 'Security'
                            New-UDRadio -Label Distribution -Value 'Distribution'
                        }
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewCategory = (Get-UDElement -Id "radioCategory").value
                    try {
                        Set-ADGroup -Identity $GroupName -GroupCategory $NewCategory
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ChangeGroupCategory" -EventID 10 -EntryType Information -Message "$($User) did change group category for $($GroupName) from $($CurrentGroupCategory) to $($NewCategory)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Group Category for $($GroupName) are now set to $($NewCategory)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

Function Show-ADGroupMemberOf {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "See what groups $($ObjectName) are member of"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon users) -size medium -Onclick { 
            Show-UDModal -Header { "$($ObjectName) are member of" } -Content {
                if ($ActiveEventLog -eq "True") {
                    Write-EventLog -LogName $EventLogName -Source "ShowMemberOf" -EventID 10 -EntryType Information -Message "$($User) did look at memberof for $($ObjectName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                }
                New-UDDynamic -Id 'MemberOf' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        $Columns = @(
                            New-UDTableColumn -Title 'Name' -Property 'Name' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'SamAccountName' -Property 'SamAccountName' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Description' -Property 'Description' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Info' -Property 'Info' -IncludeInExport -IncludeInSearch
                        )

                        $DisplayData = Get-ADPrincipalGroupMembership -Identity $ObjectName | Get-ADGroup -properties info, name, SamAccountName, Description  | Select-Object @("Name", "Samaccountname", "Description", "info")

                        if ([string]::IsNullOrEmpty($DisplayData)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'info' -Text "$($ObjectName) are not member of any group!"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -id 'MemberOfTable' -Columns $Columns -Data $DisplayData -DefaultSortDirection "Ascending" -Sort -ShowSelection -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 50
                            }
                        }
                        if ($null -ne $DisplayData) {
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Delete from selected groups"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon trash_alt) -Size large -OnClick {
                                        $MemberOfTable = Get-UDElement -Id "MemberOfTable"
                                        if ($Null -ne $MemberOfTable.selectedRows.SamAccountName) {
                                            try {
                                                $MemberOfTableSelect = @($MemberOfTable.selectedRows.SamAccountName.ForEach( { 
                                                            Remove-ADGroupMember -Identity $_ -Members $ObjectName  -Confirm:$False
                                                            if ($ActiveEventLog -eq "True") {
                                                                Write-EventLog -LogName $EventLogName -Source "RemoveFromGroup" -EventID 10 -EntryType Information -Message "$($User) did remove $($ObjectName) from $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                            }
                                                        } ) )
                                                Show-UDToast -Message "$($ObjectName) has been removed from $($MemberOfTable.selectedRows.SamAccountName -join ",")" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'MemberOf'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                        else {
                                            Show-UDToast -Message "You have not selected anything, you need to do that to delete a member!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children { }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children { }
                        }
                        New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                            New-UDTextbox -Id "txtAddTo" -Label "Enter the group you want to join" -FullWidth
                        }
                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { 
                            New-UDTooltip -TooltipContent {
                                New-UDTypography -Text "Join group"
                            } -content { 
                                New-UDButton -Icon (New-UDIcon -Icon user_plus) -size large -Onclick { 
                                    $AddToGroup = (Get-UDElement -Id "txtAddTo").value
                                    $AddToGroup = $AddToGroup.trim()
                                    
                                    if (Get-ADGroup -Filter "Samaccountname -eq '$($AddToGroup)'") { 
                                        if ($Null -ne $AddToGroup) {
                                            try {
                                                Add-ADGroupMember -Identity $AddToGroup -Members $ObjectName 
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($ObjectName) to $($AddToGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($AddToGroup) are now member of $($AddToGroup)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'MemberOf'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                        else {
                                            Show-UDToast -Message "You must enter a group name!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                    else {
                                        Show-UDToast -Message "$($AddToGroup) did not exist in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                            }
                        }
                        
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick {
                    Sync-UDElement -id 'MemberOf'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Show-WhosMemberInGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$LocalIpAddress,
        [Parameter(Mandatory)][string]$RemoteIpAddress
    )

    Show-UDModal -Header { "Show members in $($GroupName)" } -Content {
        if ($ActiveEventLog -eq "True") {
            Write-EventLog -LogName $EventLogName -Source "GroupSearch" -EventID 10 -EntryType Information -Message "$($User) did search for group $($GroupName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
        }
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDDynamic -Id 'CheckGroup' -content {
                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                    $SearchGroupUser = Get-ADGroupMember -Identity $GroupName 
                    $SearchGroupUserData = $SearchGroupUser | Foreach-Object {
                        if ($_.objectClass -eq 'user') {
                            $grpuser = Get-ADUser -Filter "samaccountname -eq '$($_.SamAccountName)'" -Properties GivenName, Surname, EmailAddress, Description
                            if ($null -ne $grpuser) {
                                [PSCustomObject]@{
                                    ObjectType     = "User"
                                    SamAccountName = $grpuser.samAccountName
                                    Name           = $grpuser.GivenName + " " + $grpuser.Surname
                                    EmailAddress   = $grpuser.EmailAddress
                                    Description    = $grpuser.Description
                                }
                            }
                        }
                        elseif ($_.objectClass -eq 'group') {
                            $grp = Get-ADGroup -Filter "samaccountname -eq '$($_.SamAccountName)'" -Properties samAccountName, Description, mail, info
                            if ($null -ne $grp) {
                                [PSCustomObject]@{
                                    ObjectType     = "Group"
                                    SamAccountName = $grp.samAccountName
                                    EmailAddress   = $grp.mail
                                    Description    = $grp.Description
                                    Info           = $grp.Info
                                }
                            }
                        }
                        elseif ($_.objectClass -eq 'computer') {
                            $grpcomp = Get-ADComputer -Filter "samaccountname -eq '$($_.SamAccountName)'"  -Properties SamAccountName, Name, Description
                            if ($null -ne $grpcomp) {
                                [PSCustomObject]@{
                                    ObjectType     = "Computer"
                                    SamAccountName = $grpcomp.SamAccountName
                                    Name           = $grpcomp.name
                                    Description    = $grpcomp.Description
                                }
                            }
                        }
                        else {
                            Write-Warning "Unknown objectClass encountered"
                        }
                    }
                    $SearchGroupUserColumns = @(
                        New-UDTableColumn -Property ObjectType -Title "Type" -IncludeInExport -IncludeInSearch
                        New-UDTableColumn -Property SamAccountName -Title "Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                        New-UDTableColumn -Property Name -Title "Name" -IncludeInExport -IncludeInSearch
                        New-UDTableColumn -Property EmailAddress -Title "Mail" -IncludeInExport -IncludeInSearch
                        New-UDTableColumn -Property Description -Title "Description" -IncludeInExport -IncludeInSearch
                        New-UDTableColumn -Property Info -Title "Info" -IncludeInExport -IncludeInSearch
                    )
                    if ([string]::IsNullOrEmpty($SearchGroupUserData)) {
                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                            New-UDAlert -Severity 'info' -Text "$($GroupName) don't have any members!"
                        }
                    }
                    else {
                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                            $SearchMemberOption = New-UDTableTextOption -Search "Search after member"
                            New-UDTable -Id 'GroupSearchTable' -Data $SearchGroupUserData -Columns $SearchGroupUserColumns -DefaultSortDirection "Ascending" -TextOption $SearchMemberOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -Sort -PageSize 10 -PageSizeOptions @(10, 20, 30, 40, 50)
                        }
                    }
                }
            } -LoadingComponent {
                New-UDProgress -Circular
            }
        }
    } -Footer {
        New-UDButton -Text "Refresh" -Size medium -OnClick {
            Sync-UDElement -Id "CheckGroup"
        }
        New-UDButton -Text "Close" -Size medium -OnClick {
            Hide-UDModal
        }
    } -FullWidth -MaxWidth 'md' -Persistent
}

Function Add-ToGroupExcel {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    Show-UDModal -Header { "Add to group from excel file" } -Content {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDDynamic -Id 'FileImport' -content {
                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children { }
                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                    New-UDUpload -Id "UploadBtn" -Text 'Select file to run' -OnUpload {
                        $Data = $Body | ConvertFrom-Json
                        $bytes = [System.Convert]::FromBase64String($Data.Data)
                        [System.IO.File]::WriteAllBytes("$($UploadTemp)$($Data.Name)", $bytes)
                        $Session:FileName = $Data.Name
                        Sync-UDElement -Id "FileImport"
                    }
                    New-UDHtml -Markup "<b>Uploaded file:</b> $($Session:FileName)"
                }
                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
            }
            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                New-UDHTML -Markup "<b>Error report</b>"
                New-UDTypography -Text "If you click in the editor and then press ctrl+f you can search, to download the report click on the Download log button."
            }
            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                New-UDCodeEditor -Id 'Report' -ReadOnly -Height 450
            }
        }
    } -Footer {
        New-UDButton -Text "Execute" -OnClick { 
            if ($Session:FileName -notlike "*.xlsx") {
                Show-UDToast -Message "You can only upload Excel files *.xlsx" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                Break
            }
            else {
                try {
                    $ExcelFile = Import-Excel -Path "$($UploadTemp)$($Session:FileName)"
                }
                catch {
                    Show-UDToast -Message "Could not import the excel file!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    Break
                }
                $Btns = @("ExecuteBtn", "CloseBtn", "LogBtn", "UploadBtn", "templatebtn")

                foreach ($btn in $Btns) {
                    Set-UDElement -Id "$($btn)" -Properties @{
                        disabled = $true 
                    }
                }
                $ErrorReport = New-Object System.Collections.Generic.List[System.Object]
                $ErrorReport.Add("Please wait, this can take a while!")
                foreach ($getinfo in $ExcelFile) {
                    if ($Null -ne $getinfo.group) {
                        if ($Null -ne $getinfo.objectname) {
                            try {
                                if ((Get-ADObject -filter "samaccountname -like '$($getinfo.objectname)'" -Properties memberof).memberof -match "CN=$($getinfo.group),*") {
                                    $ErrorReport.Add("$($getinfo.objectname) is already a member of $($getinfo.group)! Skipping!")
                                }
                                else {
                                    Add-ADGroupMember -Identity $getinfo.group.trim() -members $getinfo.objectname.trim()
                                    if ($ActiveEventLog -eq "True") {
                                        Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($getinfo.objectname) to $($getinfo.group)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                    }
                                }
                            }
                            catch {
                                $ErrorReport.Add("Could not add $($getinfo.objectname) to $($getinfo.group)")
                            }
                        }
                        else {
                            $ErrorReport.Add("Could not add a object to $($getinfo.group) as the object was missing in the file!")
                        }
                    }
                    else {
                        $ErrorReport.Add("Skipped object $($getinfo.objectname) as group was missing in the file!")
                    }
                    $JobOutput = $ErrorReport -join ([Environment]::NewLine)
                    Set-UDElement -Id 'Report' -Properties @{
                        code = $JobOutput
                    }
                }
                Remove-Item -Path "$($UploadTemp)$($Session:FileName)" -Force
                $Session:FileName = ""
                Sync-UDElement -id "FileImport"
                Show-UDToast -Message "Everything is done!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                
                foreach ($btn in $Btns) {
                    Set-UDElement -Id "$($btn)" -Properties @{
                        disabled = $false 
                    }
                }
            }
        } -Id "ExecuteBtn"
        New-UDTooltip -TooltipContent {
            New-UDTypography -Text "Download excel template"
        } -content { 
            New-UDButton -Icon (New-UDIcon -Icon FileDownload) -OnClick {
                Invoke-UDRedirect "https://$($TargetDomain)/templates/group_template.xlsx"
            } -Id "templatebtn"
        }
        New-UDTooltip -TooltipContent {
            New-UDTypography -Text "Download log file"
        } -content { 
            New-UDButton -Icon (New-UDIcon -Icon download) -OnClick {
                $code = (Get-UDElement -Id 'Report').code
                Start-UDDownload -StringData $code -FileName "Report_BulkAddUsrToGroup_$(Get-Date).log"
            } -id 'LogBtn'
        }
        New-UDButton -Icon (New-UDIcon -Icon WindowClose) -OnClick {
            Hide-UDModal
        } -id "CloseBtn"
    } -FullWidth -MaxWidth 'md' -Persistent
}

Export-ModuleMember -Function "Add-ToGroupExcel", "Show-WhosMemberInGroup", "New-ADGrp", "Add-MultiGroupBtn", "Edit-GroupInfoBtn", "Set-GroupScopeBtn", "Set-GroupCategoryBtn", "Show-ADGroupMemberOf"