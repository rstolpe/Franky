<#
    Copyright (C) 2022  Stolpe.io - The ultimate IT-Support dashboard
    <https://stolpe.io>
#
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

New-UDGrid -Spacing '1' -Container -Children {
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
    New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 12 -SmallSize 12 -Children {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 5 -MediumSize 5 -SmallSize 7 -Children {
                New-UDAutocomplete -id "txtGroupNameStart" -Icon (New-UDIcon -Icon 'users') -Label "Enter Group name" -OnLoadOptions {
                    If ($Body.length -ge 3) {
                        $Session:SelectedUser = Get-ADObject -LDAPFilter "(&(objectCategory=group)(anr=$Body))" -SearchBase $OUGrpPath -Properties name
                        $Session:SelectedUser | Select-Object -ExpandProperty name | ConvertTo-Json
                    }
                } -OnChange {
                    $Session:SelectedUser = $Body
                }
            }
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 4 -Children { 
                New-UDButton -Icon (New-UDIcon -Icon 'search') -Size large -OnClick {
                    $GroupName = (Get-UDElement -Id "txtGroupNameStart").value

                    if ([string]::IsNullOrEmpty($GroupName)) {
                        Sync-UDElement -Id 'GroupSearchStart'
                    }
                    elseif ($GroupName.EndsWith('*')) {
                        New-MultiSearch  -SearchFor $GroupName -txtBoxMultiSearch "txtGroupNameStart" -MultiSearchObj "Group" -ElementSync 'GroupSearchStart'
                    }
                    else {
                        Sync-UDElement -Id 'GroupSearchStart'
                    }
                }
                New-ADGrp -RefreshOnClose "GroupSearchStart" -BoxToSync "txtGroupNameStart"
            }
        }
        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 1 -Children { }
    }
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
}

New-UDGrid -Spacing '1' -Container -Children {
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
    New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 12 -SmallSize 12 -Children {
        New-UDCard -Content {
            New-UDDynamic -Id 'GroupSearchStart' -content {
                $GroupName = (Get-UDElement -Id "txtGroupNameStart").value

                if (-Not([string]::IsNullOrEmpty($GroupName))) {
                    $GroupName = $GroupName.Replace("CN=", "").Split(",") | Select-Object -First 1
                    $GroupName = $GroupName.trim()
                }

                if ([string]::IsNullOrEmpty($GroupName)) {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDAlert -Severity 'error' -Text "Either are the group missing or you have not written any group name!"
                    }
                }
                else {
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "GroupSearch" -EventID 10 -EntryType Information -Message "$($User) did search for $($GroupName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    New-UDGrid -Spacing '1' -Container -Children {
                        New-UDDynamic -Id 'GroupSearch' -content {
                            $SearchADGroup = Get-ADGroup -Filter "samaccountname -eq '$($GroupName)'"  -Properties Description, info, mail, ManagedBy, DistinguishedName, GroupCategory, GroupScope, whenChanged, Created, SamAccountName, SID, Name, CN, DisplayName

                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                Show-ADGroupMemberOf  -RefreshOnClose "GroupSearch"  -ObjectName $GroupName
                                Remove-ADObjectBtn  -ObjectType "Group" -ObjectName $GroupName -RefreshOnClose "GroupSearchStart"
                                New-RefreshUDElementBtn -RefreshUDElement 'GroupSearchStart'
                            }
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHTML -Markup "<br>"
                            }
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHtml -Markup "<b>Information about $($GroupName)</b>"
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Display name"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.DisplayName)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Rename-ADObjectBtn -BoxToSync "txtGroupNameStart"  -WhatToChange "DisplayName"  -RefreshOnClose "GroupSearchStart" -CurrentValue $SearchADGroup.DisplayName -ObjectToRename 'Group' -ObjectName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "CN Name"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.CN)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Rename-ADObjectBtn -BoxToSync "txtGroupNameStart"  -WhatToChange "CN"  -RefreshOnClose "GroupSearchStart" -CurrentValue $SearchADGroup.CN -ObjectToRename 'Group' -ObjectName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "SamAccountName"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.SamAccountName)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Rename-ADObjectBtn -BoxToSync "txtGroupNameStart"  -WhatToChange "SamAccountName"  -RefreshOnClose "GroupSearchStart" -CurrentValue $SearchADGroup.SamAccountName -ObjectToRename 'Group' -ObjectName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "SID"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.SID)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Description"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.Description)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Edit-DescriptionBtn  -RefreshOnClose "GroupSearch" -CurrentValue $SearchADGroup.Description -ChangeDescriptionObject 'Group' -ChangeObjectName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Info"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.info)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Edit-GroupInfoBtn  -CurrentValue $SearchADGroup.info -GroupName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "OU Placement"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.DistinguishedName)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Move-ADObjectBtn  -RefreshOnClose "GroupSearch" -CurrentValue $SearchADGroup.DistinguishedName -ObjectToMove 'Group' -GroupName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Category"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.GroupCategory)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Set-GroupCategoryBtn -CurrentGroupCategory $SearchADGroup.GroupCategory -GroupName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Scope"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.GroupScope)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Set-GroupScopeBtn -CurrentGroupScope $SearchADGroup.GroupScope -GroupName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Created"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.Created)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Last changed"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.whenChanged)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Mail"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADGroup.mail)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Edit-MailBtn  -RefreshOnClose "GroupSearch" -CurrentValue $SearchADGroup.mail -ChangeMailObject 'Group' -ChangeObjectName $GroupName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Manage by"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                $GroupManagedBy = $(try { $SearchADGroup.ManagedBy | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                if ($null -ne $GroupManagedBy) {
                                    New-UDTypography -Text "$($GroupManagedBy)"
                                }
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                $GroupManagedBy = $(try { $SearchADGroup.ManagedBy | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                Edit-ManagedByBtn -CurrentValue $GroupManagedBy -ObjectType "Group" -ObjectName $GroupName -RefreshOnClose "GroupSearch"
                            }
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHTML -Markup "<br>"
                            }
                        } -LoadingComponent {
                            New-UDProgress -Circular
                        }
                        New-UDDynamic -Id 'GroupSearchGroupList' -content {
                            $SearchGroupUser = Get-ADGroupMember -Identity $GroupName 
                            $SearchGroupUserData = $SearchGroupUser | Foreach-Object {
                                if ($_.objectClass -eq 'user') {
                                    $grpuser = Get-ADUser -Filter "samaccountname -eq '$($_.SamAccountName)'" -SearchBase $OUUsrPath -Properties GivenName, Surname, EmailAddress, Description
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
                                    $grp = Get-ADGroup -Filter "samaccountname -eq '$($_.SamAccountName)'" -SearchBase $OUGrpPath -Properties samAccountName, Description, mail, info
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
                                    $grpcomp = Get-ADComputer -Filter "samaccountname -eq '$($_.SamAccountName)'" -SearchBase $OUComputerPath  -Properties SamAccountName, Name, Description
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
                                New-UDTableColumn -Property " " -Title "" -render {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Delete $($EventData.Name) from the group $($GroupName)"
                                    } -content { 
                                        New-UDIconButton -Icon (New-UDIcon -Icon trash_alt -Style @{ color = 'rgba(0, 151, 207, 0.6)' }) -Size small -Onclick {
                                            try {
                                                Remove-ADGroupMember -Identity $GroupName -Members "$($EventData.SamAccountName)" -Confirm:$False
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "RemoveFromGroup" -EventID 10 -EntryType Information -Message "$($User) did remove $($SearchUserName) from $($EventData.Name)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($EventData.Name) are not a member of $($GroupName) anymore!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                                Sync-UDElement -Id 'UserSearchGroupList'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                                Break
                                            }
                                        }
                                    }
                                }
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
                                    New-UDTable -Id 'GroupSearchTable' -Data $SearchGroupUserData -Columns $SearchGroupUserColumns -DefaultSortDirection "Ascending" -TextOption $SearchMemberOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -Sort -PageSize 10 -PageSizeOptions @(10, 20, 30, 40, 50) -ShowSelection -PaginationLocation top
                                }
                            }
                            if (-Not([string]::IsNullOrEmpty($SearchGroupUserData))) {
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 4 -MediumSize 4 -SmallSize 2 -Children {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Delete selected from the group"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon trash_alt) -Size large -OnClick {
                                            $GroupSearchTable = Get-UDElement -Id "GroupSearchTable"
                                            if ($Null -ne $GroupSearchTable.selectedRows.SamAccountName) {
                                                try {
                                                    @($GroupSearchTable.selectedRows.SamAccountName.ForEach( { 
                                                                Remove-ADGroupMember -Identity $GroupName -Members $_  -Confirm:$False
                                                                if ($ActiveEventLog -eq "True") {
                                                                    Write-EventLog -LogName $EventLogName -Source "RemoveFromGroup" -EventID 10 -EntryType Information -Message "$($User) did remove $($_) from $($GroupName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                                }
                                                            } ) )
                                                    Show-UDToast -Message "$($GroupSearchTable.selectedRows.SamAccountName -join ",") are not a member of $($GroupName) anymore!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Sync-UDElement -Id 'GroupSearchGroupList'
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
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
                            }
                            else {
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 4 -MediumSize 4 -SmallSize 2 -Children { } 
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children { 
                                New-UDTextbox -Id "txtSearchGroupADD" -Label "Enter Username, Computername or Group name" -FullWidth
                                New-UDTypography -Text "(If your going to add a computer you need to add $ sign at the end of the computer name)" -Style @{ fontSize = 12 }
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 3 -MediumSize 3 -SmallSize 5 -Children {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Add entered Username, Computername or Group name to $($GroupName)"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon user_plus) -size large -Onclick { 
                                        $ObjectToAdd = (Get-UDElement -Id "txtSearchGroupADD").value
                                        if (-Not([string]::IsNullOrEmpty($ObjectToAdd))) {
                                            $ObjectToAdd = $ObjectToAdd.trim()
                                        }
                                                
                                        if ([string]::IsNullOrEmpty($ObjectToAdd)) {
                                            Show-UDToast -Message "You must enter a object that can be added to $($GroupName)!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                        else {
                                            try {
                                                Add-ADGroupMember -Identity $GroupName -Members $ObjectToAdd 
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($ObjectToAdd) to $($GroupName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($ObjectToAdd) are now member of $($GroupName)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'GroupSearchGroupList'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                }
                                Add-MultiUsers  -AddToGroup $GroupName -RefreshOnClose "GroupSearchGroupList"
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Refresh the group member list!"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon sync_alt) -Size large -OnClick {
                                        Sync-UDElement -Id "GroupSearchGroupList"
                                    }
                                }
                            }
                        } -LoadingComponent {
                            New-UDProgress -Circular
                        }
                    }
                }
            } -LoadingComponent {
                New-UDProgress -Circular
            }
        }       
    }
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
}