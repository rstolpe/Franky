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

function Unlock-ADUserAccountBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$AccountStatus,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Unlock $($UserName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon lock_open) -size small -Onclick { 
            Show-UDModal -Header { "Unlock $($UserName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children {}
                        New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 10 -SmallSize 10 -Children {
                            New-UDTypography -Text "Are you sure that you want to unlock $($UserName)?"
                        }
                        New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children {}
                    }
                }
            } -Footer {
                New-UDButton -Text "Unlock" -Size medium -OnClick {
                    if ($AccountStatus -eq $true) {
                        try {
                            Unlock-ADAccount -Identity $UserName 
                            Show-UDToast -Message "$($UserName) are now unlocked!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "UnlockUserAccount" -EventID 10 -EntryType Information -Message "$($User) did unlock $($UserName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            if ($NULL -ne $RefreshOnClose) {
                                Sync-UDElement -Id $RefreshOnClose
                            }
                            Hide-UDModal
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    else {
                        Show-UDToast -Message "$($UserName) are not locked!" -MessageColor 'Red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -Size medium -OnClick {
                    Hide-UDModal
                }
            }
        }
    }
}

function New-PasswordADUserBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change password for $($UserName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon key) -size medium -Onclick {
            Show-UDModal -Header { "Change password for $($UserName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDHTML -Markup "Enter the desired password, the password must be at least 10 characters.<br>"
                        New-UDDynamic -Id 'generatepassword' -content {
                            $RndPwd = New-RndPassword
                            New-UDTypography -Text "$($RndPwd)" -Style @{ 'font-weight' = '700' }
                            New-UDTooltip -TooltipContent {
                                New-UDTypography -Text "Use this password"
                            } -content { 
                                New-UDButton -Icon (New-UDIcon -Icon paste) -Size small -OnClick {
                                    Set-UDElement -Id "txtpw1" -Properties @{
                                        Value = $RndPwd
                                    }
                                    Set-UDElement -Id "txtpw2" -Properties @{
                                        Value = $RndPwd
                                    }
                                }
                            }
                        }
                        New-UDTooltip -TooltipContent {
                            New-UDTypography -Text "Generate a new random password"
                        } -content { 
                            New-UDButton -Icon (New-UDIcon -Icon sync_alt) -Size small -OnClick {
                                Sync-UDElement -Id 'generatepassword'
                            }
                        }
                        New-UDHTML -Markup "<br>"
                    }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -id "txtpw1" -Icon (New-UDIcon -Icon 'key') -Value '' -Label 'New password' -Type password -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -id "txtpw2" -Icon (New-UDIcon -Icon 'key') -Value '' -Label 'Verify password' -Type password -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDCheckBox -id "chckpwchange" -Label 'Set so user need to change there password at next login?' -LabelPlacement end
                    }
                }
            } -Footer {
                New-UDButton -Text "Change" -Size medium -OnClick {
                    $PW1 = (Get-UDElement -Id "txtpw1").value
                    $PW2 = (Get-UDElement -Id "txtpw2").value
                    $chckpwchange = (Get-UDElement -Id 'chckpwchange').checked

                    if ([string]::IsNullOrEmpty($pw1) -or [string]::IsNullOrEmpty($pw2)) {
                        Show-UDToast -Message "You need to write a new password before you can change it!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    elseif ($pw1.length -lt 10) {
                        Show-UDToast -Message "The password are too short, it must be at least 10 characters!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    }
                    else {
                        if ($PW1 -eq $PW2) {
                            try {
                                if ($chckpwchange -eq "True") {
                                    Set-ADUser -Identity $UserName -ChangePasswordAtLogon $true
                                }
                                Set-ADAccountPassword -Identity $UserName  -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $PW1 -Force)
                                Show-UDToast -Message "The password for $($UserName) has been changed!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                if ($ActiveEventLog -eq "True") {
                                    Write-EventLog -LogName $EventLogName -Source "ChangePasswordForUser" -EventID 10 -EntryType Information -Message "$($User) did change the password for $($UserName)`nLocal IP:$($LocalIpAddress)Local IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                }
                                if ($chckpwchange -eq "True") {
                                    Set-ADUser -Identity $UserName -ChangePasswordAtLogon $true
                                    if ($ActiveEventLog -eq "True") {
                                        Write-EventLog -LogName $EventLogName -Source "SetUserChangePasswordNextLogin" -EventID 21 -EntryType Information -Message "$($User) did set so $($UserName) must change password at next login!`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20
                                    }
                                }
                                Hide-UDModal
                                if ($NULL -ne $RefreshOnClose) {
                                    Sync-UDElement -Id $RefreshOnClose
                                }
                            }
                            catch {
                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                Break
                            }
                        }
                        else {
                            Show-UDToast -Message "The password and verification are not a match, try again!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break 
                        }
                    }
                }
                New-UDButton -Text "Close" -Size medium -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function New-ADAccountExpirationDateBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change account expiration date on $($UserName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon user_clock) -size small -Onclick {
            Show-UDModal -Header { "Change expiration date for $($UserName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children { }
                        New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 10 -SmallSize 10 -Children {
                            New-UDDatePicker -id "pickDate" -Format "yyyy-MM-dd"
                        }
                        New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children {}
                    }
                }
            } -Footer {
                New-UDButton -Text "Change" -Size medium -OnClick {
                    $NewDate = (Get-UDElement -Id "pickDate").value
                    try {
                        Set-ADAccountExpiration -Identity $UserName  -DateTime $NewDate
                        Show-UDToast -Message "$($UserName) expiration date has been changed to $($NewDate)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ChangeExperationDateForUser" -EventID 10 -EntryType Information -Message "$($User) did change the experation date to $($NewDate) for $($UserName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        if ($Null -ne $RefreshOnClose) {
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -Size medium -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

Function Compare-ADUserGroupsBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][String]$UserName,
        [Parameter(Mandatory)][String]$YourFullDomain,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Compare $($UserName) AD group memberships against an other user"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon not_equal) -size medium -Onclick {
            Show-UDModal -Header { "Compare $($UserName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtCompUsr' -Label "Compare $($UserName) against?" -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 7 -LargeSize 7 -MediumSize 7 -SmallSize 7 -Children { }
                }
                New-UDDynamic -Id 'CompUsrGrpsTable' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        $CompUsr = (Get-UDElement -Id "txtCompUsr").value
                        if ($NULL -ne $CompUsr) {
                            $CompUsr = $CompUsr.trim()
                        }

                        if ($null -ne $CompUsr) {
                            if (Get-ADUser -Filter "samaccountname -eq '$($CompUsr)'" -Properties samAccountName) {
                                if ($UserName -eq $CompUsr) {
                                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                        New-UDHtml -Markup "<br>"
                                        New-UDAlert -Severity 'error' -Text "You can't compare the user against it self!"
                                    }
                                }
                                else {
                                    try {
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "CompareUserADGroups" -EventID 10 -EntryType Information -Message "$($User) did compare $($Computer) against $($CompComputer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                        $Columns = @(
                                            New-UDTableColumn -Title '.' -Property '.' -render {
                                                New-UDTooltip -TooltipContent {
                                                    New-UDTypography -Text "$($UserName) to this group"
                                                } -content { 
                                                    New-UDButton -Icon (New-UDIcon -Icon sign_in_alt) -size small -Onclick {
                                                        try {
                                                            Add-ADGroupMember -Identity $EventData.SamAccountName -Members $UserName 
                                                            if ($ActiveEventLog -eq "True") {
                                                                Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($UserName) to the group $($EventData.SamAccountName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                            }
                                                            Show-UDToast -Message "$($UserName) are now member of $($EventData.SamAccountName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            Sync-UDElement -Id 'CompUsrGrpsTable'
                                                        }
                                                        catch {
                                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            Break
                                                        }
                                                    }
                                                }
                                            }
                                            New-UDTableColumn -Title 'Group' -Property 'SamAccountName' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                                            New-UDTableColumn -Title 'Description' -Property 'Description' -IncludeInExport -IncludeInSearch
                                        )
                                        $obj = Get-ADPrincipalGroupMembership -Identity $UserName  -ResourceContextServer $YourFullDomain | Sort-Object -Property SamAccountName
                                        $obj2 = Get-ADPrincipalGroupMembership -Identity $CompUsr  -ResourceContextServer $YourFullDomain | Sort-Object -Property SamAccountName
                                        $CompData = Compare-Object -ReferenceObject $obj -DifferenceObject $obj2 -Property SamAccountName | Where-Object { $_.SideIndicator -eq "=>" } | Foreach-Object { Get-ADGroup -Identity $_.SamAccountName -Property Displayname, Description | Select-Object SamAccountName, Description }
                
                                        if ([string]::IsNullOrEmpty($CompData)) {
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                                New-UDHtml -Markup "<br>"
                                                New-UDAlert -Severity 'success' -Text "$($UserName) are member in all groups that $($CompUsr) are member in!"
                                            }
                                        }
                                        else {
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                                $SearchOption = New-UDTableTextOption -Search "Search"
                                                New-UDTable -id "CompTable" -Title "$($UserName) is not a member of the following groups" -Data $CompData -Columns $Columns -DefaultSortDirection "Ascending" -TextOption $SearchOption -ShowSearch -ShowSelection -ShowPagination -Dense -Sort -Export -ExportOption "xlsx, PDF, CSV" -PageSize 200                      
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                                New-UDButton -Text "Add to selected" -OnClick {
                                                    $CompTable = Get-UDElement -Id "CompTable"
                                                    $SelectedGrp = @($CompTable.selectedRows.SamAccountName)

                                                    if ($null -ne $CompTable.selectedRows.SamAccountName) {
                                                        try {
                                                            @($CompTable.selectedRows.SamAccountName.ForEach( { 
                                                                        Add-ADGroupMember -Identity $_ -Members $UserName 
                                                                        if ($ActiveEventLog -eq "True") {
                                                                            Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($UserName) to the group $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                                        }
                                                                    } ) )
                                    
                                                            Show-UDToast -Message "$($UserName) are now member of $($SelectedGrp -join ",")!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            Sync-UDElement -Id 'CompUsrGrpsTable'
                                                        }
                                                        catch {
                                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            Break
                                                        }

                                                    }
                                                    else {
                                                        Show-UDToast -Message "You have not selected any group, you need to select at least one group!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                        Break
                                                    }

                                                }
                                            }
                                        }
                                    }
                                    catch {
                                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                            }
                            else {
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDHtml -Markup "<br>"
                                    New-UDAlert -Severity 'error' -Text "Can't find $($CompUsr) in the AD!"
                                }
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHtml -Markup "<br>"
                                New-UDAlert -Severity 'error' -Text "You must select a user to compare $($UserName) against!"
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                } 
            } -Footer {
                New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 10 -SmallSize 8 -Content { }
                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 4 -Content { 
                    New-UDButton -text 'Compare' -Onclick {
                        Sync-UDElement -Id 'CompUsrGrpsTable'
                    }

                    New-UDButton -Text "Close" -OnClick {
                        Hide-UDModal
                        if ($null -ne $RefreshOnClose) {
                            Sync-UDElement -Id $RefreshOnClose
                        }
                    }
                }
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Add-MultiUsers {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$AddToGroup,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Add multiple users at the same time"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon users) -size large -Onclick {
            Show-UDModal -Header { "Add multiple users at the same time" } -Content {
                New-UDDynamic -Id 'MoreUserSearchGroupList' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        $MoreADUserData = Get-ADUser -Filter *  -Properties samAccountName, Surname, Givenname, EmailAddress, Description | Select-Object @("Givenname", "Surname", "samAccountName", "EmailAddress", "Description")
                        $MoreADUserColumns = @(
                            New-UDTableColumn -Property samAccountName -Title "Username" -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property Givenname -Title "Givenname" -IncludeInSearch
                            New-UDTableColumn -Property Surname -Title "Surname" -IncludeInSearch
                            New-UDTableColumn -Property EmailAddress -Title "Mail" -IncludeInSearch
                            New-UDTableColumn -Property Description -Title "Description" -IncludeInSearch
                        )
                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                            New-UDTable -Id 'MoreADTable' -Data $MoreADUserData -Columns $MoreADUserColumns -Title "Select user" -DefaultSortDirection “Ascending” -ShowSearch -ShowPagination -Dense -Sort -PageSize 10 -PageSizeOptions @(10, 20) -DisablePageSizeAll -ShowSelection
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Add" -OnClick {
                    $MoreADTable = Get-UDElement -Id "MoreADTable"
                    $MoreADLog = @($MoreADTable.selectedRows.samAccountName)
                    if ($null -ne $MoreADTable.selectedRows.samAccountName) {
                        try {
                            @($MoreADTable.selectedRows.samAccountName.ForEach( { 
                                        Add-ADGroupMember -Identity $AddToGroup -Members $_  -Confirm:$False
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($_) to the group $($AddToGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                    } ) )

                            Show-UDToast -Message "$($MoreADLog -join ",") are now members of $($AddToGroup)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Hide-UDModal
                            if ($null -ne $RefreshOnClose) {
                                Sync-UDElement -Id $RefreshOnClose
                            }
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    else {
                        Show-UDToast -Message "You have not selected any users, you need to select at least one user!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                    if ($null -ne $RefreshOnClose) {
                        Sync-UDElement -Id $RefreshOnClose
                    }
                }
                                        
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

Function Set-UserPasswordExpiresBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$ExpireStatus,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    If ($ExpireStatus -eq $true) {
        $HeaderText = "Set password to expires for $($UserName)"
    }
    elseif ($ExpireStatus -eq $false) {
        $HeaderText = "Set password to never expires for $($UserName)"
    }

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "$($HeaderText)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick {
            Show-UDModal -Header { "$($HeaderText)" } -Content {
                New-UDTypography -Text "Are you sure that you want to $($HeaderText)?"
            } -Footer {
                New-UDButton -Text "Yes" -OnClick {
                    if ($ExpireStatus -eq $true) {
                        try {
                            Set-ADUser -Identity $UserName -PasswordNeverExpires:$FALSE
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SetUserPasswordExpires" -EventID 10 -EntryType Information -Message "$($User) did set so $($UserName) password expires`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            Show-UDToast -Message "$($UserName) password set to expire!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Hide-UDModal
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    elseif ($ExpireStatus -eq $FALSE) {
                        try {
                            Set-ADUser -Identity $UserName -PasswordNeverExpires:$TRUE
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SetUserPasswordExpires" -EventID 10 -EntryType Information -Message "$($User) did set so $($UserName) password never expires`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            Show-UDToast -Message "$($UserName) password set to never expire!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Hide-UDModal
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                }
                New-UDButton -Text "No" -OnClick {
                    Hide-UDModal
                }
            }
        }
    } 
}

Function Set-UserChangePasswordBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$PWChangeStatus,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    If ($PWChangeStatus -eq $true) {
        $HeaderText = "Set so $($UserName) can change password"
    }
    elseif ($PWChangeStatus -eq $false) {
        $HeaderText = "Set so $($UserName) can't change password"
    }

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "$($HeaderText)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick {
            Show-UDModal -Header { "$($HeaderText)" } -Content {
                New-UDTypography -Text "Are you sure that you want to $($HeaderText)?"
            } -Footer {
                New-UDButton -Text "Yes" -OnClick {
                    try {
                        if ($PWChangeStatus -eq $false) {
                            Set-ADUser -Identity $UserName -CannotChangePassword:$true
                            Show-UDToast -Message "$($UserName) can't change password!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SetUserCannotChangePassword" -EventID 10 -EntryType Information -Message "$($User) did set so $($UserName) can't change it's own password`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            Hide-UDModal
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        elseif ($PWChangeStatus -eq $true) {
                            Set-ADUser -Identity $UserName -CannotChangePassword:$false
                            Show-UDToast -Message "$($UserName) can now change password!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SetUserCannotChangePassword" -EventID 10 -EntryType Information -Message "$($User) did set so $($UserName) can change there own password`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            Hide-UDModal
                            Sync-UDElement -Id $RefreshOnClose
                        }
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "No" -OnClick {
                    Hide-UDModal
                }
            }
        }
    } 
}

Function Set-UserChangePasswordNextLogin {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$PWChangeStatus,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    If ($PWChangeStatus -ne 0) {
        $HeaderText = "Set so $($UserName) must change password at next login"
    }
    else {
        $HeaderText = "Set so $($UserName) don't need to change password at next login"
    }

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "$($HeaderText)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick {
            Show-UDModal -Header { "$($HeaderText)" } -Content {
                New-UDTypography -Text "Are you sure that you want to $($HeaderText)?"
            } -Footer {
                New-UDButton -Text "Yes" -OnClick {
                    try {
                        if ($ADUser.pwdLastSet -ne "0") {
                            Set-ADUser -Identity $UserName -ChangePasswordAtLogon $true
                            Show-UDToast -Message "$($UserName) must change password at next login!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SetUserChangePasswordNextLogin" -EventID 10 -EntryType Information -Message "$($User) did set so $($UserName) must change password at next login!`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            Hide-UDModal
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        else {
                            Set-ADUser -Identity $UserName -ChangePasswordAtLogon $false
                            Show-UDToast -Message "$($UserName) don't need to change password at next login!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SetUserChangePasswordNextLogin" -EventID 10 -EntryType Information -Message "$($User) did set so $($UserName) don't need to change password at next login`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            Hide-UDModal
                            Sync-UDElement -Id $RefreshOnClose
                        }
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "No" -OnClick {
                    Hide-UDModal
                }
            }
        }
    } 
}

function Show-WhatUserManage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show what objects $($UserName) is manger of"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon tools) -size medium -Onclick {
            Show-UDModal -Header { "Show what objects $($UserName) is manger of" } -Content {
                New-UDDynamic -Id 'Manager' -content {
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "ShowWhatUserManaging" -EventID 10 -EntryType Information -Message "$($User) has looked what $($UserName) are managing`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    New-UDGrid -Spacing '1' -Container -Children {
                        $MoreADUserData = Get-ADUser -Identity $UserName -Properties managedObjects | select-object managedObjects -ExpandProperty managedObjects | Foreach-Object { 
                            [PSCustomObject]@{
                                ManageObjects     = $_.Replace("CN=", "").Split(",") | Select-Object -First 1
                                DistinguishedName = $_
                            }
                        }
                        $MoreADUserColumns = @(
                            New-UDTableColumn -Property . -Title "." -Render {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Remove $($UserName) as manager for $($Eventdata.ManageObjects)"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon trash) -size small -Onclick {
                                        try {
                                            Set-ADObject -Identity $Eventdata.DistinguishedName -Clear Managedby
                                            if ($ActiveEventLog -eq "True") {
                                                Write-EventLog -LogName $EventLogName -Source "RemoveUserAsManagerFromObject" -EventID 10 -EntryType Information -Message "$($User) has removed $($UserName) as manger for $($Eventdata.ManageObjects)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                            }
                                            Show-UDToast -Message "$($UserName) don't managing $($Eventdata.ManageObjects) anymore!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Sync-UDElement -Id "Manager"
                                        }
                                        Catch {
                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                            New-UDTableColumn -Property ManageObjects -Title "Object name" -IncludeInSearch -IncludeInExport -DefaultSortColumn
                            New-UDTableColumn -Property DistinguishedName -Title "Distinguished name" -IncludeInSearch -IncludeInExport
                        )
                        if ([string]::IsNullOrEmpty($MoreADUserData)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'info' -Text "$($UserName) is not managing any groups!"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDTable -Id 'MoreADTable' -Data $MoreADUserData -Columns $MoreADUserColumns -DefaultSortDirection “Ascending” -Export -ExportOption "xlsx, PDF, CSV" -ShowSearch -ShowPagination -Dense -Sort -PageSize 10 -PageSizeOptions @(10, 20, 30, 40) -ShowSelection
                            }
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Remove from selected"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon trash) -Onclick {
                                        $ManagerTable = Get-UDElement -Id "MoreADTable"
                                        $ManagerSelected = @($ManagerTable.selectedRows.DistinguishedName)
                                        if ($Null -ne $ManagerTable.selectedRows.DistinguishedName) {                  
                                            try {
                                                @($ManagerTable.selectedRows.DistinguishedName.ForEach( { 
                                                            Set-ADObject -Identity $_ -Clear Managedby
                                                            if ($ActiveEventLog -eq "True") {
                                                                Write-EventLog -LogName $EventLogName -Source "RemoveUserAsManagerFromObject" -EventID 10 -EntryType Information -Message "$($User) has removed $($UserName) as manger for $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                            }
                                                        } ) )
                                                Show-UDToast -Message "$($UserName) don't managing $($ManagerSelected -join ",") anymore!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id "Manager"
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                        else {
                                            Show-UDToast -Message "You have not selected any group!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 5 -Children {
                    New-UDTextbox -Id "txtADDasManger" -Icon (New-UDIcon -Icon 'users') -Label "Enter group that you want to manage" -FullWidth
                }
                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 3 -Children {
                    New-UDTooltip -TooltipContent {
                        New-UDTypography -Text "Add $($UserName) as manager to selected group"
                    } -Content { 
                        New-UDButton -Icon (New-UDIcon -Icon user_plus) -Onclick { 
                            $AddToGroup = (Get-UDElement -Id "txtADDasManger").value
                            $AddToGroup = $AddToGroup.trim()

                            $CheckGroup = $(try { Get-ADGroup -Filter "samaccountname -eq '$($AddToGroup)'" } catch { $Null })
                            $CheckManager = $(try { Get-ADGroup -Filter "samaccountname -eq '$($AddToGroup)'" -properties managedby | Select-Object managedby -ExpandProperty managedby } catch { $Null })

                            if ($Null -ne $CheckGroup ) { 
                                if ([string]::IsNullOrEmpty($CheckManager)) {
                                    try {
                                        Set-ADGroup -Identity $AddToGroup -ManagedBy $UserName
                                        Show-UDToast -Message "$($UserName) is now manager of $($AddToGroup)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "ChangeUserManager" -EventID 10 -EntryType Information -Message "$($User) did change manager to $($UserName) for $($AddToGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                        Sync-UDElement -Id 'Manager'
                                    }
                                    catch {
                                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                                else {
                                    $WriteManager = $CheckManager.ManagedBy | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 }
                                    Show-UDToast -Message "The group $($AddToGroup) already has a manager $($WriteManager), you need to remove it first!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    Break
                                }
                            }
                            else {
                                Show-UDToast -Message "The group $($AddToGroup) did not exist in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                Break
                            }
                        }
                    }
                }
                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 3 -SmallSize 2 -Children { }
                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 3 -SmallSize 5 -Children {
                    New-UDButton -Text "Refresh" -Size medium -OnClick {
                        Sync-UDElement -Id "Manager"
                    }
                    New-UDButton -Text "Close" -Size medium -OnClick {
                        Hide-UDModal
                    }     
                }                    
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Edit-ADUserInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$ParamToChange,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change $($ParamToChange) for $($UserName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick {
            Show-UDModal -Header { "Change $($ParamToChange) for $($UserName)" } -Content {
                New-UDTextbox -Id "txtChange" -Label "$($ParamToChange)" -Value $CurrentValue -FullWidth
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewParam = (Get-UDElement -Id "txtChange").value

                    if ([string]::IsNullOrEmpty($NewParam)) {
                        Show-UDToast -Message "You must write something in the field above!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        try {
                            switch ($ParamToChange) {
                                EmailAddress {
                                    Set-ADUser -Identity $UserName -EmailAddress $NewParam
                                }
                                HomePhone {
                                    Set-ADUser -Identity $UserName -HomePhone $NewParam
                                }
                                MobilePhone {
                                    Set-ADUser -Identity $UserName -MobilePhone $NewParam
                                }
                                OfficePhone {
                                    Set-ADUser -Identity $UserName -OfficePhone $NewParam
                                }
                                FAX {
                                    Set-ADUser -Identity $UserName -FAX $NewParam
                                }
                                StreetAddress {
                                    Set-ADUser -Identity $UserName -StreetAddress $NewParam
                                }
                                POBOX {
                                    Set-ADUser -Identity $UserName -POBOX $NewParam
                                }
                                State {
                                    Set-ADUser -Identity $UserName -State $NewParam
                                }
                                City {
                                    Set-ADUser -Identity $UserName -City $NewParam
                                }
                                PostalCode {
                                    Set-ADUser -Identity $UserName -PostalCode $NewParam
                                }
                                Givenname {
                                    Set-ADUser -Identity $UserName -Givenname $NewParam
                                }
                                Surname {
                                    Set-ADUser -Identity $UserName -Surname $NewParam
                                }
                                Company {
                                    Set-ADUser -Identity $UserName -Company $NewParam
                                }
                                Title {
                                    Set-ADUser -Identity $UserName -Title $NewParam
                                }
                                Division {
                                    Set-ADUser -Identity $UserName -Division $NewParam
                                }
                                Department {
                                    Set-ADUser -Identity $UserName -Department $NewParam
                                }
                                Office {
                                    Set-ADUser -Identity $UserName -Office $NewParam
                                }
                                Manager {
                                    if (Get-ADUser -Filter "Samaccountname -eq '$($NewParam)'") {
                                        Set-ADUser -Identity $UserName -Manager $NewParam
                                    }
                                    else {
                                        $ManagerCheck = "False"
                                    }
                                }
                                ProfilePath {
                                    Set-ADUser -Identity $UserName -ProfilePath $NewParam
                                }
                                ScriptPath {
                                    Set-ADUser -Identity $UserName -ScriptPath $NewParam
                                }
                                HomeDirectory {
                                    Set-ADUser -Identity $UserName -HomeDirectory $NewParam
                                }
                                HomeDrive {
                                    Set-ADUser -Identity $UserName -HomeDrive $NewParam
                                }
                            }
                            if ($ManagerCheck -eq "False") {
                                Show-UDToast -Message "$($NewParam) don't exist in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                Break
                            }
                            else {
                                Show-UDToast -Message "$($ParamToChange) has changed to $($NewParam) for $($UserName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                if ($ActiveEventLog -eq "True") {
                                    Write-EventLog -LogName $EventLogName -Source "ChangeUser$($ParamToChange)" -EventID 10 -EntryType Information -Message "$($User) did change $($ParamToChange) to $($NewParam) for $($UserName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                }
                                if ($NULL -ne $RefreshOnClose) {
                                    Sync-UDElement -Id $RefreshOnClose
                                }
                                Hide-UDModal  
                            }
                        }
                        Catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                }
                New-UDButton -Text "Clear" -OnClick {
                    try {
                        switch ($ParamToChange) {
                            EmailAddress {
                                Set-ADUser -Identity $UserName -EmailAddress $Null
                            }
                            HomePhone {
                                Set-ADUser -Identity $UserName -HomePhone $Null
                            }
                            MobilePhone {
                                Set-ADUser -Identity $UserName -MobilePhone $Null
                            }
                            OfficePhone {
                                Set-ADUser -Identity $UserName -OfficePhone $Null
                            }
                            FAX {
                                Set-ADUser -Identity $UserName -FAX $Null
                            }
                            StreetAddress {
                                Set-ADUser -Identity $UserName -StreetAddress $Null
                            }
                            POBOX {
                                Set-ADUser -Identity $UserName -POBOX $Null
                            }
                            State {
                                Set-ADUser -Identity $UserName -State $Null
                            }
                            City {
                                Set-ADUser -Identity $UserName -City $Null
                            }
                            PostalCode {
                                Set-ADUser -Identity $UserName -PostalCode $Null
                            }
                            Givenname {
                                Set-ADUser -Identity $UserName -Givenname $Null
                            }
                            Surname {
                                Set-ADUser -Identity $UserName -Surname $Null
                            }
                            Company {
                                Set-ADUser -Identity $UserName -Company $Null
                            }
                            Title {
                                Set-ADUser -Identity $UserName -Title $Null
                            }
                            Division {
                                Set-ADUser -Identity $UserName -Division $Null
                            }
                            Department {
                                Set-ADUser -Identity $UserName -Department $Null
                            }
                            Office {
                                Set-ADUser -Identity $UserName -Office $Null
                            }
                            Manager {
                                Set-ADUser -Identity $UserName -Manager $Null  
                            }
                            ProfilePath {
                                Set-ADUser -Identity $UserName -ProfilePath $null
                            }
                            ScriptPath {
                                Set-ADUser -Identity $UserName -ScriptPath $null
                            }
                            HomeDirectory {
                                Set-ADUser -Identity $UserName -HomeDirectory $null
                            }
                            HomeDrive {
                                Set-ADUser -Identity $UserName -HomeDrive $Null
                            }
                        }
                        Show-UDToast -Message "$($ParamToChange) has now been cleared for $($UserName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ClearUser$($ParamToChange)" -EventID 10 -EntryType Information -Message "$($User) did clear $($ParamToChange) for $($UserName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        if ($NULL -ne $RefreshOnClose) {
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        Hide-UDModal  
                    }
                    Catch {
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

Function Edit-UserUPN {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change UPN for $($UserName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick {
            Show-UDModal -Header { "Change UPN for $($UserName)" } -Content {
                $UPN = Get-adforest | select-Object UPNSuffixes -ExpandProperty UPNSuffixes
                $ForestName = Get-adforest | select-Object name -ExpandProperty name
                $Combined = @($UPN, $ForestName)
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDSelect -id 'UPN' -FullWidth -Option {
                        New-UDSelectOption -Name $CurrentValue -Value 1
                        foreach ($NewUPNs in $Combined) {
                            New-UDSelectOption -Name "$($UserName)@$($NewUPNs)" -Value "$($UserName)@$($NewUPNs)"
                        }
                    }
                }
            } -Footer {
                New-UDButton -Text "Change" -OnClick { 
                    $SelectedUPN = Get-UDElement -Id 'UPN'

                    if ([string]::IsNullOrEmpty($SelectedUPN.value) -or $SelectedUPN.value -eq 1) {
                        Show-UDToast -Message "You need to select a new UPN!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        if (Get-ADUser -Filter "UserPrincipalName -eq '$($SelectedUPN.value)'") {
                            Show-UDToast -Message "The UPN $($SelectedUPN.value) already exists!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                        else {
                            try {
                                Set-ADUser -Identity $UserName -UserPrincipalName $SelectedUPN.value
                                Show-UDToast -Message "UPN for $($UserName) has been changed to $($SelectedUPN.value)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                if ($ActiveEventLog -eq "True") {
                                    Write-EventLog -LogName $EventLogName -Source "ChangeUserUPN" -EventID 10 -EntryType Information -Message "$($User) has changed UPN for $($Computer) to $($SelectedUPN.value)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                }
                                if ($NULL -ne $RefreshOnClose) {
                                    Sync-UDElement -Id $RefreshOnClose
                                }
                                Hide-UDModal
                            }
                            catch {
                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                Break
                            }
                        }
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

Function New-ADUserFranky {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$BoxToSync,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Create new user"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon plus) -size large -Onclick {
            Show-UDModal -Header { "Create new user" } -Content {
                $UPN = Get-adforest | select-Object UPNSuffixes -ExpandProperty UPNSuffixes
                $ForestName = Get-adforest | select-Object name -ExpandProperty name
                $Combined = @($UPN, $ForestName)
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtGivenName' -Label 'Givenname' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtSurname' -Label 'Surname' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTextbox -Id 'txtDisplayName' -Label 'Display name (Required)' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                        New-UDTextbox -Id 'txtUPN' -Label 'UPN (Required)' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                        New-UDSelect -id 'UPN' -FullWidth -Option {
                            New-UDSelectOption -Name "Select Prefix..." -Value 1
                            foreach ($UPNs in $Combined) {
                                if ($null -ne $UPNs) {
                                    New-UDSelectOption -Name "$($UPNs)" -Value "$($UPNs)"
                                }
                            }
                        }
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                        New-UDTextbox -Id 'txtSamAccountName' -Label 'SamAccountName (Required)' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDHTML -Markup "<br>"
                        New-UDHTML -Markup "Enter the desired password, the password must be at least 10 characters.<br>"
                        New-UDDynamic -Id 'generatepassword' -content {
                            $RndPwd = New-RndPassword
                            New-UDTypography -Text "$($RndPwd)" -Style @{ 'font-weight' = '700' }
                            New-UDTooltip -TooltipContent {
                                New-UDTypography -Text "Use this password"
                            } -content { 
                                New-UDButton -Icon (New-UDIcon -Icon paste) -Size small -OnClick {
                                    Set-UDElement -Id "txtPW1" -Properties @{
                                        Value = $RndPwd
                                    }
                                    Set-UDElement -Id "txtPW2" -Properties @{
                                        Value = $RndPwd
                                    }
                                }
                            }
                        }
                        New-UDTooltip -TooltipContent {
                            New-UDTypography -Text "Generate a new random password"
                        } -content { 
                            New-UDButton -Icon (New-UDIcon -Icon sync_alt) -Size small -OnClick {
                                Sync-UDElement -Id 'generatepassword'
                            }
                        }
                        New-UDHTML -Markup "<br>"
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                        New-UDTextbox -Id 'txtPW1' -Label 'Password (Required)' -Type password -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                        New-UDTextbox -Id 'txtPW2' -Label 'Verify password (Required)' -Type password -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDCheckBox -Id 'MustChangePW' -LabelPlacement end -Label 'User must change password at next logon'
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDCheckBox -Id 'CannotChangePW' -LabelPlacement end -Label 'User cannot change password'
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDCheckBox -Id 'AccountDisabled' -Checked $true -LabelPlacement end -Label 'Uncheck to disable account'
                    }
                }
            } -Footer {
                New-UDButton -text 'Create' -Onclick {
                    $GivenName = (Get-UDElement -Id "txtGivenName").value
                    $Surname = (Get-UDElement -Id "txtSurname").value
                    $DisplayName = (Get-UDElement -Id "txtDisplayName").value
                    $SamAccountName = (Get-UDElement -Id "txtSamAccountName").value
                    $CN = (Get-UDElement -Id "txtUPN").value
                    $CN = $CN.trim()
                    $SelectedUPN = (Get-UDElement -Id 'UPN').value
                    $CombinedUPN = $CN + "@" + $SelectedUPN
                    $SamAccountName = $SamAccountName.trim()
                    $DisplayName = $DisplayName.trim()
                    $MustChangePW = (Get-UDElement -Id "MustChangePW").checked
                    $CannotChangePW = (Get-UDElement -Id "CannotChangePW").checked
                    $ADAccountDisabled = (Get-UDElement -Id "AccountDisabled").checked
                    $PW1 = (Get-UDElement -Id "txtPW1").value
                    $PW2 = (Get-UDElement -Id "txtPW2").value
                    $SecPWD = ConvertTo-SecureString $PW1 -AsPlainText -Force
                  
                    if ([string]::IsNullOrEmpty($DisplayName) -or [string]::IsNullOrEmpty($SamAccountName) -or [string]::IsNullOrEmpty($CN) -or [string]::IsNullOrEmpty($PW1) -or [string]::IsNullOrEmpty($PW2) -or $SelectedUPN -like "1") {
                        Show-UDToast -Message "You must enter all the required options above!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        if (Get-ADUser -Filter "UserPrincipalName -eq '$($CombinedUPN)'") {
                            Show-UDToast -Message "The UPN $($CombinedUPN) already exists!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                        else {
                            if (Get-ADUser -Filter "samaccountname -eq '$($SamAccountName)'" -properties SamAccountName) {
                                Show-UDToast -Message "It's already a user with the SamAccountName $($SamAccountName) in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                Break
                            }
                            else {
                                if ($PW1 -eq $PW2) {
                                    try {
                                        New-ADUser -GivenName $GivenName -Surname $Surname -Name $CN -SamAccountName $SamAccountName -UserPrincipalName $CombinedUPN -DisplayName $DisplayName -Path $OUUsrPath -CannotChangePassword $CannotChangePW -ChangePasswordAtLogon $MustChangePW -Enabled $ADAccountDisabled -AccountPassword $SecPWD -Confirm:$false
                                        Show-UDToast -Message "$($SamAccountName) has been created!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "CreatedUser" -EventID 10 -EntryType Information -Message "$($User) did create the user $($SamAccountName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                        Set-UDElement -Id $BoxToSync -Properties @{
                                            Value = $SamAccountName
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
                                    Show-UDToast -Message "Password did not match, try again!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    Break
                                }
                            }
                        }
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'sm' -Persistent
        }
    }
}

Export-ModuleMember -Function "New-ADUserFranky", "Edit-UserUPN", "Edit-ADUserInfo", "Show-WhatUserManage", "Set-UserChangePasswordNextLogin", "Set-UserChangePasswordBtn", "Set-UserPasswordExpiresBtn", "Unlock-ADUserAccountBtn", "New-PasswordADUserBtn", "New-ADAccountExpirationDateBtn", "Compare-ADUserGroupsBtn", "Add-MultiUsers"