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

function Edit-DescriptionBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ChangeDescriptionObject,
        [Parameter(Mandatory)][string]$ChangeObjectName,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change description for $($ChangeObjectName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change description for $($ChangeObjectName)" } -Content {
                New-UDTextbox -Id "txtDescription" -Label "Description" -Value $CurrentValue -FullWidth
            } -Footer {
                New-UDButton -Text "Save" -OnClick { 
                    $NewDescription = (Get-UDElement -Id "txtDescription").value

                    try {
                        switch ($ChangeDescriptionObject) {
                            User {
                                Set-ADUser -Identity $ChangeObjectName  -Description $NewDescription
                            }
                            Group {
                                Set-ADGroup -Identity $ChangeObjectName  -Description $NewDescription
                            }
                            Computer {
                                Set-ADComputer -Identity $ChangeObjectName  -Description $NewDescription
                            }
                        }
                        Show-UDToast -Message "The description for $($ChangeObjectName) has been changed to $($NewDescription)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Change$($ChangeDescriptionObject)Description" -EventID 10 -EntryType Information -Message "$($User) did change the description for $($ChangeObjectName) to $($NewDescription)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
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
                New-UDButton -Text "Clear" -OnClick {
                    try {
                        switch ($ChangeDescriptionObject) {
                            User {
                                Set-ADUser -Identity $ChangeObjectName -Description $NULL
                            }
                            Group {
                                Set-ADGroup -Identity $ChangeObjectName -Description $NULL
                            }
                            Computer {
                                Set-ADComputer -Identity $ChangeObjectName -Description $NULL
                            }
                        }
                        Show-UDToast -Message "The description for $($ChangeObjectName) has now been cleared!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Clear$($ChangeDescriptionObject)Description" -EventID 10 -EntryType Information -Message "$($User) did clear the description for $($ChangeObjectName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
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
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'sm' -Persistent
        }
    }
}

function Edit-MailBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ChangeMailObject,
        [Parameter(Mandatory)][string]$ChangeObjectName,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change mail for $($ChangeObjectName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change mail for $($ChangeObjectName)" } -Content {
                New-UDTextbox -Id "txtMail" -Label "Mail" -Value $CurrentValue -FullWidth
            } -Footer {
                New-UDButton -Text "Save" -OnClick { 
                    $NewMail = (Get-UDElement -Id "txtMail").value

                    try {
                        switch ($ChangeMailObject) {
                            User {
                                Set-ADUser -Identity $ChangeObjectName -EmailAddress $NewMail
                            }
                            Group {
                                Set-ADGroup -Identity $ChangeObjectName -Replace @{mail = "$($NewMail)" }
                            }
                            Computer {
                                Set-ADComputer -Identity $ChangeObjectName -EmailAddress $NewMail
                            }
                        }
                        Show-UDToast -Message "The mail for $($ChangeObjectName) has been changed to $($NewMail)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Change$($ChangeMailObject)Mail" -EventID 10 -EntryType Information -Message "$($User) did change the mail for $($ChangeObjectName) to $($NewMail)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
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
                New-UDButton -Text "Clear" -OnClick {
                    try {
                        switch ($ChangeMailObject) {
                            User {
                                Set-ADUser -Identity $ChangeObjectName -EmailAddress $Null
                            }
                            Group {
                                Set-ADGroup -Identity $ChangeObjectName -Replace @{mail = "$($Null)" }
                            }
                            Computer {
                                Set-ADComputer -Identity $ChangeObjectName -EmailAddress $Null
                            }
                        }
                        Show-UDToast -Message "The mail for $($ChangeObjectName) has now been cleared!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Clear$($ChangeMailObject)Mail" -EventID 10 -EntryType Information -Message "$($User) did clear the mail for $($ChangeObjectName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
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
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'sm' -Persistent
        }
    }
}


## Not done! Need more work!
function Move-ADObjectBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjectToMove,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$UserName,
        [Parameter(Mandatory = $false)][string]$GroupName,
        [Parameter(Mandatory = $false)][string]$ComputerName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    switch ($ObjectToMove) {
        User {
            $ObjectToMoveName = $UserName
        }
        Group {
            $ObjectToMoveName = $GroupName
        }
        Computer {
            $ObjectToMoveName = $ComputerName
        }
    }

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Move to new OU"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon suitcase_rolling) -size small -Onclick { 
            Show-UDModal -Header { "Move $($ObjectToMoveName) to new OU" } -Content {
                ## Dropdown
            } -Footer {
                New-UDButton -Text "Move" -OnClick { 
                 
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'sm' -Persistent
        }
    }
}

function Rename-ADObjectBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjectToRename,
        [Parameter(Mandatory)][string]$WhatToChange,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory = $false)][string]$BoxToSync,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    if ($ObjectToRename -eq "Computer" -and $WhatToChange -eq "SamAccountName") {
        $CurrentValue = $CurrentValue -replace ".$"
    }

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Rename $($WhatToChange) on $($ObjectName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Rename $($WhatToChange) for $($ObjectName)" } -Content {
                New-UDTextbox -Id "txtRename" -Label "Change $($WhatToChange) on $($ObjectName)" -Value $CurrentValue -FullWidth
            } -Footer {
                New-UDButton -Text "Rename" -OnClick { 
                    $NewName = (Get-UDElement -Id "txtRename").value
                    $NewName = $NewName.trim()
                    try {
                        switch ($ObjectToRename) {
                            User {
                                switch ($WhatToChange) {
                                    SamAccountName {
                                        Set-ADUser -Identity $ObjectName -SamAccountName $NewName
                                    }
                                    DisplayName {
                                        Set-ADUser -Identity $ObjectName -DisplayName $NewName
                                    }
                                    Name {
                                        Set-ADUser -Identity $ObjectName -Name $NewName
                                    }
                                    CN {
                                        Get-ADUser -Identity $ObjectName  | Rename-ADObject -NewName $NewName
                                    }
                                }
                            }
                            Group {
                                switch ($WhatToChange ) {
                                    SamAccountName {
                                        Set-ADGroup -Identity $ObjectName -SamAccountName $NewName
                                    }
                                    CN {
                                        Get-ADGroup -Identity $ObjectName  | Rename-ADObject -NewName $NewName
                                    }
                                    DisplayName {
                                        Set-ADGroup -Identity $ObjectName  -DisplayName $NewName
                                    }
                                }
                            }
                            Computer {
                                switch ($WhatToChange ) {
                                    SamAccountName {
                                        $NewName = $NewName + "$"
                                        Set-ADComputer -Identity $ObjectName  -SamAccountName $NewName
                                        $NewName = $NewName -replace ".$"
                                    }
                                    CN {
                                        Get-ADComputer -Identity $ObjectName  | Rename-ADObject -NewName $NewName 
                                    }
                                    DisplayName {
                                        Set-ADComputer -Identity $ObjectName  -DisplayName $NewName
                                    }
                                }
                            }
                        }
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Change$($ObjectToRename)$($WhatToChange)" -EventID 10 -EntryType Information -Message "$($User) did change $($ObjectToRename) object $($WhatToChange) for $($ObjectName) to $($NewName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Set-UDElement -Id $BoxToSync -Properties @{
                            Value = $NewName
                        }
                        if ($NULL -ne $RefreshOnClose) {
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        Show-UDToast -Message "$($ObjectName) has changed $($WhatToChange) to $($NewName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
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

function Set-EnableDisableADAccountBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjectToChange,
        [Parameter(Mandatory)][string]$ObjectStatus,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory = $false)][string]$CurrentDescription,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
       
    if ($ObjectStatus -eq "true") {
        New-UDTooltip -TooltipContent {
            New-UDTypography -Text "Disable $($ObjectName)"
        } -content { 
            New-UDButton -Icon (New-UDIcon -Icon lock) -size small -Onclick { 
                Show-UDModal -Header { "Disable account for $($ObjectName)" } -Content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                            New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 10 -SmallSize 10 -Children {
                                New-UDTextbox -Id 'txtReason' -Label 'Reason for disabling?' -FullWidth
                            }
                            New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children { }
                        }
                    }
                } -Footer {
                    New-UDButton -Text "Disable" -OnClick {
                        $DescriptionReason = (Get-UDElement -Id "txtReason").value
                        try {
                            if ($ObjectToChange -eq "Computer") {
                                Set-ADComputer -Identity $ObjectName  -Description "$($CurrentDescription) - Has been disabled: $($DescriptionReason)"
                            }
                            elseif ($ObjectToChange -eq "User") {
                                Set-ADUser -Identity $ObjectName  -Description "$($CurrentDescription) - Has been disabled: $($DescriptionReason)"
                            }
                            Disable-ADAccount -Identity $ObjectName  -Confirm:$False
                            Show-UDToast -Message "$($ObjectName) are now disabled!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "Disable$($ObjectToChange)Object" -EventID 10 -EntryType Information -Message "$($User) has disabled $($ObjectName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            if ($null -ne $RefreshOnClose) {
                                Sync-UDElement -Id $RefreshOnClose
                            }
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
    elseif ($ObjectStatus -eq "False") {
        New-UDTooltip -TooltipContent {
            New-UDTypography -Text "Enable $($ObjectName)"
        } -content { 
            New-UDButton -Icon (New-UDIcon -Icon lock_open) -size small -Onclick { 
                Show-UDModal -Header { "Disable account for $($ObjectName)" } -Content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                            New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 10 -SmallSize 10 -Children { 
                                New-UDTypography -Text "Are you sure that you want to enable $($ObjectName)?"
                            }
                            New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children { }
                        }
                    }
                } -Footer {
                    New-UDButton -Text "Yes" -OnClick {
                        try {
                            Enable-ADAccount -Identity $ObjectName  -Confirm:$False
                            Show-UDToast -Message "$($ObjectName) are now enabled!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "Enable$($ObjectToChange)Object" -EventID 10 -EntryType Information -Message "$($User) has enabled $($ObjectName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            if ($null -ne $RefreshOnClose) {
                                Sync-UDElement -Id $RefreshOnClose
                            }
                            Hide-UDModal
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    New-UDButton -Text "No" -OnClick {
                        Hide-UDModal
                    }
                } -FullWidth -MaxWidth 'sm' -Persistent
            }
        }
    }  
}

function Edit-ManagedByBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change manage by for $($ObjectName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change manage by for $($ObjectName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTextbox -Id "txtChangeManagedBy" -Label "Enter username for manage by" -Value $CurrentValue -FullWidth
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $ManagedByNew = (Get-UDElement -Id "txtChangeManagedBy").value
                    $ManagedByNew = $ManagedByNew.trim()

                    if (Get-ADUser -Filter "samaccountname -eq '$($ManagedByNew)'") {
                        try {
                            if ($ObjectType -eq "Group") {
                                Set-ADGroup -Identity $ObjectName -Managedby $ManagedByNew
                            }
                            elseif ($ObjectType -eq "Computer") {
                                Set-ADComputer -Identity $ObjectName -Managedby $ManagedByNew
                            }
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "Change$($ObjectType)ManagedBy" -EventID 10 -EntryType Information -Message "$($User) did change managedby for $($ObjectType) objecy $($ObjectName) to $($ManagedByNew)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            if ($null -ne $RefreshOnClose) {
                                Sync-UDElement -Id $RefreshOnClose
                            }
                            Show-UDToast -Message "$($ManagedByNew) are now manage by $($ObjectName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Hide-UDModal
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    else {
                        Show-UDToast -Message "$($ManagedByNew) are not a member in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Clear" -OnClick {
                    try {
                        if ($ObjectType -eq "Group") {
                            Set-ADGroup -Identity $ObjectName -Managedby $null
                        }
                        elseif ($ObjectType -eq "Computer") {
                            Set-ADComputer -Identity $ObjectName -Managedby $null
                        }
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Clear$($ObjectType)ManagedBy" -EventID 10 -EntryType Information -Message "$($User) did clear managedby for $($ObjectName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        if ($null -ne $RefreshOnClose) {
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        Show-UDToast -Message "Managed by for $($ObjectName) are now cleared!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
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

function Remove-ADObjectBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Delete $($ObjectName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon trash_alt) -size medium -Onclick { 
            Show-UDModal -Header { "Delete $($ObjectName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 10 -SmallSize 10 -Children {
                        New-UDTypography -Text "Are you sure that you want to delete $($ObjectName)?"
                    }
                    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children { }
                }
            } -Footer {
                New-UDButton -Text "Yes" -Size medium -OnClick {
                    try {
                        switch ($ObjectType) {
                            User {
                                Remove-ADUser -Identity $ObjectName -Confirm:$False 
                            }
                            Computer {
                                Remove-ADComputer -Identity $ObjectName  -Confirm:$False 
                            }
                            Group {
                                Remove-ADGroup -Identity $ObjectName  -Confirm:$False 
                            }
                        }
                        Show-UDToast -Message "$($ObjectName) has now been deleted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Delete$($ObjectType)" -EventID 10 -EntryType Information -Message "$($User) did delete $($ObjectName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        if ($null -ne $RefreshOnClose) {
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "No" -Size medium -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

function Get-ADLastSeen {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][string]$ObjectType
    )

    $DCs = Get-ADDomainController -Filter { Name -like "*" } | Select-Object hostname -ExpandProperty hostname

    if ($ObjectType -eq "Computer") {
        $LogonDates = foreach ($dc in $dcs) {
            [PSCustomObject]@{
                Server    = $dc.hostname
                LastLogon = [DateTime]::FromFileTime((Get-ADComputer -Identity $ObjectName -Properties LastLogon -Server $dc.hostname).LastLogon)
            }
        }
    }
    elseif ($ObjectType -eq "User") {
        $LogonDates = foreach ($dc in $dcs) {
            [PSCustomObject]@{
                Server    = $dc.hostname
                LastLogon = [DateTime]::FromFileTime((Get-ADUser -Identity $ObjectName -Properties LastLogon -Server $dc.hostname).LastLogon)
            }
        }
    }
    ($LogonDates | Sort-Object -Property LastLogon -Descending | Select-Object -First 1).LastLogon
}

function Edit-PrimaryGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change primary group for $($ObjectName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change primary group for $($ObjectName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTextbox -Id "txtPrimaryGroup" -Label "Enter new primary group" -Value $CurrentValue -FullWidth
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewPrimaryGroup = (Get-UDElement -Id "txtPrimaryGroup").value
                    $NewPrimaryGroup = $NewPrimaryGroup.trim()

                    if (Get-ADGroup -Filter "samaccountname -eq '$($NewPrimaryGroup)'") {
                        try {
                            if ($ObjectType -eq "Computer") {
                                $ObjectDistinguishedName = (Get-ADComputer -Identity $ObjectName -ErrorAction Stop).DistinguishedName
                            }
                            elseif ($ObjectType -eq "User") {
                                $ObjectDistinguishedName = (Get-ADUser -Identity $ObjectName -ErrorAction Stop).DistinguishedName
                            }
                            if (-Not($NewPrimaryGroup -eq "Domain Users")) {
                                $GroupMembers = Get-ADGroupMember -Identity $NewPrimaryGroup -Recursive | Select-Object -ExpandProperty Name
                                if (-Not($GroupMembers -contains $ObjectName)) {
                                    Add-ADGroupMember -Identity $NewPrimaryGroup -Members $ObjectName
                                    if ($ActiveEventLog -eq "True") {
                                        Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($ObjectName) to $($NewPrimaryGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                    }
                                }
                            }

                            $GetNewPrimaryGroupToken = Get-ADGroup -Identity $NewPrimaryGroup -Properties primarygrouptoken | Select-Object primarygrouptoken -ExpandProperty primarygrouptoken
                            $ReplaceNewPrimaryGroup = @{"PrimaryGroupID" = "$($GetNewPrimaryGroupToken)" }
                            Set-ADObject -Identity $ObjectDistinguishedName -Replace $ReplaceNewPrimaryGroup
                            
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "Change$($ObjectType)PrimaryGroup" -EventID 10 -EntryType Information -Message "$($User) did change the primary group for $($ObjectName) to $($NewPrimaryGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            if ($null -ne $RefreshOnClose) {
                                Sync-UDElement -Id $RefreshOnClose
                            }
                            Show-UDToast -Message "$($NewPrimaryGroup) are now the primary group for $($ObjectName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Hide-UDModal
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    else {
                        Show-UDToast -Message "$($NewPrimaryGroup) does not exist in the AD" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
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

Export-ModuleMember -Function "Edit-PrimaryGroup", "Edit-ManagedByBtn", "Edit-DescriptionBtn", "Edit-MailBtn", "Move-ADObjectBtn", "Rename-ADObjectBtn", "Set-EnableDisableADAccountBtn", "Remove-ADObjectBtn", "Get-ADLastSeen"