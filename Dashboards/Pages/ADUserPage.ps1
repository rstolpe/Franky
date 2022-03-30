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

New-UDGrid -Spacing '1' -Container -Children {
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
    New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 12 -SmallSize 12 -Children {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 6 -Children {
                New-UDTextbox -Id "txtName" -Icon (New-UDIcon -Icon 'user') -Label "Username, UPN or mail (wildcard * accepted)" -FullWidth
            }
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 4 -Children { 
                New-UDButton -Icon (New-UDIcon -Icon 'search') -Size large -OnClick {
                    $SearchUserName = (Get-UDElement -Id "txtName").value
                    if ([string]::IsNullOrEmpty($SearchUserName)) {
                        Sync-UDElement -Id 'UserSearchStart'
                    }
                    elseif ($SearchUserName.EndsWith('*')) {
                        New-MultiSearch  -SearchFor $SearchUserName -txtBoxMultiSearch "txtName" -MultiSearchObj "User" -ElementSync 'UserSearchStart'
                    }
                    else {
                        Sync-UDElement -Id 'UserSearchStart'
                    }
                }
                New-ADUserFranky -BoxToSync "txtName" -RefreshOnClose "UserSearchStart"  -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
            }
            New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 2 -Children { }
        }
    }
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
}

New-UDGrid -Spacing '1' -Container -Children {
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
    New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 12 -SmallSize 12 -Children {
        New-UDCard -Content {
            New-UDDynamic -Id 'UserSearchStart' -content {
                $SearchUserName = (Get-UDElement -Id "txtName").value
                if ($NULL -ne $SearchUserName) {
                    $SearchUserName = $SearchUserName.trim()
                }

                if ([string]::IsNullOrEmpty($SearchUserName)) { 
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDAlert -Severity 'error' -Text "You must enter a username!"
                    }
                }
                else {
                    if ($SearchUserName -like "*@*") {
                        $SearchUserMail = $(try { Get-ADUser -Filter "EmailAddress -eq '$($SearchUserName)'" -properties emailaddress, SamAccountName } catch { $Null })
                        $SearchUserUPN = $(try { Get-ADUser -Filter "UserPrincipalName -eq '$($SearchUserName)'" -properties UserPrincipalName, SamAccountName } catch { $Null })
                            
                        if ($Null -ne $SearchUserMail) {
                            $SearchUserName = $SearchUserMail.SamAccountName
                            $Searchfor = $SearchUserMail.EmailAddress
                        }
                        elseif ($Null -ne $SearchUserUPN) {
                            $SearchUserName = $SearchUserUPN.SamAccountName
                            $Searchfor = $SearchUserUPN.UserPrincipalName
                        }

                    }
                    else {
                        $SearchUserSam = $(try { Get-ADUser -Filter "Samaccountname -eq '$($SearchUserName)'" -properties SamAccountName } catch { $Null })
                        $SearchControllUserName = $(try { Get-ADUser -Filter "Name -eq '$($SearchUserName)'" -properties SamAccountName, Name } catch { $Null })
                        $SearchUserDisplayName = $(try { Get-ADUser -Filter "DisplayName -eq '$($SearchUserName)'" -properties SamAccountName, DisplayName } catch { $Null })

                        if ($Null -ne $SearchControllUserName) {
                            $SearchUserName = $SearchControllUserName.SamAccountName
                            $Searchfor = $SearchControllUserName.name
                        }
                        elseif ($Null -ne $SearchUserSam) {
                            $SearchUserName = $SearchUserSam.SamAccountName
                            $Searchfor = $SearchUserSam.SamAccountName
                        }
                        elseif ($Null -ne $SearchUserDisplayName) {
                            $SearchUserName = $SearchUserDisplayName.SamAccountName
                            $Searchfor = $SearchUserDisplayName.DisplayName
                        }
                    }
                    if ($Null -ne $Searchfor) {     
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "UserSearch" -EventID 10 -EntryType Information -Message "$($User) did search for $($SearchUserName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }                  
                        New-UDGrid -Spacing '1' -Container -Children {
                            New-UDDynamic -Id 'UserSearch' -content {
                                $ADuser = Get-ADUser -Filter "samaccountname -eq '$($SearchUserName)'" -Properties pwdLastSet, CannotChangePassword, Description, CN, DisplayName, UserPrincipalName, MobilePhone, OfficePhone, Company, Department, Title, City, Division, Office, lockedout, passwordexpired, AccountExpirationDate, UserPrincipalName, Enabled, Passwordneverexpires, whenCreated, HomeDrive, HomeDirectory, Manager, Surname, Givenname, emailaddress, HomePhone, StreetAddress, State, postalcode, pobox, fax, SID, PrimaryGroup, OfficePhone, Country, ProfilePath, ScriptPath, DistinguishedName, co
                                $CollectPwdexpdate = (Get-ADUser -Filter "samaccountname -eq '$($SearchUserName)'" -Properties msDS-UserPasswordExpiryTimeComputed).'msDS-UserPasswordExpiryTimeComputed'
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    Show-WhatUserManage   -UserName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    New-PasswordADUserBtn   -RefreshOnClose "UserSearch" -UserName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Compare-ADUserGroupsBtn   -YourFullDomain $YourFullDomain -UserName $SearchUserName -RefreshOnClose "UserSearchGroupList" -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Remove-ADObjectBtn -RefreshOnClose "UserSearchStart"  -ObjectType "User" -ObjectName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    New-RefreshUDElementBtn -RefreshUDElement 'UserSearch'
                                }
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDHTML -Markup "<br>"
                                }
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDHtml -Markup "<b>Information about $($ADuser.DisplayName)</b>"
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text  "Enabled?"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADuser.Enabled)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Set-EnableDisableADAccountBtn -CurrentDescription $ADUser.Description -ObjectStatus $ADuser.Enabled -ObjectToChange "User"  -RefreshOnClose "UserSearch" -ObjectName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Display name"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADUser.DisplayName)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Rename-ADObjectBtn -BoxToSync "txtName"  -WhatToChange "DisplayName"  -RefreshOnClose "UserSearchStart" -CurrentValue $ADUser.DisplayName -ObjectToRename 'User' -ObjectName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "SamAccountName"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADUser.SamAccountName)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Rename-ADObjectBtn -BoxToSync "txtName"  -WhatToChange "SamAccountName"  -RefreshOnClose "UserSearchStart" -CurrentValue $ADUser.SamAccountName -ObjectToRename 'User' -ObjectName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Description"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADUser.Description)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Edit-DescriptionBtn  -RefreshOnClose "UserSearch" -CurrentValue $ADUser.Description -ChangeDescriptionObject 'User' -ChangeObjectName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "CN Name"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADUser.CN)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Rename-ADObjectBtn -BoxToSync "txtName"  -WhatToChange "CN"  -RefreshOnClose "UserSearchStart" -CurrentValue $ADUser.cn -ObjectToRename 'User' -ObjectName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "UPN"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADuser.UserPrincipalName)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Edit-UserUPN -UserName $SearchUserName -CurrentValue $ADuser.UserPrincipalName -RefreshOnClose "UserSearch"  -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "SID"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADuser.SID)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "OU placement"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    New-UDTypography -Text "$($ADuser.DistinguishedName)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Primary group"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    $ConvertPrimaryGroup = $(try { $ADuser.PrimaryGroup | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                    if ($null -ne $ConvertPrimaryGroup) {
                                        New-UDTypography -Text "$($ConvertPrimaryGroup)"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    $ConvertPrimaryGroup = $(try { $ADuser.PrimaryGroup | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                    Edit-PrimaryGroup -ObjectType "User" -ObjectName $SearchUserName -CurrentValue $ConvertPrimaryGroup -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Profile path"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($null -ne $ADuser.ProfilePath) {
                                        New-UDTypography -Text "$($ADuser.ProfilePath)"
                                    }
                                    else {
                                        New-UDTypography -Text "Missing profile path"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Edit-ADUserInfo -ParamToChange "ProfilePath" -UserName $SearchUserName -Currentvalue $ADUser.ProfilePath -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Script path"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($null -ne $ADuser.ScriptPath) {
                                        New-UDTypography -Text "$($ADuser.ScriptPath)"
                                    }
                                    else {
                                        New-UDTypography -Text "Missing script path"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Edit-ADUserInfo -ParamToChange "ScriptPath" -UserName $SearchUserName -Currentvalue $ADUser.ScriptPath -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Home folder"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($null -ne $ADuser.HomeDrive) {
                                        New-UDTypography -Text "$($ADuser.HomeDrive)"
                                    }
                                    else {
                                        New-UDTypography -Text "Missing home folder"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Edit-ADUserInfo -ParamToChange "HomeDrive" -UserName $SearchUserName -Currentvalue $ADUser.HomeDrive -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Search path to home folder"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($null -ne $ADuser.HomeDirectory) {
                                        New-UDTypography -Text "$($ADuser.HomeDirectory)"
                                    }
                                    else {
                                        New-UDTypography -Text "Missing home folder"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Edit-ADUserInfo -ParamToChange "HomeDirectory" -UserName $SearchUserName -Currentvalue $ADUser.HomeDirectory -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Last seen in the domain"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    $GetLastDate = Get-ADLastSeen -ObjectName $SearchUserName -ObjectType "User"
                                    New-UDTypography -Text "$($GetLastDate)"
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Has the account expired?"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($null -ne $ADuser.AccountExpirationDate) {
                                        $today = Get-Date
                                        if ($ADuser.AccountExpirationDate -le $today) {
                                            New-UDTypography -Text "Yes, it did expire $($ADuser.AccountExpirationDate)"
                                        }
                                        else {
                                            New-UDTypography -Text "No, the account expires $($ADuser.AccountExpirationDate)"
                                        }
                                    }
                                    else {
                                        New-UDTypography -Text "This account never expires!"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { 
                                    New-ADAccountExpirationDateBtn   -RefreshOnClose "UserSearch" -UserName $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Are the account locked?"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($ADuser.lockedout -eq $true) {
                                        New-UDTypography -Text "Yes"
                                    }
                                    elseif ($ADuser.lockedout -eq $false) {
                                        New-UDTypography -Text "No"
                                    }
                                    else {
                                        New-UDTypography -Text "N/A"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    if ($ADuser.lockedout -eq $true) {
                                        Unlock-ADUserAccountBtn -RefreshOnClose "UserSearch" -AccountStatus $ADuser.lockedout -UserName $SearchUserName   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Has the password expired?"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if (-Not($CollectPwdexpdate -eq "9223372036854775807")) {
                                        $pwdexpdate = [datetime]::FromFileTime($CollectPwdexpdate)
                                    }
                                    if ($pwdexpdate -like "1601-01-01*" -or $pwdexpdate -like "01/01/1601*") {
                                        New-UDTypography -Text "The user are set to change there password on next login."
                                    }
                                    elseif ($ADuser.Passwordneverexpires -eq $true) {
                                        New-UDTypography -Text "Password never expires"
                                    }
                                    elseif ($ADuser.passwordexpired -eq $true) {
                                        New-UDTypography -Text "Yes, it did expire $($pwdexpdate)"
                                    }
                                    elseif ($ADuser.passwordexpired -eq $false) {
                                        New-UDTypography -Text "No, it expires $($pwdexpdate)"
                                    }
                                    else {
                                        New-UDTypography -Text "N/A"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Does the password expires?"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($ADuser.Passwordneverexpires -eq $true) {
                                        New-UDTypography -Text "No"
                                    }
                                    elseif ($ADuser.Passwordneverexpires -eq $false) {
                                        New-UDTypography -Text "Yes"
                                    }
                                    else {
                                        New-UDTypography -Text "N/A" 
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Set-UserPasswordExpiresBtn -RefreshOnClose "UserSearch" -UserName $SearchUserName -ExpireStatus $ADuser.Passwordneverexpires   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Can the user change there password?"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($ADuser.CannotChangePassword -eq $true) {
                                        New-UDTypography -Text "No"
                                    }
                                    elseif ($ADuser.CannotChangePassword -eq $false) {
                                        New-UDTypography -Text "Yes"
                                    }
                                    else {
                                        New-UDTypography -Text "N/A"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Set-UserChangePasswordBtn -RefreshOnClose "UserSearch" -UserName $SearchUserName -PWChangeStatus $ADuser.CannotChangePassword   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                    New-UDTypography -Text "Must the user change password on next login?"
                                }
                                New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                    if ($ADUser.pwdLastSet -eq "0") {
                                        New-UDTypography -Text "Yes"
                                    }
                                    else {
                                        New-UDTypography -Text "No"
                                    }
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                    Set-UserChangePasswordNextLogin -RefreshOnClose "UserSearch" -UserName $SearchUserName -PWChangeStatus $ADUser.pwdLastSet   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDHtml -Markup "<br>"
                                    New-UDHtml -Markup "<B>Personal and contact information</b>"
                                    New-UDTransition -Id 'UserContactInformation' -Content {
                                        New-UDGrid -Spacing '1' -Container -Children {
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                                New-UDHtml -Markup "<br>"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Givenname and Surname"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.Givenname) $($ADUser.Surname)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "Givenname" -Currentvalue $ADUser.Givenname -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                                Edit-ADUserInfo -ParamToChange "Surname" -Currentvalue $ADUser.Surname -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Mail"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.EmailAddress)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "EmailAddress" -UserName $SearchUserName -Currentvalue $ADUser.EmailAddress -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Home Phone"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.HomePhone)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "HomePhone" -UserName $SearchUserName -Currentvalue $ADUser.homephone -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Mobile Phone"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.MobilePhone)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "MobilePhone" -UserName $SearchUserName -Currentvalue $ADUser.mobilephone -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Office phone"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.OfficePhone)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "OfficePhone" -UserName $SearchUserName -Currentvalue $ADUser.officephone -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Fax"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.FAX)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "FAX" -UserName $SearchUserName -Currentvalue $ADUser.fax -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Street Address"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.StreetAddress)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "StreetAddress" -Currentvalue $ADUser.StreetAddress -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "PO box"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.POBOX)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "POBOX" -Currentvalue $ADUser.POBOX -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "State"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.State)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "State" -Currentvalue $ADUser.State -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "City"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.city)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "City" -Currentvalue $ADUser.City -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Postal code"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.PostalCode)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "PostalCode" -Currentvalue $ADUser.PostalCode -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Country"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.co)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                            }
                                        }
                                    } -Collapse -CollapseHeight 100 -Timeout 1000
                                }

                                New-UDSwitch -OnChange {
                                    Set-UDElement -Id 'UserContactInformation' -Properties @{
                                        in = $EventData -eq 'true'
                                    } 
                                }

                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDHtml -Markup "<br>"
                                    New-UDHtml -Markup "<B>Business information</b>"
                                    New-UDTransition -Id 'BusinessInformation' -Content {
                                        New-UDGrid -Spacing '1' -Container -Children {
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                                New-UDHtml -Markup "<br>"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Company"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.Company)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "Company" -Currentvalue $ADUser.Company -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Title"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.Title)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "Title" -Currentvalue $ADUser.Title -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Division"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.Division)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "Division" -Currentvalue $ADUser.Division -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Department"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.Department)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "Department" -Currentvalue $ADUser.Department -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Office"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                New-UDTypography -Text "$($ADUser.Office)"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                Edit-ADUserInfo -ParamToChange "Office" -Currentvalue $ADUser.Office -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                                New-UDTypography -Text "Manager"
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                                $ConvertManager = $(try { $ADuser.Manager | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                                if ($null -ne $ConvertManager) {
                                                    $ShowManager = Get-Aduser -Identity $ConvertManager -Properties Surname, GivenName
                                                    New-UDTypography -Text "$($ShowManager.GivenName + " " + $ShowManager.Surname + " " + "($($ConvertManager))")"
                                                }
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                                $ConvertManager = $(try { $ADuser.Manager | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                                Edit-ADUserInfo -ParamToChange "Manager" -Currentvalue $ConvertManager -UserName $SearchUserName -RefreshOnClose "UserSearch"   -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                            }
                                        }
                                    } -Collapse -CollapseHeight 100 -Timeout 1000
                                }

                                New-UDSwitch -OnChange {
                                    Set-UDElement -Id 'BusinessInformation' -Properties @{
                                        in = $EventData -eq 'true'
                                    } 
                                }
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDHTML -Markup "<br>"
                                }
                            } -LoadingComponent {
                                New-UDProgress -Circular
                            }
                            New-UDDynamic -Id 'UserSearchGroupList' -content {
                                $SearchUserGroup = (Get-ADUser -Filter "samaccountname -eq '$($SearchUserName)'" -Properties memberOf | Select-Object -ExpandProperty memberOf)
                                $SearchUserGroupData = $SearchUserGroup | Foreach-Object { 
                                    if ($null -ne ($grp = Get-ADGroup -Filter "DistinguishedName -eq '$($_)'" -Properties samAccountName, Info, Description )) {
                                        [PSCustomObject]@{
                                            Name        = $grp.samAccountName
                                            Description = $grp.Description
                                            Info        = $grp.Info
                                        }
                                    }
                                }
                                $SearchUserGroupColumns = @(
                                    New-UDTableColumn -Property Name -Title "Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                                    New-UDTableColumn -Property Description -Title "Description" -IncludeInExport -IncludeInSearch
                                    New-UDTableColumn -Property Info -Title "Info" -IncludeInExport -IncludeInSearch
                                )
                                if ([string]::IsNullOrEmpty($SearchUserGroupData)) {
                                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                        New-UDAlert -Severity 'info' -Text "$($SearchUserName) is not a member of any groups!"
                                    }
                                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                }
                                else {
                                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                        $SearchGroupOption = New-UDTableTextOption -Search "Search"
                                        New-UDTable -Id 'UserSearchTable' -Data $SearchUserGroupData -Columns $SearchUserGroupColumns -DefaultSortDirection "Ascending" -TextOption $SearchGroupOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -Sort -PageSize 10 -PageSizeOptions @(10, 20, 30, 40, 50) -ShowSelection
                                    }
                                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                        New-UDTooltip -TooltipContent {
                                            New-UDTypography -Text "Delete $($SearchUserName) from the selected groups"
                                        } -content { 
                                            New-UDButton -Icon (New-UDIcon -Icon trash_alt) -Size large -OnClick {
                                                $UserSearchTable = Get-UDElement -Id "UserSearchTable"
                                                $UserSearchLog = @($UserSearchTable.selectedRows.name)
                                                if ($null -ne $UserSearchTable.selectedRows.name) {
                                                    try {
                                                        @($UserSearchTable.selectedRows.name.ForEach( { 
                                                                    Remove-ADGroupMember -Identity $_ -Members $SearchUserName -Confirm:$False
                                                                    if ($ActiveEventLog -eq "True") {
                                                                        Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($SearchUserName) to $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                                    }
                                                                } ) )

                                                        Show-UDToast -Message "$($SearchUserName) are not a member of $($UserSearchLog -join ",") anymore!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                        Sync-UDElement -Id 'UserSearchGroupList'
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
                                New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 1 -Children { }
                                New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 5 -Children { 
                                    New-UDTextbox -Id "txtSearchUserADD" -Icon (New-UDIcon -Icon 'users') -Label "Enter group name" -FullWidth
                                }
                                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 4 -Children { 
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Add $($SearchUserName) to the group"
                                    } -Content { 
                                        New-UDButton -Icon (New-UDIcon -Icon user_plus) -size large -Onclick { 
                                            $SearchUserADGroup = (Get-UDElement -Id "txtSearchUserADD").value
                                            $SearchUserADGroup = $SearchUserADGroup.trim()

                                            $SearchUserObj = $(try { Get-ADGroup -Filter "samaccountname -eq '$($SearchUserADGroup)'" } catch { $Null })

                                            if ($Null -ne $SearchUserObj) { 
                                                try {
                                                    Add-ADGroupMember -Identity $SearchUserADGroup -Members $SearchUserName
                                                    Show-UDToast -Message "$($SearchUserName) are now a member of $($SearchUserADGroup)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    if ($ActiveEventLog -eq "True") {
                                                        Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($SearchUserName) to $($SearchUserADGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                    }
                                                    Sync-UDElement -Id 'UserSearchGroupList'
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }
                                            else {
                                                Show-UDToast -Message "Can't find $($SearchUserADGroup) in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                    Add-MultiGroupBtn -RefreshOnClose "UserSearchGroupList"  -ObjToAdd $SearchUserName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                            } -LoadingComponent {
                                New-UDProgress -Circular
                            }
                        }
                    }
                    else { 
                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                            New-UDAlert -Severity 'error' -Text "Could not find $($SearchUserName) in the AD!"
                        }
                    }
                }
            } -LoadingComponent {
                New-UDProgress -Circular
            }
        }
        New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
    }
}