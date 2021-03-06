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

New-UDGrid -Spacing '1' -Container -Children {
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
    New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 12 -SmallSize 12 -Children {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 5 -MediumSize 5 -SmallSize 7 -Children {
                New-UDAutocomplete -id "txtComputerNameStart" -Icon (New-UDIcon -Icon 'desktop') -Label "Enter computer name" -OnLoadOptions {
                    If ($Body.length -ge 3) {
                        $Session:SelectedUser = Get-ADObject -LDAPFilter "(&(objectCategory=computer)(anr=$Body))" -SearchBase $OUComputerPath -Properties name
                        $Session:SelectedUser | Select-Object -ExpandProperty name | ConvertTo-Json
                    }
                } -OnChange {
                    $Session:SelectedUser = $Body
                }
            }
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 4 -Children { 
                New-UDTooltip -TooltipContent {
                    New-UDTypography -Text "Search"
                } -content { 
                    New-UDButton -Id "MainSearch" -Icon (New-UDIcon -Icon 'search') -Size large -OnClick {
                        Sync-UDElement -Id 'ComputerSearchStart'
                    }
                }
            }
            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 1 -Children { }
        }
    }
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
}

New-UDGrid -Spacing '1' -Container -Children {
    New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -Children { }
    New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 12 -SmallSize 12 -Children {
        New-UDCard -Content {
            New-UDDynamic -Id 'ComputerSearchStart' -content {
                $ComputerName = (Get-UDElement -Id "txtComputerNameStart").value
                if (-Not([string]::IsNullOrEmpty($ComputerName))) {
                    $ComputerName = $ComputerName.Replace("CN=", "").Split(",") | Select-Object -First 1
                    $ComputerName = $ComputerName.trim()
                }

                if ([string]::IsNullOrEmpty($ComputerName)) {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDAlert -Severity 'error' -Text "You must enter a computername!"
                    }
                }
                else {
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "ComputerSearch" -EventID 10 -EntryType Information -Message "$($User) did search for $($ComputerName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    New-UDGrid -Spacing '1' -Container -Children {
                        New-UDDynamic -Id 'ComputerSearch' -content {
                            if (Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue) {
                                $SystInfo = Get-SysInfo -Computer $ComputerName                                  
                            }
                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($ComputerName), the administrating options are limited!"
                                }
                            }
                            $SearchADComputer = Get-ADComputer -Filter "samaccountname -eq '$($ComputerName)$'"  -Properties name, CN, DisplayName, DNSHostName, OperatingSystem, Description, CanonicalName, DistinguishedName, Created, SamAccountName, OperatingSystemVersion, whenChanged, SID, IPv4Address, IPv6Address, PrimaryGroup, ManagedBy, Location, Enabled, LastLogonDate
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                Restart-ADComputer -Computer $ComputerName
                                Ping-ADComputer  -Computer $ComputerName
                                Show-MonitorInfoBtn  -Computer $ComputerName
                                Compare-ComputerGrpsBtn  -Computer $ComputerName -YourFullDomain $YourFullDomain -RefreshOnClose "ComputerSearchGroupList"
                                Show-ProcessTableBtn  -Computer $ComputerName
                                Show-ServicesTableBtn  -Computer $ComputerName
                                Show-NetAdpBtn  -Computer $ComputerName
                                Show-ScheduleTaskTableBtn  -Computer $ComputerName
                                Show-InstalledDriversBtn  -Computer $ComputerName
                                Show-AutostartTableBtn  -Computer $ComputerName
                                Show-InstalledSoftwareBtn  -Computer $ComputerName
                                Remove-ADObjectBtn -RefreshOnClose "ComputerSearchStart"  -ObjectType "Computer" -ObjectName $ComputerName
                                Remove-TempFilesClientBtn -CurrentHost $CurrentHost -RefreshOnClose "ComputerSearch" -Computer $ComputerName
                                New-RefreshUDElementBtn -RefreshUDElement 'ComputerSearch'
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children {
                                New-UDSelect -Label "User impact - $($SystInfo.Computer.UserName)" -id 'UserImpact' -FullWidth -Option {
                                    New-UDSelectOption -Name 'Select function...' -Value 1
                                    New-UDSelectOption -Name "Logout $($SystInfo.Computer.UserName) from $($ComputerName)" -Value 2
                                    New-UDSelectOption -Name "Delete user profiles from $($ComputerName)" -Value 3
                                    New-UDSelectOption -Name "Delete Edge settings for users on $($ComputerName)" -Value 4
                                    New-UDSelectOption -Name "Delete Chrome settings for users on $($ComputerName)" -Value 5
                                } -DefaultValue 1
                            }
                            New-UDGrid -Item -ExtraLargeSize 1 -LargeSize 1 -MediumSize 1 -SmallSize 1 -Children {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Open the selected function"
                                } -content { 
                                    New-UDButton -Text "Open" -size small -Onclick {
                                        $UserImpactMenu = Get-UDElement -Id 'UserImpact'
                                        if ([string]::IsNullOrEmpty($UserImpactMenu.value) -or $UserImpactMenu.value -eq 1) {
                                            Show-UDToast -Message "You need to select an option!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                        else {
                                            switch ($UserImpactMenu.Value) {
                                                2 {
                                                    if ([string]::IsNullOrEmpty($SystInfo.Computer.UserName)) {
                                                        Show-UDToast -Message "It's no one logged in on $($ComputerName)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                                    }
                                                    else {
                                                        Disconnect-UserFromComputer -CurrentLoggedInUser $SystInfo.Computer.UserName -Computer $ComputerName
                                                    }
                                                }
                                                3 {
                                                    Remove-UserProfilesBtn  -Computer $ComputerName -YourDomain $YourDomain.ToUpper()
                                                }
                                                4 {
                                                    Remove-EdgeSettings  -Computer $ComputerName
                                                }
                                                5 {
                                                    Remove-ChromeSettings -Computer $ComputerName
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 8 -MediumSize 8 -SmallSize 8 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHTML -Markup "<br>"
                            }
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHtml -Markup "<b>Information about $($SearchADComputer.Name)</b>"
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Enabled?"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                if ($SearchADComputer.Enabled -eq "True") {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Yes, $($ComputerName) are enabled."
                                    } -content { 
                                        New-UDIcon -Icon 'check' -Size lg -Style @{color = 'rgba(80, 184, 72, 0.6)' }
                                    }
                                }
                                elseif ($SearchADComputer.Enabled -eq "False") {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "No, $($ComputerName) are disabled."
                                    } -content { 
                                        New-UDIcon -Icon 'times' -Size lg -Style @{color = 'rgba(255, 0, 0, 0.6)' }
                                    }
                                }
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Set-EnableDisableADAccountBtn -CurrentDescription $SearchADComputer.Description -ObjectStatus $SearchADComputer.Enabled -ObjectToChange "Computer"  -RefreshOnClose "ComputerSearch" -ObjectName $ComputerName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Display name"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADComputer.DisplayName)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Rename-ADObjectBtn -BoxToSync "txtComputerNameStart"  -WhatToChange "DisplayName"  -RefreshOnClose "ComputerSearchStart" -CurrentValue $SearchADComputer.DisplayName -ObjectToRename 'Computer' -ObjectName $ComputerName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "CN name"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADComputer.CN)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Rename-ADObjectBtn -BoxToSync "txtComputerNameStart"  -WhatToChange "CN"  -RefreshOnClose "ComputerSearchStart" -CurrentValue $SearchADComputer.CN -ObjectToRename 'Computer' -ObjectName $SearchADComputer.samaccountname
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "SamAccountName"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADComputer.SamAccountName)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                Rename-ADObjectBtn -BoxToSync "txtComputerNameStart"  -WhatToChange "SamAccountName"  -RefreshOnClose "ComputerSearchStart" -CurrentValue $SearchADComputer.SamAccountName -ObjectToRename 'Computer' -ObjectName $ComputerName
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Description"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADComputer.Description)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { 
                                Edit-DescriptionBtn  -RefreshOnClose "ComputerSearch" -CurrentValue $SearchADComputer.Description -ChangeDescriptionObject 'Computer' -ChangeObjectName $SearchADComputer.samaccountname
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "SID"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADComputer.SID)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "OU Placement"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADComputer.DistinguishedName)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Location"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$($SearchADComputer.Location)"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Primary Group"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                $ConvertPrimaryGroup = $(try { $SearchADComputer.PrimaryGroup | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                if ($null -ne $ConvertPrimaryGroup) {
                                    New-UDTypography -Text "$($ConvertPrimaryGroup)"
                                }
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                $ConvertPrimaryGroup = $(try { $SearchADComputer.PrimaryGroup | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                Edit-PrimaryGroup -ObjectType "Computer" -ObjectName $SearchADComputer.samaccountname -CurrentValue $ConvertPrimaryGroup -RefreshOnClose "ComputerSearch"
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Managed By"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                $ComputerManagedBy = $(try { $SearchADComputer.ManagedBy | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                if ($null -ne $ComputerManagedBy) {
                                    New-UDTypography -Text "$($ComputerManagedBy)"
                                }
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                $ComputerManagedBy = $(try { $SearchADComputer.ManagedBy | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                Edit-ManagedByBtn -CurrentValue $ComputerManagedBy -ObjectType "Computer" -ObjectName $ComputerName -RefreshOnClose "ComputerSearch"
                            }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Object was created"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$(($SearchADComputer.Created).ToString("yyyy-MM-dd HH:mm"))"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Object was last changed"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                New-UDTypography -Text "$(($SearchADComputer.whenChanged).ToString("yyyy-MM-dd HH:mm"))"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                            New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                New-UDTypography -Text "Last seen in the domain"
                            }
                            New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                $GetLastDate = Get-ADLastSeen -ObjectName $SearchADComputer.samaccountname -ObjectType "Computer"
                                New-UDTypography -Text "$(($GetLastDate).ToString("yyyy-MM-dd HH:mm"))"
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }

                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHtml -Markup "<br>"
                                New-UDHtml -Markup "<B>OS information</b>"
                                New-UDTransition -Id 'OSInformation' -Content {
                                    New-UDGrid -Spacing '1' -Container -Children {
                                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                            New-UDHtml -Markup "<br>"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Version"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            New-UDTypography -Text "$($SearchADComputer.OperatingSystem) Version: $($SearchADComputer.OperatingSystemVersion)"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Installation date"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$(($SystInfo.OS.InstallDate).ToString("yyyy-MM-dd HH:mm"))"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Up-Time"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.UpTime.UpDays)$($SystInfo.UpTime.UpHours)$($SystInfo.UpTime.UpMinutes)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Current logged in user"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if (([string]::IsNullOrEmpty($SystInfo.Computer.UserName))) {
                                                New-UDTypography -Text "No user are logged in"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.Computer.UserName)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Last logged in user"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            Get-UserLoggInTime -Computer $ComputerName
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                    }
                                } -Collapse -CollapseHeight 100 -Timeout 1000
                            }

                            New-UDSwitch -OnChange {
                                Set-UDElement -Id 'OSInformation' -Properties @{
                                    in = $EventData -eq 'true'
                                } 
                            }

                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHtml -Markup "<B>Hardware information</b>"
                                New-UDTransition -Id 'HardwareInformation' -Content {
                                    New-UDGrid -Spacing '1' -Container -Children {
                                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                            New-UDHtml -Markup "<br>"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Manufacturer"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.Computer.Manufacturer)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Model"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.Computer.SystemFamily)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.Computer.Model)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Serial number"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.BIOS.SerialNumber)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "Bios Version"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.BIOS.BIOSVersion)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "RAM"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.RAM)GB"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "C:"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children { 
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.HDD.Free)GB free of $($SystInfo.HDD.total)GB"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                    }
                                } -Collapse -CollapseHeight 100 -Timeout 1000
                            }

                            New-UDSwitch -OnChange {
                                Set-UDElement -Id 'HardwareInformation' -Properties @{
                                    in = $EventData -eq 'true'
                                } 
                            }


                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHtml -Markup "<B>Network information</b>"
                                New-UDTransition -Id 'NetworkInformation' -Content {
                                    New-UDGrid -Spacing '1' -Container -Children {
                                        New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                            New-UDHtml -Markup "<br>"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "DNS/Hostname"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            New-UDTypography -Text "$($SearchADComputer.DNSHostName)"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "IPv4 Address"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            New-UDTypography -Text "$($SearchADComputer.IPv4Address)"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "IPv6 Address"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            New-UDTypography -Text "$($SearchADComputer.IPv6Address)"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                        New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children {
                                            New-UDTypography -Text "MAC address"
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children {
                                            if ([string]::IsNullOrEmpty($SystInfo)) {
                                                New-UDTypography -Text "N/A"
                                            }
                                            else {
                                                New-UDTypography -Text "$($SystInfo.NetworkMac)"
                                            }
                                        }
                                        New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                                    }
                                } -Collapse -CollapseHeight 100 -Timeout 1000
                            }

                            New-UDSwitch -OnChange {
                                Set-UDElement -Id 'NetworkInformation' -Properties @{
                                    in = $EventData -eq 'true'
                                } 
                            }

                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHTML -Markup "<br>"
                            }
                        } -LoadingComponent {
                            New-UDProgress -Circular
                        }
                        New-UDDynamic -Id 'ComputerSearchGroupList' -content {
                            $SearchComputerGroup = Get-ADPrincipalGroupMembership -Identity "$($ComputerName)$" -ResourceContextServer $YourFullDomain | Select-Object name -ExpandProperty name
                            $SearchComputerGroupData = $SearchComputerGroup | Foreach-Object { 
                                if ($null -ne ($grpComputer = Get-ADGroup -Filter "Name -eq '$($_)'" -Properties name, samAccountName, Description, info )) {
                                    [PSCustomObject]@{
                                        Name2       = $grpComputer.name
                                        Name        = $grpComputer.samAccountName
                                        Description = $grpComputer.Description
                                        Info        = $grpComputer.Info
                                    }
                                }
                            }

                            $SearchComputerGroupColumns = @(
                                New-UDTableColumn -Property " " -Title " " -render {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Remove $($ComputerName) from $($EventData.Name)"
                                    } -content { 
                                        New-UDIconButton -Icon (New-UDIcon -Icon trash_alt -Style @{ color = 'rgba(0, 151, 207, 0.6)' }) -Size small -Onclick {
                                            try {
                                                Remove-ADGroupMember -Identity $EventData.Name -Members "$($ComputerName)$" -Confirm:$False
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "RemoveFromGroup" -EventID 10 -EntryType Information -Message "$($User) did remove $($ComputerName) from $($EventData.Name)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($ComputerName) are now removed from $($EventData.Name2)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                                Sync-UDElement -Id 'ComputerSearchGroupList'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                                Break
                                            }
                                        }
                                    }
                                }
                                New-UDTableColumn -Property Name2 -Title "Group name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                                New-UDTableColumn -Property Name -Title "SamAccountName" -IncludeInExport -IncludeInSearch -Hidden
                                New-UDTableColumn -Property Description -Title "Description" -IncludeInExport -IncludeInSearch
                                New-UDTableColumn -Property Info -Title "Info" -IncludeInExport -IncludeInSearch
                            )

                            if ([string]::IsNullOrEmpty($SearchComputerGroupData)) {
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    New-UDAlert -Severity 'info' -Text "$($ComputerName) are not a member of any groups"
                                }
                            }
                            else {
                                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                    $SearchComputerOption = New-UDTableTextOption -Search "Search"
                                    New-UDTable -Id 'ComputerSearchTable' -Data $SearchComputerGroupData -Columns $SearchComputerGroupColumns -DefaultSortDirection "Ascending" -TextOption $SearchComputerOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -Sort -PageSize 10 -PaginationLocation top -PageSizeOptions @(10, 20, 30, 40, 50) -ShowSelection
                                }
                            }
                            if (-Not([string]::IsNullOrEmpty($SearchComputerGroupData))) {
                                New-UDGrid -Item -ExtraLargeSize 8 -LargeSize 6 -MediumSize 6 -SmallSize 2 -Children {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Remove $($ComputerName) from the selected groups"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon trash_alt) -Size large -OnClick {
                                            $ComputerSearchTable = Get-UDElement -Id "ComputerSearchTable"
                                            $ComputerSearchLog = @($ComputerSearchTable.selectedRows.name)
                                            if ($Null -ne $ComputerSearchTable.selectedRows.name) {                  
                                                try {
                                                    @($ComputerSearchTable.selectedRows.name.ForEach( { 
                                                                Remove-ADGroupMember -Identity $_ -Members "$($ComputerName)$"  -Confirm:$False
                                                                if ($ActiveEventLog -eq "True") {
                                                                    Write-EventLog -LogName $EventLogName -Source "RemoveFromGroup" -EventID 10 -EntryType Information -Message "$($User) did remove $($ComputerName) from $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                                }
                                                            } ) )
                                                    Show-UDToast -Message "$($ComputerName) are not a member of $($ComputerSearchLog -join ",") anymore!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Sync-UDElement -Id 'ComputerSearchGroupList'
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
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
                            else {
                                New-UDGrid -Item -ExtraLargeSize 8 -LargeSize 6 -MediumSize 6 -SmallSize 2 -Children { }
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 3 -MediumSize 3 -SmallSize 5 -Children {  
                                New-UDAutocomplete -id "txtSearchComputerADD" -Icon (New-UDIcon -Icon 'Users') -Label "Enter group name" -OnLoadOptions {
                                    If ($Body.length -ge 3) {
                                        $Session:SelectedGroup = Get-ADObject -LDAPFilter "(&(objectCategory=group)(anr=$Body))" -SearchBase $OUGrpPath -Properties SamAccountName
                                        $Session:SelectedGroup | Select-Object -ExpandProperty SamAccountName | ConvertTo-Json
                                    }
                                } -OnChange {
                                    $Session:SelectedGroup = $Body
                                }
                            }
                            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 3 -MediumSize 3 -SmallSize 5 -Children {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Add $($ComputerName) to the group"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon user_plus) -size large -Onclick { 
                                        $SearchComputerADGroup = (Get-UDElement -Id "txtSearchComputerADD").value
                                        if (-Not([string]::IsNullOrEmpty($SearchComputerADGroup))) {
                                            $SearchComputerADGroup = $SearchComputerADGroup.Replace("CN=", "").Split(",") | Select-Object -First 1
                                            $SearchComputerADGroup = $SearchComputerADGroup.trim()
                                        }

                                        if (-Not([string]::IsNullOrEmpty($SearchComputerADGroup))) {
                                            if ((Get-ADComputer -Filter "samaccountname -eq '$($ComputerName)$'" -SearchBase $OUComputerPath -Properties memberof).memberof -like "$($SearchComputerADGroup)") {
                                                Show-UDToast -Message "Computer $($ComputerName) are already a member of $($SearchComputerADGroup)!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                                Break
                                            }
                                            else {
                                                try {
                                                    Add-ADGroupMember -Identity $SearchComputerADGroup -Members "$($ComputerName)$" 
                                                    Show-UDToast -Message "$($ComputerName) are now a member of $($SearchComputerADGroup)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Sync-UDElement -Id 'ComputerSearchGroupList'
                                                    if ($ActiveEventLog -eq "True") {
                                                        Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($ComputerName) to $($SearchComputerADGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                    }
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }
                                        }
                                        else {
                                            Show-UDToast -Message "You have either missed to enter a group name or the group are missing in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                            Break        
                                        }
                                    }
                                }
                                    
                                Add-MultiGroupBtn -RefreshOnClose "ComputerSearchGroupList"  -ObjToAdd "$($ComputerName)$"
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Refresh the group member list!"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon sync_alt) -Size large -OnClick {
                                        Sync-UDElement -Id "ComputerSearchGroupList"
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