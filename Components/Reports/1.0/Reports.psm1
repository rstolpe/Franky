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

function Get-UserReports {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    Show-UDModal -Header { "Generate user reports" } -Content {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children {
                New-UDSelect -id 'SelectUserReportType' -FullWidth -Option {
                    New-UDSelectOption -Name 'Select report...' -Value 1
                    New-UDSelectOption -Name 'Disabled accounts' -Value "disabled"
                    New-UDSelectOption -Name 'Locked accounts' -Value "locked"
                    New-UDSelectOption -Name 'Password has expired' -Value "passwordexpired"
                    New-UDSelectOption -Name 'Expired user accounts' -Value "accountexpired"
                }
            }
            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                New-UDButton -Text "Generate" -size small -Onclick {
                    $SelectUserReportType = Get-UDElement -Id 'SelectUserReportType'

                    if ([string]::IsNullOrEmpty($SelectUserReportType.value) -or $SelectUserReportType.value -eq 1) {
                        Show-UDToast -Message "You need to select an option!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        Sync-UDElement -Id 'UserReport'
                    }
                }
            }
            New-UDGrid -Item -ExtraLargeSize 7 -LargeSize 7 -MediumSize 7 -SmallSize 7 -Children { }
            New-UDDynamic -Id 'UserReport' -content {
                $SelectUserReportType = Get-UDElement -Id 'SelectUserReportType'
                    
                switch ($SelectUserReportType.value) {
                    disabled {
                        $AccountReport = Search-ADAccount -AccountDisabled -UsersOnly | Select-Object samaccountname, UserPrincipalName, DistinguishedName | Foreach-Object { 
                            [PSCustomObject]@{
                                SamAccountName    = $_.SamAccountName
                                UserPrincipalName = $_.UserPrincipalName
                                DistinguishedName = $_.DistinguishedName
                            }
                        }
                    }
                    locked {
                        $AccountReport = Search-ADAccount -LockedOut -UsersOnly | Select-Object samaccountname, UserPrincipalName, DistinguishedName | Foreach-Object { 
                            [PSCustomObject]@{
                                SamAccountName    = $_.SamAccountName
                                UserPrincipalName = $_.UserPrincipalName
                                DistinguishedName = $_.DistinguishedName
                            }
                        }
                    }
                    passwordexpired {
                        $AccountReport = Search-ADAccount -PasswordExpired -UsersOnly | Select-Object samaccountname, UserPrincipalName, DistinguishedName | Select-Object samaccountname, UserPrincipalName, DistinguishedName | Foreach-Object { 
                            [PSCustomObject]@{
                                SamAccountName    = $_.SamAccountName
                                UserPrincipalName = $_.UserPrincipalName
                                DistinguishedName = $_.DistinguishedName
                            }
                        }
                    }
                    accountexpired {
                        $AccountReport = Search-ADAccount -AccountExpired -UsersOnly | Select-Object samaccountname, UserPrincipalName, DistinguishedName, AccountExpirationDate | Select-Object samaccountname, UserPrincipalName, DistinguishedName, AccountExpirationDate | Foreach-Object { 
                            [PSCustomObject]@{
                                SamAccountName        = $_.SamAccountName
                                UserPrincipalName     = $_.UserPrincipalName
                                DistinguishedName     = $_.DistinguishedName
                                AccountExpirationDate = $_.AccountExpirationDate
                            }
                        }
                    }
                }
                        
                $MoreADUserColumns = @(
                    New-UDTableColumn -Property SamAccountName -Title "SamAccountName" -IncludeInSearch -IncludeInExport -DefaultSortColumn
                    New-UDTableColumn -Property UserPrincipalName -Title "UPN" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property DistinguishedName -Title "DistinguishedName" -IncludeInSearch -IncludeInExport
                    if ($SelectUserReportType.value -eq "accountexpired") {
                        New-UDTableColumn -Property AccountExpirationDate -Title "AccountExpirationDate" -IncludeInSearch -IncludeInExport
                    }
                )
                if ($Null -ne $AccountReport) {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "Report$($SelectUserReportType.value)Users" -EventID 10 -EntryType Information -Message "$($User) has generated a report over $($SelectUserReportType.value) users`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        New-UDTable -Id 'MoreADTable' -Data $AccountReport -Columns $MoreADUserColumns -DefaultSortDirection “Ascending” -Export -ExportOption "xlsx, PDF, CSV" -ShowSearch -ShowPagination -Dense -Sort -PageSize 20 -PageSizeOptions @(30, 40, 50, 60)
                    }
                }
                else {
                    New-UDGrid -Item -LargeSize 12 -ExtraSmallSize 12 -Content {
                        New-UDAlert -Severity 'info' -Text "Could not generate a report, it's likley because you don't have anything to report"
                    }
                }
            } -LoadingComponent {
                New-UDProgress -Circular
            }
        }
    } -Footer {
        New-UDButton -Text "Refresh" -OnClick {
            Sync-UDElement -id "UserReport"
        }    
        New-UDButton -Text "Close" -OnClick {
            Hide-UDModal
        }                         
    } -FullWidth -MaxWidth 'lg' -Persistent
}

function Get-ComputerReport {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    Show-UDModal -Header { "Generate computer reports" } -Content {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children {
                New-UDSelect -id 'SelectComputerReportType' -FullWidth -Option {
                    New-UDSelectOption -Name 'Select report...' -Value 1
                    New-UDSelectOption -Name 'Disabled computers' -Value "disabled"
                }
            }
            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                New-UDButton -Text "Generate" -size small -Onclick {
                    $SelectComputerReportType = Get-UDElement -Id 'SelectComputerReportType'

                    if ([string]::IsNullOrEmpty($SelectComputerReportType.value) -or $SelectComputerReportType.value -eq 1) {
                        Show-UDToast -Message "You need to select an option!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        Sync-UDElement -Id 'ComputerReport'
                    }
                }
            }
            New-UDGrid -Item -ExtraLargeSize 7 -LargeSize 7 -MediumSize 7 -SmallSize 7 -Children { }
            New-UDDynamic -Id 'ComputerReport' -content {
                $SelectComputerReportType = Get-UDElement -Id 'SelectComputerReportType'
                    
                switch ($SelectComputerReportType.value) {
                    disabled {
                        $ComputerReport = Search-ADAccount -AccountDisabled -ComputersOnly | Select-Object name, samaccountname, DistinguishedName | Foreach-Object { 
                            [PSCustomObject]@{
                                Name              = $_.Name
                                SamAccountName    = $_.SamAccountName
                                DistinguishedName = $_.DistinguishedName
                            }
                        }
                    }
                }

                $Columns = @(
                    New-UDTableColumn -Property Name -Title "Name" -IncludeInSearch -IncludeInExport -DefaultSortColumn
                    New-UDTableColumn -Property SamAccountName -Title "SamAccountName" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property DistinguishedName -Title "DistinguishedName" -IncludeInSearch -IncludeInExport
                )
                if ($Null -ne $ComputerReport) {
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "Report$($SelectComputerReportType.value)Computer" -EventID 10 -EntryType Information -Message "$($User) has generated a report over $($SelectComputerReportType.value) computers`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTable -Id 'ComputerReportTable' -Data $ComputerReport -Columns $Columns -DefaultSortDirection “Ascending” -Export -ExportOption "xlsx, PDF, CSV" -ShowSearch -ShowPagination -Dense -Sort -PageSize 20 -PageSizeOptions @(30, 40, 50, 60)
                    }
                }
                else {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDAlert -Severity 'info' -Text "Could not generate a report, it's likley because you don't have anything to report"
                    }
                }
            } -LoadingComponent {
                New-UDProgress -Circular
            }
        }
    } -Footer {
        New-UDButton -Text "Refresh" -OnClick {
            Sync-UDElement -id "Report"
        }    
        New-UDButton -Text "Close" -OnClick {
            Hide-UDModal
        }                         
    } -FullWidth -MaxWidth 'lg' -Persistent
}

function Get-ReportGroups {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    Show-UDModal -Header { "Generate group reports" } -Content {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children {
                New-UDSelect -id 'SelectGroupReportType' -FullWidth -Option {
                    New-UDSelectOption -Name 'Select report...' -Value 1
                    New-UDSelectOption -Name 'Empty groups' -Value "Empty"
                }
            }
            New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children {
                New-UDButton -Text "Generate" -size small -Onclick {
                    $SelectGroupReportType = Get-UDElement -Id 'SelectGroupReportType'

                    if ([string]::IsNullOrEmpty($SelectGroupReportType.value) -or $SelectGroupReportType.value -eq 1) {
                        Show-UDToast -Message "You need to select an option!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        Sync-UDElement -Id 'GroupReport'
                    }
                }
            }
            New-UDGrid -Item -ExtraLargeSize 7 -LargeSize 7 -MediumSize 7 -SmallSize 7 -Children { }
            New-UDDynamic -Id 'GroupReport' -content {
                $SelectGroupReportType = Get-UDElement -Id 'SelectGroupReportType'

                switch ($SelectGroupReportType.value) {
                    Empty {
                        $GroupReport = Get-ADGroup -Filter * -Properties Members, ManagedBy, name, samaccountname, DistinguishedName, description | Where-Object { -not $_.members } | Select-Object ManagedBy, name, samaccountname, DistinguishedName, description | Foreach-Object { 
                            [PSCustomObject]@{
                                Name              = $_.Name
                                SamAccountName    = $_.SamAccountName
                                ManagedBy         = $_.ManagedBy
                                DistinguishedName = $_.DistinguishedName
                                description       = $_.description
                            }
                        }
                    }
                }

                $Columns = @(
                    New-UDTableColumn -Property Name -Title "Name" -IncludeInSearch -IncludeInExport -DefaultSortColumn
                    New-UDTableColumn -Property SamAccountName -Title "SamAccountName" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property description -Title "Description" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property ManagedBy -Title "Managed by" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property DistinguishedName -Title "DistinguishedName" -IncludeInSearch -IncludeInExport
                )

                if ($Null -ne $GroupReport) {
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "Report$($SelectGroupReportType.value)Groups" -EventID 10 -EntryType Information -Message "$($User) has generated a report over $($SelectGroupReportType.value) groups`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTable -Id 'GroupReportTable' -Data $GroupReport -Columns $Columns -DefaultSortDirection “Ascending” -Export -ExportOption "xlsx, PDF, CSV" -ShowSearch -ShowPagination -Dense -Sort -PageSize 20 -PageSizeOptions @(30, 40, 50, 60)
                    }
                }
                else {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDAlert -Severity 'info' -Text "Could not generate a report, it's likley because you don't have anything to report"
                    }
                }
            } -LoadingComponent {
                New-UDProgress -Circular
            }
        }
    } -Footer {
        New-UDButton -Text "Refresh" -OnClick {
            Sync-UDElement -id "Report"
        }    
        New-UDButton -Text "Close" -OnClick {
            Hide-UDModal
        }                         
    } -FullWidth -MaxWidth 'xl' -Persistent
}


Export-ModuleMember -Function "Get-UserReports", "Get-ComputerReport", "Get-ReportGroups"