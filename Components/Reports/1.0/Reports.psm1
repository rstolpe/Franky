﻿<#
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

function Get-UserReports {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory)][string]$ReportType,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    Show-UDModal -Header { "Generate report over $($ReportType) accounts" } -Content {
        if ($ActiveEventLog -eq "True") {
            Write-EventLog -LogName $EventLogName -Source "Report$($ReportType)Users" -EventID 10 -EntryType Information -Message "$($User) has generated a report over $($ReportType) users`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
        }
        New-UDDynamic -Id 'Report' -content {
            New-UDGrid -Spacing '1' -Container -Content {
                switch ($ReportType) {
                    Disbled {
                        $AccountReport = Get-ADUser -Filter { (Enabled -eq $False) } -Properties samaccountname, UserPrincipalName, GivenName, Surname, displayname | Select-Object GivenName, Surname, samaccountname, UserPrincipalName, displayname | Foreach-Object { 
                            [PSCustomObject]@{
                                Name              = $_.GivenName + " " + $_.Surname
                                DisplayName       = $_.DisplayName
                                SamAccountName    = $_.SamAccountName
                                UserPrincipalName = $_.UserPrincipalName
                            }
                        }
                    }
                    Locked {
                        $AccountReport = Get-ADUser -Filter { (lockedout -eq $False) } -Properties samaccountname, UserPrincipalName, GivenName, Surname, displayname | Select-Object GivenName, Surname, samaccountname, UserPrincipalName, displayname | Foreach-Object { 
                            [PSCustomObject]@{
                                Name              = $_.GivenName + " " + $_.Surname
                                DisplayName       = $_.DisplayName
                                SamAccountName    = $_.SamAccountName
                                UserPrincipalName = $_.UserPrincipalName
                            }
                        }
                    }
                    PasswordExpired {
                        $AccountReport = Get-ADUser -Filter { (PasswordExpired -eq $true) } -Properties samaccountname, UserPrincipalName, GivenName, Surname, displayname | Select-Object GivenName, Surname, samaccountname, UserPrincipalName, displayname | Foreach-Object { 
                            [PSCustomObject]@{
                                Name              = $_.GivenName + " " + $_.Surname
                                DisplayName       = $_.DisplayName
                                SamAccountName    = $_.SamAccountName
                                UserPrincipalName = $_.UserPrincipalName
                            }
                        }
                    }
                }
                $MoreADUserColumns = @(
                    New-UDTableColumn -Property Name -Title "Name" -IncludeInSearch -IncludeInExport -DefaultSortColumn
                    New-UDTableColumn -Property DisplayName -Title "DisplayName" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property SamAccountName -Title "SamAccountName" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property UserPrincipalName -Title "UPN" -IncludeInSearch -IncludeInExport
                )

                New-UDGrid -Item -Size 12 -Content {
                    New-UDTable -Id 'MoreADTable' -Data $AccountReport -Columns $MoreADUserColumns -DefaultSortDirection “Ascending” -ShowExport -ShowSearch -ShowPagination -Dense -Sort -PageSize 20 -PageSizeOptions @(30, 40, 50, 60)
                }
            }
        } -LoadingComponent {
            New-UDProgress -Circular
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

function Get-ComputerReport {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    Show-UDModal -Header { "Generate report over disabled computer accounts" } -Content {
        if ($ActiveEventLog -eq "True") {
            Write-EventLog -LogName $EventLogName -Source "ReportDisabledComputer" -EventID 10 -EntryType Information -Message "$($User) has generated a report over disabled computers`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
        }
        New-UDDynamic -Id 'Report' -content {
            New-UDGrid -Spacing '1' -Container -Content {
                $ComputerReport = Get-ADComputer -Filter { (Enabled -eq $False) } -Properties name, samaccountname, DistinguishedName, managedby, description | Select-Object name, samaccountname, DistinguishedName, managedby, description | Foreach-Object { 
                    [PSCustomObject]@{
                        Name              = $_.Name
                        SamAccountName    = $_.SamAccountName
                        managedby         = $_.managedby
                        DistinguishedName = $_.DistinguishedName
                        description       = $_.description
                    }
                }

                $Columns = @(
                    New-UDTableColumn -Property Name -Title "Name" -IncludeInSearch -IncludeInExport -DefaultSortColumn
                    New-UDTableColumn -Property SamAccountName -Title "SamAccountName" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property description -Title "Description" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property managedby -Title "Managed by" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property DistinguishedName -Title "DistinguishedName" -IncludeInSearch -IncludeInExport
                )

                New-UDGrid -Item -Size 12 -Content {
                    New-UDTable -Id 'ComputerReportTable' -Data $ComputerReport -Columns $Columns -DefaultSortDirection “Ascending” -ShowExport -ShowSearch -ShowPagination -Dense -Sort -PageSize 20 -PageSizeOptions @(30, 40, 50, 60)
                }
            }
        } -LoadingComponent {
            New-UDProgress -Circular
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

function Get-ReportEmptyGroups {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    Show-UDModal -Header { "Generate report over empty groups" } -Content {
        if ($ActiveEventLog -eq "True") {
            Write-EventLog -LogName $EventLogName -Source "ReportEmptyGroups" -EventID 10 -EntryType Information -Message "$($User) has generated a report over empty groups`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
        }
        New-UDDynamic -Id 'Report' -content {
            New-UDGrid -Spacing '1' -Container -Content {
                $GroupReport = Get-ADGroup -Filter * -Properties Members, ManagedBy, name, samaccountname, DistinguishedName, description | Where-Object-Object { -not $_.members } | Select-Object ManagedBy, name, samaccountname, DistinguishedName, description | Foreach-Object { 
                    [PSCustomObject]@{
                        Name              = $_.Name
                        SamAccountName    = $_.SamAccountName
                        ManagedBy         = $_.ManagedBy
                        DistinguishedName = $_.DistinguishedName
                        description       = $_.description
                    }
                }

                $Columns = @(
                    New-UDTableColumn -Property Name -Title "Name" -IncludeInSearch -IncludeInExport -DefaultSortColumn
                    New-UDTableColumn -Property SamAccountName -Title "SamAccountName" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property description -Title "Description" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property ManagedBy -Title "Managed by" -IncludeInSearch -IncludeInExport
                    New-UDTableColumn -Property DistinguishedName -Title "DistinguishedName" -IncludeInSearch -IncludeInExport
                )

                New-UDGrid -Item -Size 12 -Content {
                    New-UDTable -Id 'ComputerReportTable' -Data $GroupReport -Columns $Columns -DefaultSortDirection “Ascending” -ShowExport -ShowSearch -ShowPagination -Dense -Sort -PageSize 20 -PageSizeOptions @(30, 40, 50, 60)
                }
            }
        } -LoadingComponent {
            New-UDProgress -Circular
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


Export-ModuleMember -Function "Get-UserReports", "Get-ComputerReport", "Get-ReportEmptyGroups"