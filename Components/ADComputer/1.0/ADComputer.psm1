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

Function Show-MonitorInfoBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][String]$Computer,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show information about connected displays on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon desktop) -size medium -Onclick {
            Show-UDModal -Header { "Monitor information from $Computer" } -Content {
                New-UDDynamic -Id 'DisplayInfo' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowMonitorInfo" -EventID 10 -EntryType Information -Message "$($User) did look at monitor info for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }

                        $Columns = @(
                            New-UDTableColumn -Title 'Active' -Property 'Active' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'Manufacturer' -Property 'ManufacturerName' -IncludeInExport -IncludeInSearch -Render {
                                switch ($EventData.ManufacturerName) {
                                    'PHL' { "Philips" }
                                    'SMS' { "Samsung" }
                                    Default { $EventData.UserFriendlyName }
                                }
                            }
                            New-UDTableColumn -Title 'Model' -Property 'UserFriendlyName' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Serial Number' -Property 'SerialNumberID' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Year Of Manufacture' -Property 'YearOfManufacture' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Week Of Manufacture' -Property 'WeekOfManufacture' -IncludeInExport -IncludeInSearch
                        )

                        $DisplayData = Get-CimInstance -ComputerName $Computer -ClassName WmiMonitorID -Namespace root\wmi | Foreach-Object {
                            if ($null -ne $_) {
                                [PSCustomObject]@{
                                    Active            = $_.Active
                                    ManufacturerName  = ($_.Manufacturername | ForEach-Object { [char]$_ }) -join ""
                                    UserFriendlyName  = ($_.UserFriendlyName | ForEach-Object { [char]$_ }) -join ""
                                    SerialNumberID    = ($_.SerialNumberID | ForEach-Object { [char]$_ }) -join ""
                                    YearOfManufacture = $_.YearOfManufacture
                                    WeekOfManufacture = $_.WeekOfManufacture
                                }
                            }
                        }

                        if ([string]::IsNullOrEmpty($DisplayData)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $DisplayData -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'DisplayInfo'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Show-InstalledDriversBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show installed drivers on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon screwdriver) -size medium -Onclick {
            Show-UDModal -Header { "All installed drivers on $($Computer)" } -Content {
                New-UDDynamic -Id 'DriversData' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowInstalledDrivers" -EventID 10 -EntryType Information -Message "$($User) did look at installed drivers for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $DriversData = Get-CimInstance -Computer $Computer win32_PnpSignedDriver | select-object Description, DeviceClass, DeviceName, DriverDate, DriverProviderName, DriverVersion, Manufacturer | Foreach-Object {
                            if ($null -ne $_) {
                                [PSCustomObject]@{
                                    dManufacturer       = $_.Manufacturer
                                    dDriverProviderName = $_.DriverProviderName
                                    dDeviceName         = $_.DeviceName
                                    dDescription        = $_.Description
                                    dDeviceClass        = $_.DeviceClass
                                    dDriverVersion      = $_.DriverVersion
                                    dDriverDate         = if ($null -eq $_.DriverDate) { (Get-Date -Year 1970 -Month 01 -Day 01).ToShortDateString() } else { $_.DriverDate.ToShortDateString() }
                                }
                            }
                        }

                        $DriversColumns = @(
                            New-UDTableColumn -Property dManufacturer -Title "Manufacturer" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDriverProviderName -Title "Driver Provider Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property dDeviceName -Title "Device name" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDescription -Title "Description" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDeviceClass -Title "Device Class" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDriverVersion -Title "Version" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDriverDate -Title "Date" -IncludeInExport -IncludeInSearch
                        )
                        if ([string]::IsNullOrEmpty($DriversData)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'DriversSearchTable' -Data $DriversData -Columns $DriversColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 20
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick {
                    Sync-UDElement -Id 'DriversData'
                }
                New-UDButton -Text "Close" -Size medium -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'xl' -Persistent
        }
    }
}

Function Get-SysInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][String]$Computer
    )
    $CimSession = New-CimSession -ComputerName $Computer
    if ($null -ne $CimSession) {
        [PSCustomObject]@{
            Computer   = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemFamily, UserName
            OS         = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem | select-object LastBootUpTime, InstallDate
            UpTime     = (get-date) - (Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem).LastBootUpTime | Select-Object days, hours, minutes
            BIOS       = Get-CimInstance -CimSession $CimSession -ClassName Win32_BIOS | Select-Object BIOSVersion, SerialNumber
            RAM        = (Get-CimInstance -CimSession $CimSession -ClassName Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1gb
            HDD        = Get-CimInstance -CimSession $CimSession -ClassName Win32_LogicalDisk | where-object DeviceID -eq "C:" | Select-Object -Property DeviceID, @{'Name' = 'Total'; Expression = { [int]($_.Size / 1GB) } }, @{'Name' = 'Free'; Expression = { [int]($_.FreeSpace / 1GB) } }
            NetworkMac = (Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'").MACAddress
        }
        Remove-CimSession -InstanceId $CimSession.InstanceId
    }
}

function Show-NetAdpBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show network adapters on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon ethernet) -size medium -Onclick {
            Show-UDModal -Header { "All network adapters on $Computer" } -Content {
                New-UDDynamic -Id 'AdapterData' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowNetworkAdapters" -EventID 10 -EntryType Information -Message "$($User) did look at network adapters for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $CimSession = New-CimSession -ComputerName $Computer
                        $AllAdapters = Get-NetAdapter -CimSession $CimSession -Name * | select-object @("Name", "InterfaceDescription", "Status", "LinkSpeed", "MacAddress")
                        Remove-CimSession -InstanceId $CimSession.InstanceId

                        $AdaptersColumns = @(
                            New-UDTableColumn -Property Name -Title "Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property InterfaceDescription -Title "Description" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property Status -Title "Status" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property LinkSpeed -Title "Link Speed" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property MacAddress -Title "MAC Address" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property Functions -Title ' ' -Render {
                                if ($EventData.Status -eq "Up") {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Disable Network adapter $($EventData.Name)"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon stop) -size small -Onclick {
                                            try {
                                                $CimSession = New-CimSession -ComputerName $Computer
                                                Disable-NetAdapter -CimSession $CimSession -Name $EventData.Name
                                                Remove-CimSession -InstanceId $CimSession.InstanceId
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "DisableNetworkAdapter" -EventID 10 -EntryType Information -Message "$($User) did disable network adapter for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($EventData.Name) has been disabled!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'AdapterData'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                }
                                else {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Enable Network adapter $($EventData.Name)"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon play) -size small -Onclick {
                                            try {
                                                $CimSession = New-CimSession -ComputerName $Computer
                                                Enable-NetAdapter -CimSession $CimSession -Name $EventData.Name
                                                Remove-CimSession -InstanceId $CimSession.InstanceId
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "EnableNetworkAdapter" -EventID 10 -EntryType Information -Message "$($User) did enable network adapter for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($EventData.Name) has been enabled!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'AdapterData'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                }

                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Restart network adapter $($EventData.Name)"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon undo_alt) -size small -Onclick {
                                        try {
                                            $CimSession = New-CimSession -ComputerName $Computer
                                            Restart-NetAdapter -CimSession $CimSession -Name $EventData.Name
                                            Remove-CimSession -InstanceId $CimSession.InstanceId
                                            if ($ActiveEventLog -eq "True") {
                                                Write-EventLog -LogName $EventLogName -Source "RestartNetworkAdapter" -EventID 10 -EntryType Information -Message "$($User) did restart network adapter for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                            }
                                            Show-UDToast -Message "$($EventData.Name) has been restarted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Sync-UDElement -Id 'AdapterData'
                                        }
                                        catch {
                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                        )
                        if ([string]::IsNullOrEmpty($AllAdapters)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'AdapterSearchTable' -Data $AllAdapters -Columns $AdaptersColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 20
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -Id 'AdapterData'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }                
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Show-ProcessTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show processes on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon tasks) -size medium -Onclick {
            Show-UDModal -Header { "Show process on $($Computer)" } -Content {
                New-UDDynamic -Id 'ProcessStart' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowProcess" -EventID 10 -EntryType Information -Message "$($User) did look at processes for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        
                        $Columns = @(
                            New-UDTableColumn -Property " " -Title " " -Render {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Stop process $($EventData.ProcessName)"
                                } -content { 
                                    #New-UDIconButton -Icon (New-UDIcon -Icon times_circle -Style @{ color = 'rgba(255, 0, 0, 0.6)' }) -Size small -Onclick {
                                    New-UDButton -Icon (New-UDIcon -Icon times_circle) -size small -Onclick {
                                        $KillProcessID = $EventData.id
                                        try {
                                            Get-CimInstance -ClassName Win32_Process -ComputerName $Computer -Filter "ProcessId = '$($EventData.id)'" | Invoke-CimMethod -MethodName Terminate
                                            if ($ActiveEventLog -eq "True") {
                                                Write-EventLog -LogName $EventLogName -Source "KillProcess" -EventID 10 -EntryType Information -Message "$($User) did kill process $($EventData.ProcessName) ID $($KillProcessID) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                            }
                                            Show-UDToast -Message "The Process $($EventData.ProcessName) has been terminated!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Sync-UDElement -id 'ProcessStart'
                                        }
                                        catch {
                                            Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                            Break
                                        }
                                    }
                                }
                            }
                            New-UDTableColumn -Title 'Id' -Property 'ID' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Name' -Property 'ProcessName' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'User' -Property 'UserName' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'RAM' -Property 'WorkingSetSize' -IncludeInExport -Render {
                                $EventData.WorkingSetSize | ConvertTo-ByteString
                            }
                            New-UDTableColumn -Title 'Command Line' -Property 'CommandLine' -IncludeInExport -IncludeInSearch
                        )

                        $CimSession = New-CimSession -ComputerName $Computer
                        $Processes = Get-CimInstance -CimSession $CimSession -ClassName Win32_Process | ForEach-Object {
                            [PSCustomObject]@{
                                ProcessName    = $_.name
                                ID             = $_.ProcessID
                                WorkingSetSize = $_.WorkingSetSize
                                UserName       = (Invoke-CimMethod -CimSession $CimSession -InputObject $_ -MethodName GetOwner | Select-Object User -ExpandProperty user)
                                CommandLine    = $_.CommandLine
                            }
                        }
                        Remove-CimSession -InstanceId $CimSession.InstanceId

                        if ([string]::IsNullOrEmpty($Processes)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Processes -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'ProcessStart'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -Persistent
        }
    }
}

function Show-InstalledSoftwareBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "List installed softwares on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon list_ul) -size medium -Onclick {
            Show-UDModal -Header { "All installed softwares on $($Computer)" } -Content {
                New-UDDynamic -Id 'InstallSWData' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowInstalledSoftware" -EventID 10 -EntryType Information -Message "$($User) did look at installed software for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $InstallData = Get-CimInstance -Computer $Computer -ClassName win32_product | Select-Object Name, PackageName, InstallDate

                        $InstallColumns = @(
                            New-UDTableColumn -Property Name -Title "Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property PackageName -Title "Package Name" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property InstallDate -Title "Installation Date" -IncludeInExport -IncludeInSearch
                        )
                        if ([string]::IsNullOrEmpty($InstallData)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'InstallSWSearchTable' -Data $InstallData -Columns $InstallColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 20
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick {
                    Sync-UDElement -Id 'InstallSWData'
                }
                New-UDButton -Text "Close" -Size medium -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Show-AutostartTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show autostarts on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon play) -size medium -Onclick {
            Show-UDModal -Header { "Autostart on $($Computer)" } -Content {
                New-UDDynamic -Id 'Autostart' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowAutostart" -EventID 10 -EntryType Information -Message "$($User) did look at autostart for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $Columns = @(
                            New-UDTableColumn -Title 'Name' -Property 'Name' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'User' -Property 'User' -IncludeInExport -IncludeInSearch -Render {
                                switch ($EventData.User) {
                                    Public { "All users" }
                                    Default { $EventData.User }
                                }
                            }
                        )
                        $Autostarts = Get-CimInstance -Computer $Computer Win32_StartupCommand | Select-Object @("Name", "User")
                        if ([string]::IsNullOrEmpty($Autostarts)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Autostarts -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'Autostarts'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Show-ServicesTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show services on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon clipboard_list) -size medium -Onclick {
            Show-UDModal -Header { "Services on $($Computer)" } -Content {
                New-UDDynamic -Id 'serviceTable' -Content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowServices" -EventID 10 -EntryType Information -Message "$($User) did look at Services for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }

                        $Columns = @(
                            New-UDTableColumn -Title 'Name' -Property 'Name' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'Description' -Property 'DisplayName' -IncludeInExport
                            New-UDTableColumn -Title 'Start Type' -Property 'StartType' -IncludeInExport -IncludeInSearch -Hidden
                            New-UDTableColumn -Title 'Start Type' -Property '.' -IncludeInExport -IncludeInSearch -Render {
                                New-UDSelect -id "$($Eventdata.Name)StartupTypeSelect" -Option {
                                    switch ($Eventdata.StartType) {
                                        Manual {
                                            New-UDSelectOption -Name 'Manual' -Value "Manual"
                                            New-UDSelectOption -Name 'Automatic' -Value "Automatic"
                                            New-UDSelectOption -Name 'Disabled' -Value "Disabled"
                                        }
                                        Automatic {
                                            New-UDSelectOption -Name 'Automatic' -Value "Automatic"
                                            New-UDSelectOption -Name 'Manual' -Value "Manual"
                                            New-UDSelectOption -Name 'Disabled' -Value "Disabled"

                                        }
                                        Disabled {
                                            New-UDSelectOption -Name 'Disabled' -Value "Disabled"
                                            New-UDSelectOption -Name 'Automatic' -Value "Automatic"
                                            New-UDSelectOption -Name 'Manual' -Value "Manual"
                                        }
                                    }
                                }
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Change startup type"
                                } -content { 
                                    New-UDButton  -Icon (New-UDIcon -Icon exchange_alt) -size small -OnClick { 
                                        $StartupTypeSelectSwitch = Get-UDElement -Id "$($Eventdata.Name)StartupTypeSelect"
                                        $StartupService = $EventData.Name
                                        $StartUpTypeChoosen = $StartupTypeSelectSwitch.Value
                                        if ([string]::IsNullOrEmpty($StartupTypeSelectSwitch) -or $Eventdata.StartType -eq $StartUpTypeChoosen) {
                                            Show-UDToast -Message "You must choose a startup type!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }

                                        try {
                                            switch ($StartupTypeSelectSwitch.Value) {
                                                Automatic {
                                                    Invoke-Command -ComputerName $Computer -Scriptblock {
                                                        Param($StartUpTypeChoosen, $StartupService)
                                                        Set-Service -Name $StartupService -StartupType $StartUpTypeChoosen
                                                    } -ArgumentList $StartUpTypeChoosen, $StartupService
                                                }
                                                Manual {
                                                    Invoke-Command -ComputerName $Computer -Scriptblock {
                                                        Param($StartUpTypeChoosen, $StartupService)
                                                        Set-Service -Name $StartupService -StartupType $StartUpTypeChoosen
                                                    } -ArgumentList $StartUpTypeChoosen, $StartupService
                                                }
                                                Disabled {
                                                    Invoke-Command -ComputerName $Computer -Scriptblock {
                                                        Param($StartUpTypeChoosen, $StartupService)
                                                        Set-Service -Name $StartupService -StartupType $StartUpTypeChoosen
                                                    } -ArgumentList $StartUpTypeChoosen, $StartupService
                                                }
                                            }
                                            if ($ActiveEventLog -eq "True") {
                                                Write-EventLog -LogName $EventLogName -Source "ChangeServiceStartUp" -EventID 10 -EntryType Information -Message "$($User) did change startup type for service $($StartupService) to $($StartUpTypeChoosen)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                            }
                                            Show-UDToast -Message "The Services $($StartupService) has changed startup type to $($StartUpTypeChoosen)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Sync-UDElement -Id 'serviceTable'
                                        }
                                        catch {
                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                            New-UDTableColumn -Title 'Status' -Property 'Status' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title '.' -Property 'Actions' -Render {
                                if ($EventData.Status -eq 'Running') {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Stop"
                                    } -content { 
                                        New-UDButton  -Icon (New-UDIcon -Icon stop) -size small -OnClick { 
                                            try {
                                                $KillService = $EventData.Name
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($KillService)
                                                    Stop-Service $KillService -ErrorAction stop
                                                } -ArgumentList $KillService
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "StopServices" -EventID 10 -EntryType Information -Message "$($User) did stop the services $($EventData.Name) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "The Services $($EventData.Name) has been stopped!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'serviceTable'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Restart"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon redo_alt) -size small -OnClick { 
                                            try {
                                                $RestartService = $EventData.Name
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($RestartService)
                                                    Restart-Service $RestartService -ErrorAction stop
                                                } -ArgumentList $RestartService
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "RestartServices" -EventID 10 -EntryType Information -Message "$($User) did restart the services $($EventData.Name) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "The services $($EventData.Name) has restarted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'serviceTable'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }

                                        }
                                    }
                                }
                                else {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Start"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon play) -size small -OnClick { 
                                            try {
                                                $StartService = $EventData.Name
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($StartService)
                                                    Start-Service $StartService -ErrorAction stop
                                                } -ArgumentList $StartService
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "StartServices" -EventID 10 -EntryType Information -Message "$($User) did start the services $($EventData.Name) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "The services $($EventData.Name) has started!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'serviceTable'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }

                                        }
                                    }
                                }
                            }
                        )

                        $Services = Invoke-Command -ComputerName $Computer -Scriptblock { Get-Service }
                        if ([string]::IsNullOrEmpty($Services)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Services -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'serviceTable'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Remove-UserProfilesBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$YourDomain
    )

    
    Show-UDModal -Header { "Delete user profile from $($Computer)" } -Content {
        New-UDDynamic -Id 'ShowUsrProfdata' -content {
            New-UDGrid -Spacing '1' -Container -Children {
                if ($ActiveEventLog -eq "True") {
                    Write-EventLog -LogName $EventLogName -Source "ShowComputerUserProfiles" -EventID 10 -EntryType Information -Message "$($User) has been looking at $($Computer) user profiles`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                }
                $ExcludedProfiles = @("C:\Users\Administrator", "C:\Users\Administratör")
                $SearchComputerGroupData = Get-CimInstance -ComputerName $Computer -className Win32_UserProfile | Where-Object { (-Not ($_.Special)) } | Foreach-Object {
                    if (-Not ($_.LocalPath -in $ExcludedProfiles)) {
                        [PSCustomObject]@{
                            ProfileUserName = $_.LocalPath.split('\')[-1]
                            ProfilePath     = $_.LocalPath
                            LastUsed        = ($_.LastUseTime -as [DateTime]).ToString("yyyy-MM-dd HH:mm")
                            ProfileLoaded   = $_.Loaded
                        }
                    }
                }

                $SearchComputerGroupColumns = @(
                    New-UDTableColumn -Property ProfileUserName -Title "User" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                    New-UDTableColumn -Property ProfilePath -Title "Search path" -IncludeInExport -IncludeInSearch
                    New-UDTableColumn -Property LastUsed -Title "Last Used" -IncludeInExport -IncludeInSearch
                    New-UDTableColumn -Property NotUsedFor -Title "Not used for" -IncludeInExport -IncludeInSearch -Render {
                        if (-Not([string]::IsNullOrEmpty($Eventdata.LastUsed))) {
                            $Age = NEW-TIMESPAN -Start $Eventdata.LastUsed -End (Get-Date) | Select-Object days, hours, Minutes  | Foreach-Object {
                                [PSCustomObject]@{
                                    Ndays    = if ($Null -eq $_.Days -or $_.Days -eq "0") { $Null } else { "$($_.Days) days " }
                                    NHours   = if ($Null -eq $_.Hours -or $_.Hours -eq "0") { $Null } else { "$($_.Hours) hours " }
                                    NMinutes = if ($Null -eq $_.Minutes -or $_.Minutes -eq "0") { $Null } else { "$($_.Minutes) min" }
                                }
                            }
                            "$($Age.Ndays)$($Age.NHours)$($Age.NMinutes)"
                        }
                        else {
                            $Null
                        }
                    }
                    New-UDTableColumn -Property ProfileLoaded -Title "In use?" -Render {
                        Switch ($EventData.ProfileLoaded) {
                            False {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "The profile for $($EventData.ProfileUserName) are not in use and can be deleted!"
                                } -content { 
                                    New-UDIcon -Icon 'times' -Size lg -Style @{color = 'rgba(80, 184, 72, 0.6)' }
                                }
                            }
                            True {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "The profile for $($EventData.ProfileUserName) are in use and can't be deleted!"
                                } -content { 
                                    New-UDIcon -Icon 'check' -Size lg -Style @{color = 'rgba(255, 0, 0, 0.6)' }
                                }
                            }
                            Default {
                                $EventData.Enabled
                            }
                        }
                    }
                    New-UDTableColumn -Property Delete -Title " " -Render {
                        New-UDTooltip -TooltipContent {
                            New-UDTypography -Text "Delete the user profile for $($EventData.ProfileUserName)"
                        } -content { 
                            New-UDButton -Icon (New-UDIcon -Icon trash_alt -Style @{ color = 'rgba(0, 151, 207, 0.6)' }) -Size small -Onclick {
                                if ($EventData.ProfileLoaded -eq "True") {
                                    Show-UDToast -Message "The profile for $($EventData.ProfileUserName) are in use and can't be deleted!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                }
                                else {
                                    try {
                                        Show-UDToast -Message "Deleting of the profile for $($EventData.ProfileUserName) has started, please wait..." -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                        $Btns = @("CloseBtn", "SelectedBtn")
                                        foreach ($btn in $btns) {
                                            Set-UDElement -Id $btn -Properties @{
                                                disabled = $true 
                                            }
                                        }
                                        Get-CimInstance -ComputerName $Computer Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\$($EventData.ProfileUserName)" } | Remove-CimInstance
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "DeletedUserProfile" -EventID 10 -EntryType Information -Message "$($User) did delete $($UserRmProfileName) user profile from $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                        Show-UDToast -Message "The profile for $($EventData.ProfileUserName) has been deleted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                        foreach ($btn in $btns) {
                                            Set-UDElement -Id $btn -Properties @{
                                                disabled = $false
                                            }
                                        }
                                        Sync-UDElement -id 'ShowUsrProfdata'
                                    }
                                    catch {
                                        foreach ($btn in $btns) {
                                            Set-UDElement -Id $btn -Properties @{
                                                disabled = $false
                                            }
                                        }
                                        Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 4000
                                        Sync-UDElement -id 'ShowUsrProfdata'
                                        Break
                                    }
                                }
                            }
                        }
                    }
                )
                if ([string]::IsNullOrEmpty($SearchComputerGroupData)) {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDAlert -Severity 'error' -Text "$($Computer) has no user profiles or could not establish a connection to $($Computer)"
                    }
                }
                else {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        $SearchOption = New-UDTableTextOption -Search "Search"
                        New-UDTable -Id 'ComputerSearchTable' -Data $SearchComputerGroupData -Columns $SearchComputerGroupColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 20 -ShowSelection
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDButton -Text "Delete selected" -OnClick {
                            $ComputerSearchTable = Get-UDElement -Id "ComputerSearchTable"
                            $ComputerSearchLog = @($ComputerSearchTable.selectedRows.User)
                            if ($Null -ne $ComputerSearchTable.selectedRows.User) {                  
                                try {
                                    $Btns = @("CloseBtn", "SelectedBtn", "RefreshBtn")
                                    foreach ($btn in $btns) {
                                        Set-UDElement -Id $btn -Properties @{
                                            disabled = $true 
                                            text     = "Deleting..."
                                        }
                                    }
                                    @($ComputerSearchTable.selectedRows.ForEach( { 
                                                if ($_.ProfileLoaded -like "False") {
                                                    $UserRmProfileName = $_.User.Replace("$($YourDomain)\", "")
                                                    Get-WmiObject -ComputerName $Computer Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\$($UserRmProfileName)" } | Remove-WmiObject
                                                    if ($ActiveEventLog -eq "True") {
                                                        Write-EventLog -LogName $EventLogName -Source "DeletedUserProfile" -EventID 10 -EntryType Information -Message "$($User) did delete $($UserRmProfileName) user profile from $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                    }
                                                }
                                            } ) )
                                    Show-UDToast -Message "The profiles for $($ComputerSearchLog -join ",") has been deleted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    foreach ($btn in $btns) {
                                        Set-UDElement -Id $btn -Properties @{
                                            disabled = $false
                                        }
                                    }
                                    Sync-UDElement -id 'ShowUsrProfdata'
                                }
                                catch {
                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                    foreach ($btn in $btns) {
                                        Set-UDElement -Id $btn -Properties @{
                                            disabled = $false
                                        }
                                    }
                                    Sync-UDElement -id 'ShowUsrProfdata'
                                    Break
                                }
                            }
                            else {
                                Show-UDToast -Message "You have not selected any profile!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                foreach ($btn in $btns) {
                                    Set-UDElement -Id $btn -Properties @{
                                        disabled = $false
                                    }
                                }
                                Break
                            }
                        } -id "SelectedBtn"
                    }
                }
            }
        } -LoadingComponent {
            New-UDProgress -Circular
        }                
    } -Footer {
        New-UDButton -Text "Refresh" -OnClick { 
            Sync-UDElement -id 'ShowUsrProfdata'
        } -id "RefreshBtn"
        New-UDButton -Text "Close" -OnClick {
            Hide-UDModal
        } -id "CloseBtn"
                                        
    } -FullWidth -MaxWidth 'lg' -Persistent
}

Function Compare-ComputerGrpsBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][String]$Computer,
        [Parameter(Mandatory)][String]$YourFullDomain,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
        [Parameter(Mandatory = $false)][String]$RefreshOnClose
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Compare $($Computer)s AD group memberships against an other computer"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon not_equal) -size medium -Onclick {
            Show-UDModal -Header { "Compare $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtCompComputer' -Label "Compare against?"
                    }
                    New-UDGrid -Item -ExtraLargeSize 7 -LargeSize 7 -MediumSize 7 -SmallSize 7 -Children { }
                }
                New-UDDynamic -Id 'CompUsrGrpsTable' -content {
                    New-UDGrid -Spacing '1' -Container -Children {
                        $CompComputer = (Get-UDElement -Id "txtCompComputer").value
                        if ($NULL -ne $CompComputer) {
                            $CompComputer = $CompComputer.trim()
                        }

                        if ($null -ne $CompComputer) {
                            if (Get-ADComputer -Filter "samaccountname -eq '$($CompComputer)$'") {
                                if ($Computer -eq $CompComputer) {
                                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                        New-UDHtml -Markup "<br>"
                                        New-UDAlert -Severity 'error' -Text "You can't compare $($Computer) to it self! "
                                    }
                                }
                                else {
                                    try {
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "CompareComputerADGroups" -EventID 10 -EntryType Information -Message "$($User) did compare $($Computer) against $($CompComputer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                        $Columns = @(
                                            New-UDTableColumn -Title '.' -Property '.' -render {
                                                New-UDTooltip -TooltipContent {
                                                    New-UDTypography -Text "Add $($Computer) to this group"
                                                } -content { 
                                                    New-UDButton -Icon (New-UDIcon -Icon sign_in_alt) -size small -Onclick {
                                                        try {
                                                            Add-ADGroupMember -Identity $EventData.SamAccountName -Members "$($Computer)$" 
                                                            Show-UDToast -Message "$($Computer) are now member of $($EventData.SamAccountName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            if ($ActiveEventLog -eq "True") {
                                                                Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($Computer) to the group $($EventData.SamAccountName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                            }
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
                                        $obj = Get-ADPrincipalGroupMembership -Identity "$($Computer)$"  -ResourceContextServer $YourFullDomain | Sort-Object -Property SamAccountName
                                        $obj2 = Get-ADPrincipalGroupMembership -Identity "$($CompComputer)$"  -ResourceContextServer $YourFullDomain | Sort-Object -Property SamAccountName
                                        $CompData = Compare-Object -ReferenceObject $obj -DifferenceObject $obj2 -Property SamAccountName | Where-Object { $_.SideIndicator -eq "=>" } | Foreach-Object { Get-ADGroup -Identity $_.SamAccountName -Property Displayname, Description | Select-Object SamAccountName, Description }
                
                                        if ([string]::IsNullOrEmpty($CompData)) {
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                                New-UDHtml -Markup "<br>"
                                                New-UDAlert -Severity 'success' -Text "$($Computer) are member in all groups that $($CompComputer) are member in!"
                                            }
                                        }
                                        else {
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                                $SearchOption = New-UDTableTextOption -Search "Search"
                                                New-UDTable -Title "$($Computer) is not a member of the following groups" -id "CompTable" -Data $CompData -Columns $Columns -DefaultSortDirection "Ascending" -TextOption $SearchOption -ShowSearch -ShowSelection -ShowPagination -Dense -Sort -Export -ExportOption "xlsx, PDF, CSV" -PageSize 200                      
                                            }
                                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children { 
                                                New-UDButton -Text "Add to selected" -OnClick {
                                                    $CompTable = Get-UDElement -Id "CompTable"
                                                    $SelectedGrp = @($CompTable.selectedRows.SamAccountName)

                                                    if ($null -ne $CompTable.selectedRows.SamAccountName) {
                                                        try {
                                                            @($CompTable.selectedRows.SamAccountName.ForEach( { 
                                                                        Add-ADGroupMember -Identity $_ -Members "$($Computer)$" 
                                                                        if ($ActiveEventLog -eq "True") {
                                                                            Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($Computer) to the group $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                                        }
                                                                    } ) )
                                    
                                                            Show-UDToast -Message "$($Computer) is now member of $($SelectedGrp -join ",")!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
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
                                    New-UDAlert -Severity 'error' -Text "Could not find $($CompComputer) in the AD!"
                                }
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDHtml -Markup "<br>"
                                New-UDAlert -Severity 'error' -Text "You need to type a computer name that you want to compare $($Computer) against!"
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                } 
            } -Footer {
                New-UDGrid -Item -ExtraLargeSize 10 -LargeSize 10 -MediumSize 10 -SmallSize 8 -Children { }
                New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 4 -Children {
                    New-UDButton -text 'Compare' -Onclick {
                        Sync-UDElement -Id 'CompUsrGrpsTable'
                    }

                    New-UDButton -Text "Close" -OnClick {
                        if ($null -ne $RefreshOnClose) {
                            Sync-UDElement -Id $RefreshOnClose
                        }
                        Hide-UDModal
                    }
                }
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Show-SchedualTaskTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show scheduled tasks on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon business_time) -size medium -Onclick {
            Show-UDModal -Header { "Schedual Tasks on $($Computer)" } -Content {
                New-UDDynamic -Id 'Schedual' -content {
                    New-UDGrid -Spacing '1' -Container -Children {

                        $Columns = @(
                            New-UDTableColumn -Title '.' -Property '.' -Render {
                                if ($EventData.State -notlike 'Running' ) {
                                    if ($EventData.State -like 'Disabled') {
                                        New-UDTooltip -TooltipContent {
                                            New-UDTypography -Text "Enable"
                                        } -content { 
                                            New-UDButton -Icon (New-UDIcon -Icon play) -size small -OnClick {
                                                try {
                                                    $CimSession = New-CimSession -ComputerName $Computer
                                                    Enable-ScheduledTask -CimSession $CimSession -TaskName $EventData.TaskName
                                                    Remove-CimSession -InstanceId $CimSession.InstanceId
                                                    Sync-UDElement -id "Schedual"
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }
                                        }
                                    }
                                    elseif ($EventData.State -like 'Ready') {
                                        New-UDTooltip -TooltipContent {
                                            New-UDTypography -Text "Disable"
                                        } -content { 
                                            New-UDButton -Icon (New-UDIcon -Icon stop) -size small -OnClick {
                                                try {
                                                    $CimSession = New-CimSession -ComputerName $Computer
                                                    Disable-ScheduledTask -CimSession $CimSession -TaskName $EventData.TaskName
                                                    Remove-CimSession -InstanceId $CimSession.InstanceId
                                                    Sync-UDElement -id "Schedual"
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }    
                                        }
                                    }
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Run"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon play_circle) -size small -OnClick {
                                            try {
                                                $CimSession = New-CimSession -ComputerName $Computer
                                                Start-ScheduledTask -CimSession $CimSession -TaskName $EventData.TaskName
                                                Remove-CimSession -InstanceId $CimSession.InstanceId
                                                Sync-UDElement -id "Schedual"
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }      
                                }
                            }
                            New-UDTableColumn -Title 'State' -Property 'State' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Task Name' -Property 'TaskName' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'Description' -Property 'Description' -IncludeInExport -IncludeInSearch
                        )
                        $CimSession = New-CimSession -ComputerName $Computer
                        $Schedules = Get-ScheduledTask -CimSession $CimSession -TaskPath "\" | select-object State, TaskName, Description
                        Remove-CimSession -InstanceId $CimSession.InstanceId
                        if ([string]::IsNullOrEmpty($Schedules )) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Schedules  -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh list" -OnClick { 
                    Sync-UDElement -id 'Schedual'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -Persistent
        }
    }
}

Function Restart-ADComputer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Reboot $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon power_off) -size medium -Onclick {
            Show-UDModal -Header { "Reboot $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTypography -Text "Are you sure that you want to reboot $($Computer)?" -Align center
                    }
                }
            } -Footer {
                New-UDButton -Text "Yes" -OnClick { 
                    try {
                        Restart-Computer -ComputerName $Computer -Force
                        Show-UDToast -Message "$($Computer) has now been rebooted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "RebootComputer" -EventID 10 -EntryType Information -Message "$($User) did reboot $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "No" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

Function Disconnect-UserFromComputer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$CurrentLoggedInUser
    )

    Show-UDModal -Header { "Logout $($CurrentLoggedInUser) from $($Computer)" } -Content {
        New-UDGrid -Spacing '1' -Container -Children {
            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                New-UDTypography -Text "Are you sure that you want to logout $($CurrentLoggedInUser) from $($Computer)?" -Align center
            }
        }
    } -Footer {
        New-UDButton -Text "Yes" -OnClick { 
            try {
                Invoke-CimMethod -ClassName Win32_Operatingsystem -ComputerName $Computer -MethodName Win32Shutdown -Arguments @{ Flags = 0 }
                Show-UDToast -Message "$($SystInfo.Computer.UserName) has been logged out from $($Computer)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                if ($ActiveEventLog -eq "True") {
                    Write-EventLog -LogName $EventLogName -Source "LogOutUser" -EventID 10 -EntryType Information -Message "$($User) did logout $($SystInfo.Computer.UserName) from $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                }
                Hide-UDModal
            }
            catch {
                Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                Break
            }
        }
        New-UDButton -Text "No" -OnClick {
            Hide-UDModal
        }
    } -MaxWidth 'xs' -Persistent
}

function Remove-TempFilesClientBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory)][string]$CurrentHost,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Clean temp files from $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon broom) -size medium -Onclick {
            Show-UDModal -Header { "Clean temp files from $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 6 -LargeSize 6 -MediumSize 6 -SmallSize 6 -Children { 
                        New-UDTypography -Text "If you click in the editor and then press ctrl+f you can search"
                    }
                    New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDCodeEditor -Id 'CleanClientCode' -ReadOnly -Height 450
                    }
                }
            } -Footer {
                New-UDButton -Text "Start" -OnClick {
                    $Btns = @("StartBtn", "CloseBtn", "LogBtn")

                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $true 
                            text     = "Cleaning..."
                        }
                    }

                    try {
                        $CleanReport = New-Object System.Collections.Generic.List[System.Object]
                        $CleanReport.Add("Please wait, this can take a while...")
                        Invoke-Command -ComputerName $Computer -Scriptblock { 
                            $WindowsOld = "C:\Windows.old"
                            $Users = Get-ChildItem -Path C:\Users
                            $WSUSCache = "C:\Windows\SoftwareDistribution\Download"
                            $TempFolders = @("C:\Temp", "C:\Tmp", "C:\Windows\Temp", "C:\Windows\Prefetch")

                            foreach ($tfolder in $TempFolders) {
                                if (Test-Path -Path $tfolder) {
                                    $CleanReport.Add("Deleting all files in $tfolder...")
                                    Remove-Item "$($tfolder)\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                                }  
                            }

                            foreach ($usr in $Users) {
                                $UsrTemp = "C:\Users\$usr\AppData\Local\Temp"
                                if (Test-Path -Path $UsrTemp) {
                                    $CleanReport.Add("Deleting all files in $UsrTemp...")
                                    Remove-Item "$($UsrTemp)\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                                } 
                            }

                            $CleanReport.Add("disabeling wuauserv...")
                            Stop-Service -Name 'wuauserv'
                            do {
                                $CleanReport.Add('Waiting for wuauserv to stop...')
                                Start-Sleep -s 1

                            } while (Get-Process wuauserv -ErrorAction SilentlyContinue)
    
                            $CleanReport.Add("Deleting Windows Update Cache...")
                            Remove-Item "$($WSUSCache)\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                            $CleanReport.Add("Start wuauserv again...")
                            Start-Service -Name 'wuauserv'

                            if (Test-Path -Path $WindowsOld) {
                                $CleanReport.Add("Deleting folder C:\Windows.old...")
                                Remove-Item "$($WindowsOld)\" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                            }

                            if (Test-Path -Path C:\'$Windows.~BT\') {
                                takeown /F C:\'$Windows.~BT\*' /R /A
                                icacls C:\'$Windows.~BT\*.*' /T /grant administrators:F
                                $CleanReport.Add("Deleting folder C:\Windows.~BT\...")
                                Remove-Item C:\'$Windows.~BT\' -Recurse -Force -Confirm:$False -ErrorAction SilentlyContinue
                            }

                            if (Test-Path -Path C:\'$Windows.~WS\') {
                                takeown /F C:\'$Windows.~WS\*' /R /A
                                icacls C:\'$Windows.~WS\*.*' /T /grant administrators:F
                                $CleanReport.Add("Deleting folder C:\Windows.~WS\...")
                                Remove-Item C:\'$Windows.~WS\' -Recurse -Force -Confirm:$False -ErrorAction SilentlyContinue
                            }
                        }
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "TempFileCleaning" -EventID 10 -EntryType Information -Message "$($User) did run the CleanClient script on $($CleanComputer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $CleanReport.Add("Everything is now done, you can close the window!")
                        $JobOutput = $CleanReport -join ([Environment]::NewLine)
                        Set-UDElement -Id 'CleanClientCode' -Properties @{
                            code = $JobOutput
                        } 
                        Set-UDElement -Id 'CloseBtn' -Properties @{
                            disabled = $false 
                            text     = "Close"
                        }

                        Set-UDElement -Id 'StartBtn' -Properties @{
                            disabled = $false 
                            text     = "Start"
                        }
                        Set-UDElement -Id 'LogBtn' -Properties @{
                            disabled = $false 
                            text     = "Download Log"
                        }
                        Sync-UDElement -Id $RefreshOnClose
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
 
                        Set-UDElement -Id 'CloseBtn' -Properties @{
                            disabled = $false 
                            text     = "Close"
                        }

                        Set-UDElement -Id 'StartBtn' -Properties @{
                            disabled = $false 
                            text     = "Start"
                        }
                        Set-UDElement -Id 'LogBtn' -Properties @{
                            disabled = $false 
                            text     = "Download Log"
                        }
                        Break
                    }
                } -id 'StartBtn'

                New-UDButton -Text 'Download Log' -OnClick {
                    $code = (Get-UDElement -Id 'CleanClientCode').code
                    Start-UDDownload -StringData $code -FileName "$($Computer)-CleanTempFilesFrom.log"
                } -id 'LogBtn'

                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                } -id 'CloseBtn'
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

Function Ping-ADComputer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Send ping to $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon hands_helping) -size medium -Onclick {
            Show-UDModal -Header { "Send ping to $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDDynamic -Id 'Ping' -content {
                        $PingColumns = @(
                            New-UDTableColumn -Property PingSucceeded -Title "Ping Success" -IncludeInExport -DefaultSortColumn -Render {
                                switch ($Eventdata.PingSucceeded) {
                                    True {
                                        New-UDIcon -Icon 'check' -Size lg -Style @{color = 'rgba(80, 184, 72, 0.6)' }
                                    }
                                    False {
                                        New-UDIcon -Icon 'times' -Size lg -Style @{color = 'rgba(255, 0, 0, 0.6)' }
                                    }
                                }
                            }
                            New-UDTableColumn -Property NameResolutionSucceeded -Title "NS Success" -IncludeInExport -IncludeInSearch -Render {
                                switch ($Eventdata.NameResolutionSucceeded) {
                                    True {
                                        New-UDIcon -Icon 'check' -Size lg -Style @{color = 'rgba(80, 184, 72, 0.6)' }
                                    }
                                    False {
                                        New-UDIcon -Icon 'times' -Size lg -Style @{color = 'rgba(255, 0, 0, 0.6)' }
                                    }
                                }
                            }
                            New-UDTableColumn -Property TcpTestSucceeded -Title "TCP Test Success" -IncludeInExport -IncludeInSearch -Render {
                                switch ($Eventdata.TcpTestSucceeded) {
                                    True {
                                        New-UDIcon -Icon 'check' -Size lg -Style @{color = 'rgba(80, 184, 72, 0.6)' }
                                    }
                                    False {
                                        New-UDIcon -Icon 'times' -Size lg -Style @{color = 'rgba(255, 0, 0, 0.6)' }
                                    }
                                }
                            }
                            New-UDTableColumn -Property RemoteAddress -Title "Remote Address" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property InterfaceAlias -Title "Interface Alias" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property InterfaceDescription -Title "Interface Description" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property ResolvedAddresses -Title "Resolved Addresses" -IncludeInExport -IncludeInSearch
                        )

                        $PingResults = Test-NetConnection -ComputerName $Computer -InformationLevel "Detailed" | Foreach-Object {
                            if ($null -ne $_) {
                                [PSCustomObject]@{
                                    PingSucceeded           = $_.PingSucceeded
                                    NameResolutionSucceeded = $_.NameResolutionSucceeded
                                    TcpTestSucceeded        = $_.TcpTestSucceeded
                                    RemoteAddress           = $_.RemoteAddress
                                    InterfaceAlias          = $_.InterfaceAlias
                                    InterfaceDescription    = $_.InterfaceDescription
                                    ResolvedAddresses       = [string]$_.ResolvedAddresses
                                }
                            }
                        }

                        if ([string]::IsNullOrEmpty($PingResults)) {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'PingTable' -Data $PingResults -Columns $PingColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF, CSV" -PageSize 20
                            }
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SendPing" -EventID 10 -EntryType Information -Message "$($User) did ping $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                        }
                    } -LoadingComponent {
                        New-UDProgress -Circular
                    }
                }
            } -Footer {
                New-UDButton -Text "Ping" -OnClick {
                    $Btns = @("PingBtn", "CloseBtn")

                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $true 
                        }
                    }
                    try {
                        Sync-UDElement -Id "Ping"
                        foreach ($btn in $Btns) {
                            Set-UDElement -Id "$($btn)" -Properties @{
                                disabled = $false 
                            }
                        }
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        foreach ($btn in $Btns) {
                            Set-UDElement -Id "$($btn)" -Properties @{
                                disabled = $false 
                            }
                        }
                        Break
                    }
                } -id 'PingBtn'

                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                } -id 'CloseBtn'
            } -FullWidth
        }
    }
}

Function Remove-EdgeSettings {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )


    Show-UDModal -Header { "Delete Microsoft Edge settings on $($Computer) for a user" } -Content {
        New-UDDynamic -Id 'Edge' -content {
            $Profiles = Get-CimInstance -ComputerName $Computer -className Win32_UserProfile | Where-Object { (!$_.Special) -and ($_.LocalPath -ne 'C:\Users\Administrator') -and ($_.LocalPath -ne 'C:\Users\Administratör') } | ForEach-Object { $_.LocalPath.split('\')[-1] }
            New-UDGrid -Spacing '1' -Container -Children {
                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                    New-UDTypography -Text "The users bookmarks will be restored after the settings has been deleted." -Align Center
                }
                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children { }
                New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children {
                    New-UDSelect -Id 'EdgeUser' -FullWidth -Option {
                        New-UDSelectOption -Name 'Select user...' -Value 1
                        foreach ($user in $profiles) {
                            New-UDSelectOption -Name $user -Value $user
                        }
                    } -DefaultValue 1
                }
                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children { }
            }
        } -LoadingComponent {
            New-UDProgress -Circular
        }
    } -Footer {
        New-UDButton -Text "Delete" -OnClick { 
            $UserToClean = Get-UDElement -Id 'EdgeUser'
            $UserToClean = $UserToClean.value
            if ([string]::IsNullOrEmpty($UserToClean) -or $UserToClean -eq 1) {
                Show-UDToast -Message "You need to select a user!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                Break
            }
            else {
                try {
                    $Btns = @("EdgeUser", "DeleteBtn", "CloseBtn")

                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $true 
                        }
                    }
                    $CimSession = New-CimSession -ComputerName $Computer
                    $MSEdgeProcess = Get-CimInstance -CimSession $CimSession -Class Win32_Process -Property Name | where-object { $_.name -eq "msedge.exe" }
                    if ($Null -ne $MSEdgeProcess) {
                        [void]($MSEdgeProcess | Invoke-CimMethod -MethodName Terminate)
                    }
                    Remove-CimSession -InstanceId $CimSession.InstanceId
                    Invoke-Command -ComputerName $Computer -Scriptblock {
                        Param($UserToClean)
                        $msedgepath = "C:\Users\$($UserToClean)\AppData\Local\Microsoft\Edge\User Data\"
                        $msedgebookmark = "C:\Users\$($UserToClean)\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
                        $MSEdgeBookmarkFolderPath = "C:\Users\$($UserToClean)\AppData\Local\Microsoft\Edge\User Data\Default\"

                        if (Test-Path -Path $msedgebookmark -PathType Leaf) {
                            if (Test-Path -Path "C:\Temp") {
                                Copy-Item $msedgebookmark -Destination "C:\Temp"
                            }
                            else {
                                New-Item -Path "C:\" -Name "Temp" -ItemType "directory" > $Null
                                Copy-Item $msedgebookmark -Destination "C:\Temp"
                            }
                        }

                        if (Test-Path -Path $msedgepath) {
                            Remove-Item $msedgepath -Recurse -Force
                        }
                        if (Test-Path -Path "C:\Temp\Bookmarks"-PathType Leaf) {
                            New-Item -ItemType Directory -Force -Path $MSEdgeBookmarkFolderPath
                            Copy-Item "C:\Temp\Bookmarks" -Destination $MSEdgeBookmarkFolderPath
                            Remove-Item "C:\Temp\Bookmarks" -Recurse -Force
                        }
                    } -ArgumentList $UserToClean

                    Show-UDToast -Message "Edge settings for $($UserToClean) on $($Computer) has now been deleted! And the bookmarks has been restored!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "DeleteEdgeSettings" -EventID 10 -EntryType Information -Message "$($User) deleted Edge settings on $($Computer) for $($UserToClean)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $false 
                        }
                    }
                    Sync-UDElement -Id "Edge"
                }
                catch {
                    Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $false 
                        }
                    }
                    Sync-UDElement -Id "Edge"
                    Break
                }
            }
        } -Id "DeleteBtn"
        New-UDButton -Text "Close" -OnClick {
            Hide-UDModal
        } -id "CloseBtn"
    } -FullWidth -MaxWidth 'md' -Persistent
}

Function Remove-ChromeSettings {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Computer
    )

    Show-UDModal -Header { "Delete Google Chrome settings on $($Computer) for a user" } -Content {
        New-UDDynamic -Id 'Chrome' -content {
            $Profiles = Get-CimInstance -ComputerName $Computer -className Win32_UserProfile | Where-Object { (!$_.Special) -and ($_.LocalPath -ne 'C:\Users\Administrator') -and ($_.LocalPath -ne 'C:\Users\Administratör') } | ForEach-Object { $_.LocalPath.split('\')[-1] }
            New-UDGrid -Spacing '1' -Container -Children {
                New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                    New-UDTypography -Text "The users bookmarks will be restored after the settings has been deleted." -Align Center
                }
                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children { }
                New-UDGrid -Item -ExtraLargeSize 3 -LargeSize 3 -MediumSize 3 -SmallSize 3 -Children {
                    New-UDSelect -Id 'ChromeUser' -FullWidth -Option {
                        New-UDSelectOption -Name 'Select user...' -Value 1
                        foreach ($user in $profiles) {
                            New-UDSelectOption -Name $user -Value $user
                        }
                    } -DefaultValue 1
                }
                New-UDGrid -Item -ExtraLargeSize 4 -LargeSize 4 -MediumSize 4 -SmallSize 4 -Children { }
            }
        } -LoadingComponent {
            New-UDProgress -Circular
        }
    } -Footer {
        New-UDButton -Text "Delete" -OnClick { 
            $UserToClean = Get-UDElement -Id 'ChromeUser'
            $UserToClean = $UserToClean.value
            if ([string]::IsNullOrEmpty($UserToClean) -or $UserToClean -eq 1) {
                Show-UDToast -Message "You need to select a user!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                Break
            }
            else {
                try {
                    $Btns = @("ChromeUser", "DeleteBtn", "CloseBtn")

                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $true 
                        }
                    }
                    $CimSession = New-CimSession -ComputerName $Computer
                    $ChromeProcess = Get-CimInstance -CimSession $CimSession -Class Win32_Process -Property Name | where-object { $_.name -eq "chrome.exe" }
                    if ($Null -ne $ChromeProcess) {
                        [void]($ChromeProcess | Invoke-CimMethod -MethodName Terminate)
                    }
                    Remove-CimSession -InstanceId $CimSession.InstanceId

                    Invoke-Command -ComputerName $Computer -Scriptblock {
                        Param($UserToClean)
                        $chromepath = "C:\Users\$($UserToClean)\AppData\Local\Google\Chrome\User Data\"
                        $chromebookmark = "C:\Users\$($UserToClean)\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
                        $ChromeBookmarkFolderPath = "C:\Users\$($UserToClean)\AppData\Local\Google\Chrome\User Data\Default\"

                        if (Test-Path -Path $chromebookmark -PathType Leaf) {
                            if (Test-Path -Path "C:\Temp") {
                                Copy-Item $chromebookmark -Destination "C:\Temp"
                            }
                            else {
                                New-Item -Path "C:\" -Name "Temp" -ItemType "directory" > $Null
                                Copy-Item $chromebookmark -Destination "C:\Temp"
                            }
                        }

                        if (Test-Path -Path $chromepath) {
                            Remove-Item $chromepath -Recurse -Force
                        }
                        if (Test-Path -Path "C:\Temp\Bookmarks"-PathType Leaf) {
                            New-Item -ItemType Directory -Force -Path $ChromeBookmarkFolderPath
                            Copy-Item "C:\Temp\Bookmarks" -Destination $ChromeBookmarkFolderPath
                            Remove-Item "C:\Temp\Bookmarks" -Recurse -Force
                        }
                    } -ArgumentList $UserToClean

                    Show-UDToast -Message "Chrome settings for $($UserToClean) on $($Computer) has now been deleted! And the bookmarks has been restored!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "DeleteChromeSettings" -EventID 10 -EntryType Information -Message "$($User) deleted Chrome settings on $($Computer) for $($UserToClean)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $false
                        }
                    }
                    Sync-UDElement -id "Chrome"
                }
                catch {
                    Show-UDToast -Message "$($PSItem.Exception.Message)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $false
                        }
                    }
                    Sync-UDElement -id "Chrome"
                    Break
                }
            }
        } -Id "DeleteBtn"
        New-UDButton -Text "Close" -OnClick {
            Hide-UDModal
        } -id "CloseBtn"
    } -FullWidth -MaxWidth 'md' -Persistent
}

Function New-ADComputerFranky {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$BoxToSync,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Create new computer"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon plus) -size large -Onclick {
            Show-UDModal -Header { "Create new computer" } -Content {
                New-UDGrid -Spacing '1' -Container -Children {
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtComputerName' -Label 'Computer name (Required)' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 2 -LargeSize 2 -MediumSize 2 -SmallSize 2 -Children { }
                    New-UDGrid -Item -ExtraLargeSize 5 -LargeSize 5 -MediumSize 5 -SmallSize 5 -Children {
                        New-UDTextbox -Id 'txtComputerDisplayName' -Label 'Enter Display Name for the computer' -FullWidth
                    }
                    New-UDGrid -Item -ExtraLargeSize 12 -LargeSize 12 -MediumSize 12 -SmallSize 12 -Children {
                        New-UDTextbox -Id 'txtComputerDescription' -Label 'Enter description' -FullWidth
                    }
                }
            } -Footer {
                New-UDButton -text 'Create' -Onclick {
                    $NewComputerName = (Get-UDElement -Id "txtComputerName").value
                    $NewComputerDisplayName = (Get-UDElement -Id "txtComputerDisplayName").value
                    $NewComputerDescription = (Get-UDElement -Id "txtComputerDescription").value
                    $NewComputerName = $NewComputerName.trim()

                  
                    if ([string]::IsNullOrEmpty($NewComputerName)) {
                        Show-UDToast -Message "You must enter all the required options above!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        if (Get-ADComputer -Filter "samaccountname -eq '$($NewComputerName)'" -properties SamAccountName) {
                            Show-UDToast -Message "It's already a computer with the SamAccountName $($NewComputerName) in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                        else {
                            if ([string]::IsNullOrEmpty($NewComputerDisplayName)) {
                                $NewComputerDisplayName = $NewComputerName
                            }
                            try {
                                New-ADComputer -Name $NewComputerName -SamAccountName $NewComputerName -DisplayName $NewComputerDisplayName -Description $NewComputerDescription -Path $OUComputerPath
                                Show-UDToast -Message "$($NewComputerName) has been created!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                if ($ActiveEventLog -eq "True") {
                                    Write-EventLog -LogName $EventLogName -Source "CreatedComputer" -EventID 10 -EntryType Information -Message "$($User) did create the computer $($NewComputerName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                }
                                Set-UDElement -Id $BoxToSync -Properties @{
                                    Value = $NewComputerName
                                }
                                Sync-UDElement -id $RefreshOnClose
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
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

Export-ModuleMember -Function "New-ADComputerFranky", "Remove-ChromeSettings", "Remove-EdgeSettings", "Ping-ADComputer", "Disconnect-UserFromComputer", "Restart-ADComputer", "Show-MonitorInfoBtn", "Show-InstalledDriversBtn", "Get-SysInfo", "Show-NetAdpBtn", "Show-ProcessTableBtn", "Show-InstalledSoftwareBtn", "Show-AutostartTableBtn", "Show-ServicesTableBtn", "Remove-UserProfilesBtn", "Compare-ComputerGrpsBtn", "Show-SchedualTaskTableBtn", "Remove-TempFilesClientBtn"