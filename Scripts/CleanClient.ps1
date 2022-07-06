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

Param(
    [Parameter(Mandatory)][string]$CleanComputer,
    [Parameter(Mandatory = $false)][string]$User,
    [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
    [Parameter(Mandatory = $false)][string]$LocalIpAddress
)


Invoke-Command -ComputerName $CleanComputer -Scriptblock { 
    $WindowsOld = "C:\Windows.old"
    $Users = Get-ChildItem -Path C:\Users
    $WSUSCache = "C:\Windows\SoftwareDistribution\Download"
    $TempFolders = @("C:\Temp", "C:\Tmp", "C:\Windows\Temp", "C:\Windows\Prefetch")

    foreach ($tfolder in $TempFolders) {
        if (Test-Path -Path $tfolder) {
            Write-Host "Deleting all files in $tfolder..."
            Remove-Item "$($tfolder)\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
        }  
    }

    foreach ($usr in $Users) {
        $UsrTemp = "C:\Users\$usr\AppData\Local\Temp"
        if (Test-Path -Path $UsrTemp) {
            Write-Host "Deleting all files in $UsrTemp..."
            Remove-Item "$($UsrTemp)\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
        } 
    }

    write-host "disabling wuauserv..."
    Stop-Service -Name 'wuauserv'
    do {
        Write-Host 'Waiting for wuauserv to stop...'
        Start-Sleep -s 1

    } while (Get-Process wuauserv -ErrorAction SilentlyContinue)
    
    write-host "Deleting Windows Update Cache..."
    Remove-Item "$($WSUSCache)\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    write-host "Start wuauserv again..."
    Start-Service -Name 'wuauserv'

    if (Test-Path -Path $WindowsOld) {
        Write-Host "Deleting folder C:\Windows.old..."
        Remove-Item "$($WindowsOld)\" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    }

    if (Test-Path -Path C:\'$Windows.~BT\') {
        takeown /F C:\'$Windows.~BT\*' /R /A
        icacls C:\'$Windows.~BT\*.*' /T /grant administrators:F
        Write-Host "Deleting folder C:\Windows.~BT\..."
        Remove-Item C:\'$Windows.~BT\' -Recurse -Force -Confirm:$False -ErrorAction SilentlyContinue
    }

    if (Test-Path -Path C:\'$Windows.~WS\') {
        takeown /F C:\'$Windows.~WS\*' /R /A
        icacls C:\'$Windows.~WS\*.*' /T /grant administrators:F
        Write-Host "Deleting folder C:\Windows.~WS\..."
        Remove-Item C:\'$Windows.~WS\' -Recurse -Force -Confirm:$False -ErrorAction SilentlyContinue
    }
}
if ($ActiveEventLog -eq "True") {
    Write-EventLog -LogName $EventLogName -Source "TempFileCleaning" -EventID 10 -EntryType Information -Message "$($User) did run the CleanClient script on $($CleanComputer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
}
Write-Host "Everything is now done, you can close the window!"