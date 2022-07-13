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

#If you want to run PS5.1 just remove the # at the line below and put # in front of the second line.
# New-PSUEnvironment -Name "Franky" -Version "5.1" -Path "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Modules @('ActiveDirectory', 'ImportExcel') -Variables @('EventLogName', 'DashboardName', 'YourDomain', 'YourFullDomain', 'AccessPort', 'OUComputerPath', 'OUGrpPath', 'OUUsrPath', 'UDScriptRoot', 'NavBarLogo', 'UploadTemp')
New-PSUEnvironment -Name "Franky" -Version "7.2.5" -Path "C:\Program Files\PowerShell\7\pwsh.exe" -Modules @('ImportExcel') -Variables @('ActivateLoadBalancing', 'EventLogName', 'DashboardName', 'YourDomain', 'YourFullDomain', 'AccessPort', 'OUComputerPath', 'OUGrpPath', 'OUUsrPath', 'UDScriptRoot', 'NavBarLogo', 'UploadTemp')