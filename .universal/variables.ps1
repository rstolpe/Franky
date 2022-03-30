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
#
# Variables for logging
New-PSUVariable -Name "EventLogName" -Value "Franky" -Description "Write the name you want for the EventLog"
New-PSUVariable -Name "ActiveEventLog" -Value $True -Type "Bool" -Description "Activate logging to EventLog"

# Variables for the dashboard
New-PSUVariable -Name "DashboardName" -Value "Franky" -Description "The name you want for the dashboard"
New-PSUVariable -Name "NavBarLogo" -Value "/pictures/" -Description "Path to the logo"
New-PSUVariable -Name "UDScriptRoot" -Value "C:\ProgramData\UniversalAutomation\Repository\Dashboards" -Description "Path to where you save your pages"

# Variables for domain settings
New-PSUVariable -Name "YourDomain" -Value "localhost" -Description "Your short domain for example FR and NOT the full one like FR.se"
New-PSUVariable -Name "YourFullDomain" -Value "localhost" -Description "Your full domain for example FR.se NOT only FR"
New-PSUVariable -Name "AccessPort" -Value "5000" -Description "Enter the port that you use to access Franky/PSU WebGUI"

# Variables for OU etc.
New-PSUVariable -Name "OUComputerPath" -Value "OUPath" -Description "OU path to where you have your Computer objects"
New-PSUVariable -Name "OUGrpPath" -Value "OUPath" -Description "OU path to where you have your group objects"
New-PSUVariable -Name "OUUsrPath" -Value "OUUsrPath" -Description "OU path to where you have your user objects"

# Temp folder for uploaded files
New-PSUVariable -Name "UploadTemp" -Value "C:\Temp\" -Description "Path to folder where uploaded temp files are stored"