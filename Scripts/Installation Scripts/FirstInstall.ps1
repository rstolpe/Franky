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

# You should run this script after you have installed PowerShell Universal on your host
# Run the script on your host.

#Write the path to your OU where you have your groups.
$PathDefaultGroupsOU = ""
# Write the username of the user that you want to be admin over Franky
$UserToAddAsAdmin = ""
# Write your FQDN for your PSU server for example psu.keepcodeopen.com
$FQDN = ""
# Write your domain only for example keepcodeopen.com
$DNSDomain = ""

$GroupsToCreate = @("Franky.Access", "Franky", "Franky.PowerUser", "Franky.Operator", "Franky.Administrator", "Franky.Execute", "Franky.Reader")

Write-Output "Installing modules that you need..."
Install-Module ImportExcel -Force
Install-Module Microsoft.Graph -Force
Install-Module VMWare.PowerCli -Force

Write-output "Creating needed groups and setting it up..."
foreach ($grp in $GroupsToCreate) {
    New-ADGroup -Name $grp -Path $PathDefaultGroupsOU -GroupCategory Security -GroupScope Global -DisplayName $grp
}
foreach ($grps in $GroupsToCreate) {
    if ($grps -notlike "Franky.Access") {
        Add-ADGroupMember -Identity "Franky.Access" -Members $grps
    }
}

Write-Output "Adding user to Franky.Administrator group..."
Add-ADGroupMember -Identity "Franky.Administrator" -Members $UserToAddAsAdmin

Write-output "Opening port 80 and 443 on the server..."
New-NetFirewallRule -Name "Allow PowerShell Universal port 80 and 443" -DisplayName "Allow PowerShell Universal port 80 and 443" -Program "C:\Program Files (x86)\Universal\Universal.Server.exe" -Direction Inbound -LocalPort 80, 443 -Protocol TCP

Write-Output "Creating new certification..."
New-SelfSignedCertificate -DnsName $DNSDomain, $FQDN -CertStoreLocation "cert:\LocalMachine\My"

Write-output "You need to save the following and follow the instructions!"
Write-output "If you forget to save it, it's stored in C:\Temp\ remember to delete the file when your done!"

Write-Output "Add the following to appsettings.json row 10, replace Franky.com with the following."
Write-Output "$($DNSDomain)"

Write-output "Here is the SID of Franky.Access you need to add that to authentication.ps1"
Get-AdGroup -Identity "Franky.Access" -properties SID | Select-Object SID