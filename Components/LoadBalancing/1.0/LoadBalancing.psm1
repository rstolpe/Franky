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

<#
Change the Host1 etc. to the right hostname it should NOT be FQDN. Create one AppToken on each PowerShell Universal server
and remember the expiration date if you don't set it to never expire.
Then paste it inside matching hostname below inside the ""
#>
function Get-AppToken {
    $CurrentHostName = [System.Net.Dns]::GetHostName()

    switch ($CurrentHostName) {
        Host1 {
            [PSCustomObject]@{
                CurrentAppToken = ""
            }
        }
        Host2 {
            [PSCustomObject]@{
                CurrentAppToken = ""
            }
        }
        Host3 {
            [PSCustomObject]@{
                CurrentAppToken = ""
            }
        }
    }
}

Export-ModuleMember -Function "Get-AppToken"