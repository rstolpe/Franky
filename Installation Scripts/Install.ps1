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

$Today = Get-Date
$CollectPSVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Patch)"
$NeededPSVersion = "7.2.5"
$DownloadPSSource = "https://github.com/PowerShell/PowerShell/releases/download/v7.2.5/PowerShell-7.2.5-win-x64.msi"
$DestinationPS = "C:\Temp\PowerShell-7.2.5-win-x64.msi"
$GroupsToCreate = @("Franky.Access", "Franky", "Franky.PowerUser", "Franky.Operator", "Franky.Administrator", "Franky.Execute", "Franky.Reader")
$NeededModules = @("ImportExcel", "Microsoft.Graph", "VMWare.PowerCLI")
# Update NeededModules to PSCustomObject with modulename and version number
$DownloadLatestFranky = "https://github.com/rstolpe/Franky/archive/refs/tags/v1.0-Beta2.2.zip"
$DestinationFranky = "C:\Temp\Franky-$($Today.ToString("yyyy-MM-dd")).zip"
$UnzippedFolderName = "Franky-1.0-Beta2.2"
$DownloadPSU = "https://imsreleases.blob.core.windows.net/universal/production/3.0.6/PowerShellUniversal.3.0.6.msi"
$DestinationPSU = "C:\Temp\PowerShellUniversal.3.0.6.msi"
$EventSources = @("CreatedUser", "CompareUserADGroups", "ReportAccountExpiredUsers", "ShowMemberOf", "ReportDisabledComputer", "ReportEmptyGroups", "ReportPasswordExpiredUsers", "ReportLockedUsers", "ReportDisabledUsers", "CreateUser", "ChangeComputerPrimaryGroup", "ChangeUserPrimaryGroup", "ChangeUserUPN", "CreatedComputer", "ChangeUserHomeDrive", "ChangeUserHomeDirectory", "ChangeUserScriptPath", "ChangeUserProfilePath", "DeleteChromeSettings", "DeleteEdgeSettings", "ClearGroupInfo", "ClearUserMail", "ClearGroupMail", "ClearComputerMail", "ClearComputerManagedBy", "ClearGroupManagedBy", "ClearGroupDescription", "ClearComputerDescription", "ClearUserDescription", "ClearUserManager", "ClearUserOffice", "ClearUserDepartment", "ClearUserDivision", "ClearUserTitle", "ClearUserCompany", "ClearUserGivenname", "ClearUserSurname", "ClearUserPostalCode", "ClearUserCity", "ClearUserState", "ClearUserPOBOX", "ClearUserStreetAddress", "ClearUserFAX", "ClearUserOfficePhone", "ClearUserMobilePhone", "ClearUserHomePhone", "ClearUserEmailAddress", "ChangeUserManager", "ChangeUserOffice", "ChangeUserDepartment", "ChangeUserDivision", "ChangeUserTitle", "ChangeUserCompany", "ChangeUserGivenname", "ChangeUserSurname", "ChangeUserPostalCode", "ChangeUserCity", "ChangeUserState", "ChangeUserPOBOX", "ChangeUserStreetAddress", "ChangeUserFAX", "ChangeUserOfficePhone", "ChangeUserMobilePhone", "ChangeUserHomePhone", "ChangeUserEmailAddress", "RemoveUserAsManagerFromObject", "ShowWhatUserManaging", "RemovedManageByFromGroup", "RemovedManageByFromComputer", "ChangeServiceStartUp", "EnableSchedualTask", "DisableSchedualTask", "RunSchedualTask", "CreateComputer", "SendPing", "LoginFailed", "CreateUser", "MoveUserObject", "SetUserChangePasswordNextLogin", "SetUserCannotChangePassword", "SetUserPasswordExpires", "UserSearch", "MoveComputerObject", "TempFileCleaning", "ChangeExperationDateForUser", "ChangePasswordForUser", "UnlockUserAccount", "RestartServices", "GroupSearch", "AddToGroup", "RemoveFromGroup", "DeleteGroup", "DeleteUser", "DeleteComputer", "EditGroupInfo", "ChangeGroupManagedBy", "ChangeUserDescription", "ChangeGroupDescription", "ChangeComputerDescription", "ChangeUserMail", "ChangeGroupMail", "ChangeComputerMail", "ChangeGroupSamAccountName", "ChangeGroupCN", "ChangeGroupDisplayName", "ChangeGroupScope", "ChangeGroupCategory", "CreatedGroup", "ComputerSearch", "LogOutUser", "RebootComputer", "ShowMonitorInfo", "ShowInstalledDrivers", "ShowNetworkAdapters", "ShowProcess", "ShowInstalledSoftware", "ShowAutostart", "ShowServices", "ShowSchedualTask", "DisableNetworkAdapter", "EnableNetworkAdapter", "RestartNetworkAdapter", "KillProcess", "StopServices", "StartServices", "DeletedUserProfile", "CompareComputerADGroups", "DisableComputerObject", "EnableComputerObject", "DisableUserObject", "EnableUserObject", "ChangeComputerCN", "ChangeComputerSamAccountName", "ChangeComputerDisplayName", "ChangeUserCN", "ChangeUserSamAccountName", "ChangeUserDisplayName", "ChangeComputerManagedBy", "ShowComputerUserProfiles")

Function Test-NeededThings {
    Write-Host "`n=== Checking if Active Directory module are installed ===`n"
    if (-Not(Get-Module -ListAvailable -Name "ActiveDirectory")) {
        Throw "ActiveDirectory module are not installed, you need to install RSAT before you can use this script"
    }

    if (-Not(Test-Path -Path "C:\Temp")) {
        New-Item "C:\Temp" -Type Directory
    }

    Write-Host "`n=== Checking if right PowerShell version are installed ===`n"
    if ($NeededPSVersion -ne $CollectPSVersion) {
        Write-Host "You don't have the correct version of PowerShell installed, downloading it now to C:\Temp, Please install PowerShell and then run this script again"
        Invoke-WebRequest -Uri $DownloadPSSource -OutFile $DestinationPS
        Exit
    }
    else {
        Write-Host "The correct PowerShell version are installed, continuing the script" -ForegroundColor Green
    }

    Start-FrankyPrompt
}

Function Show-FrankyInstall {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][Int]$Install,
        [Parameter(Mandatory)][String]$FQDN,
        [Parameter(Mandatory)][String]$PathDefaultGroupsOU,
        [Parameter(Mandatory)][String]$UserToAddAsAdmin
    )

    Write-Host "=== Installing/updating modules that are needed ===`n"
    foreach ($m in $NeededModules) {
        if (Get-Module -ListAvailable -Name $m) {
            # Check so the version number is the accepted one, if not update the module
        }
        else {
            Write-Host "Installing module $m as it's missing..."
            try {
                Install-Module -Name $m -Force
                Write-Host "$m is now installed!" -ForegroundColor Green
            }
            catch {
                write-Host "Could not install $($m)" -ForegroundColor Red
                Write-Host "$($PSItem.Exception.Message)" -ForegroundColor Red
                Break
            }
        }
    }

    if ($Install -eq "1") {
        try {
            $DNSDomain = (Get-ADDomain).DNSroot
        }
        catch {
            Write-Error "$($PSItem.Exception.Message)" -ForegroundColor Red
            Throw "Can't get the DNSroot, exiting the script!"
        }


        Write-Host "`n=== Creating needed groups and adding them correctly ===`n"
        foreach ($grp in $GroupsToCreate) {
            try {
                New-ADGroup -Name $grp -Path $PathDefaultGroupsOU -GroupCategory Security -GroupScope Global -DisplayName $grp
                Write-Host "Successfully created group $grp" -ForegroundColor Green
            }
            catch {
                Write-Error "$($PSItem.Exception.Message)" -ForegroundColor Red
                Throw "Can't create groups, exiting the script"
            }
        }
        foreach ($grps in $GroupsToCreate) {
            if ($grps -notlike "Franky.Access") {
                try {
                    Add-ADGroupMember -Identity "Franky.Access" -Members $grps
                    Write-Host "Successfully added $grps to Franky.Access" -ForegroundColor Green
                }
                catch {
                    Write-Error "$($PSItem.Exception.Message)" -ForegroundColor Red
                    Write-Error "Could not add $grps to Franky.Access, it's not critical so continuing the script. Remember to add $grps to Franky.Access later!" -ForegroundColor Red
                    continue
                }
            }
        }

        Write-Host "`n=== Adding user to Franky.Administrator group ===`n"
        try {
            Write-Host "Adding $UserToAddAsAdmin to Franky.Administrator..."
            Add-ADGroupMember -Identity "Franky.Administrator" -Members $UserToAddAsAdmin
            Write-Host "Successfully added $UserToAddAsAdmin to Franky.Administrator" -ForegroundColor Green
        }
        Catch {
            Write-Error "$($PSItem.Exception.Message)" -ForegroundColor Red
            Write-Error "Could not add $UserToAddAsAdmin to Franky.Administrator, it's not critical so continuing the script. Remember to add $UserToAddAsAdmin to Franky.Administrator later!" -ForegroundColor Red
            continue
        }

        Write-Host "`n=== Opening port 80 and 443 in Windows Firewall ===`n"
        try {
            New-NetFirewallRule -Name "Allow PowerShell Universal port 80 and 443" -DisplayName "Allow PowerShell Universal port 80 and 443" -Program "C:\Program Files (x86)\Universal\Universal.Server.exe" -Direction Inbound -LocalPort 80, 443 -Protocol TCP
            Write-Host "Successfully opened port 80 and 443 in Windows Firewall" -ForegroundColor Green
        }
        catch {
            Write-Error "$($PSItem.Exception.Message)" -ForegroundColor Red
            Write-Error "Could not open port 80 and 443 in Windows Firewall, it's not critical so continuing the script but remember to open the ports later!" -ForegroundColor Red
            continue
        }

        Write-Host "`n=== Creating new certification ===`n"
        try {
            Write-Host "Creating self signed certification"
            New-SelfSignedCertificate -DnsName $DNSDomain, $FQDN -CertStoreLocation "cert:\LocalMachine\My"
            Write-Host "Successfully created self signed certification" -ForegroundColor Green
            Write-Host "If you forget to save it, it's stored in C:\Temp\ remember to delete the file when your done!`n"
        }
        Catch {
            Write-Error "Something went wrong when trying to create self signed certification" -ForegroundColor Red
            Write-Error "$($PSItem.Exception.Message)" -ForegroundColor Red
            Break
        }

        Write-Host "`n== Information ==`n"
        Write-Host "Add the following to appsettings.json row 10, replace Franky.com with the following."
        Write-Output "$($DNSDomain)"
        Write-Host "Here is the SID of Franky.Access you need to add that to authentication.ps1"
        Get-AdGroup -Identity "Franky.Access" -properties SID | Select-Object SID
    }

    Write-Host "`n== Adding sources to Franky in EventLog ==`n"
    Write-Host "Starting to add..."
    foreach ($source in $EventSources) {
        New-EventLog -Source $source -LogName "Franky" -erroraction 'silentlycontinue'
    }
    Write-Host "Every source is added" -ForegroundColor Green

    Write-Host "`n== Downloading latest version of Franky ==`n"
    Write-Host "Downloading Franky to C:\Temp"
    Invoke-WebRequest -Uri $DownloadLatestFranky -OutFile $DestinationFranky
    Write-Host "Franky is downloaded" -ForegroundColor Green
    Write-Host "Unzipping Franky..."
    Expand-Archive -Path $DestinationFranky -DestinationPath "C:\Temp\"
    Write-Host "Franky is unzipped" -ForegroundColor Green
    if ($Install -eq "1") {
        # Copy all files to the correct destination
        # $UnzippedFolderName is the name of the folder where it has been saved in
    }
    elseif ($Install -eq "2") {
        # Prompt and ask if they want to copy all the Franky files to PSU.
    }

    if ($Install -eq "1") {
        Write-Host "`n== Creating the configuration files ==`n"
        # Write the configuration files
    }

    Write-Host "`n== Downloading latest supported version of PowerShell Universal ==`n"
    Write-Host "Downloading PowerShell Universal to C:\Temp"
    Invoke-WebRequest -Uri $DownloadPSU -OutFile $DestinationPSU
    Write-Host "PowerShell Universal is downloaded" -ForegroundColor Green
    Write-Host "Now you just need to install PowerShell Universal and your all set!" -ForegroundColor Green
}

Function Start-FrankyPrompt {
    Write-Host "== Installation script for Franky ==`n"
    Write-Host "Press '1' to install"
    Write-Host "Press '2' to upgrade"
    Write-Host "Press 'Q' to quit"
    do {
        $WhatToDo = Read-Host "What do you want to do?"
        if ($WhatToDo -eq "Q") {
            exit
        }
    } until ($WhatToDo -eq 1 -or $WhatToDo -eq 2)

    $FQDN = Read-Host "Enter your FQDN for Franky, for example psu.stolpe.io"

    do {
        $PathDefaultGroupsOU = Read-Host "Write the OU path to where your saving your groups for example OU=Groups,DC=psu,DC=keepcodeopen,DC=com"
        $CheckOUPath = $(try { Get-ADOrganizationalUnit -Identity $PathDefaultGroupsOU } catch { $Null })
        if ($Null -eq $CheckOUPath) {
            Write-Host "The OU path $CheckOUPath did not exist, please try again"
        }
    } until ($Null -ne $CheckOUPath)

    do {
        $UserToAddAsAdmin = Read-Host "Write the username of the user you want to be admin over Franky"
        $CheckAdminUser = $(try { Get-ADUser -Filter "samaccountname -eq '$($UserToAddAsAdmin)'" } catch { $Null })
        if ($Null -eq $CheckAdminUser) {
            Write-Host "User $CheckAdminUser did not exist in the AD, please try an other username"
        }
    } until ($Null -ne $CheckAdminUser)
    Write-Host "`n"
    Show-FrankyInstall -Install $WhatToDo -FQDN $FQDN -PathDefaultGroupsOU $PathDefaultGroupsOU -UserToAddAsAdmin $UserToAddAsAdmin
}

Test-NeededThings